use std::{
    collections::BTreeMap,
    io::BufWriter,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use argp::FromArgs;
use ds_rom::rom::{Rom, RomLoadOptions};
use object::{Architecture, BinaryFormat, Endianness, RelocationFlags};

use crate::{
    config::{
        config::{Config, ConfigAutoload, ConfigModule, ConfigOverlay},
        delinks::{DelinkFile, Delinks},
        module::{Module, ModuleKind},
        relocation::Relocations,
        section::SectionKind,
        symbol::SymbolMaps,
    },
    util::io::{create_dir_all, create_file, open_file},
};

/// Delinks an extracted ROM into relocatable ELF files.
#[derive(FromArgs)]
#[argp(subcommand, name = "delink")]
pub struct Delink {
    /// Path to config.yaml.
    #[argp(option, short = 'c')]
    config_path: PathBuf,

    /// ELF file output path.
    #[argp(option, short = 'e')]
    elf_path: PathBuf,
}

impl Delink {
    pub fn run(&self) -> Result<()> {
        let config: Config = serde_yml::from_reader(open_file(&self.config_path)?)?;
        let config_path = self.config_path.parent().unwrap();

        let mut symbol_maps = SymbolMaps::from_config(config_path, &config)?;
        let rom = Rom::load(
            config_path.join(&config.rom_config),
            RomLoadOptions { key: None, compress: false, encrypt: false, load_files: false },
        )?;

        self.delink_arm9(&config.main_module, &rom, &mut symbol_maps)?;
        self.disassemble_autoloads(&config.autoloads, &rom, &mut symbol_maps)?;
        self.disassemble_overlays(&config.overlays, &rom, &mut symbol_maps)?;

        Ok(())
    }

    fn delink_arm9(&self, config: &ConfigModule, rom: &Rom, symbol_maps: &mut SymbolMaps) -> Result<()> {
        let config_path = self.config_path.parent().unwrap();

        let module_kind = ModuleKind::Arm9;
        let delinks = Delinks::from_file(config_path.join(&config.delinks), module_kind)?;
        let symbol_map = symbol_maps.get_mut(module_kind);
        let relocations = Relocations::from_file(config_path.join(&config.relocations))?;

        let code = rom.arm9().code()?;
        let module = Module::new_arm9(config.name.clone(), symbol_map, relocations, delinks.sections, &code)?;

        for file in &delinks.files {
            let (file_path, _) = file.split_file_ext();
            Self::create_elf_file(&module, file, self.elf_path.join(format!("{}/{file_path}.o", config.name)), &symbol_maps)?;
        }

        Ok(())
    }

    fn disassemble_autoloads(&self, autoloads: &[ConfigAutoload], rom: &Rom, symbol_maps: &mut SymbolMaps) -> Result<()> {
        let rom_autoloads = rom.arm9().autoloads()?;
        for autoload in autoloads {
            let config_path = self.config_path.parent().unwrap();

            let module_kind = ModuleKind::Autoload(autoload.kind);
            let delinks = Delinks::from_file(config_path.join(&autoload.module.delinks), module_kind)?;
            let symbol_map = symbol_maps.get_mut(module_kind);
            let relocations = Relocations::from_file(config_path.join(&autoload.module.relocations))?;

            let code = rom_autoloads
                .iter()
                .find(|a| a.kind() == autoload.kind)
                .with_context(|| format!("Autoload {} not present in ROM", autoload.kind))?
                .code();
            let module = Module::new_autoload(
                autoload.module.name.clone(),
                symbol_map,
                relocations,
                delinks.sections,
                autoload.kind,
                &code,
            )?;

            for file in &delinks.files {
                let (file_path, _) = file.split_file_ext();
                Self::create_elf_file(
                    &module,
                    file,
                    self.elf_path.join(format!("{}/{file_path}.o", autoload.module.name)),
                    &symbol_maps,
                )?;
            }
        }

        Ok(())
    }

    fn disassemble_overlays(&self, overlays: &[ConfigOverlay], rom: &Rom, symbol_maps: &mut SymbolMaps) -> Result<()> {
        let config_path = self.config_path.parent().unwrap();

        for overlay in overlays {
            let module_kind = ModuleKind::Overlay(overlay.id);
            let delinks = Delinks::from_file(config_path.join(&overlay.module.delinks), module_kind)?;
            let symbol_map = symbol_maps.get_mut(module_kind);
            let relocations = Relocations::from_file(config_path.join(&overlay.module.relocations))?;

            let code = rom.arm9_overlays()[overlay.id as usize].code();
            let module = Module::new_overlay(
                overlay.module.name.clone(),
                symbol_map,
                relocations,
                delinks.sections,
                overlay.id,
                &code,
            )?;

            for file in &delinks.files {
                let (file_path, _) = file.split_file_ext();
                Self::create_elf_file(
                    &module,
                    file,
                    self.elf_path.join(format!("{}/{file_path}.o", overlay.module.name)),
                    &symbol_maps,
                )?;
            }
        }

        Ok(())
    }

    fn create_elf_file<P: AsRef<Path>>(
        module: &Module,
        delink_file: &DelinkFile,
        path: P,
        symbol_maps: &SymbolMaps,
    ) -> Result<()> {
        let path = path.as_ref();

        create_dir_all(path.parent().unwrap())?;

        let object = Self::delink(symbol_maps, module, delink_file)?;
        let file = create_file(path)?;
        let writer = BufWriter::new(file);
        object.write_stream(writer).unwrap();

        Ok(())
    }

    fn delink<'a>(symbol_maps: &SymbolMaps, module: &Module, delink_file: &DelinkFile) -> Result<object::write::Object<'a>> {
        let symbol_map = symbol_maps.get(module.kind()).unwrap();
        let mut object = object::write::Object::new(BinaryFormat::Elf, Architecture::Arm, Endianness::Little);

        // Maps address to ObjSection/ObjSymbol
        let mut obj_sections = BTreeMap::new();
        let mut obj_symbols = BTreeMap::new();

        for file_section in delink_file.sections.iter() {
            // Get section data
            let code = file_section.relocatable_code(module)?.unwrap_or_else(|| vec![]);
            let name = file_section.name().as_bytes().to_vec();
            let kind = match file_section.kind() {
                SectionKind::Code => object::SectionKind::Text,
                SectionKind::Data => object::SectionKind::Data, // TODO: use ReadOnlyData if .rodata?
                SectionKind::Bss => object::SectionKind::UninitializedData,
            };

            // Create section
            let obj_section_id = object.add_section(vec![], name, kind);
            let section = object.section_mut(obj_section_id);
            if file_section.kind() == SectionKind::Bss {
                section.append_bss(file_section.size() as u64, file_section.alignment() as u64);
            } else {
                section.set_data(code, file_section.alignment() as u64);
            }

            // Add symbols to section
            let mut symbols = symbol_map.iter_by_address(file_section.address_range()).peekable();
            while let Some(symbol) = symbols.next() {
                // Get symbol data
                let max_address = symbols.peek().map(|s| s.addr).unwrap_or(file_section.end_address());
                let kind = symbol.kind.into_obj_symbol_kind();
                let scope = symbol.kind.into_obj_symbol_scope();
                let value = (symbol.addr - file_section.start_address()) as u64;

                // Create symbol
                let symbol_section = object::write::SymbolSection::Section(obj_section_id);
                let symbol_id = object.add_symbol(object::write::Symbol {
                    name: symbol.name.clone().into_bytes(),
                    value,
                    size: symbol.size(max_address) as u64,
                    kind,
                    scope,
                    weak: false,
                    section: symbol_section,
                    flags: object::SymbolFlags::None,
                });
                obj_symbols.insert((symbol.addr, module.kind()), symbol_id);

                if file_section.kind() == SectionKind::Code {
                    // Create mapping symbol
                    if let Some(name) = symbol.mapping_symbol_name() {
                        object.add_symbol(object::write::Symbol {
                            name: name.to_string().into_bytes(),
                            value,
                            size: 0,
                            kind: object::SymbolKind::Label,
                            scope: object::SymbolScope::Compilation,
                            weak: false,
                            section: symbol_section,
                            flags: object::SymbolFlags::None,
                        });
                    }
                }
            }

            obj_sections.insert(file_section.start_address(), obj_section_id);
        }

        // Must start a new loop here so we can know which section a symbol ID belongs to
        for file_section in delink_file.sections.iter() {
            let obj_section_id = *obj_sections.get(&file_section.start_address()).unwrap();

            // Add relocations to section
            for (_, relocation) in module.relocations().iter_range(file_section.address_range()) {
                // Get relocation data
                let offset = relocation.from_address() - file_section.start_address();
                let dest_addr = relocation.to_address();
                let reloc_module = relocation.module().first_module().unwrap();

                // Get destination symbol
                let symbol_key = (dest_addr, reloc_module);
                let symbol_id = if let Some(obj_symbol_id) = obj_symbols.get(&symbol_key) {
                    *obj_symbol_id
                } else {
                    // Get external symbol data
                    let external_symbol_map = symbol_maps.get(reloc_module).unwrap();
                    let symbol = if let Some((_, symbol)) = external_symbol_map.by_address(dest_addr)? {
                        symbol
                    } else if let Some((_, symbol)) = external_symbol_map.get_function(dest_addr)? {
                        symbol
                    } else {
                        log::error!(
                            "No symbol found for relocation from 0x{:08x} in {} to 0x{:08x} in {}",
                            relocation.from_address(),
                            module.kind(),
                            dest_addr,
                            reloc_module
                        );
                        bail!("No symbol found for relocation",)
                    };

                    // Add external symbol to section
                    let kind = relocation.kind().into_obj_symbol_kind();
                    let symbol_section = object::write::SymbolSection::Undefined;
                    let symbol_id = object.add_symbol(object::write::Symbol {
                        name: symbol.name.clone().into_bytes(),
                        value: 0,
                        size: 0,
                        kind,
                        scope: object::SymbolScope::Compilation,
                        weak: false,
                        section: symbol_section,
                        flags: object::SymbolFlags::None,
                    });
                    obj_symbols.insert(symbol_key, symbol_id);
                    symbol_id
                };

                // Create relocation
                let r_type = relocation.kind().into_elf_relocation_type();
                object.add_relocation(
                    obj_section_id,
                    object::write::Relocation {
                        offset: offset as u64,
                        symbol: symbol_id,
                        addend: 0,
                        flags: RelocationFlags::Elf { r_type },
                    },
                )?;
            }
        }
        Ok(object)
    }
}
