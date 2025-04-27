use std::{
    collections::BTreeMap,
    io::BufWriter,
    path::{Path, PathBuf},
};

use anyhow::{bail, Result};
use clap::Args;
use ds_decomp::config::{
    config::{Config, ConfigModule},
    delinks::{DelinkFile, Delinks},
    module::{Module, ModuleKind, ModuleOptions},
    relocations::{RelocationKind, Relocations},
    section::SectionKind,
    symbol::{SymbolKind, SymbolMaps},
};
use ds_rom::rom::{Rom, RomLoadOptions};
use object::{Architecture, BinaryFormat, Endianness, RelocationFlags};
use serde::Serialize;

use crate::{
    config::{
        delinks::DelinksExt,
        relocation::{RelocationKindExt, RelocationModuleExt},
        section::SectionExt,
        symbol::{SymbolExt, SymbolKindExt},
    },
    rom::rom::RomExt,
    util::{
        io::{create_dir_all, create_file},
        path::PathExt,
    },
};

use super::Lcf;

/// Delinks an extracted ROM into relocatable ELF files.
#[derive(Args)]
pub struct Delink {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    pub config_path: PathBuf,

    /// Emit all mapping symbols, not just code-related ones.
    #[arg(long, short = 'M')]
    pub all_mapping_symbols: bool,
}

#[derive(Default, Serialize)]
struct DelinkResult {
    num_files: usize,
    num_gaps: usize,
}

impl Delink {
    pub fn run(&self) -> Result<()> {
        let config = Config::from_file(&self.config_path)?;
        let config_path = self.config_path.parent().unwrap();

        let mut symbol_maps = SymbolMaps::from_config(config_path, &config)?;
        let rom = Rom::load(
            config_path.join(&config.rom_config),
            RomLoadOptions {
                key: None,
                compress: false,
                encrypt: false,
                load_files: false,
                load_header: false,
                load_banner: false,
            },
        )?;

        let elf_path = config_path.join(config.delinks_path);
        let mut result = DelinkResult::default();

        self.delink_module(&config.main_module, ModuleKind::Arm9, &rom, &elf_path, &mut symbol_maps, &mut result)?;
        for autoload in &config.autoloads {
            self.delink_module(
                &autoload.module,
                ModuleKind::Autoload(autoload.kind),
                &rom,
                &elf_path,
                &mut symbol_maps,
                &mut result,
            )?;
        }
        for overlay in &config.overlays {
            self.delink_module(
                &overlay.module,
                ModuleKind::Overlay(overlay.id),
                &rom,
                &elf_path,
                &mut symbol_maps,
                &mut result,
            )?;
        }

        serde_yml::to_writer(create_file(elf_path.normalize_join("delink.yaml")?)?, &result)?;

        Ok(())
    }

    fn delink_module(
        &self,
        config: &ConfigModule,
        kind: ModuleKind,
        rom: &Rom,
        elf_path: &Path,
        symbol_maps: &mut SymbolMaps,
        result: &mut DelinkResult,
    ) -> Result<()> {
        let config_path = self.config_path.parent().unwrap();

        let delinks = Delinks::from_file_and_generate_gaps(config_path.join(&config.delinks), kind)?;
        let symbol_map = symbol_maps.get_mut(kind);
        let relocations = Relocations::from_file(config_path.join(&config.relocations))?;

        let code = rom.get_code(kind)?;
        let module = Module::new(
            symbol_map,
            ModuleOptions {
                kind,
                name: config.name.clone(),
                relocations,
                sections: delinks.sections,
                code: &code,
                signed: false, // Doesn't matter, only used by `rom config` command
            },
        )?;

        for file in &delinks.files {
            let (file_path, _) = file.split_file_ext();
            self.create_elf_file(&module, file, elf_path.join(format!("{file_path}.o")), symbol_maps)?;

            if file.gap() {
                result.num_gaps += 1;
            } else {
                result.num_files += 1;
            }
        }

        Ok(())
    }

    fn create_elf_file<P: AsRef<Path>>(
        &self,
        module: &Module,
        delink_file: &DelinkFile,
        path: P,
        symbol_maps: &SymbolMaps,
    ) -> Result<()> {
        let path = path.as_ref();

        create_dir_all(path.parent().unwrap())?;

        let object = self.delink(symbol_maps, module, delink_file)?;
        let file = create_file(path)?;
        let writer = BufWriter::new(file);
        object.write_stream(writer).unwrap();

        Ok(())
    }

    fn delink<'a>(
        &self,
        symbol_maps: &SymbolMaps,
        module: &Module,
        delink_file: &DelinkFile,
    ) -> Result<object::write::Object<'a>> {
        let symbol_map = symbol_maps.get(module.kind()).unwrap();
        let mut object = object::write::Object::new(BinaryFormat::Elf, Architecture::Arm, Endianness::Little);
        object.elf_is_rela = Some(true);

        // Maps address to ObjSection/ObjSymbol
        let mut obj_sections = BTreeMap::new();
        let mut obj_symbols = BTreeMap::new();

        let mut error = false;

        for file_section in delink_file.sections.iter() {
            // Get section data
            let code = file_section.relocatable_code(module)?.unwrap_or_else(Vec::new);
            let name = file_section.name().as_bytes().to_vec();
            let kind = match file_section.kind() {
                SectionKind::Code => object::SectionKind::Text,
                SectionKind::Data => object::SectionKind::Data,
                SectionKind::Rodata => object::SectionKind::ReadOnlyData,
                SectionKind::Bss => object::SectionKind::UninitializedData,
            };

            // Create section
            let obj_section_id = object.add_section(vec![], name.clone(), kind);
            let section = object.section_mut(obj_section_id);
            if file_section.kind() == SectionKind::Bss {
                section.append_bss(file_section.size() as u64, 1);
            } else {
                let alignment = if file_section.kind().is_executable() { 4 } else { 1 };
                section.set_data(code, alignment);
            }

            // Add dummy symbol to make linker notice the section
            object.add_symbol(object::write::Symbol {
                name, // same name as section
                value: 0,
                size: 0,
                kind: object::SymbolKind::Label,
                scope: object::SymbolScope::Compilation,
                weak: false,
                section: object::write::SymbolSection::Section(obj_section_id),
                flags: object::SymbolFlags::None,
            });

            // Add symbols to section
            let mut symbols = symbol_map.iter_by_address(file_section.address_range()).peekable();
            while let Some(symbol) = symbols.next() {
                // Get symbol data
                let max_address = symbols.peek().map(|s| s.addr).unwrap_or(file_section.end_address());
                let kind = symbol.kind.as_obj_symbol_kind();
                let scope = symbol.get_obj_symbol_scope();
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

                if self.all_mapping_symbols
                    || matches!(symbol.kind, SymbolKind::Function(_) | SymbolKind::Label(_) | SymbolKind::PoolConstant)
                {
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

        // Maps overlay ID to ObjSymbol
        let mut overlay_id_symbols = BTreeMap::new();

        // Must start a new loop here so we can know which section a symbol ID belongs to
        for file_section in delink_file.sections.iter() {
            let obj_section_id = *obj_sections.get(&file_section.start_address()).unwrap();

            // Add relocations to section
            for (_, relocation) in module.relocations().iter_range(file_section.address_range()) {
                // Get relocation data
                let offset = relocation.from_address() - file_section.start_address();
                let dest_addr = relocation.to_address();

                let symbol_id = if relocation.kind() == RelocationKind::OverlayId {
                    let overlay_id = dest_addr;
                    if let Some(symbol_id) = overlay_id_symbols.get(&overlay_id) {
                        *symbol_id
                    } else {
                        // Create overlay ID symbol
                        let symbol_id = object.add_symbol(object::write::Symbol {
                            name: Lcf::overlay_id_symbol_name(overlay_id as u16).into_bytes(),
                            value: 0,
                            size: 0,
                            kind: object::SymbolKind::Unknown,
                            scope: object::SymbolScope::Compilation,
                            weak: false,
                            section: object::write::SymbolSection::Undefined,
                            flags: object::SymbolFlags::None,
                        });
                        overlay_id_symbols.insert(dest_addr, symbol_id);
                        symbol_id
                    }
                } else {
                    let Some(reloc_module) = relocation.module().first_module() else {
                        log::warn!(
                            "No module for relocation from {:#010x} in {} to {:#010x}",
                            relocation.from_address(),
                            module.kind(),
                            dest_addr,
                        );
                        continue;
                    };

                    // Get destination symbol
                    let symbol_key = (dest_addr, reloc_module);
                    if let Some(obj_symbol_id) = obj_symbols.get(&symbol_key) {
                        *obj_symbol_id
                    } else {
                        // Get external symbol data
                        let external_symbol_map = symbol_maps.get(reloc_module).unwrap();
                        let symbol = if let Some((_, symbol)) = external_symbol_map.first_at_address(dest_addr) {
                            symbol
                        } else if let Some((_, symbol)) = external_symbol_map.get_function(dest_addr)? {
                            symbol
                        } else {
                            log::error!(
                                "No symbol found for relocation from {:#010x} in {} to {:#010x} in {}",
                                relocation.from_address(),
                                module.kind(),
                                dest_addr,
                                reloc_module
                            );
                            error = true;
                            continue;
                        };

                        // Add external symbol to section
                        let kind = relocation.kind().as_obj_symbol_kind();
                        let symbol_section = object::write::SymbolSection::Undefined;
                        let symbol_id = object.add_symbol(object::write::Symbol {
                            name: symbol.name.clone().into_bytes(),
                            value: 0,
                            size: 0,
                            kind,
                            scope: object::SymbolScope::Compilation,
                            weak: true,
                            section: symbol_section,
                            flags: object::SymbolFlags::None,
                        });
                        obj_symbols.insert(symbol_key, symbol_id);
                        symbol_id
                    }
                };

                // Create relocation
                let r_type = relocation.kind().as_elf_relocation_type();
                let addend = relocation.addend();
                object.add_relocation(
                    obj_section_id,
                    object::write::Relocation {
                        offset: offset as u64,
                        symbol: symbol_id,
                        addend,
                        flags: RelocationFlags::Elf { r_type },
                    },
                )?;
            }
        }

        if error {
            bail!("Failed to delink '{}', see errors above", delink_file.name);
        }

        Ok(object)
    }
}
