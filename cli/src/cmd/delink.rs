use std::{
    collections::BTreeMap,
    io::BufWriter,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::Args;
use ds_decomp::config::{
    config::{Config, ConfigModule},
    delinks::{DelinkFile, Delinks},
    module::{Module, ModuleKind},
    relocations::RelocationKind,
    section::{DTCM_SECTION, SectionKind},
    symbol::{InstructionMode, SymFunction, SymbolKind, SymbolMaps},
};
use ds_rom::rom::{Rom, RomLoadOptions, raw::AutoloadKind};
use object::{Architecture, BinaryFormat, Endianness, RelocationFlags};

use super::Lcf;
use crate::{
    config::{
        delinks::DelinksExt,
        relocation::{RelocationKindExt, RelocationModuleExt},
        section::SectionExt,
        symbol::{SymbolExt, SymbolKindExt},
    },
    util::io::{create_dir_all, create_file},
};

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

struct Delinker<'a> {
    config_path: PathBuf,
    config: &'a Config,
    rom: Rom<'a>,
    symbol_maps: SymbolMaps,
    elf_path: PathBuf,
    all_mapping_symbols: bool,
    dtcm_end: u32,
}

impl Delink {
    pub fn run(&self) -> Result<()> {
        let config = Config::from_file(&self.config_path)?;
        let config_path = self.config_path.parent().unwrap().to_path_buf();

        let symbol_maps = SymbolMaps::from_config(&config_path, &config)?;
        let rom = Rom::load(config_path.join(&config.rom_config), RomLoadOptions {
            key: None,
            compress: false,
            encrypt: false,
            load_files: false,
            load_header: false,
            load_banner: false,
            load_multiboot_signature: false,
        })?;
        let dtcm_end = rom
            .arm9()
            .autoloads()?
            .iter()
            .find_map(|a| (a.kind() == AutoloadKind::Dtcm).then_some(a.end_address()))
            .context("Failed to find end address of DTCM autoload")?;

        let elf_path = config_path.join(&config.delinks_path);

        let mut delinker = Delinker {
            config: &config,
            config_path,
            rom,
            symbol_maps,
            elf_path,
            all_mapping_symbols: self.all_mapping_symbols,
            dtcm_end,
        };

        delinker.delink_module(&config.main_module, ModuleKind::Arm9)?;
        for autoload in &config.autoloads {
            delinker.delink_module(&autoload.module, ModuleKind::Autoload(autoload.kind))?;
        }
        for overlay in &config.overlays {
            delinker.delink_module(&overlay.module, ModuleKind::Overlay(overlay.id))?;
        }

        Ok(())
    }
}

impl<'a> Delinker<'a> {
    fn delink_module(&mut self, module_config: &ConfigModule, kind: ModuleKind) -> Result<()> {
        let delinks = if kind == ModuleKind::Autoload(AutoloadKind::Dtcm) {
            Delinks::new_dtcm(&self.config_path, self.config, module_config)?
        } else {
            Delinks::from_file_and_generate_gaps(self.config_path.join(&module_config.delinks), kind)?
        };

        let module = self.config.load_module(&self.config_path, &mut self.symbol_maps, kind, &self.rom)?;
        let symbol_map = self.symbol_maps.get(kind).unwrap();

        for file in &delinks.files {
            for section in file.sections.iter() {
                let (symbol_map, section_end) = if section.name() == DTCM_SECTION {
                    (self.symbol_maps.get(ModuleKind::Autoload(AutoloadKind::Dtcm)).unwrap(), self.dtcm_end)
                } else {
                    let (_, module_section) = module.sections().by_name(section.name()).unwrap();
                    (symbol_map, module_section.end_address())
                };

                if let Some((symbol, size)) = symbol_map.get_symbol_containing(section.end_address() - 1, section_end)?
                    && symbol.addr >= section.start_address()
                    && symbol.addr < section.end_address()
                    && symbol.addr + size > section.end_address()
                {
                    bail!(
                        "Last symbol '{}' in section '{}' of file '{}' has the range {:#010x}..{:#010x} but is not contained within the file's section range ({:#010x}..{:#010x})",
                        symbol.name,
                        section.name(),
                        file.name,
                        symbol.addr,
                        symbol.addr + size,
                        section.start_address(),
                        section.end_address(),
                    );
                }
            }

            let (file_path, _) = file.split_file_ext();
            self.create_elf_file(&module, file, self.elf_path.join(format!("{file_path}.o")))?;
        }

        Ok(())
    }

    fn create_elf_file<P: AsRef<Path>>(&self, module: &Module, delink_file: &DelinkFile, path: P) -> Result<()> {
        let path = path.as_ref();

        create_dir_all(path.parent().unwrap())?;

        let object = self.delink(&self.symbol_maps, module, delink_file)?;
        let file = create_file(path)?;
        let writer = BufWriter::new(file);
        object.write_stream(writer).unwrap();

        Ok(())
    }

    fn delink(
        &self,
        symbol_maps: &SymbolMaps,
        module: &Module,
        delink_file: &DelinkFile,
    ) -> Result<object::write::Object<'_>> {
        let symbol_map = symbol_maps.get(module.kind()).unwrap();
        let dtcm_symbol_map = symbol_maps.get(ModuleKind::Autoload(AutoloadKind::Dtcm)).unwrap();
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
            if !file_section.kind().is_initialized() {
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
                kind: object::SymbolKind::Section,
                scope: object::SymbolScope::Compilation,
                weak: false,
                section: object::write::SymbolSection::Section(obj_section_id),
                flags: object::SymbolFlags::None,
            });

            // Add symbols to section
            let (search_symbol_map, symbol_module) = if file_section.name() == DTCM_SECTION {
                (dtcm_symbol_map, ModuleKind::Autoload(AutoloadKind::Dtcm))
            } else {
                (symbol_map, module.kind())
            };
            let mut symbols = search_symbol_map.iter_by_address(file_section.address_range()).filter(|s| !s.skip).peekable();
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

                let is_thumb = matches!(symbol.kind, SymbolKind::Function(SymFunction { mode: InstructionMode::Thumb, .. }));
                let thumb_bit = if is_thumb { 1 } else { 0 };
                obj_symbols.insert((symbol.addr | thumb_bit, symbol_module), symbol_id);

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
                    // Special case for overlay ID relocations
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
                    // Normal symbol relocation
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
                    if let Some(obj_symbol) = obj_symbols.get(&symbol_key) {
                        // Use existing symbol
                        *obj_symbol
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

                        if symbol.local {
                            let (reloc_base, offset) = relocation
                                .find_symbol_location(symbol_map)
                                .map(|(symbol, offset)| (symbol.name.as_str(), offset))
                                .unwrap_or(("<unknown>", 0));
                            log::error!(
                                "Imported symbol {} at {:#010x} in {} is local, it cannot be used in relocation from {:#010x} in {} ({} + {:#x})",
                                symbol.name,
                                dest_addr,
                                reloc_module,
                                relocation.from_address(),
                                module.kind(),
                                reloc_base,
                                offset,
                            );
                            error = true;
                            continue;
                        }

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
                object.add_relocation(obj_section_id, object::write::Relocation {
                    offset: offset as u64,
                    symbol: symbol_id,
                    addend,
                    flags: RelocationFlags::Elf { r_type },
                })?;
            }
        }

        if error {
            bail!("Failed to delink '{}', see errors above", delink_file.name);
        }

        Ok(object)
    }
}
