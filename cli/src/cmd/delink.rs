use std::{
    collections::BTreeMap,
    io::BufWriter,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, bail};
use clap::Args;
use ds_decomp::config::{
    config::Config,
    delinks::{DelinkFile, Delinks},
    module::ModuleKind,
    relocations::RelocationKind,
    section::{MigrateSection, Section, SectionKind},
    symbol::{InstructionMode, SymFunction, SymbolKind},
};
use ds_rom::rom::{Rom, RomLoadOptions, raw::AutoloadKind};
use object::{Architecture, BinaryFormat, Endianness, RelocationFlags};

use super::Lcf;
use crate::{
    config::{
        delinks::{DelinksMap, DelinksMapOptions},
        program::Program,
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
    rom: Rom<'a>,
    program: Program,
    elf_path: PathBuf,
    all_mapping_symbols: bool,
}

impl Delink {
    pub fn run(&self) -> Result<()> {
        let config = Config::from_file(&self.config_path)?;
        let config_path = self.config_path.parent().unwrap();

        let delinks_map = DelinksMap::from_config(&config, config_path, DelinksMapOptions { migrate_sections: true })?;

        let rom = Rom::load(config_path.join(&config.rom_config), RomLoadOptions {
            key: None,
            compress: false,
            encrypt: false,
            load_files: false,
            load_header: false,
            load_banner: false,
            load_multiboot_signature: false,
        })?;

        let elf_path = config_path.join(&config.delinks_path);

        let program = Program::from_config(config_path, &config, &rom)?;
        let mut delinker = Delinker { rom, program, elf_path, all_mapping_symbols: self.all_mapping_symbols };

        for delinks in delinks_map.iter() {
            delinker.delink_module(delinks)?;
        }

        Ok(())
    }
}

impl<'a> Delinker<'a> {
    fn delink_module(&mut self, delinks: &Delinks) -> Result<()> {
        let symbol_map = self.program.symbol_maps().get(delinks.module_kind()).unwrap();

        for file in &delinks.files {
            if file.sections.len() > 0 && file.sections.iter().all(|s| s.migration().is_some()) {
                // File was migrated, it will be delinked from its source module
                continue;
            }

            for section in file.sections.iter() {
                let module = self.program.by_module_kind(delinks.module_kind()).unwrap();
                let (symbol_map, section_end) = match MigrateSection::parse(section.name())? {
                    Some(migrate_section) => {
                        let autoload_kind = match migrate_section {
                            MigrateSection::Dtcm => AutoloadKind::Dtcm,
                            MigrateSection::Itcm => AutoloadKind::Itcm,
                            MigrateSection::AutoloadData(index) | MigrateSection::AutoloadBss(index) => {
                                AutoloadKind::Unknown(index)
                            }
                        };
                        let autoload_end = self
                            .rom
                            .arm9()
                            .autoloads()?
                            .iter()
                            .find_map(|a| (a.kind() == autoload_kind).then_some(a.end_address()))
                            .context("Failed to find end address of DTCM autoload")?;
                        (self.program.symbol_maps().get(ModuleKind::Autoload(autoload_kind)).unwrap(), autoload_end)
                    }
                    None => {
                        let (_, module_section) = module.sections().by_name(section.name()).unwrap();
                        (symbol_map, module_section.end_address())
                    }
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
            self.create_elf_file(file, delinks.module_kind(), self.elf_path.join(format!("{file_path}.o")))?;
        }

        Ok(())
    }

    fn create_elf_file<P: AsRef<Path>>(&self, delink_file: &DelinkFile, module_kind: ModuleKind, path: P) -> Result<()> {
        let path = path.as_ref();

        create_dir_all(path.parent().unwrap())?;

        let object = self.delink(delink_file, module_kind)?;
        let file = create_file(path)?;
        let writer = BufWriter::new(file);
        object.write_stream(writer).unwrap();

        Ok(())
    }

    fn delink(&'a self, delink_file: &'a DelinkFile, module_kind: ModuleKind) -> Result<object::write::Object<'a>> {
        let mut delink_object = DelinkObject::new(&self.program, module_kind);

        for file_section in delink_file.sections.iter() {
            if file_section.migration().is_some() {
                // Skip sections that were migrated into this module, those sections will be
                // delinked from the source module
                continue;
            }
            delink_object.define_section(file_section, self.all_mapping_symbols)?;
        }
        for file_section in delink_file.migrated_sections.iter() {
            delink_object.define_section(file_section, self.all_mapping_symbols)?;
        }

        let mut error = false;

        // Must start a new loop here so we can know which section a symbol ID belongs to
        for file_section in delink_file.sections.iter() {
            error |= delink_object.define_relocations(file_section)?;
        }
        for file_section in delink_file.migrated_sections.iter() {
            error |= delink_object.define_relocations(file_section)?;
        }
        if error {
            bail!("Failed to delink '{}', see errors above", delink_file.name);
        }

        Ok(delink_object.into_object())
    }
}

struct DelinkObject<'a> {
    object: object::write::Object<'a>,
    // Maps address to ObjSection
    obj_sections: BTreeMap<u32, object::write::SectionId>,
    // Maps address and module to ObjSymbol
    obj_symbols: BTreeMap<(u32, ModuleKind), object::write::SymbolId>,
    // Maps overlay ID to ObjSymbol
    overlay_id_symbols: BTreeMap<u32, object::write::SymbolId>,

    program: &'a Program,
    current_module: ModuleKind,
}

impl<'a> DelinkObject<'a> {
    fn new(program: &'a Program, current_module: ModuleKind) -> Self {
        let mut object = object::write::Object::new(BinaryFormat::Elf, Architecture::Arm, Endianness::Little);
        object.elf_is_rela = Some(true);

        Self {
            object,
            obj_sections: BTreeMap::new(),
            obj_symbols: BTreeMap::new(),
            overlay_id_symbols: BTreeMap::new(),
            program,
            current_module,
        }
    }

    fn define_section(&mut self, file_section: &Section, all_mapping_symbols: bool) -> Result<(), anyhow::Error> {
        let symbol_module = if let Some(migration) = MigrateSection::parse(file_section.name())? {
            migration.module_kind()
        } else {
            self.current_module
        };
        let module = self.program.by_module_kind(symbol_module).unwrap();

        let code = file_section
            .relocatable_code(module)
            .with_context(|| format!("when delinking module {}", self.current_module))?
            .unwrap_or_else(Vec::new);
        let name = file_section.source_name().as_bytes().to_vec();
        let kind = match file_section.kind() {
            SectionKind::Code => object::SectionKind::Text,
            SectionKind::Data => object::SectionKind::Data,
            SectionKind::Rodata => object::SectionKind::ReadOnlyData,
            SectionKind::Bss => object::SectionKind::UninitializedData,
        };
        let obj_section_id = self.object.add_section(vec![], name.clone(), kind);
        let section = self.object.section_mut(obj_section_id);
        if !file_section.kind().is_initialized() {
            section.append_bss(file_section.size() as u64, 1);
        } else {
            let alignment = if file_section.kind().is_executable() { 4 } else { 1 };
            section.set_data(code, alignment);
        }
        self.object.add_symbol(object::write::Symbol {
            name, // same name as section
            value: 0,
            size: 0,
            kind: object::SymbolKind::Section,
            scope: object::SymbolScope::Compilation,
            weak: false,
            section: object::write::SymbolSection::Section(obj_section_id),
            flags: object::SymbolFlags::None,
        });
        let search_symbol_map = self.program.symbol_maps().get(symbol_module).context("Failed to find symbol map")?;
        let mut symbols = search_symbol_map.iter_by_address(file_section.address_range()).filter(|s| !s.skip).peekable();
        while let Some(symbol) = symbols.next() {
            // Get symbol data
            let max_address = symbols.peek().map(|s| s.addr).unwrap_or(file_section.end_address());
            let kind = symbol.kind.as_obj_symbol_kind();
            let scope = symbol.get_obj_symbol_scope();
            let value = (symbol.addr - file_section.start_address()) as u64;

            // Create symbol
            let symbol_section = object::write::SymbolSection::Section(obj_section_id);
            let symbol_id = self.object.add_symbol(object::write::Symbol {
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
            self.obj_symbols.insert((symbol.addr | thumb_bit, symbol_module), symbol_id);

            if all_mapping_symbols
                || matches!(symbol.kind, SymbolKind::Function(_) | SymbolKind::Label(_) | SymbolKind::PoolConstant)
            {
                // Create mapping symbol
                if let Some(name) = symbol.mapping_symbol_name() {
                    self.object.add_symbol(object::write::Symbol {
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
        self.obj_sections.insert(file_section.start_address(), obj_section_id);
        Ok(())
    }

    fn define_relocations(&mut self, file_section: &Section) -> Result<bool, anyhow::Error> {
        let symbol_map = self.program.symbol_maps().get(self.current_module).unwrap();

        let mut error = false;

        let obj_section_id = *self
            .obj_sections
            .get(&file_section.start_address())
            .with_context(|| {
                format!("Failed to find ObjSection {} in module {} while delinking", file_section.name(), self.current_module)
            })
            .unwrap();
        let module_kind = MigrateSection::parse(file_section.name())?.map(|m| m.module_kind()).unwrap_or(self.current_module);
        let module = self.program.by_module_kind(module_kind).unwrap();
        for (_, relocation) in module.relocations().iter_range(file_section.address_range()) {
            // Get relocation data
            let offset = relocation.from_address() - file_section.start_address();
            let dest_addr = relocation.to_address();

            let symbol_id = if relocation.kind() == RelocationKind::OverlayId {
                // Special case for overlay ID relocations
                let overlay_id = dest_addr;
                if let Some(symbol_id) = self.overlay_id_symbols.get(&overlay_id) {
                    *symbol_id
                } else {
                    // Create overlay ID symbol
                    let symbol_id = self.object.add_symbol(object::write::Symbol {
                        name: Lcf::overlay_id_symbol_name(overlay_id as u16).into_bytes(),
                        value: 0,
                        size: 0,
                        kind: object::SymbolKind::Unknown,
                        scope: object::SymbolScope::Compilation,
                        weak: false,
                        section: object::write::SymbolSection::Undefined,
                        flags: object::SymbolFlags::None,
                    });
                    self.overlay_id_symbols.insert(dest_addr, symbol_id);
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
                if let Some(obj_symbol) = self.obj_symbols.get(&symbol_key) {
                    // Use existing symbol
                    *obj_symbol
                } else {
                    // Get external symbol data
                    let external_symbol_map = self.program.symbol_maps().get(reloc_module).unwrap();
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
                    let symbol_id = self.object.add_symbol(object::write::Symbol {
                        name: symbol.name.clone().into_bytes(),
                        value: 0,
                        size: 0,
                        kind,
                        scope: object::SymbolScope::Compilation,
                        weak: true,
                        section: symbol_section,
                        flags: object::SymbolFlags::None,
                    });
                    self.obj_symbols.insert(symbol_key, symbol_id);
                    symbol_id
                }
            };

            // Create relocation
            let r_type = relocation.kind().as_elf_relocation_type();
            let addend = relocation.addend();
            self.object.add_relocation(obj_section_id, object::write::Relocation {
                offset: offset as u64,
                symbol: symbol_id,
                addend,
                flags: RelocationFlags::Elf { r_type },
            })?;
        }
        Ok(error)
    }

    fn into_object(self) -> object::write::Object<'a> {
        self.object
    }
}
