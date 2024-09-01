use std::{
    fs::{create_dir_all, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::Result;
use clap::Args;

use crate::{
    config::{
        config::{Config, ConfigAutoload, ConfigModule, ConfigOverlay},
        delinks::{DelinkFile, Delinks},
        module::{Module, ModuleKind},
        section::Section,
        symbol::{Symbol, SymbolKind, SymbolMaps},
        xref::Xrefs,
    },
    util::io::{create_file, open_file, read_file},
};

/// Disassembles an extracted ROM.
#[derive(Debug, Args)]
pub struct Disassemble {
    /// Path to config.yaml.
    #[arg(short = 'c', long)]
    config_yaml_path: PathBuf,

    /// Assembly code output path.
    #[arg(short = 'a', long)]
    asm_path: PathBuf,
}

impl Disassemble {
    pub fn run(&self) -> Result<()> {
        let config: Config = serde_yml::from_reader(open_file(&self.config_yaml_path)?)?;
        let config_path = self.config_yaml_path.parent().unwrap();

        let mut symbol_maps = SymbolMaps::from_config(config_path, &config)?;

        self.disassemble_arm9(&config.module, &mut symbol_maps)?;
        self.disassemble_autoloads(&config.autoloads, &mut symbol_maps)?;
        self.disassemble_overlays(&config.overlays, &mut symbol_maps)?;

        Ok(())
    }

    fn disassemble_arm9(&self, config: &ConfigModule, symbol_maps: &mut SymbolMaps) -> Result<()> {
        let config_path = self.config_yaml_path.parent().unwrap();

        let module_kind = ModuleKind::Arm9;
        let delinks = Delinks::from_file(config_path.join(&config.delinks), module_kind)?;
        let symbol_map = symbol_maps.get_mut(module_kind);
        let xrefs = Xrefs::from_file(config_path.join(&config.xrefs))?;

        let code = read_file(config_path.join(&config.object))?;
        let module = Module::new_arm9(config.name.clone(), symbol_map, xrefs, delinks.sections, &code)?;

        for file in &delinks.files {
            let (file_path, _) = file.split_file_ext();
            Self::create_assembly_file(
                &module,
                file,
                self.asm_path.join(format!("{}/{file_path}.s", config.name)),
                &symbol_maps,
            )?;
        }

        Ok(())
    }

    fn disassemble_autoloads(&self, autoloads: &[ConfigAutoload], symbol_maps: &mut SymbolMaps) -> Result<()> {
        for autoload in autoloads {
            let config_path = self.config_yaml_path.parent().unwrap();

            let module_kind = ModuleKind::Autoload(autoload.kind);
            let delinks = Delinks::from_file(config_path.join(&autoload.module.delinks), module_kind)?;
            let symbol_map = symbol_maps.get_mut(module_kind);
            let xrefs = Xrefs::from_file(config_path.join(&autoload.module.xrefs))?;

            let code = read_file(config_path.join(&autoload.module.object))?;
            let module =
                Module::new_autoload(autoload.module.name.clone(), symbol_map, xrefs, delinks.sections, autoload.kind, &code)?;

            for file in &delinks.files {
                let (file_path, _) = file.split_file_ext();
                Self::create_assembly_file(
                    &module,
                    file,
                    self.asm_path.join(format!("{}/{file_path}.s", autoload.module.name)),
                    &symbol_maps,
                )?;
            }
        }

        Ok(())
    }

    fn disassemble_overlays(&self, overlays: &[ConfigOverlay], symbol_maps: &mut SymbolMaps) -> Result<()> {
        let config_path = self.config_yaml_path.parent().unwrap();

        for overlay in overlays {
            let module_kind = ModuleKind::Overlay(overlay.id);
            let delinks = Delinks::from_file(config_path.join(&overlay.module.delinks), module_kind)?;
            let symbol_map = symbol_maps.get_mut(module_kind);
            let xrefs = Xrefs::from_file(config_path.join(&overlay.module.xrefs))?;

            let code = read_file(config_path.join(&overlay.module.object))?;
            let module =
                Module::new_overlay(overlay.module.name.clone(), symbol_map, xrefs, delinks.sections, overlay.id, &code)?;

            for file in &delinks.files {
                let (file_path, _) = file.split_file_ext();
                Self::create_assembly_file(
                    &module,
                    file,
                    self.asm_path.join(format!("{}/{file_path}.s", overlay.module.name)),
                    &symbol_maps,
                )?;
            }
        }

        Ok(())
    }

    fn create_assembly_file<P: AsRef<Path>>(
        module: &Module,
        delink_file: &DelinkFile,
        path: P,
        symbol_maps: &SymbolMaps,
    ) -> Result<()> {
        let path = path.as_ref();

        create_dir_all(path.parent().unwrap())?;
        let asm_file = create_file(&path)?;
        let mut writer = BufWriter::new(asm_file);

        Self::disassemble(module, delink_file, &mut writer, symbol_maps)?;

        Ok(())
    }

    fn disassemble(
        module: &Module,
        delink_file: &DelinkFile,
        writer: &mut BufWriter<File>,
        symbol_maps: &SymbolMaps,
    ) -> Result<()> {
        writeln!(writer, "    .include \"macros/function.inc\"")?;
        writeln!(writer)?;

        let symbol_map = symbol_maps.get(module.kind()).unwrap();

        for section in delink_file.sections.sorted_by_address() {
            let code = section.code_from_module(&module)?;
            match section.name() {
                ".text" => writeln!(writer, "    .text")?,
                _ => writeln!(writer, "    .section {}, 4, 1, 4", section.name())?,
            }
            let mut offset = 0; // offset within section
            let mut symbol_iter = symbol_map.iter_by_address().peekable();
            while let Some(symbol) = symbol_iter.next() {
                if symbol.addr < section.start_address() || symbol.addr >= section.end_address() {
                    continue;
                }
                match symbol.kind {
                    SymbolKind::Function(_) => {
                        let function = module.get_function(symbol.addr).unwrap();

                        let function_offset = function.start_address() - section.start_address();
                        if offset < function_offset {
                            Self::dump_bytes(code.unwrap(), offset, function_offset, writer)?;
                            writeln!(writer)?;
                        }

                        writeln!(writer, "{}", function.display(module.kind(), symbol_map, symbol_maps, module.xrefs()))?;
                        offset = function.end_address() - section.start_address();
                    }
                    SymbolKind::Data(data) => {
                        let start = (symbol.addr - section.start_address()) as usize;

                        let size = data
                            .size()
                            .unwrap_or_else(|| Self::size_to_next_symbol(section, symbol, symbol_iter.peek()) as usize);

                        let end = start + size;
                        let bytes = &code.unwrap()[start..end];
                        write!(writer, "{}:", symbol.name)?;

                        if symbol.ambiguous {
                            write!(writer, " ; ambiguous")?;
                        }
                        writeln!(writer)?;

                        writeln!(
                            writer,
                            "{}",
                            data.display_assembly(symbol, bytes, module.kind(), symbol_map, symbol_maps, module.xrefs())
                        )?;
                        offset = end as u32;
                    }
                    SymbolKind::Bss(bss) => {
                        let size = bss.size.unwrap_or_else(|| Self::size_to_next_symbol(section, symbol, symbol_iter.peek()));
                        writeln!(writer, "{}: .space {:#x}", symbol.name, size)?;
                        offset += size;
                    }
                    _ => {}
                }
            }

            let end_offset = section.end_address() - section.start_address();
            if offset < end_offset {
                if let Some(code) = code {
                    Self::dump_bytes(code, offset, end_offset, writer)?;
                    writeln!(writer)?;
                } else {
                    writeln!(writer, "    .space {:#x}", end_offset - offset)?;
                }
            }
        }

        Ok(())
    }

    fn size_to_next_symbol(section: &Section, symbol: &Symbol, next: Option<&&Symbol>) -> u32 {
        if let Some(next_symbol) = next {
            next_symbol.addr.min(section.end_address()) - symbol.addr
        } else {
            section.end_address() - symbol.addr
        }
    }

    fn dump_bytes(code: &[u8], mut offset: u32, end_offset: u32, writer: &mut BufWriter<File>) -> Result<()> {
        while offset < end_offset {
            write!(writer, "    .byte ")?;
            for i in 0..16.min(end_offset - offset) {
                if i != 0 {
                    write!(writer, ", ")?;
                }
                write!(writer, "0x{:02x}", code[offset as usize])?;
                offset += 1;
            }
            writeln!(writer)?;
        }
        Ok(())
    }
}
