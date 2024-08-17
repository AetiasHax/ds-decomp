use std::{
    fs::{create_dir_all, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::Result;
use clap::Args;

use crate::{
    config::{
        config::{Config, ConfigModule, ConfigOverlay},
        delinks::Delinks,
        module::Module,
        section::Section,
        symbol::{Symbol, SymbolKind, SymbolMap},
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

        self.disassemble_arm9(&config.module)?;
        self.disassemble_autoloads(&config.autoloads)?;
        self.disassemble_overlays(&config.overlays)?;

        Ok(())
    }

    fn disassemble_arm9(&self, config: &ConfigModule) -> Result<()> {
        let config_path = self.config_yaml_path.parent().unwrap();

        let Delinks { sections, files } = Delinks::from_file(config_path.join(&config.delinks))?;
        let symbol_map = SymbolMap::from_file(config_path.join(&config.symbols))?;

        let code = read_file(config_path.join(&config.object))?;
        let module = Module::new_arm9(symbol_map, sections, &code)?;

        Self::create_assembly_file(&module, self.asm_path.join(format!("{0}/{0}.s", config.name)))?;

        Ok(())
    }

    fn disassemble_autoloads(&self, autoloads: &[ConfigModule]) -> Result<()> {
        for autoload in autoloads {
            let config_path = self.config_yaml_path.parent().unwrap();

            let Delinks { sections, files } = Delinks::from_file(config_path.join(&autoload.delinks))?;
            let symbol_map = SymbolMap::from_file(config_path.join(&autoload.symbols))?;

            let code = read_file(config_path.join(&autoload.object))?;
            let module = Module::new_autoload(symbol_map, sections, &code)?;

            Self::create_assembly_file(&module, self.asm_path.join(format!("{0}/{0}.s", autoload.name)))?;
        }

        Ok(())
    }

    fn disassemble_overlays(&self, overlays: &[ConfigOverlay]) -> Result<()> {
        let config_path = self.config_yaml_path.parent().unwrap();

        for overlay in overlays {
            let Delinks { sections, files } = Delinks::from_file(config_path.join(&overlay.module.delinks))?;
            let symbol_map = SymbolMap::from_file(config_path.join(&overlay.module.symbols))?;

            let code = read_file(config_path.join(&overlay.module.object))?;
            let module = Module::new_overlay(symbol_map, sections, overlay.id, &code)?;

            Self::create_assembly_file(&module, self.asm_path.join(format!("{0}/{0}.s", overlay.module.name)))?;
        }

        Ok(())
    }

    fn create_assembly_file<P: AsRef<Path>>(module: &Module, path: P) -> Result<()> {
        let path = path.as_ref();

        create_dir_all(path.parent().unwrap())?;
        let asm_file = create_file(&path)?;
        let mut writer = BufWriter::new(asm_file);

        Self::disassemble(module, &mut writer)?;

        Ok(())
    }

    fn disassemble(module: &Module, writer: &mut BufWriter<File>) -> Result<()> {
        writeln!(writer, "    .include \"macros/function.inc\"")?;
        // writeln!(writer, "    .include \"main/main.inc\"")?; // TODO: Generate .inc files
        writeln!(writer)?;

        for section in module.sections().sorted_by_address() {
            let code = section.code(&module)?;
            match section.name.as_str() {
                ".text" => writeln!(writer, "    .text")?,
                _ => writeln!(writer, "    .section {}, 4, 1, 4", section.name)?,
            }
            let mut offset = 0;
            let mut symbol_iter = module.symbol_map().iter_by_address().peekable();
            while let Some(symbol) = symbol_iter.next() {
                if symbol.addr < section.start_address || symbol.addr >= section.end_address {
                    continue;
                }
                match symbol.kind {
                    SymbolKind::Function(_) => {
                        let function = module.get_function(symbol.addr).unwrap();

                        let function_offset = function.start_address() - section.start_address;
                        if offset < function_offset {
                            Self::dump_bytes(code.unwrap(), offset, function_offset, writer)?;
                            writeln!(writer)?;
                        }

                        writeln!(writer, "{}", function.display(module.symbol_map()))?;
                        offset = function.end_address() - section.start_address;
                    }
                    SymbolKind::Data(data) => {
                        let start = (symbol.addr - section.start_address) as usize;

                        let size = data
                            .size()
                            .unwrap_or_else(|| Self::size_to_next_symbol(section, symbol, symbol_iter.peek()) as usize);

                        let end = start + size;
                        let items = &code.unwrap()[start..end];
                        writeln!(writer, "{}:\n{}", symbol.name, data.display_assembly(items))?;
                    }
                    SymbolKind::Bss(bss) => {
                        let size = bss.size.unwrap_or_else(|| Self::size_to_next_symbol(section, symbol, symbol_iter.peek()));
                        writeln!(writer, "{}:\n    .space {:#x}", symbol.name, size)?
                    }
                    _ => {}
                }
            }

            let end_offset = section.end_address - section.start_address;
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
            next_symbol.addr.min(section.end_address) - symbol.addr
        } else {
            section.end_address - symbol.addr
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
