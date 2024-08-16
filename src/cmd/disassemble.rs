use std::{
    fs::{create_dir_all, File},
    io::{BufWriter, Write},
    path::PathBuf,
};

use anyhow::{Context, Result};
use clap::Args;
use ds_rom::rom::{Header, Overlay, OverlayConfig};

use crate::{
    config::{
        config::{Config, ConfigModule, ConfigOverlay},
        delinks::Delinks,
        module::Module,
        symbol::{SymbolKind, SymbolMap},
    },
    util::{
        ds::load_arm9,
        io::{create_file, open_file, read_file},
    },
};

/// Disassembles an extracted ROM.
#[derive(Debug, Args)]
pub struct Disassemble {
    /// Extraction path.
    #[arg(short = 'e', long)]
    extract_path: PathBuf,

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
        let header: Header = serde_yml::from_reader(open_file(self.extract_path.join("header.yaml"))?)?;

        self.disassemble_arm9(&config.module, &header)?;
        self.disassemble_overlays(&config.overlays, &header)?;

        Ok(())
    }

    fn disassemble_arm9(&self, config: &ConfigModule, header: &Header) -> Result<()> {
        let config_path = self.config_yaml_path.parent().unwrap();

        let Delinks { sections, files } = Delinks::from_file(config_path.join(&config.delinks))?;
        let symbol_map = SymbolMap::from_file(config_path.join(&config.symbols))?;

        let arm9 = load_arm9(self.extract_path.join("arm9"), header)?;

        let module = Module::new_arm9(symbol_map, &arm9, sections)?;

        let asm_main_path = self.asm_path.join("main");
        create_dir_all(&asm_main_path)?;
        let asm_file = create_file(asm_main_path.join("main.s"))?;
        let mut writer = BufWriter::new(asm_file);

        Self::disassemble(&module, &mut writer)?;

        Ok(())
    }

    fn disassemble_overlays(&self, overlays: &[ConfigOverlay], header: &Header) -> Result<()> {
        let config_path = self.config_yaml_path.parent().unwrap();

        let overlay_configs: Vec<OverlayConfig> =
            serde_yml::from_reader(open_file(self.extract_path.join("arm9_overlays/overlays.yaml"))?)?;

        for overlay in overlays {
            let name = format!("ov{:03}", overlay.id);

            let Delinks { sections, files } = Delinks::from_file(config_path.join(&overlay.module.delinks))?;
            let symbol_map = SymbolMap::from_file(config_path.join(&overlay.module.symbols))?;

            let data_path = config_path.join(&overlay.module.object);
            let data = read_file(&data_path)?;

            let overlay_config = overlay_configs
                .iter()
                .find(|c| c.info.id == overlay.id)
                .with_context(|| format!("couldn't find overlay with ID {}", overlay.id))?;
            let overlay = Overlay::new(data, header.version(), overlay_config.info.clone());

            let module = Module::new_overlay(symbol_map, &overlay, sections)?;

            let asm_path = self.asm_path.join(&name);
            create_dir_all(&asm_path)?;
            let asm_file = create_file(asm_path.join(format!("{name}.s")))?;
            let mut writer = BufWriter::new(asm_file);

            Self::disassemble(&module, &mut writer)?;
        }

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
            for symbol in module.symbol_map().iter_by_address() {
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
                        let start = (symbol.addr - module.base_address()) as usize;
                        let end = start + data.size();
                        let items = &code.unwrap()[start..end];
                        write!(writer, "{}", data.display_assembly(items))?;
                    }
                    SymbolKind::Bss(bss) => writeln!(writer, "    .space {:#x}", bss.size)?,
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
