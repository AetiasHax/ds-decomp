use std::{
    fs::{create_dir_all, File},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::Args;
use ds_decomp::config::{
    config::{Config, ConfigModule},
    delinks::{DelinkFile, Delinks},
    module::{Module, ModuleKind, ModuleOptions},
    relocations::Relocations,
    section::Section,
    symbol::{InstructionMode, Symbol, SymbolKind, SymbolMaps},
};
use ds_rom::rom::{Rom, RomLoadOptions};

use crate::{
    analysis::functions::FunctionExt,
    config::{
        delinks::DelinksExt,
        symbol::{SymDataExt, SymbolLookup},
    },
    rom::rom::RomExt,
    util::io::create_file,
};

/// Disassembles an extracted ROM.
#[derive(Args)]
pub struct Disassemble {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    pub config_path: PathBuf,

    /// Assembly code output path.
    #[arg(long, short = 'a')]
    pub asm_path: PathBuf,

    /// Disassemble with Unified Assembler Language (UAL) syntax.
    #[arg(long, short = 'u')]
    pub ual: bool,
}

impl Disassemble {
    pub fn run(&self) -> Result<()> {
        let config = Config::from_file(&self.config_path)?;
        let config_path = self.config_path.parent().unwrap();

        let rom_config_path = config_path.join(&config.rom_config);
        let rom = Rom::load(
            &rom_config_path,
            RomLoadOptions {
                key: None,
                compress: false,
                encrypt: false,
                load_files: false,
                load_header: false,
                load_banner: false,
            },
        )?;

        let mut symbol_maps = SymbolMaps::from_config(config_path, &config)?;

        self.disassemble_module(&config.main_module, ModuleKind::Arm9, &mut symbol_maps, &rom)?;
        for autoload in &config.autoloads {
            self.disassemble_module(&autoload.module, ModuleKind::Autoload(autoload.kind), &mut symbol_maps, &rom)?;
        }
        for overlay in &config.overlays {
            self.disassemble_module(&overlay.module, ModuleKind::Overlay(overlay.id), &mut symbol_maps, &rom)?;
        }

        Ok(())
    }

    fn disassemble_module(
        &self,
        config: &ConfigModule,
        kind: ModuleKind,
        symbol_maps: &mut SymbolMaps,
        rom: &Rom,
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
            self.create_assembly_file(
                &module,
                file,
                self.asm_path.join(format!("{}/{file_path}.s", config.name)),
                symbol_maps,
            )?;
        }

        Ok(())
    }

    fn create_assembly_file<P: AsRef<Path>>(
        &self,
        module: &Module,
        delink_file: &DelinkFile,
        path: P,
        symbol_maps: &SymbolMaps,
    ) -> Result<()> {
        let path = path.as_ref();

        create_dir_all(path.parent().unwrap())?;
        let asm_file = create_file(path)?;
        let mut writer = BufWriter::new(asm_file);

        self.disassemble(module, delink_file, &mut writer, symbol_maps)?;

        Ok(())
    }

    fn disassemble(
        &self,
        module: &Module,
        delink_file: &DelinkFile,
        writer: &mut BufWriter<File>,
        symbol_maps: &SymbolMaps,
    ) -> Result<()> {
        writeln!(writer, "    .include \"macros/function.inc\"")?;
        writeln!(writer)?;

        let symbol_map = symbol_maps.get(module.kind()).unwrap();

        for section in delink_file.sections.sorted_by_address() {
            // write section directive
            match section.name() {
                ".text" => writeln!(writer, "    .text")?,
                _ => writeln!(writer, "    .section {}, 4, 1, 4", section.name())?,
            }

            let code = section.code_from_module(module)?;
            let mut offset = 0; // offset within section

            let symbol_lookup =
                SymbolLookup { module_kind: module.kind(), symbol_map, symbol_maps, relocations: module.relocations() };

            let mut symbol_iter = symbol_map.iter_by_address(section.address_range()).peekable();
            while let Some(symbol) = symbol_iter.next() {
                debug_assert!(symbol.addr >= section.start_address() && symbol.addr < section.end_address());
                match symbol.kind {
                    SymbolKind::Function(sym_function) => {
                        if sym_function.unknown {
                            let function_offset = symbol.addr - section.start_address();
                            if offset < function_offset {
                                Self::dump_bytes(code.unwrap(), offset, function_offset, writer)?;
                                writeln!(writer)?;
                                offset = function_offset;
                            }

                            writeln!(writer, "    .global {}", symbol.name)?;
                            match sym_function.mode {
                                InstructionMode::Arm => writeln!(writer, "    arm_func_start {}", symbol.name)?,
                                InstructionMode::Thumb => writeln!(writer, "    thumb_func_start {}", symbol.name)?,
                            }
                            writeln!(writer, "{}: ; {:#010x}", symbol.name, symbol.addr)?;
                        } else {
                            let function = module.get_function(symbol.addr).with_context(|| format!(
                                "Tried to disassemble function symbol '{}' at {:#010x} but the function was not found in the module",
                                symbol.name,
                                symbol.addr,
                            ))?;

                            let function_offset = function.start_address() - section.start_address();
                            if offset < function_offset {
                                Self::dump_bytes(code.unwrap(), offset, function_offset, writer)?;
                                writeln!(writer)?;
                            }

                            function.write_assembly(writer, &symbol_lookup, module.code(), module.base_address(), self.ual)?;
                            offset = function.end_address() - section.start_address();
                        }
                    }
                    SymbolKind::Data(data) => {
                        let start = (symbol.addr - section.start_address()) as usize;

                        let size =
                            data.size().unwrap_or_else(|| Self::size_to_next_symbol(section, symbol, symbol_iter.peek()));

                        let end = start + size as usize;
                        let bytes = &code.unwrap()[start..end];
                        write!(writer, "{}:", symbol.name)?;

                        if symbol.ambiguous {
                            write!(writer, " ; ambiguous")?;
                        }
                        writeln!(writer)?;

                        data.write_assembly(writer, symbol, bytes, &symbol_lookup)?;
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
