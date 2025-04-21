use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use ds_decomp::config::{
    config::{Config, ConfigModule},
    delinks::Delinks,
    module::{Module, ModuleKind, ModuleOptions},
    relocations::Relocations,
    symbol::{SymbolKind, SymbolMaps},
};
use ds_rom::rom::{Rom, RomLoadOptions};

use crate::{config::delinks::DelinksExt, rom::rom::RomExt};

/// Excludes trailing NOP instruction from the end of every Thumb function symbol.
#[derive(Args, Clone)]
pub struct FixThumbNop {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    config_path: PathBuf,

    /// Dry run, do not write to any files.
    #[arg(long, short = 'd')]
    dry: bool,
}

impl FixThumbNop {
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

        let mut num_changes = 0;
        num_changes += self.fix_module(&config.main_module, ModuleKind::Arm9, &rom, &mut symbol_maps)?;
        for autoload in &config.autoloads {
            num_changes += self.fix_module(&autoload.module, ModuleKind::Autoload(autoload.kind), &rom, &mut symbol_maps)?;
        }
        for overlay in &config.overlays {
            num_changes += self.fix_module(&overlay.module, ModuleKind::Overlay(overlay.id), &rom, &mut symbol_maps)?;
        }

        if !self.dry {
            symbol_maps.to_files(&config, config_path)?;
            log::info!("Fixed {} symbols", num_changes);
        } else {
            log::info!("Would fix {} symbols", num_changes);
        }

        Ok(())
    }

    fn fix_module(&self, config: &ConfigModule, kind: ModuleKind, rom: &Rom, symbol_maps: &mut SymbolMaps) -> Result<usize> {
        log::info!("Fixing {}", kind);

        let mut num_changes = 0;

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

        for function in module.sections().functions() {
            if !function.is_thumb() {
                continue;
            }

            let last_instruction_address = function.end_address() - 2;
            if function.pool_constants().contains(&(last_instruction_address & !3)) {
                continue;
            }
            // Function is Thumb and does not end with a pool constant

            let last_instruction_offset = (last_instruction_address - module.base_address()) as usize;
            let last_instruction = u16::from_le_bytes([code[last_instruction_offset], code[last_instruction_offset + 1]]);
            if last_instruction != 0x0000 {
                continue;
            }
            // Last instruction is mov r0, r0

            let Some(symbol) = symbol_map.get_function_mut(function.start_address())? else {
                continue;
            };
            let SymbolKind::Function(sym_function) = &mut symbol.kind else {
                continue;
            };
            sym_function.size -= 2;
            num_changes += 1;
        }

        Ok(num_changes)
    }
}
