use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use ds_decomp::config::{
    config::Config,
    module::{ModuleKind, OVERLAY_SIGNATURES_SYMBOL_NAME},
    symbol::{SymData, SymbolMapError, SymbolMaps},
};

/// Adds or renames the overlay signature table symbol.
#[derive(Args, Clone)]
pub struct FixOvSigs {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    config_path: PathBuf,

    /// Dry run, do not write to any files.
    #[arg(long, short = 'd')]
    dry: bool,
}

impl FixOvSigs {
    pub fn run(&self) -> Result<()> {
        let config = Config::from_file(&self.config_path)?;
        let config_path = self.config_path.parent().unwrap();

        let mut symbol_maps = SymbolMaps::from_config(config_path, &config)?;

        let rom = config.load_rom(config_path)?;

        let arm9 = rom.arm9();
        if arm9.overlay_signatures_offset() == 0 {
            log::info!("This game has no overlay signature table, no changes will be made.");
            return Ok(());
        }

        let overlay_signatures_address = arm9.base_address() + arm9.overlay_signatures_offset();
        log::info!("Overlay signature table exists at {:#010x}", overlay_signatures_address);

        let symbol_map = symbol_maps.get_mut(ModuleKind::Arm9);
        match symbol_map
            .rename_by_address(overlay_signatures_address, OVERLAY_SIGNATURES_SYMBOL_NAME)
        {
            Ok(renamed) => {
                if !renamed {
                    log::info!("OverlaySignatures symbol already exists, no changes will be made.");
                    return Ok(());
                }
            }
            Err(SymbolMapError::NoSymbolToRename { .. }) => {
                symbol_map.add_data(
                    Some(OVERLAY_SIGNATURES_SYMBOL_NAME.to_string()),
                    overlay_signatures_address,
                    SymData::Any,
                )?;
            }
            Err(e) => Err(e)?,
        };

        if self.dry {
            log::info!("Dry run, not writing changes to files.");
            return Ok(());
        }

        symbol_maps.to_files(&config, config_path)?;

        Ok(())
    }
}
