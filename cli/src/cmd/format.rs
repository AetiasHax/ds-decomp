use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use ds_decomp::config::{
    config::{Config, ConfigModule},
    delinks::Delinks,
    module::ModuleKind,
    relocations::Relocations,
    symbol::SymbolMap,
};

use crate::config::delinks::DelinksExt;

/// Formats all .txt config files.
#[derive(Args)]
pub struct Format {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    pub config_path: PathBuf,
}

impl Format {
    pub fn run(&self) -> Result<()> {
        let config = Config::from_file(&self.config_path)?;
        self.format_module(&config.main_module, ModuleKind::Arm9)?;
        for autoload in &config.autoloads {
            self.format_module(&autoload.module, ModuleKind::Autoload(autoload.kind))?;
        }
        for overlay in &config.overlays {
            self.format_module(&overlay.module, ModuleKind::Overlay(overlay.id))?;
        }

        Ok(())
    }

    fn format_module(&self, config_module: &ConfigModule, module_kind: ModuleKind) -> Result<()> {
        let config_path = self.config_path.parent().unwrap().to_path_buf();

        let delinks_path = config_path.join(&config_module.delinks);
        let mut delinks = Delinks::from_file(&delinks_path, module_kind)?;
        delinks.sort_files()?;
        delinks.to_file(delinks_path)?;

        let symbols_path = config_path.join(&config_module.symbols);
        let symbol_map = SymbolMap::from_file(&symbols_path)?;
        // Writes symbols sorted by address
        symbol_map.to_file(symbols_path)?;

        let relocations_path = config_path.join(&config_module.relocations);
        let relocations = Relocations::from_file(&relocations_path)?;
        // Writes relocations sorted by from address
        relocations.to_file(relocations_path)?;

        Ok(())
    }
}
