use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use ds_decomp::config::{
    config::{Config, ConfigModule},
    module::ModuleKind,
    relocations::{Relocation, RelocationModule, Relocations},
    symbol::{Symbol, SymbolMap, SymbolMaps},
};

#[derive(Args, Clone)]
pub struct DumpAmbigRelocs {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    config_path: PathBuf,
}

impl DumpAmbigRelocs {
    pub fn run(&self) -> Result<()> {
        let config = Config::from_file(&self.config_path)?;
        let config_path = self.config_path.parent().unwrap();

        let ambig_relocs = self.get_all_ambiguous_relocations(config_path, &config)?;
        for reloc in &ambig_relocs {
            let symbol_info = if let Some(symbol) = &reloc.symbol {
                let name = demangle(&symbol.name);
                format!("{} + {:#x}", name, reloc.offset)
            } else {
                "<no symbol>".to_string()
            };
            println!("{:#010x} -> {:#010x} ({})", reloc.relocation.from_address(), reloc.relocation.to_address(), symbol_info);
        }

        Ok(())
    }

    fn get_all_ambiguous_relocations(&self, config_path: &Path, config: &Config) -> Result<Vec<RelocInfo>> {
        let symbol_maps = SymbolMaps::from_config(config_path, config)?;

        let mut ambig_relocs = Vec::new();
        ambig_relocs.extend(self.get_ambiguous_relocations(
            config_path,
            &config.main_module,
            symbol_maps.get(ModuleKind::Arm9).context("No symbol map found for main module")?,
        )?);
        for autoload in &config.autoloads {
            let symbol_map = symbol_maps
                .get(ModuleKind::Autoload(autoload.kind))
                .context(format!("No symbol map found for autoload '{}'", autoload.kind))?;
            ambig_relocs.extend(self.get_ambiguous_relocations(config_path, &autoload.module, symbol_map)?);
        }
        for overlay in &config.overlays {
            let symbol_map = symbol_maps
                .get(ModuleKind::Overlay(overlay.id))
                .context(format!("No symbol map found for overlay {}", overlay.id))?;
            ambig_relocs.extend(self.get_ambiguous_relocations(config_path, &overlay.module, symbol_map)?);
        }

        Ok(ambig_relocs)
    }

    fn get_ambiguous_relocations(
        &self,
        config_path: &Path,
        module_config: &ConfigModule,
        symbol_map: &SymbolMap,
    ) -> Result<Vec<RelocInfo>> {
        let relocations = Relocations::from_file(config_path.join(&module_config.relocations))?;
        let infos = relocations
            .iter()
            .filter_map(|relocation| {
                if !matches!(relocation.module(), RelocationModule::Overlays { .. }) {
                    return None;
                }
                let relocation = relocation.clone();
                let symbol = symbol_map
                    .first_symbol_before(relocation.from_address())
                    .and_then(|symbols| (!symbols.is_empty()).then_some(symbols[0].1))
                    .cloned();
                let offset = if let Some(symbol) = &symbol { relocation.from_address() - symbol.addr } else { 0 };

                Some(RelocInfo { relocation, symbol, offset })
            })
            .collect();
        Ok(infos)
    }
}

struct RelocInfo {
    relocation: Relocation,
    symbol: Option<Symbol>,
    offset: u32,
}

fn demangle(s: &str) -> String {
    if s.starts_with("_Z") {
        match cpp_demangle::Symbol::new(s) {
            Ok(demangled) => demangled.to_string(),
            Err(_) => s.into(),
        }
    } else {
        s.into()
    }
}
