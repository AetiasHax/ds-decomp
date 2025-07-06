use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use ds_decomp::config::{
    config::{Config, ConfigModule},
    module::ModuleKind,
    relocations::{Relocation, RelocationModule, Relocations},
    symbol::{Symbol, SymbolMaps},
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
        for reloc_info in &ambig_relocs {
            let symbol_info = if let Some(symbol) = &reloc_info.symbol {
                let name = demangle(&symbol.name);
                format!("{} + {:#x}", name, reloc_info.offset)
            } else {
                "<no symbol>".to_string()
            };
            println!(
                "{}: {:#010x} -> {:#010x} ({})",
                reloc_info.module_kind,
                reloc_info.relocation.from_address(),
                reloc_info.relocation.to_address(),
                symbol_info
            );
        }

        Ok(())
    }

    fn get_all_ambiguous_relocations(&self, config_path: &Path, config: &Config) -> Result<Vec<RelocInfo>> {
        let symbol_maps = SymbolMaps::from_config(config_path, config)?;

        let mut ambig_relocs = Vec::new();
        ambig_relocs.extend(self.get_ambiguous_relocations(
            config_path,
            &config.main_module,
            &symbol_maps,
            ModuleKind::Arm9,
        )?);
        for autoload in &config.autoloads {
            ambig_relocs.extend(self.get_ambiguous_relocations(
                config_path,
                &autoload.module,
                &symbol_maps,
                ModuleKind::Autoload(autoload.kind),
            )?);
        }
        for overlay in &config.overlays {
            ambig_relocs.extend(self.get_ambiguous_relocations(
                config_path,
                &overlay.module,
                &symbol_maps,
                ModuleKind::Overlay(overlay.id),
            )?);
        }

        Ok(ambig_relocs)
    }

    fn get_ambiguous_relocations(
        &self,
        config_path: &Path,
        module_config: &ConfigModule,
        symbol_maps: &SymbolMaps,
        module_kind: ModuleKind,
    ) -> Result<Vec<RelocInfo>> {
        let symbol_map = symbol_maps.get(module_kind).context(format!("No symbol map found for module {}", module_kind))?;
        let relocations = Relocations::from_file(config_path.join(&module_config.relocations))?;
        let infos = relocations
            .iter()
            .filter_map(|relocation| {
                if !matches!(relocation.module(), RelocationModule::Overlays { .. }) {
                    return None;
                }
                let (symbol, offset) = if let Some((symbol, offset)) = relocation.find_symbol_location(symbol_map) {
                    (Some(symbol.clone()), offset)
                } else {
                    (None, 0)
                };
                let relocation = relocation.clone();

                Some(RelocInfo { module_kind, relocation, symbol, offset })
            })
            .collect();
        Ok(infos)
    }
}

struct RelocInfo {
    module_kind: ModuleKind,
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
