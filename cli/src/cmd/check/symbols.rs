use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Args;
use ds_decomp::config::{
    config::Config,
    module::ModuleKind,
    symbol::{SymbolKind, SymbolMap, SymbolMaps},
};

use crate::{config::symbol::SymbolMapsExt, util::io::read_file};

/// Verifies that built modules are matching the base ROM.
#[derive(Args)]
pub struct CheckSymbols {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    pub config_path: PathBuf,

    /// Path to built/linked ELF file.
    #[arg(long, short = 'e')]
    pub elf_path: PathBuf,

    /// Return failing exit code if a symbol has an unexpected address.
    #[arg(long, short = 'f')]
    pub fail: bool,

    /// Maximum number of lines per module to print for each symbol mismatch.
    #[arg(long, short = 'm', default_value_t = 0)]
    pub max_lines: usize,
}

impl CheckSymbols {
    pub fn run(&self) -> Result<()> {
        let config = Config::from_file(&self.config_path)?;
        let config_path = self.config_path.parent().unwrap();

        let elf_file = read_file(&self.elf_path)?;
        let object = object::File::parse(&*elf_file)?;
        let object_symbol_maps = SymbolMaps::from_object(&object)?;

        let mut success = true;

        let symbol_maps = SymbolMaps::from_config(config_path, &config)?;
        if let Some(target_symbols) = symbol_maps.get(ModuleKind::Arm9) {
            let object_symbols =
                object_symbol_maps.get(ModuleKind::Arm9).context("ARM9 symbols not found in linked binary")?;
            success &= self.check_symbol_map(object_symbols, target_symbols, ModuleKind::Arm9);
        }
        for autoload in &config.autoloads {
            let module_kind = ModuleKind::Autoload(autoload.kind);
            if let Some(target_symbols) = symbol_maps.get(module_kind) {
                let object_symbols = object_symbol_maps
                    .get(module_kind)
                    .with_context(|| format!("Symbols for {module_kind} not found in linked binary"))?;
                success &= self.check_symbol_map(object_symbols, target_symbols, module_kind);
            }
        }
        for overlay in &config.overlays {
            let module_kind = ModuleKind::Overlay(overlay.id);
            if let Some(target_symbols) = symbol_maps.get(module_kind) {
                let object_symbols = object_symbol_maps
                    .get(module_kind)
                    .with_context(|| format!("Symbols for {module_kind} not found in linked binary"))?;
                success &= self.check_symbol_map(object_symbols, target_symbols, module_kind);
            }
        }

        if self.fail && !success {
            bail!("Some symbol(s) did not match.");
        }

        Ok(())
    }

    fn check_symbol_map(&self, object: &SymbolMap, target: &SymbolMap, module_kind: ModuleKind) -> bool {
        let mut num_mismatches = 0;

        for target_symbol in target.iter() {
            if num_mismatches >= self.max_lines && self.max_lines > 0 {
                log::warn!("Too many mismatches, stopping further checks.");
                break;
            }

            let Some(symbol_iter) = object.for_address(target_symbol.addr) else {
                num_mismatches += 1;
                log::error!(
                    "Symbol '{}' in {} at {:#010x} not found in linked binary",
                    target_symbol.name,
                    module_kind,
                    target_symbol.addr
                );
                if let Some(candidates) = object.for_name(&target_symbol.name) {
                    for (_, candidate) in candidates {
                        log::error!("  Matching name found at {:#010x}", candidate.addr);
                    }
                }
                continue;
            };
            let symbols = symbol_iter.map(|(_, symbol)| symbol).collect::<Vec<_>>();

            let Some(matching_symbol) =
                symbols.iter().find(|symbol| symbol_name_fuzzy_match(&symbol.name, &target_symbol.name))
            else {
                num_mismatches += 1;
                log::error!(
                    "Symbol '{}' in {} at {:#010x} not found in linked binary",
                    target_symbol.name,
                    module_kind,
                    target_symbol.addr
                );
                if let Some(candidates) = object.for_name(&target_symbol.name) {
                    for (_, candidate) in candidates {
                        log::error!("  Matching name found at {:#010x}", candidate.addr);
                    }
                }
                if let Some(candidates) = object.for_address(target_symbol.addr) {
                    for (_, candidate) in candidates {
                        log::error!("  Possible name: {}", candidate.name);
                    }
                }
                continue;
            };

            let is_label = matches!(target_symbol.kind, SymbolKind::Label(_));

            // The object crate always interprets labels as local for some reason
            if !is_label {
                if matching_symbol.local && !target_symbol.local {
                    num_mismatches += 1;
                    log::error!(
                        "Symbol '{}' at {:#010x} in {} is expected to be global but is local",
                        target_symbol.name,
                        target_symbol.addr,
                        module_kind
                    );
                    continue;
                }
                if !matching_symbol.local && target_symbol.local {
                    num_mismatches += 1;
                    log::error!(
                        "Symbol '{}' at {:#010x} in {} is expected to be local but is global",
                        target_symbol.name,
                        target_symbol.addr,
                        module_kind
                    );
                    continue;
                }
            }
        }

        num_mismatches == 0
    }
}

pub fn symbol_name_fuzzy_match(a: &str, b: &str) -> bool {
    if a == b {
        return true;
    }
    if a.starts_with('@') && b.starts_with('@') {
        // Both symbols are anonymous data objects
        return true;
    }
    if let (Some((a_name, _)), Some((b_name, _))) = (a.split_once('$'), b.split_once('$')) {
        // Both symbols are scoped static objects
        return a_name == b_name;
    }
    false
}
