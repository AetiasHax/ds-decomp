use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use ds_decomp::config::{
    config::Config,
    module::ModuleKind,
    symbol::{SymbolMap, SymbolMaps},
};

use crate::{cmd::symbol_name_fuzzy_match, config::symbol::SymbolMapsExt, util::io::read_file};

/// Applies symbol properties from the built binary to symbols.txt files.
#[derive(Args)]
pub struct Apply {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    pub config_path: PathBuf,

    /// Path to built/linked ELF file.
    #[arg(long, short = 'e')]
    pub elf_path: PathBuf,

    /// Dry run, do not write to any files.
    #[arg(long, short = 'd')]
    pub dry: bool,

    /// Verbose output.
    #[arg(long, short = 'v')]
    pub verbose: bool,

    /// Use exact symbol name matching instead of fuzzy matching.
    #[arg(long, short = 'F')]
    pub no_fuzzy: bool,
}

impl Apply {
    pub fn run(&self) -> Result<()> {
        let config = Config::from_file(&self.config_path)?;
        let config_path = self.config_path.parent().unwrap();
        let mut symbol_maps = SymbolMaps::from_config(config_path, &config)?;

        let elf_file = read_file(&self.elf_path)?;
        let object = object::File::parse(&*elf_file)?;

        let object_symbol_maps = SymbolMaps::from_object(&object)?;

        let mut num_changes = 0;
        for (module_kind, symbol_map) in symbol_maps.iter_mut() {
            let Some(object_symbols) = object_symbol_maps.get(module_kind) else {
                log::error!("No symbols found for module kind {:?}", module_kind);
                continue;
            };
            num_changes += self.apply_symbol_map(object_symbols, symbol_map, module_kind);
        }

        if !self.dry {
            symbol_maps.to_files(&config, config_path)?;
            log::info!("Applied {} symbol changes", num_changes);
        } else {
            log::info!("Would apply {} symbol changes", num_changes);
        }

        Ok(())
    }

    fn apply_symbol_map(&self, object: &SymbolMap, target: &mut SymbolMap, module_kind: ModuleKind) -> usize {
        let mut num_changes = 0;

        for target_symbol_index in target.indices_by_address().copied().collect::<Vec<_>>().iter() {
            let target_symbol = target.get_mut(*target_symbol_index).unwrap();

            let Some(object_symbols) = object.for_address(target_symbol.addr) else {
                if self.verbose {
                    log::warn!(
                        "Skipping symbol '{}' in {} at {:#010x}, not found in linked binary",
                        target_symbol.name,
                        module_kind,
                        target_symbol.addr
                    );
                }
                continue;
            };
            let object_symbols = object_symbols.map(|(_, s)| s).collect::<Vec<_>>();

            let object_symbol = if let Some(object_symbol) = object_symbols.iter().find(|s| s.name == target_symbol.name) {
                object_symbol
            } else if object_symbols.len() == 1 {
                object_symbols[0]
            } else {
                if self.verbose {
                    log::warn!(
                        "Skipping symbol '{}' in {} at {:#010x}, had multiple matching symbols in linked binary",
                        target_symbol.name,
                        module_kind,
                        target_symbol.addr
                    );
                }
                continue;
            };

            let mut changed = false;
            let name_matches = if self.no_fuzzy {
                target_symbol.name == object_symbol.name
            } else {
                symbol_name_fuzzy_match(&target_symbol.name, &object_symbol.name)
            };
            if !name_matches {
                log::info!(
                    "Renaming symbol '{}' in {} at {:#010x} to '{}'",
                    target_symbol.name,
                    module_kind,
                    target_symbol.addr,
                    object_symbol.name
                );
                changed = true;
            };
            if target_symbol.local != object_symbol.local {
                log::info!(
                    "Changing symbol '{}' in {} at {:#010x} to {}",
                    target_symbol.name,
                    module_kind,
                    target_symbol.addr,
                    if object_symbol.local { "local" } else { "global" }
                );
                changed = true;
            }
            if !name_matches {
                target_symbol.name = object_symbol.name.clone();
            }
            target_symbol.local = object_symbol.local;
            if changed {
                num_changes += 1;
            }
        }

        num_changes
    }
}
