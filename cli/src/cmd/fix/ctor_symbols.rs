use crate::util::bytes::FromSlice;
use std::path::PathBuf;

use anyhow::{Result, bail};
use clap::Args;
use ds_decomp::config::{
    config::{Config, ConfigModule},
    delinks::Delinks,
    module::ModuleKind,
    symbol::{SymData, Symbol, SymbolKind, SymbolMaps},
};
use ds_rom::rom::{Rom, RomLoadOptions};

use crate::rom::rom::RomExt;

/// Adds missing symbols in the .init and .ctor sections.
#[derive(Args, Clone)]
pub struct FixCtorSymbols {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    config_path: PathBuf,

    /// Dry run, do not write to any files.
    #[arg(long, short = 'd')]
    dry: bool,
}

impl FixCtorSymbols {
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

        self.fix_module(&config.main_module, ModuleKind::Arm9, &mut symbol_maps, &rom)?;
        for autoload in &config.autoloads {
            self.fix_module(&autoload.module, ModuleKind::Autoload(autoload.kind), &mut symbol_maps, &rom)?;
        }
        for overlay in &config.overlays {
            self.fix_module(&overlay.module, ModuleKind::Overlay(overlay.id), &mut symbol_maps, &rom)?;
        }

        if self.dry {
            log::info!("Dry run, not writing changes to files.");
            return Ok(());
        }

        symbol_maps.to_files(&config, config_path)?;

        Ok(())
    }

    fn fix_module(
        &self,
        module_config: &ConfigModule,
        module_kind: ModuleKind,
        symbol_maps: &mut SymbolMaps,
        rom: &Rom,
    ) -> Result<()> {
        let config_path = self.config_path.parent().unwrap();

        let code = rom.get_code(module_kind)?;

        let delinks = Delinks::from_file(config_path.join(&module_config.delinks), module_kind)?;
        let base_address = delinks.sections.base_address().unwrap();
        let symbol_map = symbol_maps.get_mut(module_kind);
        let Some((_, ctor_section)) = delinks.sections.by_name(".ctor") else {
            return Ok(());
        };
        let ctor_addresses = (ctor_section.start_address()..ctor_section.end_address()).step_by(4);
        for ctor_pointer_address in ctor_addresses {
            let ctor_pointer = u32::from_le_slice(&code[(ctor_pointer_address - base_address) as usize..]) & !1;
            if ctor_pointer == 0 {
                continue;
            }

            let overlay_prefix = match module_kind {
                ModuleKind::Overlay(id) => format!("ov{id:03}_"),
                _ => String::new(),
            };

            if let Some((_, symbol)) = symbol_map.by_address(ctor_pointer)? {
                if !symbol.name.starts_with("__sinit_") {
                    let new_name = format!("__sinit_{overlay_prefix}{ctor_pointer:08x}");
                    log::info!("Renaming static initializer at {ctor_pointer:#010x} in module {module_kind} to '{new_name}'");
                    symbol_map.rename_by_address(ctor_pointer, &new_name)?;
                }
            } else {
                bail!("Could not find static initializer function at address {ctor_pointer:#010x} in module {module_kind}");
            }

            if let Some((index, symbol)) = symbol_map.by_address(ctor_pointer_address)? {
                if !symbol.name.starts_with(".p__sinit_") {
                    let new_name = format!(".p__sinit_{overlay_prefix}{ctor_pointer:08x}");
                    log::info!(
                        "Renaming static initializer pointer at {ctor_pointer_address:#010x} in module {module_kind} to '{new_name}'"
                    );
                    symbol_map.rename_by_address(ctor_pointer_address, &new_name)?;
                }
                let symbol_mut = symbol_map.get_mut(index).unwrap();
                symbol_mut.kind = SymbolKind::Data(SymData::Word { count: Some(1) });
                symbol_mut.ambiguous = false;
            } else {
                let new_name = format!(".p__sinit_{overlay_prefix}{ctor_pointer:08x}");
                log::info!(
                    "Adding static initializer pointer '{new_name}' at {ctor_pointer_address:#010x} in module {module_kind}",
                );
                symbol_map.add(Symbol::new_data(new_name, ctor_pointer_address, SymData::Word { count: Some(1) }, false));
            }
        }

        Ok(())
    }
}
