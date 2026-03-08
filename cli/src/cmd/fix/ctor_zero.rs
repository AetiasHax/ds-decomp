use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Args;
use ds_decomp::{
    config::{
        config::Config,
        link_time_const::LinkTimeConst,
        module::ModuleKind,
        relocations::{RelocationKind, RelocationModule},
        symbol::{Symbol, SymbolMaps},
    },
    rom::rom::RomExt,
};
use ds_rom::rom::{Rom, RomLoadOptions};

use crate::config::{
    delinks::{DelinksMap, DelinksMapOptions},
    relocation::RelocationsMap,
};

/// Truncates trailing zero value from .ctor sections.
#[derive(Args, Clone)]
pub struct FixCtorZero {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    config_path: PathBuf,

    /// Dry run, do not write to any files.
    #[arg(long, short = 'd')]
    dry: bool,

    /// Force changes to be applied despite errors.
    #[arg(long, short = 'f')]
    force: bool,
}

impl FixCtorZero {
    pub fn run(&self) -> Result<()> {
        let config = Config::from_file(&self.config_path)?;
        let config_path = self.config_path.parent().unwrap();

        let rom = Rom::load(config_path.join(&config.rom_config), RomLoadOptions {
            key: None,
            compress: false,
            encrypt: false,
            load_files: false,
            load_header: false,
            load_banner: false,
            load_multiboot_signature: false,
        })?;

        let mut delinks_map = DelinksMap::from_config(&config, config_path, DelinksMapOptions {
            migrate_sections: false,
            generate_gap_files: false,
        })?;
        let mut symbol_maps = SymbolMaps::from_config(config_path, &config)?;
        let mut relocs_map = RelocationsMap::from_config(&config, config_path)?;

        let mut removed_symbols: Vec<(ModuleKind, Symbol)> = Vec::new();
        let mut arm9_ctor_start = None;

        let mut error = false;
        let mut changed = false;
        for (kind, _) in config.iter_modules() {
            log::debug!("Processing module {kind}");

            // Truncate section
            let delinks = delinks_map.get_mut(kind).context("Failed to get delinks")?;
            let base_address =
                delinks.sections.base_address().context("Failed to get base address")?;
            let Some((_, ctor_section)) = delinks.sections.by_name_mut(".ctor") else {
                match kind {
                    ModuleKind::Arm9 | ModuleKind::Overlay(_) => {
                        log::error!("No .ctor section found in {kind}");
                        error = true;
                    }
                    ModuleKind::Autoload(_) => {
                        log::debug!("Skipping {kind} as it has no .ctor section");
                    }
                }
                continue;
            };
            let start_addr = ctor_section.start_address();
            if kind == ModuleKind::Arm9 {
                arm9_ctor_start = Some(start_addr);
            }
            let end_addr = ctor_section.end_address();
            if end_addr <= start_addr {
                // Empty
                log::debug!("Skipping {kind} as the .ctor section is empty");
                continue;
            }
            log::debug!("Found .ctor section at {start_addr:#010x}..{end_addr:#010x}");
            if !start_addr.is_multiple_of(4) {
                log::error!(
                    "The start address of .ctor in {kind} must be aligned by 4 (got {start_addr:#010x})"
                );
                error = true;
                continue;
            }
            if !end_addr.is_multiple_of(4) {
                log::error!(
                    "The end address of .ctor in {kind} must be aligned by 4 (got {end_addr:#010x})"
                );
                error = true;
                continue;
            }
            let code = rom.get_code(kind)?;
            let ctor_code = {
                let start = (start_addr - base_address) as usize;
                let end = (end_addr - base_address) as usize;
                &code[start..end]
            };
            let last_word = u32::from_le_bytes(
                ctor_code[ctor_code.len() - 4..]
                    .try_into()
                    .context("Failed to get last four bytes of .ctor")?,
            );
            if last_word != 0 {
                log::debug!(".ctor section ends with {last_word:#010x} so it is already truncated");
                continue;
            }
            let old_end_addr = end_addr;
            let end_addr = old_end_addr - 4;
            ctor_section.set_end_address(end_addr);
            changed = true;
            log::info!("Truncating .ctor section of {kind}");

            // Remove symbols from truncated area
            let symbol_map = symbol_maps.get_mut(kind);
            let ids_to_remove = symbol_map
                .iter_by_address(end_addr..old_end_addr)
                .map(|(id, _)| id)
                .collect::<Vec<_>>();
            for id in ids_to_remove {
                let symbol = symbol_map.remove(id).unwrap();
                log::info!("Removing symbol {} in {}", symbol.name, kind);
                removed_symbols.push((kind, symbol));
                changed = true;
            }
        }

        let arm9_ctor_start =
            arm9_ctor_start.context("Failed to find .ctor in main ARM9 module")?;

        // Update reloc to main .ctor to use link-time constant
        {
            let relocs = relocs_map.get_mut(ModuleKind::Arm9).unwrap();
            for from in relocs.get_by_to_address(arm9_ctor_start).to_vec() {
                let reloc = relocs.get_mut(from).unwrap();
                reloc.set_kind(RelocationKind::LinkTimeConst(LinkTimeConst::Arm9CtorStart));
                changed = true;
                log::info!(
                    "Updating relocation in ARM9 main from {:#010x} to {:#010x} so it uses the ARM9_CTOR_START link-time constant",
                    from,
                    reloc.to_address()
                );
            }
        }

        // New loop to delete relocations to all symbols in `removed_symbols`
        for (source_kind, _) in config.iter_modules() {
            let relocs = relocs_map.get_mut(source_kind).context("Failed to find relocations")?;
            for (target_kind, symbol) in &removed_symbols {
                for from in relocs.get_by_to_address(symbol.addr).to_vec() {
                    let reloc = relocs.get_mut(from).unwrap();
                    match reloc.module() {
                        RelocationModule::None => {}
                        RelocationModule::Overlay { id } => {
                            if let ModuleKind::Overlay(target_id) = *target_kind
                                && *id == target_id
                            {
                                log::error!(
                                    "Symbol {} from {} was tagged for removal but an unambiguous relocation was pointing to it from address {:#010x} of {}",
                                    symbol.name,
                                    target_kind,
                                    from,
                                    source_kind
                                );
                                error = true;
                                continue;
                            }
                        }
                        RelocationModule::Overlays { ids } => {
                            if let ModuleKind::Overlay(target_id) = *target_kind
                                && ids.contains(&target_id)
                            {
                                let mut ids = ids.clone();
                                ids.retain(|&id| id != target_id);
                                match ids.len() {
                                    0 => panic!(
                                        "RelocationModule::Overlays must have at least 2 overlay IDs"
                                    ),
                                    1 => reloc.set_module(RelocationModule::Overlay { id: ids[0] }),
                                    2.. => reloc.set_module(RelocationModule::Overlays { ids }),
                                };
                                changed = true;
                                log::info!(
                                    "Removed target overlay {target_id} from relocation from {from:#010x} in {source_kind}"
                                );
                            }
                        }
                        RelocationModule::Main
                        | RelocationModule::Itcm
                        | RelocationModule::Dtcm
                        | RelocationModule::Autoload { .. } => {}
                    }
                }
            }
        }

        if error && !self.force {
            bail!(
                "Errors were detected, see logs above. No changes were done to your config files. If you want to ignore the errors, use the --force option."
            );
        }

        if self.dry {
            if changed {
                log::info!("Fix successful (dry run), no changes applied to project");
            } else {
                log::info!("Fix successful (dry run), but would have had no effect on the project")
            }
        } else if changed {
            log::info!("Fix successful, applying changes to project");
            delinks_map.to_files(&config, config_path)?;
            symbol_maps.to_files(&config, config_path)?;
            relocs_map.to_files(&config, config_path)?;
        } else {
            log::info!("Fix successful, but had no effect on the project");
        }

        Ok(())
    }
}
