use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use ds_decomp::config::{config::Config, module::ModuleKind};
use ds_rom::crypto::dsprot::DsProtDecryptOptions;

use crate::util::io;

/// Enables decryption of DS Protect functions, if they exist.
#[derive(Args)]
pub struct FixDsprot {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    config_path: PathBuf,

    /// Dry run, do not write to any files.
    #[arg(long, short = 'd')]
    dry: bool,
}

impl FixDsprot {
    pub fn run(&self) -> Result<()> {
        let mut config = Config::from_file(&self.config_path)?;
        let config_path = self.config_path.parent().unwrap();

        if config.enable_dsprot {
            log::error!(
                "DS Protect decryption already enabled because `enable_dsprot` is set to true."
            );
            return Ok(());
        }

        let mut rom = config.load_rom(config_path)?;
        let decrypt_options = DsProtDecryptOptions { decode_relocations: false };

        let mut dsprot_module = None;

        if rom.arm9_mut().dsprot_state().is_present() {
            rom.arm9_mut().decrypt_dsprot(&decrypt_options)?;
            let code_hash = fxhash::hash64(rom.arm9().code()?);
            dsprot_module = Some((ModuleKind::Arm9, code_hash));
        } else {
            for overlay in rom.arm9_overlays_mut() {
                if overlay.dsprot_state().is_present() {
                    overlay.decrypt_dsprot(&decrypt_options)?;
                    let code_hash = fxhash::hash64(overlay.code());
                    dsprot_module = Some((ModuleKind::Overlay(overlay.id()), code_hash));
                }
            }
        }

        let Some((dsprot_module, code_hash)) = dsprot_module else {
            log::info!("DS Protect not found, no changes will be made.");
            return Ok(());
        };

        log::info!("DS Protect found in {}", dsprot_module);
        config.enable_dsprot = true;
        let module_config = config.get_module_config_by_kind_mut(dsprot_module).unwrap();
        module_config.hash = format!("{code_hash:016x}");

        if self.dry {
            log::info!("Dry run, not updating config.yaml.");
        } else {
            log::info!("Enabling DS Protect decryption and updating hash for {}", dsprot_module);
            serde_saphyr::to_io_writer(&mut io::create_file(&self.config_path)?, &config)?;
        }

        Ok(())
    }
}
