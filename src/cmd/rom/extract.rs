use std::path::PathBuf;

use anyhow::{bail, Result};

use argp::FromArgs;
use ds_rom::{
    crypto::blowfish::BlowfishKey,
    rom::{raw, Rom, RomSaveError},
};

/// Extracts a ROM to a given path.
#[derive(FromArgs)]
#[argp(subcommand, name = "extract")]
pub struct Extract {
    /// Nintendo DS game ROM.
    #[argp(option, short = 'r')]
    rom: PathBuf,

    /// Nintendo DS ARM7 BIOS file.
    #[argp(option, short = '7')]
    arm7_bios: Option<PathBuf>,

    /// Output path.
    #[argp(option, short = 'o')]
    output_path: PathBuf,
}

impl Extract {
    pub fn run(&self) -> Result<()> {
        let raw_rom = raw::Rom::from_file(&self.rom)?;
        let key =
            if let Some(arm7_bios) = &self.arm7_bios { Some(BlowfishKey::from_arm7_bios_path(arm7_bios)?) } else { None };
        let rom = Rom::extract(&raw_rom)?;

        match rom.save(&self.output_path, key.as_ref()) {
            Err(RomSaveError::BlowfishKeyNeeded) => {
                log::error!("The ROM is encrypted, please provide ARM7 BIOS");
                bail!("The ROM is encrypted, please provide ARM7 BIOS");
            }
            result => Ok(result?),
        }
    }
}
