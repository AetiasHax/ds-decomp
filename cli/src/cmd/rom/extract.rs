use std::path::PathBuf;

use anyhow::{bail, Result};

use clap::Args;
use ds_rom::{
    crypto::blowfish::BlowfishKey,
    rom::{raw, Rom, RomSaveError},
};
use log;

/// Extracts a ROM to a given path.
#[derive(Args, Clone)]
pub struct Extract {
    /// Nintendo DS game ROM.
    #[arg(long, short = 'r')]
    rom: PathBuf,

    /// Nintendo DS ARM7 BIOS file.
    #[arg(long, short = '7')]
    arm7_bios: Option<PathBuf>,

    /// Output path.
    #[arg(long, short = 'o')]
    output_path: PathBuf,

    /// Verbose output.
    #[arg(long, short = 'v', default_value_t = false)]
    verbose: bool,
}

impl Extract {
    pub fn run(&self) -> Result<()> {
        
        let v: bool = self.verbose;

        let path = self.rom.display();
        if v {
            println!("File reads:");
            println!("\t{path}");
        }
        let raw_rom = raw::Rom::from_file(&self.rom)?;
        
        let key = if let Some(arm7_bios) = &self.arm7_bios {
            let path = arm7_bios.display();
            if v { println!("\t{path}"); }
            Some(BlowfishKey::from_arm7_bios_path(arm7_bios)?)
        } else {
            log::warn!("No ARM 7 Bios file used.");
            None
        };

        let rom = Rom::extract(&raw_rom)?;

        match rom.save(&self.output_path, key.as_ref()) {
            Err(RomSaveError::BlowfishKeyNeeded) => {
                log::error!("The ROM is encrypted, please provide ARM7 BIOS");
                bail!("The ROM is encrypted, please provide ARM7 BIOS");
            }
            Err(_) => {
                log::error!("Rom extraction error.");
                bail!("Exiting...");
            }
            Ok( axs ) => {
                if v { 
                    println!("File writes:");
                    for path in axs.get_writes() {
                        println!("\t{}", path.display());
                    }
                }
                Ok(())
            },
        }
    }
}
