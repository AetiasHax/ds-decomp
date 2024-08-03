use std::{
    fs::{self, File},
    path::PathBuf,
};

use anyhow::Result;
use clap::Args;
use ds_rom::rom::Arm9BuildConfig;
use fxhash::FxHasher64;

use crate::config::config::{Config, ConfigModule};

/// Generates a config for the given extracted ROM.
#[derive(Debug, Args)]
pub struct Init {
    /// Extraction path.
    #[arg(short = 'e', long)]
    extract_path: PathBuf,

    /// Config path.
    #[arg(short = 'c', long)]
    config_path: PathBuf,
}

impl Init {
    pub fn run(&self) -> Result<()> {
        let mut overlays = vec![];
        let overlays_config_file = self.extract_path.join("arm9_overlays");

        let object_file = self.extract_path.join("arm9.bin");
        let build_config: Arm9BuildConfig = serde_yml::from_reader(File::open(self.extract_path.join("arm9.yaml"))?)?;

        let object_bytes = fs::read(&object_file)?;
        let object_hash = fxhash::hash64(&object_bytes);

        let config = Config {
            module: ConfigModule {
                object: object_file,
                hash: object_hash,
                splits: "./splits.txt".into(),
                symbols: "./symbols.txt".into(),
                overlay_loads: "./overlay_loads.txt".into(),
            },
            overlays,
        };

        Ok(())
    }
}
