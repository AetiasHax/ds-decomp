use std::path::PathBuf;

use anyhow::Result;
use clap::Args;

/// Disassembles an extracted ROM.
#[derive(Debug, Args)]
pub struct Disassemble {
    /// Extraction path.
    #[arg(short = 'e', long)]
    extract_path: PathBuf,

    /// Config path.
    #[arg(short = 'c', long)]
    config_path: PathBuf,
}

impl Disassemble {
    pub fn run(&self) -> Result<()> {
        Ok(())
    }
}
