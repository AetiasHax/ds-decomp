mod build;
mod config;
mod extract;

use build::*;
pub use config::*;
use extract::*;

use anyhow::Result;
use clap::{Args, Subcommand};

/// Subcommands for extracting/building a ROM.
#[derive(Args)]
pub struct RomArgs {
    #[command(subcommand)]
    command: RomCommand,
}

impl RomArgs {
    pub fn run(&self) -> Result<()> {
        match &self.command {
            RomCommand::Extract(extract) => extract.run(),
            RomCommand::Build(build) => build.run(),
            RomCommand::Config(config) => config.run(),
        }
    }
}

#[derive(Subcommand)]
enum RomCommand {
    Extract(Extract),
    Build(Build),
    Config(ConfigRom),
}
