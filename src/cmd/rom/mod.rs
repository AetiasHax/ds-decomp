mod build;
mod config;
mod extract;

use build::*;
use config::*;
use extract::*;

use anyhow::Result;
use argp::FromArgs;

/// Subcommands for extracting/building a ROM.
#[derive(FromArgs)]
#[argp(subcommand, name = "rom")]
pub struct RomArgs {
    #[argp(subcommand)]
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

#[derive(FromArgs)]
#[argp(subcommand)]
enum RomCommand {
    Extract(Extract),
    Build(Build),
    Config(ConfigRom),
}
