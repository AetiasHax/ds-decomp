mod modules;

pub use modules::*;

use anyhow::Result;
use clap::{Args, Subcommand};

/// Subcommands for checking/verifying build output.
#[derive(Args)]
pub struct CheckArgs {
    #[command(subcommand)]
    command: CheckCommand,
}

impl CheckArgs {
    pub fn run(&self) -> Result<()> {
        match &self.command {
            CheckCommand::Modules(modules) => modules.run(),
        }
    }
}

#[derive(Subcommand)]
enum CheckCommand {
    Modules(CheckModules),
}
