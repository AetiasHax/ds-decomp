mod modules;
mod symbols;

use anyhow::Result;
use clap::{Args, Subcommand};
pub use modules::*;
pub use symbols::*;

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
            CheckCommand::Symbols(symbols) => symbols.run(),
        }
    }
}

#[derive(Subcommand)]
enum CheckCommand {
    Modules(CheckModules),
    Symbols(CheckSymbols),
}
