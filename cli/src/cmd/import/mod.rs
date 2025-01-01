mod symbols;

use symbols::*;

use anyhow::Result;
use clap::{Args, Subcommand};

/// Subcommands for importing config data from existing builds.
#[derive(Args)]
pub struct ImportArgs {
    #[command(subcommand)]
    command: ImportCommand,
}

impl ImportArgs {
    pub fn run(&self) -> Result<()> {
        match &self.command {
            ImportCommand::Symbols(symbols) => symbols.run(),
        }
    }
}

#[derive(Subcommand)]
enum ImportCommand {
    Symbols(ImportSymbols),
}
