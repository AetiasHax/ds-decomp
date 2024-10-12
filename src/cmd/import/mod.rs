mod symbols;

use symbols::*;

use anyhow::Result;
use argp::FromArgs;

/// Subcommands for importing config data from existing builds.
#[derive(FromArgs)]
#[argp(subcommand, name = "import")]
pub struct ImportArgs {
    #[argp(subcommand)]
    command: ImportCommand,
}

impl ImportArgs {
    pub fn run(&self) -> Result<()> {
        match &self.command {
            ImportCommand::Symbols(symbols) => symbols.run(),
        }
    }
}

#[derive(FromArgs)]
#[argp(subcommand)]
enum ImportCommand {
    Symbols(ImportSymbols),
}
