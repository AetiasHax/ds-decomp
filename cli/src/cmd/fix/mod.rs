mod ctor_symbols;
mod thumb_nop;

use clap::{Args, Subcommand};
use ctor_symbols::*;
use thumb_nop::*;

/// Subcommands for retroactively fixing already initialized dsd projects.
#[derive(Args)]
pub struct FixArgs {
    #[command(subcommand)]
    command: FixCommands,
}

impl FixArgs {
    pub fn run(&self) -> anyhow::Result<()> {
        match &self.command {
            FixCommands::ThumbNop(thumb_nop) => thumb_nop.run(),
            FixCommands::CtorSymbols(ctor_symbols) => ctor_symbols.run(),
        }
    }
}

#[derive(Subcommand)]
enum FixCommands {
    ThumbNop(FixThumbNop),
    CtorSymbols(FixCtorSymbols),
}
