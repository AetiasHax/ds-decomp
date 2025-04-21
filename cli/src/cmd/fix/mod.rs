mod thumb_nop;

use thumb_nop::*;

use clap::{Args, Subcommand};

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
        }
    }
}

#[derive(Subcommand)]
enum FixCommands {
    ThumbNop(FixThumbNop),
}
