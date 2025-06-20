mod new;

use clap::{Args, Subcommand};
pub use new::*;

/// Subcommands for creating/applying signatures.
#[derive(Args)]
pub struct SigArgs {
    #[command(subcommand)]
    command: SigCommand,
}

impl SigArgs {
    pub fn run(&self) -> anyhow::Result<()> {
        match &self.command {
            SigCommand::New(new) => new.run(),
        }
    }
}

#[derive(Subcommand)]
enum SigCommand {
    New(NewSignature),
}
