mod apply;
mod new;

use clap::{Args, Subcommand};

pub use apply::*;
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
            SigCommand::Apply(apply) => apply.run(),
        }
    }
}

#[derive(Subcommand)]
enum SigCommand {
    New(NewSignature),
    Apply(ApplySignature),
}
