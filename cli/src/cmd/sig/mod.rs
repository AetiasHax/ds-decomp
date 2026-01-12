mod apply;
mod list;
mod new;

pub use apply::*;
use clap::{Args, Subcommand};
pub use list::*;
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
            SigCommand::List(list) => list.run(),
        }
    }
}

#[derive(Subcommand)]
enum SigCommand {
    New(NewSignature),
    Apply(ApplySignature),
    List(ListSignatures),
}
