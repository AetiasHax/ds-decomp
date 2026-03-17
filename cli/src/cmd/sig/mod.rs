mod apply;
mod list;
mod new;
mod new_elf;

pub use apply::*;
use clap::{Args, Subcommand};
pub use list::*;
pub use new::*;
pub use new_elf::*;

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
            SigCommand::NewElf(new_elf) => new_elf.run(),
        }
    }
}

#[derive(Subcommand)]
enum SigCommand {
    New(NewSignature),
    Apply(ApplySignature),
    List(ListSignatures),
    NewElf(NewElfSignature),
}
