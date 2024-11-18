mod modules;

pub use modules::*;

use anyhow::Result;
use argp::FromArgs;

/// Subcommands for checking/verifying build output.
#[derive(FromArgs)]
#[argp(subcommand, name = "check")]
pub struct CheckArgs {
    #[argp(subcommand)]
    command: CheckCommand,
}

impl CheckArgs {
    pub fn run(&self) -> Result<()> {
        match &self.command {
            CheckCommand::Modules(modules) => modules.run(),
        }
    }
}

#[derive(FromArgs)]
#[argp(subcommand)]
enum CheckCommand {
    Modules(CheckModules),
}
