mod delinks;

use delinks::*;

use clap::{Args, Subcommand};

#[derive(Args)]
pub struct JsonArgs {
    #[command(subcommand)]
    command: JsonCommand,
}

impl JsonArgs {
    pub fn run(&self) -> anyhow::Result<()> {
        match &self.command {
            JsonCommand::Delinks(delinks) => delinks.run(),
        }
    }
}

#[derive(Subcommand)]
enum JsonCommand {
    Delinks(JsonDelinks),
}
