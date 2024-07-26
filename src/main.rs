pub mod analysis;
pub mod cmd;

use anyhow::Result;
use clap::{Parser, Subcommand};
use cmd::Overlay;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Overlay(Overlay),
}

impl Command {
    fn run(&self) -> Result<()> {
        match self {
            Command::Overlay(overlay) => overlay.run(),
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    args.command.run()
}
