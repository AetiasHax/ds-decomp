pub mod analysis;
pub mod cmd;
pub mod config;
pub mod util;

use anyhow::Result;
use clap::{Parser, Subcommand};
use cmd::{Arm9, Disassemble, Init, Overlay};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Overlay(Overlay),
    Arm9(Arm9),
    #[command(name = "dis")]
    Disassemble(Disassemble),
    Init(Init),
}

impl Command {
    fn run(&self) -> Result<()> {
        match self {
            Command::Overlay(overlay) => overlay.run(),
            Command::Arm9(arm9) => arm9.run(),
            Command::Disassemble(disassemble) => disassemble.run(),
            Command::Init(init) => init.run(),
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    args.command.run()
}
