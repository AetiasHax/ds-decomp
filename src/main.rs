pub mod analysis;
pub mod cmd;
pub mod config;
pub mod util;

use anyhow::Result;
use clap::{Parser, Subcommand};
use cmd::{Disassemble, Init};

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    #[command(name = "dis")]
    Disassemble(Disassemble),
    Init(Init),
}

impl Command {
    fn run(&self) -> Result<()> {
        match self {
            Command::Disassemble(disassemble) => disassemble.run(),
            Command::Init(init) => init.run(),
        }
    }
}

fn main() -> Result<()> {
    let args = Args::parse();
    args.command.run()
}
