pub mod analysis;
pub mod cmd;
pub mod config;
pub mod util;

use anyhow::Result;
use clap::{Parser, Subcommand};
use cmd::{Delink, Disassemble, Init};
use log::LevelFilter;

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
    Delink(Delink),
    Init(Init),
}

impl Command {
    fn run(&self) -> Result<()> {
        match self {
            Command::Disassemble(disassemble) => disassemble.run(),
            Command::Delink(delink) => delink.run(),
            Command::Init(init) => init.run(),
        }
    }
}

fn main() -> Result<()> {
    env_logger::builder().filter_level(LevelFilter::Warn).init();

    let args = Args::parse();
    args.command.run()
}
