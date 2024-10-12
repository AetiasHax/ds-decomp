pub mod analysis;
pub mod cmd;
pub mod config;
pub mod util;

use anyhow::Result;
use argp::FromArgs;
use cmd::{Delink, Disassemble, ImportArgs, Init, Lcf, RomArgs};
use log::LevelFilter;

/// Command-line toolkit for decompiling DS games.
#[derive(FromArgs)]
struct Args {
    #[argp(subcommand)]
    command: Command,
}

#[derive(FromArgs)]
#[argp(subcommand)]
enum Command {
    Disassemble(Disassemble),
    Delink(Delink),
    Init(Init),
    Rom(RomArgs),
    Lcf(Lcf),
    Import(ImportArgs),
}

impl Command {
    fn run(&self) -> Result<()> {
        match self {
            Command::Disassemble(disassemble) => disassemble.run(),
            Command::Delink(delink) => delink.run(),
            Command::Init(init) => init.run(),
            Command::Rom(rom) => rom.run(),
            Command::Lcf(lcf) => lcf.run(),
            Command::Import(import) => import.run(),
        }
    }
}

fn main() -> Result<()> {
    env_logger::builder().filter_level(LevelFilter::Info).init();

    let args: Args = argp::parse_args_or_exit(argp::DEFAULT);
    args.command.run()
}
