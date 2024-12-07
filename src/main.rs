use anyhow::Result;
use clap::{Parser, Subcommand};
use ds_decomp::cmd::{CheckArgs, Delink, Disassemble, ImportArgs, Init, Lcf, Objdiff, RomArgs};
use log::LevelFilter;

/// Command-line toolkit for decompiling DS games.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Enables debug logs.
    #[arg(long, short)]
    debug: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    #[command(name = "dis")]
    Disassemble(Disassemble),
    Delink(Delink),
    Init(Init),
    Rom(RomArgs),
    Lcf(Lcf),
    Import(ImportArgs),
    Check(CheckArgs),
    Objdiff(Objdiff),
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
            Command::Check(check) => check.run(),
            Command::Objdiff(objdiff) => objdiff.run(),
        }
    }
}

fn main() -> Result<()> {
    let args: Cli = Cli::parse();

    let level = if args.debug { LevelFilter::Debug } else { LevelFilter::Info };
    env_logger::builder().filter_level(level).init();

    args.command.run()
}
