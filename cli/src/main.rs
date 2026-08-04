use anyhow::Result;
use clap::{Parser, Subcommand};
use ds_decomp_cli::cmd::{
    Apply, CheckArgs, Delink, DiffArgs, Disassemble, DumpArgs, FixArgs, Format, ImportArgs, Init,
    JsonArgs, Lcf, Objdiff, RomArgs, SigArgs,
};
use env_logger::WriteStyle;
use log::LevelFilter;

/// Command-line toolkit for decompiling DS games.
#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    /// Enables debug logs.
    #[arg(long, short)]
    debug: bool,

    /// Forces colored output.
    #[arg(long, short)]
    force_color: bool,

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
    Fix(FixArgs),
    Apply(Apply),
    Dump(DumpArgs),
    Json(JsonArgs),
    Sig(SigArgs),
    Format(Format),
    Diff(DiffArgs),
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
            Command::Fix(fix) => fix.run(),
            Command::Apply(apply) => apply.run(),
            Command::Dump(dump) => dump.run(),
            Command::Json(json) => json.run(),
            Command::Sig(sig) => sig.run(),
            Command::Format(format) => format.run(),
            Command::Diff(diff) => diff.run(),
        }
    }

    fn configure_logger(&self, builder: &mut env_logger::Builder) -> Result<()> {
        #[allow(clippy::single_match)]
        match self {
            Command::Diff(diff) => diff.configure_logger(builder)?,
            _ => {}
        };
        Ok(())
    }
}

fn main() -> Result<()> {
    let args: Cli = Cli::parse();

    let level = if args.debug { LevelFilter::Debug } else { LevelFilter::Info };
    let write_style = if args.force_color { WriteStyle::Always } else { WriteStyle::Auto };
    let mut builder = env_logger::builder();
    if !args.debug {
        builder.format_timestamp(None).format_target(false);
    }
    match args.command {
        Command::Json(_) => {
            builder.filter_level(LevelFilter::Off);
        }
        _ => {
            builder.filter_level(level).write_style(write_style);
        }
    }
    args.command.configure_logger(&mut builder)?;
    builder.init();

    args.command.run()
}
