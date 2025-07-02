mod ambig_relocs;
mod elf_symbols;

use ambig_relocs::*;
use elf_symbols::*;

use clap::{Args, Subcommand};

/// Subcommands for dumping information from a dsd project.
#[derive(Args)]
pub struct DumpArgs {
    #[command(subcommand)]
    command: DumpCommands,
}

impl DumpArgs {
    pub fn run(&self) -> anyhow::Result<()> {
        match &self.command {
            DumpCommands::ElfSymbols(dump_elf_symbols) => dump_elf_symbols.run(),
            DumpCommands::AmbigRelocs(dump_ambig_relocs) => dump_ambig_relocs.run(),
        }
    }
}

#[derive(Subcommand)]
enum DumpCommands {
    ElfSymbols(DumpElfSymbols),
    AmbigRelocs(DumpAmbigRelocs),
}
