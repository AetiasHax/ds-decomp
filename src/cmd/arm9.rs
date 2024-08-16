use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use ds_rom::rom::Header;

use crate::{
    config::{module::Module, symbol::SymbolMap},
    util::{ds::load_arm9, io::open_file},
};

/// Disassembles the main ARM9 module.
#[derive(Debug, Args)]
pub struct Arm9 {
    /// Path to header.yaml.
    #[arg(short = 'H', long)]
    header_path: PathBuf,

    /// Path to arm9 directory.
    #[arg(short = 'p', long)]
    arm9_path: PathBuf,
}

impl Arm9 {
    pub fn run(&self) -> Result<()> {
        let header: Header = serde_yml::from_reader(open_file(&self.header_path)?)?;
        let arm9 = load_arm9(&self.arm9_path, &header)?;

        let symbols = SymbolMap::new();
        let module = Module::analyze_arm9(symbols, &arm9)?;

        for function in module.sections().get(".text").unwrap().functions.values() {
            println!("{}", function.display(module.symbol_map()));
        }

        Ok(())
    }
}
