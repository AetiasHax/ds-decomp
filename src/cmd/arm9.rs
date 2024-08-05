use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use ds_rom::rom::{self, Arm9BuildConfig, Autoload, Header};

use crate::{
    config::{module::Module, symbol::SymbolMap},
    util::io::{open_file, read_file},
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

        let arm9_build_config: Arm9BuildConfig = serde_yml::from_reader(open_file(self.arm9_path.join("arm9.yaml"))?)?;
        let arm9 = read_file(self.arm9_path.join("arm9.bin"))?;

        let itcm = read_file(self.arm9_path.join("itcm.bin"))?;
        let itcm_info = serde_yml::from_reader(open_file(self.arm9_path.join("itcm.yaml"))?)?;
        let itcm = Autoload::new(itcm, itcm_info);

        let dtcm = read_file(self.arm9_path.join("dtcm.bin"))?;
        let dtcm_info = serde_yml::from_reader(open_file(self.arm9_path.join("dtcm.yaml"))?)?;
        let dtcm = Autoload::new(dtcm, dtcm_info);

        let arm9 = rom::Arm9::with_two_tcms(arm9, itcm, dtcm, header.version(), arm9_build_config.offsets)?;

        let symbols = SymbolMap::new();
        let mut module = Module::new_arm9(symbols, &arm9)?;
        module.find_sections_arm9()?;

        for function in &module.sections().get(".text").unwrap().functions {
            println!("{}", function.display(module.symbol_map()));
        }

        Ok(())
    }
}
