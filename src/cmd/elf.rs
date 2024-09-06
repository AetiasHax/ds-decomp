use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use object::{Object, ReadCache};

use crate::util::io::open_file;

#[derive(Debug, Args)]
pub struct Elf {
    /// Path to ELF file.
    #[arg(short = 'p', long)]
    path: PathBuf,

    /// Dump section information.
    #[arg(short = 's', long)]
    sections: bool,
}

impl Elf {
    pub fn run(&self) -> Result<()> {
        let file = open_file(&self.path)?;
        let reader = ReadCache::new(file);
        let object = object::read::File::parse(&reader)?;

        if self.sections {
            for section in object.sections() {
                println!("{:#x?}", section);
            }
        }

        Ok(())
    }
}
