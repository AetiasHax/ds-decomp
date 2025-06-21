use anyhow::Result;
use clap::Args;

use crate::analysis::signature::Signatures;

#[derive(Args)]
pub struct ListSignatures {}

impl ListSignatures {
    pub fn run(&self) -> Result<()> {
        for name in Signatures::iter_names() {
            println!("{name}");
        }

        Ok(())
    }
}
