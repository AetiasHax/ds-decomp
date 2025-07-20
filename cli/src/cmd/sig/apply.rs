use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use ds_decomp::config::config::Config;

use crate::{
    analysis::signature::{ApplyResult, Signatures},
    config::program::Program,
};

#[derive(Args)]
pub struct ApplySignature {
    /// Path to config.yaml
    #[arg(long, short = 'c')]
    config_path: PathBuf,

    /// Signature to apply.
    #[arg(long, short = 's')]
    signature: Option<String>,

    /// Apply all known signatures.
    #[arg(long, short = 'a', default_value_t = false)]
    all: bool,

    /// Dry run, do not write to any files.
    #[arg(long, short = 'd', default_value_t = false)]
    dry: bool,
}

impl ApplySignature {
    pub fn run(&self) -> Result<()> {
        let config_path = self.config_path.parent().unwrap();

        let config = Config::from_file(&self.config_path)?;
        let rom = config.load_rom(config_path)?;
        let mut program = Program::from_config(config_path, &config, &rom)?;

        if self.all {
            for signatures in Signatures::list()? {
                self.apply_signatures(&mut program, &signatures)?;
            }
        } else if let Some(signature_name) = &self.signature {
            let signatures = Signatures::get(signature_name)?;
            self.apply_signatures(&mut program, &signatures)?;
        } else {
            log::error!("No signature specified. Use --signature or --all to apply signatures.");
            return Ok(());
        }

        if !self.dry {
            program.write_to_files(config_path, &config)?;
        } else {
            log::info!("Dry run enabled, no changes were written");
        }

        Ok(())
    }

    fn apply_signatures(&self, program: &mut Program, signatures: &Signatures) -> Result<()> {
        log::info!("Applying signature: {}", signatures.name());
        match signatures.apply(program)? {
            ApplyResult::Applied => {}
            ApplyResult::NotFound => log::error!("No matching function found"),
            ApplyResult::MultipleFound => log::error!("Multiple matching functions found, cannot apply signature"),
        }
        Ok(())
    }
}
