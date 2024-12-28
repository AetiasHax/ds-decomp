use std::{
    fmt::Display,
    path::{Path, PathBuf},
};

use anyhow::{bail, Context, Result};
use clap::Args;
use ds_decomp_config::config::{
    config::{Config, ConfigModule},
    module::ModuleKind,
};

use crate::util::io::read_file;

/// Verifies that built modules are matching the base ROM.
#[derive(Args)]
pub struct CheckModules {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    pub config_path: PathBuf,

    /// Return failing exit code if a module doesn't pass the checks.
    #[arg(long, short = 'f')]
    pub fail: bool,
}

#[derive(PartialEq, Eq)]
enum CheckResult {
    ChecksumFailed,
    Ok, // OK
}

impl CheckModules {
    pub fn run(&self) -> Result<()> {
        let config = Config::from_file(&self.config_path)?;
        let config_path = self.config_path.parent().unwrap();

        let mut success = true;

        success &= self.print_check_module(&config.main_module, ModuleKind::Arm9, config_path)?;
        for autoload in &config.autoloads {
            success &= self.print_check_module(&autoload.module, ModuleKind::Autoload(autoload.kind), config_path)?;
        }
        for overlay in &config.overlays {
            success &= self.print_check_module(&overlay.module, ModuleKind::Overlay(overlay.id), config_path)?;
        }

        if self.fail && !success {
            bail!("Some module(s) didn't pass the checks.");
        }

        Ok(())
    }

    fn print_check_module(&self, module: &ConfigModule, module_kind: ModuleKind, config_path: &Path) -> Result<bool> {
        let result = self.check_module(module, config_path)?;
        log::info!("Check {module_kind}: {result}");
        Ok(result == CheckResult::Ok)
    }

    fn check_module(&self, module: &ConfigModule, config_path: &Path) -> Result<CheckResult> {
        let base_hash = u64::from_str_radix(&module.hash, 16).with_context(|| format!("Invalid hash '{}'", module.hash))?;

        let code = read_file(config_path.join(&module.object))?;
        let code_hash = fxhash::hash64(&code);

        if code_hash != base_hash {
            Ok(CheckResult::ChecksumFailed)
        } else {
            Ok(CheckResult::Ok)
        }
    }
}

impl Display for CheckResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckResult::ChecksumFailed => write!(f, "checksum failed"),
            CheckResult::Ok => write!(f, "OK"),
        }
    }
}
