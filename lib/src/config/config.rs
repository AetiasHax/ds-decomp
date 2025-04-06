use std::{
    backtrace::Backtrace,
    path::{Path, PathBuf},
};

use ds_rom::rom::raw::AutoloadKind;
use serde::{Deserialize, Serialize};
use snafu::Snafu;

use crate::util::io::{open_file, FileError};

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub rom_config: PathBuf,
    pub build_path: PathBuf,
    pub delinks_path: PathBuf,
    pub main_module: ConfigModule,
    pub autoloads: Vec<ConfigAutoload>,
    pub overlays: Vec<ConfigOverlay>,
}

#[derive(Debug, Snafu)]
pub enum ConfigParseError {
    #[snafu(transparent)]
    File { source: FileError },
    #[snafu(display("Failed to parse dsd config file '{}': {error}\n{backtrace}", path.display()))]
    SerdeYml { path: PathBuf, error: serde_yml::Error, backtrace: Backtrace },
}

impl Config {
    pub fn from_file(path: &Path) -> Result<Config, ConfigParseError> {
        let file = open_file(path)?;
        serde_yml::from_reader(file).map_err(|error| SerdeYmlSnafu { path, error }.build())
    }
}

#[derive(Serialize, Deserialize)]
pub struct ConfigModule {
    /// Name of module
    pub name: String,
    /// Binary file to build
    pub object: PathBuf,
    /// 64-bit fxhash of the binary file
    pub hash: String,
    /// Path to delinks file
    pub delinks: PathBuf,
    /// Path to symbols file
    pub symbols: PathBuf,
    /// Path to relocs file
    pub relocations: PathBuf,
}

#[derive(Serialize, Deserialize)]
pub struct ConfigOverlay {
    pub id: u16,
    #[serde(default = "default_overlay_signed", skip_serializing_if = "skip_overlay_signed")]
    pub signed: bool,
    #[serde(flatten)]
    pub module: ConfigModule,
}

fn default_overlay_signed() -> bool {
    false
}

fn skip_overlay_signed(signed: &bool) -> bool {
    *signed == default_overlay_signed()
}

#[derive(Serialize, Deserialize)]
pub struct ConfigAutoload {
    pub kind: AutoloadKind,
    #[serde(flatten)]
    pub module: ConfigModule,
}
