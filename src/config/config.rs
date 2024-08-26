use std::path::PathBuf;

use ds_rom::rom::raw::AutoloadKind;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Config {
    #[serde(flatten)]
    pub module: ConfigModule,
    pub autoloads: Vec<ConfigAutoload>,
    pub overlays: Vec<ConfigOverlay>,
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
    /// Path to xrefs file
    pub xrefs: PathBuf,
}

#[derive(Serialize, Deserialize)]
pub struct ConfigOverlay {
    pub id: u16,
    #[serde(flatten)]
    pub module: ConfigModule,
}

#[derive(Serialize, Deserialize)]
pub struct ConfigAutoload {
    pub kind: AutoloadKind,
    #[serde(flatten)]
    pub module: ConfigModule,
}
