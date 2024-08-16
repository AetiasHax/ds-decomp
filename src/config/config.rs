use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub module: ConfigModule,
    pub autoloads: Vec<ConfigModule>,
    pub overlays: Vec<ConfigOverlay>,
}

#[derive(Serialize, Deserialize)]
pub struct ConfigModule {
    /// Binary file to build
    pub object: PathBuf,
    /// 64-bit fxhash of the binary file
    pub hash: String,
    /// Path to delinks file
    pub delinks: PathBuf,
    /// Path to symbols file
    pub symbols: PathBuf,
    /// Path to overlay loads file
    pub overlay_loads: PathBuf,
}

#[derive(Serialize, Deserialize)]
pub struct ConfigOverlay {
    pub module: ConfigModule,
    pub id: u32,
}
