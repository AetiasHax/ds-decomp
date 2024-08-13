use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct Config {
    pub module: ConfigModule,
    pub overlays: Vec<ConfigModule>,
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
