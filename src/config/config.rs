use std::path::PathBuf;

pub struct Config {
    pub module: ConfigModule,
    pub overlays: Vec<ConfigModule>,
}

pub struct ConfigModule {
    /// Binary file to build
    pub object: PathBuf,
    /// 64-bit fxhash of the binary file
    pub hash: u64,
    /// Path to splits file
    pub splits: PathBuf,
    /// Path to symbols file
    pub symbols: PathBuf,
    /// Path to overlay loads file
    pub overlay_loads: PathBuf,
}
