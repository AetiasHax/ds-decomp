use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use ds_rom::rom::{self, Header, OverlayConfig};
use path_slash::PathBufExt;
use pathdiff::diff_paths;

use crate::{
    config::{
        config::{Config, ConfigModule},
        delinks::Delinks,
        module::Module,
        symbol::SymbolMap,
    },
    util::{
        ds::load_arm9,
        io::{create_dir_all, create_file, open_file, read_file},
    },
};

/// Generates a config for the given extracted ROM.
#[derive(Debug, Args)]
pub struct Init {
    /// Extraction path.
    #[arg(short = 'e', long)]
    extract_path: PathBuf,

    /// Output path.
    #[arg(short = 'o', long)]
    output_path: PathBuf,
}

impl Init {
    pub fn run(&self) -> Result<()> {
        let header_path = self.extract_path.join("header.yaml");
        let header: Header = serde_yml::from_reader(open_file(header_path)?)?;

        let arm9_output_path = self.output_path.join("arm9");
        let arm9_overlays_output_path = arm9_output_path.join("overlays");
        let arm9_config_path = arm9_output_path.join("config.yaml");

        let arm9_overlays = self.read_overlays(&arm9_output_path, &arm9_overlays_output_path, &header, "arm9")?;
        let arm9_config = self.read_arm9(&arm9_output_path, &header, arm9_overlays)?;

        create_dir_all(&arm9_output_path)?;
        serde_yml::to_writer(create_file(arm9_config_path)?, &arm9_config)?;

        Ok(())
    }

    fn make_path<P: AsRef<Path>, B: AsRef<Path>>(path: P, base: B) -> PathBuf {
        PathBuf::from_backslash_lossy(diff_paths(path, &base).unwrap())
    }

    fn read_arm9(&self, path: &Path, header: &Header, overlays: Vec<ConfigModule>) -> Result<Config> {
        let arm9_path = self.extract_path.join("arm9");
        let arm9_bin_file = arm9_path.join("arm9.bin");

        let arm9 = load_arm9(arm9_path, header)?;
        let object_hash = fxhash::hash64(arm9.full_data());

        let symbols = SymbolMap::new();
        let module = Module::new_arm9_and_find_sections(symbols, &arm9)?;

        let delinks_path = path.join("delinks.txt");
        Delinks::to_file(&delinks_path, module.sections())?;

        let symbols_path = path.join("symbols.txt");
        module.symbol_map().to_file(&symbols_path)?;

        let overlay_loads_path = path.join("overlay_loads.txt");

        Ok(Config {
            module: ConfigModule {
                object: Self::make_path(arm9_bin_file, path),
                hash: format!("{:016x}", object_hash),
                delinks: Self::make_path(delinks_path, path),
                symbols: Self::make_path(symbols_path, path),
                overlay_loads: Self::make_path(overlay_loads_path, path),
            },
            overlays,
        })
    }

    fn read_overlays(&self, root: &Path, path: &Path, header: &Header, processor: &str) -> Result<Vec<ConfigModule>> {
        let mut overlays = vec![];
        let overlays_path = self.extract_path.join(format!("{processor}_overlays"));
        let overlays_config_file = overlays_path.join(format!("overlays.yaml"));
        let overlay_configs: Vec<OverlayConfig> = serde_yml::from_reader(open_file(overlays_config_file)?)?;

        for config in overlay_configs {
            let id = config.info.id;

            let data_path = overlays_path.join(config.file_name);
            let data = read_file(&data_path)?;
            let data_hash = fxhash::hash64(&data);

            let symbols = SymbolMap::new();
            let overlay = rom::Overlay::new(data, header.version(), config.info);
            let module = Module::new_overlay_and_find_sections(symbols, &overlay)?;

            let overlay_config_path = path.join(format!("ov{:03}", id));
            create_dir_all(&overlay_config_path)?;

            let delinks_path = overlay_config_path.join("delinks.txt");
            Delinks::to_file(&delinks_path, module.sections())?;

            let symbols_path = overlay_config_path.join("symbols.txt");
            module.symbol_map().to_file(&symbols_path)?;

            let overlay_loads_path = overlay_config_path.join("overlay_loads.txt");

            overlays.push(ConfigModule {
                object: Self::make_path(data_path, root),
                hash: format!("{:016x}", data_hash),
                delinks: Self::make_path(delinks_path, root),
                symbols: Self::make_path(symbols_path, root),
                overlay_loads: Self::make_path(overlay_loads_path, root),
            });
        }

        Ok(overlays)
    }
}
