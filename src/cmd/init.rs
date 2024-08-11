use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use ds_rom::rom::{self, Arm9BuildConfig, Autoload, Header, OverlayConfig};

use crate::{
    config::{
        config::{Config, ConfigModule},
        delinks::Delinks,
        module::Module,
        symbol::SymbolMap,
    },
    util::io::{create_dir_all, create_file, open_file, read_file},
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

        let arm9_overlays = self.read_overlays(&arm9_overlays_output_path, &header, "arm9")?;
        let arm9_config = self.read_arm9(&arm9_output_path, &header, arm9_overlays)?;

        create_dir_all(&arm9_output_path)?;
        serde_yml::to_writer(create_file(arm9_config_path)?, &arm9_config)?;

        Ok(())
    }

    fn read_arm9(&self, path: &Path, header: &Header, overlays: Vec<ConfigModule>) -> Result<Config> {
        let arm9_path = self.extract_path.join("arm9");
        let arm9_bin_file = arm9_path.join("arm9.bin");

        let arm9_build_config: Arm9BuildConfig = serde_yml::from_reader(open_file(arm9_path.join("arm9.yaml"))?)?;
        let arm9 = read_file(&arm9_bin_file)?;
        let object_hash = fxhash::hash64(&arm9);

        let itcm = read_file(arm9_path.join("itcm.bin"))?;
        let itcm_info = serde_yml::from_reader(open_file(arm9_path.join("itcm.yaml"))?)?;
        let itcm = Autoload::new(itcm, itcm_info);

        let dtcm = read_file(arm9_path.join("dtcm.bin"))?;
        let dtcm_info = serde_yml::from_reader(open_file(arm9_path.join("dtcm.yaml"))?)?;
        let dtcm = Autoload::new(dtcm, dtcm_info);

        let arm9 = rom::Arm9::with_two_tcms(arm9, itcm, dtcm, header.version(), arm9_build_config.offsets)?;

        let symbols = SymbolMap::new();
        let mut module = Module::new_arm9(symbols, &arm9)?;
        module.find_sections_arm9()?;

        let delinks_path = path.join("delinks.txt");
        Delinks::to_file(&delinks_path, module.sections())?;

        let symbols_path = path.join("symbols.txt");
        module.symbol_map().to_file(symbols_path)?;

        Ok(Config {
            module: ConfigModule {
                object: arm9_bin_file,
                hash: object_hash,
                delinks: delinks_path,
                symbols: "./symbols.txt".into(),
                overlay_loads: "./overlay_loads.txt".into(),
            },
            overlays,
        })
    }

    fn read_overlays(&self, path: &Path, header: &Header, processor: &str) -> Result<Vec<ConfigModule>> {
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
            let mut module = Module::new_overlay(symbols, &overlay)?;
            module.find_sections_overlay()?;

            let overlay_config_path = path.join(format!("ov{:03}", id));
            create_dir_all(&overlay_config_path)?;

            let delinks_path = overlay_config_path.join("delinks.txt");
            Delinks::to_file(&delinks_path, module.sections())?;

            let symbols_path = overlay_config_path.join("symbols.txt");
            module.symbol_map().to_file(symbols_path)?;

            overlays.push(ConfigModule {
                object: data_path,
                hash: data_hash,
                delinks: delinks_path,
                symbols: overlay_config_path.join("symbols.txt"),
                overlay_loads: overlay_config_path.join("overlay_loads.txt"),
            });
        }

        Ok(overlays)
    }
}
