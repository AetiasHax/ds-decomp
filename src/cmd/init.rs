use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use ds_rom::rom::{self, Header, OverlayConfig};
use path_slash::PathBufExt;
use pathdiff::diff_paths;

use crate::{
    config::{
        config::{Config, ConfigModule, ConfigOverlay},
        delinks::Delinks,
        module::Module,
        symbol::SymbolMap,
    },
    util::{
        ds::{load_arm9, load_dtcm, load_itcm},
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
        let autoloads = self.read_autoloads(&arm9_output_path)?;
        let arm9_config = self.read_arm9(&arm9_output_path, &header, arm9_overlays, autoloads)?;

        create_dir_all(&arm9_output_path)?;
        serde_yml::to_writer(create_file(arm9_config_path)?, &arm9_config)?;

        Ok(())
    }

    fn make_path<P: AsRef<Path>, B: AsRef<Path>>(path: P, base: B) -> PathBuf {
        PathBuf::from(diff_paths(path, &base).unwrap().to_slash_lossy().as_ref())
    }

    fn read_arm9(
        &self,
        path: &Path,
        header: &Header,
        overlays: Vec<ConfigOverlay>,
        autoloads: Vec<ConfigModule>,
    ) -> Result<Config> {
        let arm9_path = self.extract_path.join("arm9");
        let arm9_bin_file = arm9_path.join("arm9.bin");

        let arm9 = load_arm9(arm9_path, header)?;
        let object_hash = fxhash::hash64(arm9.full_data());

        let symbols = SymbolMap::new();
        let module = Module::analyze_arm9(symbols, &arm9)?;

        let delinks_path = path.join("delinks.txt");
        Delinks::to_file(&delinks_path, module.sections())?;

        let symbols_path = path.join("symbols.txt");
        module.symbol_map().to_file(&symbols_path)?;

        let overlay_loads_path = path.join("overlay_loads.txt");

        Ok(Config {
            module: ConfigModule {
                name: "main".to_string(),
                object: Self::make_path(arm9_bin_file, path),
                hash: format!("{:016x}", object_hash),
                delinks: Self::make_path(delinks_path, path),
                symbols: Self::make_path(symbols_path, path),
                overlay_loads: Self::make_path(overlay_loads_path, path),
            },
            autoloads,
            overlays,
        })
    }

    fn read_autoloads(&self, path: &Path) -> Result<Vec<ConfigModule>> {
        let arm9_path = self.extract_path.join("arm9");
        let itcm_bin_file = arm9_path.join("itcm.bin");
        let dtcm_bin_file = arm9_path.join("dtcm.bin");

        let itcm = load_itcm(&arm9_path)?;
        let dtcm = load_dtcm(&arm9_path)?;

        let itcm_hash = fxhash::hash64(itcm.full_data());
        let dtcm_hash = fxhash::hash64(dtcm.full_data());

        let itcm = Module::analyze_itcm(SymbolMap::new(), &itcm)?;
        let dtcm = Module::analyze_dtcm(SymbolMap::new(), &dtcm)?;

        let itcm_path = path.join("itcm");
        create_dir_all(&itcm_path)?;
        let itcm_delinks_path = itcm_path.join("delinks.txt");
        let itcm_symbols_path = itcm_path.join("symbols.txt");
        let itcm_overlay_loads_path = itcm_path.join("overlay_loads.txt");
        Delinks::to_file(&itcm_delinks_path, itcm.sections())?;
        itcm.symbol_map().to_file(&itcm_symbols_path)?;

        let dtcm_path = path.join("dtcm");
        create_dir_all(&dtcm_path)?;
        let dtcm_delinks_path = dtcm_path.join("delinks.txt");
        let dtcm_symbols_path = dtcm_path.join("symbols.txt");
        let dtcm_overlay_loads_path = dtcm_path.join("overlay_loads.txt");
        Delinks::to_file(&dtcm_delinks_path, dtcm.sections())?;
        dtcm.symbol_map().to_file(&dtcm_symbols_path)?;

        Ok(vec![
            ConfigModule {
                name: "itcm".to_string(),
                object: Self::make_path(itcm_bin_file, path),
                hash: format!("{:016x}", itcm_hash),
                delinks: Self::make_path(itcm_delinks_path, path),
                symbols: Self::make_path(itcm_symbols_path, path),
                overlay_loads: Self::make_path(itcm_overlay_loads_path, path),
            },
            ConfigModule {
                name: "dtcm".to_string(),
                object: Self::make_path(dtcm_bin_file, path),
                hash: format!("{:016x}", dtcm_hash),
                delinks: Self::make_path(dtcm_delinks_path, path),
                symbols: Self::make_path(dtcm_symbols_path, path),
                overlay_loads: Self::make_path(dtcm_overlay_loads_path, path),
            },
        ])
    }

    fn read_overlays(&self, root: &Path, path: &Path, header: &Header, processor: &str) -> Result<Vec<ConfigOverlay>> {
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
            let module = Module::analyze_overlay(symbols, &overlay)?;

            let overlay_config_path = path.join(format!("ov{:03}", id));
            create_dir_all(&overlay_config_path)?;

            let delinks_path = overlay_config_path.join("delinks.txt");
            Delinks::to_file(&delinks_path, module.sections())?;

            let symbols_path = overlay_config_path.join("symbols.txt");
            module.symbol_map().to_file(&symbols_path)?;

            let overlay_loads_path = overlay_config_path.join("overlay_loads.txt");

            overlays.push(ConfigOverlay {
                module: ConfigModule {
                    name: format!("ov{:03}", id),
                    object: Self::make_path(data_path, root),
                    hash: format!("{:016x}", data_hash),
                    delinks: Self::make_path(delinks_path, root),
                    symbols: Self::make_path(symbols_path, root),
                    overlay_loads: Self::make_path(overlay_loads_path, root),
                },
                id,
            });
        }

        Ok(overlays)
    }
}
