use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use clap::Args;
use ds_rom::rom::{self, raw::AutoloadKind, Rom, RomLoadOptions};
use path_slash::PathBufExt;
use pathdiff::diff_paths;

use crate::{
    config::{
        config::{Config, ConfigAutoload, ConfigModule, ConfigOverlay},
        delinks::Delinks,
        module::{Module, ModuleKind},
        program::Program,
    },
    util::io::{create_dir_all, create_file},
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
        let rom = Rom::load(
            &self.extract_path,
            RomLoadOptions { compress: false, encrypt: false, load_files: false, ..Default::default() },
        )?;

        let arm9_output_path = self.output_path.join("arm9");
        let arm9_overlays_output_path = arm9_output_path.join("overlays");
        let arm9_config_path = arm9_output_path.join("config.yaml");

        let main = Module::analyze_arm9(rom.arm9())?;
        let overlays = rom.arm9_overlays().iter().map(|ov| Module::analyze_overlay(ov)).collect::<Result<Vec<_>>>()?;
        let autoloads = rom.arm9().autoloads()?;
        let autoloads = autoloads
            .iter()
            .map(|autoload| match autoload.kind() {
                AutoloadKind::Itcm => Module::analyze_itcm(autoload),
                AutoloadKind::Dtcm => Module::analyze_dtcm(autoload),
                AutoloadKind::Unknown => bail!("unknown autoload kind"),
            })
            .collect::<Result<Vec<_>>>()?;

        let mut program = Program::new(main, overlays, autoloads);
        program.analyze_cross_references()?;

        let overlay_configs =
            self.overlay_configs(&arm9_output_path, &arm9_overlays_output_path, program.overlays(), "arm9")?;
        let autoload_configs = self.autoload_configs(&arm9_output_path, program.autoloads())?;
        let arm9_config = self.arm9_config(&arm9_output_path, program.main(), overlay_configs, autoload_configs)?;

        create_dir_all(&arm9_output_path)?;
        serde_yml::to_writer(create_file(arm9_config_path)?, &arm9_config)?;

        Ok(())
    }

    fn make_path<P: AsRef<Path>, B: AsRef<Path>>(path: P, base: B) -> PathBuf {
        PathBuf::from(diff_paths(path, &base).unwrap().to_slash_lossy().as_ref())
    }

    fn arm9_config(
        &self,
        path: &Path,
        module: &Module,
        overlays: Vec<ConfigOverlay>,
        autoloads: Vec<ConfigAutoload>,
    ) -> Result<Config> {
        let code_hash = fxhash::hash64(module.code());

        let delinks_path = path.join("delinks.txt");
        Delinks::to_file(&delinks_path, module.sections())?;

        let symbols_path = path.join("symbols.txt");
        module.symbol_map().to_file(&symbols_path)?;

        let overlay_loads_path = path.join("overlay_loads.txt");

        Ok(Config {
            module: ConfigModule {
                name: "main".to_string(),
                object: Self::make_path(self.extract_path.join(rom::ARM9_BIN_PATH), path),
                hash: format!("{:016x}", code_hash),
                delinks: Self::make_path(delinks_path, path),
                symbols: Self::make_path(symbols_path, path),
                overlay_loads: Self::make_path(overlay_loads_path, path),
            },
            autoloads,
            overlays,
        })
    }

    fn autoload_configs(&self, path: &Path, modules: &[Module]) -> Result<Vec<ConfigAutoload>> {
        let mut autoloads = vec![];
        for module in modules {
            let code_hash = fxhash::hash64(module.code());
            let ModuleKind::Autoload(kind) = module.kind() else {
                panic!("expected autoload module");
            };
            let (name, bin_path) = match kind {
                AutoloadKind::Itcm => ("itcm", rom::ITCM_BIN_PATH),
                AutoloadKind::Dtcm => ("dtcm", rom::DTCM_BIN_PATH),
                _ => panic!("unknown autoload kind"),
            };

            let autoload_path = path.join(name);
            create_dir_all(&autoload_path)?;
            let delinks_path = autoload_path.join("delinks.txt");
            let symbols_path = autoload_path.join("symbols.txt");
            let overlay_loads_path = autoload_path.join("overlay_loads.txt");
            Delinks::to_file(&delinks_path, module.sections())?;
            module.symbol_map().to_file(&symbols_path)?;

            autoloads.push(ConfigAutoload {
                module: ConfigModule {
                    name: module.name().to_string(),
                    object: Self::make_path(self.extract_path.join(bin_path), path),
                    hash: format!("{:016x}", code_hash),
                    delinks: Self::make_path(delinks_path, path),
                    symbols: Self::make_path(symbols_path, path),
                    overlay_loads: Self::make_path(overlay_loads_path, path),
                },
                kind,
            })
        }

        Ok(autoloads)
    }

    fn overlay_configs(&self, root: &Path, path: &Path, modules: &[Module], processor: &str) -> Result<Vec<ConfigOverlay>> {
        let mut overlays = vec![];
        let overlays_path = self.extract_path.join(format!("{processor}_overlays"));

        for module in modules {
            let ModuleKind::Overlay(id) = module.kind() else {
                panic!("expected overlay module");
            };

            let code_path = overlays_path.join(format!("{}.bin", module.name()));
            let code_hash = fxhash::hash64(module.code());

            let overlay_config_path = path.join(module.name());
            create_dir_all(&overlay_config_path)?;

            let delinks_path = overlay_config_path.join("delinks.txt");
            Delinks::to_file(&delinks_path, module.sections())?;

            let symbols_path = overlay_config_path.join("symbols.txt");
            module.symbol_map().to_file(&symbols_path)?;

            let overlay_loads_path = overlay_config_path.join("overlay_loads.txt");

            overlays.push(ConfigOverlay {
                module: ConfigModule {
                    name: module.name().to_string(),
                    object: Self::make_path(code_path, root),
                    hash: format!("{:016x}", code_hash),
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
