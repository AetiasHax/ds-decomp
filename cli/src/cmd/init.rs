use std::path::{Path, PathBuf};

use anyhow::{Result, bail};
use clap::Args;
use ds_decomp::config::{
    config::{Config, ConfigAutoload, ConfigModule, ConfigOverlay},
    delinks::Delinks,
    module::{AnalysisOptions, Module, ModuleKind},
    symbol::SymbolMaps,
};
use ds_rom::rom::{Rom, RomConfig, RomLoadOptions, raw::AutoloadKind};
use path_slash::PathBufExt;
use pathdiff::diff_paths;

use crate::{
    config::program::Program,
    util::io::{create_dir_all, create_file, open_file},
};

/// Generates a config for the given extracted ROM.
#[derive(Args)]
pub struct Init {
    /// Path to config file in the extract directory.
    #[arg(long, short = 'r')]
    pub rom_config: PathBuf,

    /// Output path.
    #[arg(long, short = 'o')]
    pub output_path: PathBuf,

    /// Dry run, do not write files to output path.
    #[arg(long, short = 'd')]
    pub dry: bool,

    /// Path to build directory.
    #[arg(long, short = 'b')]
    pub build_path: PathBuf,

    /// Skips relocation analysis across modules. symbols.txt and relocs.txt will be incomplete.
    #[arg(long, hide = true)]
    pub skip_reloc_analysis: bool,

    /// Generates function symbols when a local function call doesn't lead to a known function. This can happen if the
    /// destination function is encrypted or otherwise wasn't found during function analysis.
    #[arg(long, hide = true)]
    pub allow_unknown_function_calls: bool,

    /// Adds a comment to every relocation in relocs.txt explaining where/why it was generated.
    #[arg(long, hide = true)]
    pub provide_reloc_source: bool,
}

impl Init {
    pub fn run(&self) -> Result<()> {
        let rom = Rom::load(
            &self.rom_config,
            RomLoadOptions {
                compress: false,
                encrypt: false,
                load_files: false,
                ..Default::default()
            },
        )?;

        let arm9_output_path = self.output_path.join("arm9");
        let arm9_overlays_output_path = arm9_output_path.join("overlays");
        let arm9_config_path = arm9_output_path.join("config.yaml");

        let mut symbol_maps = SymbolMaps::new();

        let analysis_options = AnalysisOptions {
            allow_unknown_function_calls: self.allow_unknown_function_calls,
            provide_reloc_source: self.provide_reloc_source,
        };

        let autoloads = rom.arm9().autoloads()?;
        let unknown_autoloads =
            autoloads.iter().filter(|autoload| matches!(autoload.kind(), AutoloadKind::Unknown(_))).collect::<Vec<_>>();

        let main = Module::analyze_arm9(rom.arm9(), &unknown_autoloads, &mut symbol_maps, &analysis_options)?;
        let overlays = rom
            .arm9_overlays()
            .iter()
            .map(|ov| Ok(Module::analyze_overlay(ov, &mut symbol_maps, &analysis_options)?))
            .collect::<Result<Vec<_>>>()?;
        let autoloads = autoloads
            .iter()
            .map(|autoload| match autoload.kind() {
                AutoloadKind::Itcm => Ok(Module::analyze_itcm(autoload, &mut symbol_maps, &analysis_options)?),
                AutoloadKind::Dtcm => Ok(Module::analyze_dtcm(autoload, &mut symbol_maps, &analysis_options)?),
                AutoloadKind::Unknown(_) => {
                    Ok(Module::analyze_unknown_autoload(autoload, &mut symbol_maps, &analysis_options)?)
                }
            })
            .collect::<Result<Vec<_>>>()?;

        let mut program = Program::new(main, overlays, autoloads, symbol_maps);
        if !self.skip_reloc_analysis {
            program.analyze_cross_references(&analysis_options)?;
        }

        // Generate configs
        let mut rom_config: RomConfig = serde_yml::from_reader(open_file(&self.rom_config)?)?;
        rom_config.arm9_bin = self.build_path.join("build/arm9.bin");
        rom_config.itcm.bin = self.build_path.join("build/itcm.bin");
        rom_config.dtcm.bin = self.build_path.join("build/dtcm.bin");
        rom_config.unknown_autoloads.iter_mut().for_each(|autoload| {
            autoload.files.bin = self.build_path.join(format!("build/autoload_{}.bin", autoload.index));
        });
        rom_config.arm9_overlays = Some(self.build_path.join("build/arm9_overlays.yaml"));
        let rom_config = rom_config;

        let overlay_configs = self.overlay_configs(
            &arm9_output_path,
            &arm9_overlays_output_path,
            program.overlays(),
            "arm9",
            program.symbol_maps(),
        )?;
        let autoload_configs =
            self.autoload_configs(&arm9_output_path, &rom_config, program.autoloads(), program.symbol_maps())?;
        let arm9_config = self.arm9_config(
            &arm9_output_path,
            &rom_config,
            program.main(),
            overlay_configs,
            autoload_configs,
            program.symbol_maps(),
        )?;

        if !self.dry {
            create_dir_all(&arm9_output_path)?;
            serde_yml::to_writer(create_file(arm9_config_path)?, &arm9_config)?;
        }

        Ok(())
    }

    fn make_path<P: AsRef<Path>, B: AsRef<Path>>(path: P, base: B) -> Result<PathBuf> {
        let path = path.as_ref();
        let base = base.as_ref();
        let Some(diff) = diff_paths(path, base) else {
            bail!("Failed to calculate path difference between '{}' and '{}'", path.display(), base.display());
        };
        Ok(PathBuf::from(diff.to_slash_lossy().as_ref()))
    }

    fn arm9_config(
        &self,
        path: &Path,
        rom_config: &RomConfig,
        module: &Module,
        overlays: Vec<ConfigOverlay>,
        autoloads: Vec<ConfigAutoload>,
        symbol_maps: &SymbolMaps,
    ) -> Result<Config> {
        let code_hash = fxhash::hash64(module.code());

        let delinks_path = path.join("delinks.txt");
        let symbols_path = path.join("symbols.txt");
        let relocations_path = path.join("relocs.txt");

        if !self.dry {
            Delinks::to_file(&delinks_path, module.sections())?;
            symbol_maps.get(module.kind()).unwrap().to_file(&symbols_path)?;
            module.relocations().to_file(&relocations_path)?;
        }

        Ok(Config {
            rom_config: Self::make_path(&self.rom_config, path)?,
            build_path: Self::make_path(&self.build_path, path)?,
            delinks_path: Self::make_path(self.build_path.join("delinks"), path)?,
            main_module: ConfigModule {
                name: "main".to_string(),
                object: Self::make_path(&rom_config.arm9_bin, path)?,
                hash: format!("{code_hash:016x}"),
                delinks: Self::make_path(delinks_path, path)?,
                symbols: Self::make_path(symbols_path, path)?,
                relocations: Self::make_path(relocations_path, path)?,
            },
            autoloads,
            overlays,
        })
    }

    fn autoload_configs(
        &self,
        path: &Path,
        rom_config: &RomConfig,
        modules: &[Module],
        symbol_maps: &SymbolMaps,
    ) -> Result<Vec<ConfigAutoload>> {
        let mut autoloads = vec![];
        for module in modules {
            let code_hash = fxhash::hash64(module.code());
            let ModuleKind::Autoload(kind) = module.kind() else {
                log::error!("Expected autoload module");
                bail!("Expected autoload module");
            };
            let (name, code_path) = match kind {
                AutoloadKind::Itcm => ("itcm".into(), &rom_config.itcm.bin),
                AutoloadKind::Dtcm => ("dtcm".into(), &rom_config.dtcm.bin),
                AutoloadKind::Unknown(index) => {
                    let Some(rom_autoload) = rom_config.unknown_autoloads.iter().find(|a| a.index == index) else {
                        log::error!("Unknown autoload index {index} not found in ROM config file");
                        bail!("Unknown autoload index {index} not found in ROM config file");
                    };
                    let name = format!("autoload_{index}");
                    (name, &rom_autoload.files.bin)
                }
            };

            let autoload_path = path.join(name);
            create_dir_all(&autoload_path)?;

            let delinks_path = autoload_path.join("delinks.txt");
            let symbols_path = autoload_path.join("symbols.txt");
            let relocs_path = autoload_path.join("relocs.txt");

            if !self.dry {
                Delinks::to_file(&delinks_path, module.sections())?;
                symbol_maps.get(module.kind()).unwrap().to_file(&symbols_path)?;
                module.relocations().to_file(&relocs_path)?;
            }

            autoloads.push(ConfigAutoload {
                module: ConfigModule {
                    name: module.name().to_string(),
                    object: Self::make_path(code_path, path)?,
                    hash: format!("{code_hash:016x}"),
                    delinks: Self::make_path(delinks_path, path)?,
                    symbols: Self::make_path(symbols_path, path)?,
                    relocations: Self::make_path(relocs_path, path)?,
                },
                kind,
            })
        }

        Ok(autoloads)
    }

    fn overlay_configs(
        &self,
        root: &Path,
        path: &Path,
        modules: &[Module],
        processor: &str,
        symbol_maps: &SymbolMaps,
    ) -> Result<Vec<ConfigOverlay>> {
        let mut overlays = vec![];

        for module in modules {
            let ModuleKind::Overlay(id) = module.kind() else {
                log::error!("Expected overlay module");
                bail!("Expected overlay module")
            };

            let code_path = self.build_path.join(format!("build/{processor}_{}.bin", module.name()));
            let code_hash = fxhash::hash64(module.code());

            let overlay_config_path = path.join(module.name());
            create_dir_all(&overlay_config_path)?;

            let delinks_path = overlay_config_path.join("delinks.txt");
            let symbols_path = overlay_config_path.join("symbols.txt");
            let relocs_path = overlay_config_path.join("relocs.txt");

            if !self.dry {
                Delinks::to_file(&delinks_path, module.sections())?;
                symbol_maps.get(module.kind()).unwrap().to_file(&symbols_path)?;
                module.relocations().to_file(&relocs_path)?;
            }

            overlays.push(ConfigOverlay {
                module: ConfigModule {
                    name: module.name().to_string(),
                    object: Self::make_path(code_path, root)?,
                    hash: format!("{code_hash:016x}"),
                    delinks: Self::make_path(delinks_path, root)?,
                    symbols: Self::make_path(symbols_path, root)?,
                    relocations: Self::make_path(relocs_path, root)?,
                },
                signed: module.signed(),
                id,
            });
        }

        Ok(overlays)
    }
}
