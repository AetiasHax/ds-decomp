use std::path::PathBuf;

use anyhow::Result;
use argp::FromArgs;
use globset::Glob;
use objdiff_core::config::ProjectObject;

use crate::{
    config::{
        config::{Config, ConfigModule},
        delinks::Delinks,
        module::ModuleKind,
    },
    util::io::open_file,
};

// 2.0.0 added ARM and DS support
const MIN_OBJDIFF_VERSION: &str = "2.0.0";

/// Generates an objdiff configuration.
#[derive(FromArgs)]
#[argp(subcommand, name = "objdiff")]
pub struct Objdiff {
    /// Path to config.yaml.
    #[argp(option, short = 'c')]
    config_path: PathBuf,

    /// Includes decomp.me scratches.
    #[argp(switch, short = 's')]
    scratch: bool,

    /// See https://decomp.me/api/compiler with compilers for the `nds_arm9` platform.
    #[argp(option, short = 'C')]
    compiler: Option<String>,

    /// Flags to pass to the compiler.
    #[argp(option, short = 'f')]
    c_flags: Option<String>,

    /// Custom build command.
    #[argp(option, short = 'm')]
    custom_make: Option<String>,

    /// Arguments to custom build command.
    #[argp(option, short = 'M')]
    custom_args: Vec<String>,
}

impl Objdiff {
    pub fn run(&self) -> Result<()> {
        let config: Config = serde_yml::from_reader(open_file(&self.config_path)?)?;
        let config_path = self.config_path.parent().unwrap();

        let mut units = vec![];
        units.extend(self.get_units(&config.main_module, ModuleKind::Arm9, config_path, &config)?);
        for autoload in &config.autoloads {
            units.extend(self.get_units(&autoload.module, ModuleKind::Autoload(autoload.kind), config_path, &config)?);
        }
        for overlay in &config.overlays {
            units.extend(self.get_units(&overlay.module, ModuleKind::Overlay(overlay.id), config_path, &config)?);
        }

        let project_config = objdiff_core::config::ProjectConfig {
            min_version: Some(MIN_OBJDIFF_VERSION.to_string()),
            custom_make: self.custom_make.clone(),
            custom_args: if self.custom_args.is_empty() { None } else { Some(self.custom_args.clone()) },
            target_dir: Some(config_path.join(config.build_path)),
            base_dir: Some(config_path.join(config.delinks_path)),
            build_base: Some(false),
            build_target: Some(true),
            watch_patterns: Some(vec![
                Glob::new("*.c")?,
                Glob::new("*.cp")?,
                Glob::new("*.cpp")?,
                Glob::new("*.cxx")?,
                Glob::new("*.h")?,
                Glob::new("*.hp")?,
                Glob::new("*.hpp")?,
                Glob::new("*.hxx")?,
            ]),
            units: Some(units),
            progress_categories: None,
        };

        objdiff_core::config::save_project_config(
            &project_config,
            &objdiff_core::config::ProjectConfigInfo { path: PathBuf::from("objdiff.json"), timestamp: None },
        )?;

        Ok(())
    }

    fn get_units(
        &self,
        module: &ConfigModule,
        module_kind: ModuleKind,
        config_path: &std::path::Path,
        config: &Config,
    ) -> Result<Vec<ProjectObject>> {
        let delinks = Delinks::from_file(config_path.join(&module.delinks), module_kind)?;
        Ok(delinks
            .files
            .iter()
            .map(|file| {
                let (file_path, extension) = file.split_file_ext();

                objdiff_core::config::ProjectObject {
                    name: Some(file_path.to_string()),
                    path: None,
                    target_path: Some(config_path.join(&config.delinks_path).join(file_path).with_extension("o")),
                    base_path: (!file.gap())
                        .then_some(config_path.join(&config.build_path).join(file_path).with_extension("o")),
                    scratch: if !file.gap() && self.scratch {
                        let ctx_extension = if extension.is_empty() { ".ctx".to_string() } else { format!("{extension}.ctx") };

                        Some(objdiff_core::config::ScratchConfig {
                            platform: Some("nds_arm9".to_string()),
                            compiler: self.compiler.clone(),
                            c_flags: self.c_flags.clone(),
                            ctx_path: Some(
                                self.config_path.join(&config.build_path).join(file_path).with_extension(ctx_extension),
                            ),
                            build_ctx: Some(true),
                        })
                    } else {
                        None
                    },
                    metadata: Some(objdiff_core::config::ProjectObjectMetadata {
                        complete: Some(file.complete),
                        reverse_fn_order: Some(false),
                        source_path: (!file.gap()).then_some(file.name.clone()),
                        progress_categories: None,
                        auto_generated: Some(file.gap()),
                    }),
                    ..Default::default()
                }
            })
            .collect())
    }
}
