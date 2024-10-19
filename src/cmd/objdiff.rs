use std::path::{Path, PathBuf};

use anyhow::Result;
use argp::FromArgs;
use globset::Glob;
use objdiff_core::config::ProjectObject;
use path_slash::PathBufExt;
use pathdiff::diff_paths;

use crate::{
    config::{
        config::{Config, ConfigModule},
        delinks::Delinks,
        module::ModuleKind,
    },
    util::io::{create_dir_all, open_file},
};

const MIN_OBJDIFF_VERSION: &str = "2.3.2";

/// Generates an objdiff configuration.
#[derive(FromArgs)]
#[argp(subcommand, name = "objdiff")]
pub struct Objdiff {
    /// Path to config.yaml.
    #[argp(option, short = 'c')]
    config_path: PathBuf,

    /// Path to directory to generate objdiff.json.
    #[argp(option, short = 'o')]
    output_path: Option<PathBuf>,

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

        let output_path = self.output_path.clone().unwrap_or(PathBuf::from("."));
        let abs_output_path = std::path::absolute(&output_path)?;

        let mut units = vec![];
        units.extend(self.get_units(&config.main_module, ModuleKind::Arm9, config_path, &config, &abs_output_path)?);
        for autoload in &config.autoloads {
            units.extend(self.get_units(
                &autoload.module,
                ModuleKind::Autoload(autoload.kind),
                config_path,
                &config,
                &abs_output_path,
            )?);
        }
        for overlay in &config.overlays {
            units.extend(self.get_units(
                &overlay.module,
                ModuleKind::Overlay(overlay.id),
                config_path,
                &config,
                &abs_output_path,
            )?);
        }

        let target_dir = normalize_diff_paths(config_path.join(config.build_path), &abs_output_path)?;
        let base_dir = normalize_diff_paths(config_path.join(config.delinks_path), &abs_output_path)?;

        let project_config = objdiff_core::config::ProjectConfig {
            min_version: Some(MIN_OBJDIFF_VERSION.to_string()),
            custom_make: self.custom_make.clone(),
            custom_args: if self.custom_args.is_empty() { None } else { Some(self.custom_args.clone()) },
            target_dir: Some(target_dir),
            base_dir: Some(base_dir),
            build_base: Some(true),
            build_target: Some(false),
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

        create_dir_all(&output_path)?;
        objdiff_core::config::save_project_config(
            &project_config,
            &objdiff_core::config::ProjectConfigInfo { path: output_path.join("objdiff.json"), timestamp: None },
        )?;

        Ok(())
    }

    fn get_units(
        &self,
        module: &ConfigModule,
        module_kind: ModuleKind,
        config_path: &Path,
        config: &Config,
        abs_output_path: &Path,
    ) -> Result<Vec<ProjectObject>> {
        let delinks = Delinks::from_file(config_path.join(&module.delinks), module_kind)?;
        Ok(delinks
            .files
            .iter()
            .map(|file| {
                let (file_path, extension) = file.split_file_ext();

                let target_path = normalize_diff_paths(
                    config_path.join(&config.delinks_path).join(file_path).with_extension("o"),
                    abs_output_path,
                )?;

                let base_path = if !file.gap() {
                    Some(normalize_diff_paths(
                        config_path.join(&config.build_path).join(file_path).with_extension("o"),
                        abs_output_path,
                    )?)
                } else {
                    None
                };

                let scratch = if !file.gap() && self.scratch {
                    let ctx_extension = if extension.is_empty() { ".ctx".to_string() } else { format!("ctx.{extension}") };

                    let ctx_path = normalize_diff_paths(
                        self.config_path.join(&config.build_path).join(file_path).with_extension(ctx_extension),
                        abs_output_path,
                    )?;

                    Some(objdiff_core::config::ScratchConfig {
                        platform: Some("nds_arm9".to_string()),
                        compiler: self.compiler.clone(),
                        c_flags: self.c_flags.clone(),
                        ctx_path: Some(ctx_path),
                        build_ctx: Some(true),
                    })
                } else {
                    None
                };

                let source_path = if !file.gap() {
                    let path = normalize_diff_paths(file.name.clone(), abs_output_path)?;
                    Some(path.to_string_lossy().to_string())
                } else {
                    None
                };

                Ok(objdiff_core::config::ProjectObject {
                    name: Some(file_path.to_string()),
                    path: None,
                    target_path: Some(target_path),
                    base_path,
                    scratch,
                    metadata: Some(objdiff_core::config::ProjectObjectMetadata {
                        complete: Some(file.complete),
                        reverse_fn_order: Some(false),
                        source_path,
                        progress_categories: None,
                        auto_generated: Some(file.gap()),
                    }),
                    ..Default::default()
                })
            })
            .collect::<Result<Vec<_>>>()?)
    }
}

fn normalize_diff_paths<P: AsRef<Path>, B: AsRef<Path>>(path: P, base: B) -> Result<PathBuf> {
    let diff = diff_paths(std::path::absolute(path.as_ref())?, base.as_ref()).unwrap();
    Ok(PathBuf::from(diff.to_slash_lossy().as_ref()))
}
