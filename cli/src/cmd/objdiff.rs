use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};

use anyhow::Result;
use clap::Args;
use ds_decomp::config::{
    config::Config,
    delinks::{Categories, Delinks},
};
use objdiff_core::config::{ProjectObject, ProjectProgressCategory};

use crate::{
    config::delinks::{DelinksMap, DelinksMapOptions},
    util::{io::create_dir_all, path::PathExt},
};

const MIN_OBJDIFF_VERSION: &str = "2.3.2";

/// Generates an objdiff configuration.
#[derive(Args)]
pub struct Objdiff {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    config_path: PathBuf,

    /// Path to directory to generate objdiff.json.
    #[arg(long, short = 'o')]
    output_path: Option<PathBuf>,

    /// Includes decomp.me scratches.
    #[arg(long, short = 's')]
    scratch: bool,

    /// See https://decomp.me/api/compiler with compilers for the `nds_arm9` platform.
    #[arg(long, short = 'C')]
    compiler: Option<String>,

    /// Flags to pass to the compiler in decomp.me.
    #[arg(long, short = 'f', allow_hyphen_values = true)]
    c_flags: Option<String>,

    /// Preset ID to use in decomp.me.
    #[arg(long, short = 'p')]
    preset_id: Option<u32>,

    /// Custom build command.
    #[arg(long, short = 'm')]
    custom_make: Option<String>,

    /// Arguments to custom build command.
    #[arg(long, short = 'M', allow_hyphen_values = true)]
    custom_args: Vec<String>,
}

impl Objdiff {
    pub fn run(&self) -> Result<()> {
        let config = Config::from_file(&self.config_path)?;
        let config_path = self.config_path.parent().unwrap();

        let output_path = self.output_path.clone().unwrap_or(PathBuf::from("."));
        let abs_output_path = std::path::absolute(&output_path)?;

        let mut existing_units: HashMap<String, ProjectObject> = HashMap::new();
        if let Some((Ok(project_config), _)) = objdiff_core::config::try_project_config(&output_path)
            && let Some(units) = project_config.units
        {
            for unit in units {
                let Some(name) = unit.name.clone() else {
                    continue;
                };
                existing_units.insert(name, unit);
            }
        }

        let delinks_map = DelinksMap::from_config(&config, config_path, DelinksMapOptions { migrate_sections: true })?;

        let mut units = Vec::new();
        let mut categories = Categories::new();

        for delinks in delinks_map.iter() {
            let (new_units, new_categories) = self.get_units(delinks, config_path, &config, &abs_output_path)?;
            units.extend(new_units);
            categories.extend(new_categories);
        }

        for unit in &mut units {
            let Some(ref name) = unit.name else {
                continue;
            };
            let Some(existing_unit) = existing_units.get(name) else {
                continue;
            };
            unit.symbol_mappings = existing_unit.symbol_mappings.clone();
        }

        let target_dir = config_path.join(config.build_path).clean_diff_paths(&abs_output_path)?.to_utf8_unix_path_buf();
        let base_dir = config_path.join(config.delinks_path).clean_diff_paths(&abs_output_path)?.to_utf8_unix_path_buf();

        let project_config = objdiff_core::config::ProjectConfig {
            min_version: Some(MIN_OBJDIFF_VERSION.to_string()),
            custom_make: self.custom_make.clone(),
            custom_args: if self.custom_args.is_empty() {
                None
            } else {
                Some(self.custom_args.clone())
            },
            target_dir: Some(target_dir),
            base_dir: Some(base_dir),
            build_base: Some(true),
            build_target: Some(false),
            watch_patterns: Some(vec![
                "*.c".into(),
                "*.cp".into(),
                "*.cpp".into(),
                "*.cxx".into(),
                "*.h".into(),
                "*.hp".into(),
                "*.hpp".into(),
                "*.hxx".into(),
                "*.py".into(),
                "*.yml".into(),
                "*.yaml".into(),
                "*.txt".into(),
                "*.json".into(),
            ]),
            units: Some(units),
            progress_categories: if categories.categories.is_empty() {
                None
            } else {
                Some(
                    categories
                        .categories
                        .iter()
                        .map(|category| ProjectProgressCategory { id: category.clone(), name: category.clone() })
                        .collect(),
                )
            },
            ..Default::default()
        };

        create_dir_all(&output_path)?;
        objdiff_core::config::save_project_config(&project_config, &objdiff_core::config::ProjectConfigInfo {
            path: output_path.join("objdiff.json"),
            timestamp: None,
        })?;

        Ok(())
    }

    fn get_units(
        &self,
        delinks: &Delinks,
        config_path: &Path,
        config: &Config,
        abs_output_path: &Path,
    ) -> Result<(Vec<ProjectObject>, Categories)> {
        let mut all_categories = delinks.global_categories.clone();
        let units = delinks
            .files
            .iter()
            .map(|file| {
                let (file_path, extension) = file.split_file_ext();

                let target_path = config_path
                    .join(&config.delinks_path)
                    .join(file_path)
                    .with_extension("o")
                    .clean_diff_paths(abs_output_path)?
                    .to_utf8_unix_path_buf();

                let base_path = if !file.gap() {
                    Some(
                        config_path
                            .join(&config.build_path)
                            .join(file_path)
                            .with_extension("o")
                            .clean_diff_paths(abs_output_path)?
                            .to_utf8_unix_path_buf(),
                    )
                } else {
                    None
                };

                let scratch = if !file.gap() && self.scratch {
                    let ctx_extension = if extension.is_empty() {
                        ".ctx".to_string()
                    } else {
                        format!("ctx.{extension}")
                    };

                    let ctx_path = config_path
                        .to_owned()
                        .join(&config.build_path)
                        .join(file_path)
                        .with_extension(ctx_extension)
                        .clean_diff_paths(abs_output_path)?
                        .to_utf8_unix_path_buf();

                    Some(objdiff_core::config::ScratchConfig {
                        platform: Some("nds_arm9".to_string()),
                        compiler: self.compiler.clone(),
                        c_flags: self.c_flags.clone(),
                        ctx_path: Some(ctx_path),
                        build_ctx: Some(true),
                        preset_id: self.preset_id,
                    })
                } else {
                    None
                };

                let source_path = if !file.gap() {
                    let path = PathBuf::from(file.name.clone()).clean_diff_paths(abs_output_path)?.to_utf8_unix_path_buf();
                    Some(path)
                } else {
                    None
                };

                all_categories.extend(file.categories.clone());

                let mut categories = file.categories.clone();
                categories.extend(delinks.global_categories.clone());

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
                        progress_categories: if categories.categories.is_empty() {
                            None
                        } else {
                            Some(categories.categories.clone())
                        },
                        auto_generated: Some(file.gap()),
                    }),
                    ..Default::default()
                })
            })
            .collect::<Result<Vec<_>>>()?;
        Ok((units, all_categories))
    }
}
