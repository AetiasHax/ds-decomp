use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use ds_decomp::config::{
    config::Config,
    delinks::{DelinkFile, Delinks},
    module::ModuleKind,
};
use ds_rom::rom::raw::AutoloadKind;
use serde::Serialize;

use crate::{cmd::ARM9_LCF_FILE_NAME, config::delinks::DelinksExt, util::path::PathExt};

#[derive(Args)]
pub struct JsonDelinks {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    pub config_path: PathBuf,
}

#[derive(Serialize)]
pub struct ModulesJson {
    pub arm9_lcf_file: PathBuf,
    pub arm9_objects_file: PathBuf,
    pub files: Vec<DelinkFileJson>,
}

#[derive(Serialize)]
pub struct DelinkFileJson {
    pub name: String,
    pub delink_file: PathBuf,
    pub object_to_link: PathBuf,
}

impl JsonDelinks {
    pub fn run(&self) -> Result<()> {
        let json = self.modules_json()?;
        let json_string = serde_json::to_string_pretty(&json)?;
        println!("{json_string}");

        Ok(())
    }

    pub fn modules_json(&self) -> Result<ModulesJson> {
        let config = Config::from_file(&self.config_path)?;
        let config_dir = self.config_path.parent().unwrap();

        let build_path = config_dir.join(&config.build_path);
        let delinks_path = config_dir.join(&config.delinks_path);

        let files = Self::get_delink_files(config_dir, &config)?
            .into_iter()
            .map(|file| {
                let (file_path, _) = file.split_file_ext();
                let base_path = if file.complete { &build_path } else { &delinks_path };
                let object_to_link = base_path.join(file_path).clean().with_extension("o");
                let delink_file = delinks_path.join(file_path).clean().with_extension("o");

                Ok(DelinkFileJson { name: file.name, delink_file, object_to_link })
            })
            .collect::<Result<Vec<_>>>()?;

        let arm9_lcf_file = build_path.join(ARM9_LCF_FILE_NAME).clean();
        let arm9_objects_file = build_path.join("objects.txt").clean();

        Ok(ModulesJson { arm9_lcf_file, arm9_objects_file, files })
    }

    pub fn get_delink_files(config_dir: &Path, config: &Config) -> Result<Vec<DelinkFile>> {
        let mut delink_files = vec![];

        // Main module
        delink_files.extend(
            Delinks::from_file_and_generate_gaps(config_dir.join(&config.main_module.delinks), ModuleKind::Arm9)?
                .without_dtcm_sections()
                .files,
        );

        // Autoloads
        for autoload in &config.autoloads {
            let delinks = if autoload.kind == AutoloadKind::Dtcm {
                Delinks::new_dtcm(config_dir, config, &autoload.module)?
            } else {
                Delinks::from_file_and_generate_gaps(
                    config_dir.join(&autoload.module.delinks),
                    ModuleKind::Autoload(autoload.kind),
                )?
                .without_dtcm_sections()
            };
            delink_files.extend(delinks.files);
        }

        // Overlays
        for overlay in &config.overlays {
            delink_files.extend(
                Delinks::from_file_and_generate_gaps(
                    config_dir.join(&overlay.module.delinks),
                    ModuleKind::Overlay(overlay.id),
                )?
                .without_dtcm_sections()
                .files,
            );
        }

        Ok(delink_files)
    }
}
