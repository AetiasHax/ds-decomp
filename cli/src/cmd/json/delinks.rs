use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use ds_decomp::config::config::Config;
use serde::Serialize;

use crate::{
    cmd::ARM9_LCF_FILE_NAME,
    config::delinks::{DelinksMap, DelinksMapOptions},
    util::path::PathExt,
};

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

        let delinks_map = DelinksMap::from_config(&config, config_dir, DelinksMapOptions {
            // Migrating would create delink files with identical names, which is wasteful when we
            // call `DelinksMap::delink_files()` later
            migrate_sections: false,
        })?;

        let files = delinks_map
            .delink_files()
            .map(|file| {
                let (file_path, _) = file.split_file_ext();
                let base_path = if file.complete { &build_path } else { &delinks_path };
                let object_to_link = base_path.join(file_path).clean().with_extension("o");
                let delink_file = delinks_path.join(file_path).clean().with_extension("o");

                Ok(DelinkFileJson { name: file.name.clone(), delink_file, object_to_link })
            })
            .collect::<Result<Vec<_>>>()?;

        let arm9_lcf_file = build_path.join(ARM9_LCF_FILE_NAME).clean();
        let arm9_objects_file = build_path.join("objects.txt").clean();

        Ok(ModulesJson { arm9_lcf_file, arm9_objects_file, files })
    }
}
