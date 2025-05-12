use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use ds_decomp::config::{
    config::{Config, ConfigModule},
    delinks::Delinks,
    module::ModuleKind,
    section::SectionKind,
};
use serde::Serialize;

use crate::config::delinks::DelinksExt;

#[derive(Args)]
pub struct JsonDelinks {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    config_path: PathBuf,
}

#[derive(Serialize)]
struct ModulesJson {
    modules: Vec<ModuleDelinksJson>,
}

#[derive(Serialize)]
struct ModuleDelinksJson {
    name: String,
    sections: Vec<SectionJson>,
    files: Vec<DelinkFileJson>,
}

#[derive(Serialize)]
struct SectionJson {
    name: String,
    kind: SectionKind,
    start: u32,
    end: u32,
    align: u32,
}

#[derive(Serialize)]
struct DelinkFileJson {
    name: String,
    complete: bool,
    sections: Vec<DelinkFileSectionJson>,
}

#[derive(Serialize)]
struct DelinkFileSectionJson {
    name: String,
    start: u32,
    end: u32,
}

impl JsonDelinks {
    pub fn run(&self) -> Result<()> {
        let config = Config::from_file(&self.config_path)?;

        let mut modules = vec![];
        modules.push(self.module_json(&config.main_module, ModuleKind::Arm9)?);
        for autoload in &config.autoloads {
            modules.push(self.module_json(&autoload.module, ModuleKind::Autoload(autoload.kind))?);
        }
        for overlay in &config.overlays {
            modules.push(self.module_json(&overlay.module, ModuleKind::Overlay(overlay.id))?);
        }

        let json = ModulesJson { modules };
        let json_string = serde_json::to_string_pretty(&json)?;
        println!("{json_string}");

        Ok(())
    }

    fn module_json(&self, config: &ConfigModule, module_kind: ModuleKind) -> Result<ModuleDelinksJson> {
        let config_dir = self.config_path.parent().unwrap();
        let delinks_path = config_dir.join(&config.delinks);

        // Generate gaps to sort file list
        let delinks = Delinks::from_file_and_generate_gaps(&delinks_path, module_kind)?;

        let sections = delinks
            .sections
            .sorted_by_address()
            .iter()
            .map(|section| SectionJson {
                name: section.name().to_string(),
                kind: section.kind(),
                start: section.start_address(),
                end: section.end_address(),
                align: section.alignment(),
            })
            .collect::<Vec<_>>();

        let files = delinks
            .files
            .iter()
            .filter(|file| !file.gap)
            .map(|file| {
                let sections = file
                    .sections
                    .sorted_by_address()
                    .iter()
                    .map(|section| DelinkFileSectionJson {
                        name: section.name().to_string(),
                        start: section.start_address(),
                        end: section.end_address(),
                    })
                    .collect::<Vec<_>>();

                DelinkFileJson { name: file.name.clone(), sections, complete: file.complete }
            })
            .collect::<Vec<_>>();

        Ok(ModuleDelinksJson { name: config.name.clone(), sections, files })
    }
}
