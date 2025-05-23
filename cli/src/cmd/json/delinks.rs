use std::path::{Path, PathBuf};

use anyhow::Result;
use clap::Args;
use ds_decomp::config::{
    config::{Config, ConfigModule},
    delinks::Delinks,
    module::ModuleKind,
    section::SectionKind,
};
use serde::Serialize;

use crate::{
    cmd::{Lcf, ARM9_LCF_FILE_NAME, LCF_DIR_NAME},
    config::delinks::DelinksExt,
    util::path::PathExt,
};

#[derive(Args)]
pub struct JsonDelinks {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    pub config_path: PathBuf,
}

pub const MODULES_DIR_NAME: &str = "modules";

#[derive(Serialize)]
pub struct ModulesJson {
    pub arm9_lcf_file: PathBuf,
    pub modules: Vec<ModuleDelinksJson>,
}

#[derive(Serialize)]
pub struct ModuleDelinksJson {
    pub name: String,
    pub lcf_file: PathBuf,
    pub elf_file: PathBuf,
    pub sections: Vec<SectionJson>,
    pub files: Vec<DelinkFileJson>,
}

#[derive(Serialize)]
pub struct SectionJson {
    pub name: String,
    pub kind: SectionKind,
    pub start: u32,
    pub end: u32,
    pub align: u32,
}

#[derive(Serialize)]
pub struct DelinkFileJson {
    pub name: String,
    pub complete: bool,
    pub delink_file: PathBuf,
    pub object_to_link: PathBuf,
    pub sections: Vec<DelinkFileSectionJson>,
}

#[derive(Serialize)]
pub struct DelinkFileSectionJson {
    pub name: String,
    pub start: u32,
    pub end: u32,
}

struct Context<'a> {
    build_path: &'a Path,
    delinks_path: &'a Path,
    lcf_path: &'a Path,
    modules_path: &'a Path,
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
        let lcf_path = config_dir.join(&config.build_path).join(LCF_DIR_NAME);
        let modules_path = config_dir.join(&config.build_path).join(MODULES_DIR_NAME);
        let context =
            Context { lcf_path: &lcf_path, build_path: &build_path, delinks_path: &delinks_path, modules_path: &modules_path };

        let mut modules = vec![];
        modules.push(self.module_json(&config.main_module, ModuleKind::Arm9, &context)?);
        for autoload in &config.autoloads {
            modules.push(self.module_json(&autoload.module, ModuleKind::Autoload(autoload.kind), &context)?);
        }
        for overlay in &config.overlays {
            modules.push(self.module_json(&overlay.module, ModuleKind::Overlay(overlay.id), &context)?);
        }

        let arm9_lcf_file = context.lcf_path.normalize_join(ARM9_LCF_FILE_NAME)?;

        Ok(ModulesJson { arm9_lcf_file, modules })
    }

    fn module_json(&self, config: &ConfigModule, module_kind: ModuleKind, context: &Context) -> Result<ModuleDelinksJson> {
        let config_dir = self.config_path.parent().unwrap();
        let delinks_path = config_dir.join(&config.delinks);

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

                let (file_path, _) = file.split_file_ext();
                let base_path = if file.complete { context.build_path } else { context.delinks_path };
                let object_to_link = base_path.normalize_join(file_path)?.with_extension("o");
                let delink_file = context.delinks_path.normalize_join(file_path)?.with_extension("o");

                Ok(DelinkFileJson { name: file.name.clone(), sections, complete: file.complete, delink_file, object_to_link })
            })
            .collect::<Result<Vec<_>, anyhow::Error>>()?;

        let lcf_file = context.lcf_path.normalize_join(Lcf::module_lcf_file_name(module_kind))?;
        let elf_file = context.modules_path.normalize_join(&config.name)?.with_extension("o");

        Ok(ModuleDelinksJson { name: config.name.clone(), lcf_file, elf_file, sections, files })
    }
}
