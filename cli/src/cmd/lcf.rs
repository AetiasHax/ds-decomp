use std::{
    collections::{HashMap, hash_map},
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::{Result, bail};
use clap::Args;
use ds_decomp::config::{
    config::{Config, ConfigModule},
    delinks::Delinks,
    module::ModuleKind,
};
use ds_rom::rom::{Rom, RomLoadOptions, raw::AutoloadKind};
use serde::Serialize;
use tinytemplate::TinyTemplate;

use crate::{
    analysis::overlay_groups::OverlayGroups,
    cmd::JsonDelinks,
    config::{delinks::DelinksExt, section::SectionExt},
    util::{
        io::{create_dir_all, create_file_and_dirs},
        path::PathExt,
    },
};

/// Generates linker scripts for all modules in a dsd config.
#[derive(Args)]
pub struct Lcf {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    pub config_path: PathBuf,
}

static ARM9_LCF_TEMPLATE: &str = include_str!("../../../assets/arm9.lcf.template");

pub const ARM9_LCF_FILE_NAME: &str = "arm9.lcf";
pub const ARM9_OBJECTS_FILE_NAME: &str = "objects.txt";

#[derive(Serialize, Clone)]
struct LcfModule {
    name: String,
    origin: String,
    end_address: u32,
    output_file: String,
    link_section: String,
    object: String,
    sections: Vec<LcfSection>,
}

#[derive(Serialize, Clone)]
struct LcfSection {
    name: String,
    alignment: u32,
    end_alignment: u32,
    start_symbol: String,
    end_symbol: String,
    files: Vec<LcfFile>,
}

#[derive(Serialize, Clone)]
struct LcfFile {
    name: String,
}

#[derive(Serialize)]
struct Arm9LcfContext {
    modules: Vec<LcfModule>,
    overlays: Vec<Arm9LcfOverlay>,
}

#[derive(Serialize)]
struct Arm9LcfOverlay {
    id_symbol: String,
    id: u16,
}

impl Lcf {
    pub fn run(&self) -> Result<()> {
        let config = Config::from_file(&self.config_path)?;
        self.validate_all_file_names(&config)?;
        let config_dir = self.config_path.parent().unwrap();

        let rom = Rom::load(config_dir.join(&config.rom_config), RomLoadOptions {
            key: None,
            compress: false,
            encrypt: false,
            load_files: false,
            load_header: false,
            load_banner: false,
        })?;

        let build_path = config_dir.join(&config.build_path).clean();

        let link_modules = LinkModules::new(&rom, &config, config_dir)?;

        let mut tt = TinyTemplate::new();
        tt.add_template("arm9", ARM9_LCF_TEMPLATE)?;

        let arm9_context = Arm9LcfContext {
            modules: link_modules.modules,
            overlays: config
                .overlays
                .iter()
                .map(|overlay| Arm9LcfOverlay { id_symbol: Self::overlay_id_symbol_name(overlay.id), id: overlay.id })
                .collect(),
        };
        self.write_arm9_lcf(&arm9_context, &tt, &build_path)?;
        self.write_arm9_objects(&config, &build_path)?;

        // mwldarm doesn't create the build directory for the modules
        create_dir_all(build_path.join("build"))?;

        Ok(())
    }

    fn write_arm9_lcf(&self, context: &Arm9LcfContext, tt: &TinyTemplate, lcf_path: &Path) -> Result<()> {
        let lcf_file_path = lcf_path.join("arm9.lcf");
        let lcf_string = tt.render("arm9", &context)?;

        let file = create_file_and_dirs(lcf_file_path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(lcf_string.as_bytes())?;

        Ok(())
    }

    fn write_arm9_objects(&self, config: &Config, lcf_path: &Path) -> Result<()> {
        let config_dir = self.config_path.parent().unwrap();
        let objects_file_path = lcf_path.join(ARM9_OBJECTS_FILE_NAME);
        let mut writer = BufWriter::new(create_file_and_dirs(objects_file_path)?);
        for file in JsonDelinks::get_delink_files(config_dir, config)?.iter() {
            let (file_path, _) = file.split_file_ext();
            let base_path = if file.complete {
                &config_dir.join(&config.build_path)
            } else {
                &config_dir.join(&config.delinks_path)
            };
            let file = base_path.join(file_path).with_extension("o").clean();
            writeln!(writer, "{}", file.display())?;
        }
        Ok(())
    }

    pub fn overlay_id_symbol_name(id: u16) -> String {
        format!("OVERLAY_{id}_ID")
    }

    pub fn module_lcf_file_name(kind: ModuleKind) -> String {
        match kind {
            ModuleKind::Arm9 => "main.lcf".to_string(),
            ModuleKind::Autoload(autoload) => match autoload {
                AutoloadKind::Itcm => "itcm.lcf".to_string(),
                AutoloadKind::Dtcm => "dtcm.lcf".to_string(),
                AutoloadKind::Unknown(autoload_index) => format!("autoload_{autoload_index:03}.lcf"),
            },
            ModuleKind::Overlay(overlay_id) => format!("overlay_{overlay_id:03}.lcf"),
        }
    }

    fn validate_all_file_names(&self, config: &Config) -> Result<()> {
        let mut delink_files: HashMap<String, ModuleKind> = HashMap::new();
        let mut success = true;
        success &= self.validate_file_names(&config.main_module, ModuleKind::Arm9, &mut delink_files)?;
        for autoload in &config.autoloads {
            success &= self.validate_file_names(&autoload.module, ModuleKind::Autoload(autoload.kind), &mut delink_files)?;
        }
        for overlay in &config.overlays {
            success &= self.validate_file_names(&overlay.module, ModuleKind::Overlay(overlay.id), &mut delink_files)?;
        }
        if !success {
            bail!("Duplicate file names found, see logs above");
        }
        Ok(())
    }

    fn validate_file_names(
        &self,
        config_module: &ConfigModule,
        module_kind: ModuleKind,
        delink_files: &mut HashMap<String, ModuleKind>,
    ) -> Result<bool> {
        let config_dir = self.config_path.parent().unwrap();
        let delinks = Delinks::from_file(config_dir.join(&config_module.delinks), module_kind)?;
        let mut success = true;
        for file in delinks.files {
            let filename = file.name.rsplit_once(['/', '\\']).unwrap_or(("", &file.name)).1;
            match delink_files.entry(filename.to_string()) {
                hash_map::Entry::Occupied(occupied_entry) => {
                    log::error!("Delink file name '{}' in {} already used in {}", filename, module_kind, occupied_entry.get());
                    success = false;
                }
                hash_map::Entry::Vacant(vacant_entry) => {
                    vacant_entry.insert(module_kind);
                }
            }
        }
        Ok(success)
    }
}

impl LcfModule {
    fn new(kind: ModuleKind, origin: String, config: &Config, config_dir: &Path) -> Result<Self> {
        let module_config = match kind {
            ModuleKind::Arm9 => &config.main_module,
            ModuleKind::Autoload(autoload) => &config.autoloads.iter().find(|a| a.kind == autoload).unwrap().module,
            ModuleKind::Overlay(overlay_id) => &config.overlays.iter().find(|o| o.id == overlay_id).unwrap().module,
        };

        let output_file = format!("build/{}", module_config.object.file_name().unwrap().to_string_lossy());
        let module_name = match kind {
            ModuleKind::Arm9 => "ARM9".to_string(),
            ModuleKind::Autoload(autoload) => match autoload {
                AutoloadKind::Itcm => "ITCM".to_string(),
                AutoloadKind::Dtcm => "DTCM".to_string(),
                AutoloadKind::Unknown(autoload_index) => format!("AUTOLOAD_{autoload_index}"),
            },
            ModuleKind::Overlay(overlay_id) => format!("OV{overlay_id:03}"),
        };
        let link_section = format!(".{}", module_name.to_lowercase());

        let object = format!("{}.o", module_config.name);

        let delinks_path = config_dir.join(&module_config.delinks).clean();
        let delinks = if kind == ModuleKind::Autoload(AutoloadKind::Dtcm) {
            Delinks::new_dtcm(config_dir, config, module_config)?
        } else {
            Delinks::from_file_and_generate_gaps(delinks_path, kind)?.without_dtcm_sections()
        };

        let sections = delinks
            .sections
            .sorted_by_address()
            .iter()
            .map(|section| {
                let name = section.name().to_string();
                let alignment = section.alignment();
                let end_address = section.end_address();
                let end_alignment = if end_address % 32 == 0 { 32 } else { 4 };
                let boundary_name = section.boundary_name();
                let start_symbol = format!("{module_name}_{boundary_name}_START");
                let end_symbol = format!("{module_name}_{boundary_name}_END");
                let files = delinks
                    .files
                    .iter()
                    .filter(|file| file.sections.by_name(&name).is_some())
                    .map(|file| {
                        let (file, _) = file.split_file_ext();
                        let name = file.rsplit_once(['/', '\\']).map(|(_, basefile)| basefile).unwrap_or(file);
                        LcfFile { name: format!("{name}.o") }
                    })
                    .collect::<Vec<_>>();
                LcfSection { name, alignment, end_alignment, start_symbol, end_symbol, files }
            })
            .collect::<Vec<_>>();

        let end_address = delinks.sections.end_address().unwrap();

        Ok(Self { name: module_name, origin, end_address, output_file, link_section, object, sections })
    }
}

struct LinkModules {
    modules: Vec<LcfModule>,
    last_static_index: usize,
}

impl LinkModules {
    pub fn new(rom: &Rom<'_>, config: &Config, config_dir: &Path) -> Result<Self> {
        let mut link_modules = Self::find_static(rom, config, config_dir)?;
        let static_end_address = link_modules.last_static_module().end_address;
        log::debug!("Static end address: {:#010x}", static_end_address);
        let overlay_groups = OverlayGroups::analyze(static_end_address, rom.arm9_overlays())?;
        for group in overlay_groups.iter() {
            let origin = if group.after.is_empty() {
                let last_static_module = link_modules.last_static_module();
                format!("AFTER({})", last_static_module.name)
            } else {
                format!("AFTER({})", group.after.iter().map(|id| format!("OV{id:03}")).collect::<Vec<_>>().join(", "))
            };
            for &overlay_id in &group.overlays {
                let kind = ModuleKind::Overlay(overlay_id);
                link_modules.modules.push(LcfModule::new(kind, origin.clone(), config, config_dir)?);
            }
        }
        Ok(link_modules)
    }

    fn find_static(rom: &Rom<'_>, config: &Config, config_dir: &Path) -> Result<Self> {
        let arm9 = rom.arm9();
        let mut modules = vec![];
        modules.push(LcfModule::new(ModuleKind::Arm9, format!("{:#010x}", arm9.base_address()), config, config_dir)?);
        let mut prev_static_index = 0;

        // Find contiguous autoloads after the main program
        let mut sorted_autoloads = rom.arm9().autoloads()?;
        sorted_autoloads.sort_unstable_by_key(|a| a.base_address());
        for autoload in sorted_autoloads {
            let prev_module = &modules[prev_static_index];
            let origin = if autoload.base_address() == prev_module.end_address {
                prev_static_index = modules.len();
                format!("AFTER({})", prev_module.name)
            } else {
                format!("{:#010x}", autoload.base_address())
            };
            modules.push(LcfModule::new(ModuleKind::Autoload(autoload.kind()), origin, config, config_dir)?);
        }
        Ok(Self { modules, last_static_index: prev_static_index })
    }

    fn last_static_module(&self) -> &LcfModule {
        &self.modules[self.last_static_index]
    }
}
