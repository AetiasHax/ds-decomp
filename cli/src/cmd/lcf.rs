use std::{
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::Result;
use clap::Args;
use ds_decomp::config::{config::Config, delinks::Delinks, module::ModuleKind};
use ds_rom::rom::{raw::AutoloadKind, Rom, RomLoadOptions};
use serde::Serialize;
use tinytemplate::TinyTemplate;

use crate::{
    analysis::overlay_groups::OverlayGroups,
    config::section::SectionExt,
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

static MODULE_LCF_TEMPLATE: &str = include_str!("../../../assets/module.lcf.template");
static ARM9_LCF_TEMPLATE: &str = include_str!("../../../assets/arm9.lcf.template");

pub const LCF_DIR_NAME: &str = "lcf";
pub const ARM9_LCF_FILE_NAME: &str = "arm9.lcf";

#[derive(Serialize)]
struct ModuleLcfContext {
    module: LcfModule,
}

#[derive(Serialize, Clone)]
struct LcfModule {
    name: String,
    #[serde(skip)]
    kind: ModuleKind,
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
    start_symbol: String,
    end_symbol: String,
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
        let config_dir = self.config_path.parent().unwrap();

        let rom = Rom::load(
            config_dir.join(&config.rom_config),
            RomLoadOptions {
                key: None,
                compress: false,
                encrypt: false,
                load_files: false,
                load_header: false,
                load_banner: false,
            },
        )?;

        let build_path = config_dir.normalize_join(&config.build_path)?;
        let lcf_path = build_path.join(LCF_DIR_NAME);

        let link_modules = LinkModules::new(&rom, &config, config_dir)?;

        let mut tt = TinyTemplate::new();
        tt.add_template("module", MODULE_LCF_TEMPLATE)?;
        tt.add_template("arm9", ARM9_LCF_TEMPLATE)?;

        for module in &link_modules.modules {
            self.write_module_lcf(module.clone(), &tt, &lcf_path)?;
        }

        let arm9_context = Arm9LcfContext {
            modules: link_modules.modules,
            overlays: config
                .overlays
                .iter()
                .map(|overlay| Arm9LcfOverlay { id_symbol: Self::overlay_id_symbol_name(overlay.id), id: overlay.id })
                .collect(),
        };
        self.write_arm9_lcf(arm9_context, &tt, &lcf_path)?;

        // mwldarm doesn't create the build directory for the modules
        create_dir_all(build_path.join("build"))?;

        Ok(())
    }

    fn write_module_lcf(&self, module: LcfModule, tt: &TinyTemplate, lcf_path: &Path) -> Result<()> {
        let lcf_file_path = lcf_path.join(Self::module_lcf_file_name(module.kind));

        log::debug!("Writing module LCF for {} to {}", module.kind, lcf_file_path.display());

        let context = ModuleLcfContext { module };
        let lcf_string = tt.render("module", &context)?;

        let file = create_file_and_dirs(lcf_file_path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(lcf_string.as_bytes())?;

        Ok(())
    }

    fn write_arm9_lcf(&self, context: Arm9LcfContext, tt: &TinyTemplate, lcf_path: &Path) -> Result<()> {
        let lcf_file_path = lcf_path.join("arm9.lcf");
        let lcf_string = tt.render("arm9", &context)?;

        let file = create_file_and_dirs(lcf_file_path)?;
        let mut writer = BufWriter::new(file);
        writer.write_all(lcf_string.as_bytes())?;

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

        let delinks_path = config_dir.normalize_join(&module_config.delinks)?;
        let delinks = Delinks::from_file(delinks_path, kind)?;

        let sections = delinks
            .sections
            .sorted_by_address()
            .iter()
            .map(|section| {
                let name = section.name().to_string();
                let alignment = section.alignment();
                let boundary_name = section.boundary_name();
                let start_symbol = format!("{module_name}_{boundary_name}_START");
                let end_symbol = format!("{module_name}_{boundary_name}_END");
                LcfSection { name, alignment, start_symbol, end_symbol }
            })
            .collect::<Vec<_>>();

        let end_address = delinks.sections.end_address().unwrap();

        Ok(Self { name: module_name, kind, origin, end_address, output_file, link_section, object, sections })
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
