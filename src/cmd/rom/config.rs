use std::{
    ops::Range,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use argp::FromArgs;
use ds_rom::rom::{raw::AutoloadKind, OverlayConfig, Rom, RomConfig, RomLoadOptions};
use object::{Object, ObjectSection, ObjectSymbol};
use path_slash::PathExt;
use pathdiff::diff_paths;

use crate::{
    config::{
        config::Config,
        delinks::Delinks,
        module::ModuleKind,
        section::{Section, Sections},
    },
    util::io::{create_file, open_file, read_file},
};

/// Creates a configuration to build a ROM from linked binaries.
#[derive(FromArgs)]
#[argp(subcommand, name = "config")]
pub struct ConfigRom {
    /// Path to linked ELF file
    #[argp(option, short = 'e')]
    elf: PathBuf,

    /// Path to config YAML
    #[argp(option, short = 'c')]
    config: PathBuf,
}

impl ConfigRom {
    pub fn run(&self) -> Result<()> {
        let config: Config = serde_yml::from_reader(open_file(&self.config)?)?;
        let config_path = self.config.parent().unwrap();

        let old_rom_paths_path = config_path.join(&config.rom_config);

        let rom =
            Rom::load(&old_rom_paths_path, RomLoadOptions { key: None, compress: false, encrypt: false, load_files: false })?;

        let mut rom_paths = rom.config().clone();
        let new_rom_paths_path = config_path.join(&config.main_module.object).parent().unwrap().join("rom_config.yaml");

        self.update_relative_paths(&mut rom_paths, &old_rom_paths_path, &new_rom_paths_path);

        let file = read_file(&self.elf)?;
        let object = object::File::parse(&*file)?;

        // println!("Entry: {:#x}", object.entry());

        // for section in object.sections() {
        //     println!("Section: {} ({:#x})", section.name()?, section.address());
        //     for symbol in object.symbols() {
        //         if symbol.section_index() == Some(section.index()) {
        //             if symbol.name()?.ends_with("START") {
        //                 println!("Symbol: {} ({:#x})", symbol.name()?, symbol.address());
        //             }
        //         }
        //     }
        // }

        self.config_arm9(&object, &config, &rom, &mut rom_paths, &new_rom_paths_path)?;
        self.config_autoloads(&object, &config, &rom, &mut rom_paths, &new_rom_paths_path)?;
        self.config_overlays(&object, &config, &rom, &mut rom_paths, &new_rom_paths_path)?;

        serde_yml::to_writer(create_file(&new_rom_paths_path)?, &rom_paths)?;

        Ok(())
    }

    fn update_relative_paths(&self, rom_paths: &mut RomConfig, old: &Path, new: &Path) {
        let RomConfig {
            // Update these paths
            arm7_bin,
            header,
            header_logo,
            arm7_config,
            arm7_overlays,
            banner,
            files_dir,
            path_order,

            // These files will be remade
            arm9_bin: _,
            arm9_config: _,
            itcm_bin: _,
            itcm_config: _,
            dtcm_bin: _,
            dtcm_config: _,
            arm9_overlays: _,

            // Other non-path values
            padding_value: _,
        } = rom_paths;

        let old = old.parent().unwrap();
        let new = new.parent().unwrap();

        rom_paths.arm7_bin = Self::make_path(old.join(arm7_bin), new);
        rom_paths.arm7_config = Self::make_path(old.join(arm7_config), new);
        if let Some(arm7_overlays) = arm7_overlays {
            rom_paths.arm7_overlays = Some(Self::make_path(old.join(arm7_overlays), new));
        }
        rom_paths.banner = Self::make_path(old.join(banner), new);
        rom_paths.files_dir = Self::make_path(old.join(files_dir), new);
        rom_paths.header = Self::make_path(old.join(header), new);
        rom_paths.header_logo = Self::make_path(old.join(header_logo), new);
        rom_paths.path_order = Self::make_path(old.join(path_order), new);
    }

    fn config_overlays(
        &self,
        object: &object::File<'_>,
        config: &Config,
        rom: &Rom<'_>,
        rom_paths: &mut RomConfig,
        rom_paths_path: &Path,
    ) -> Result<()> {
        let config_path = self.config.parent().unwrap();

        let mut overlay_configs = vec![];
        for overlay in &config.overlays {
            let delinks = Delinks::from_file(config_path.join(&overlay.module.delinks), ModuleKind::Overlay(overlay.id))?;
            let rom_overlay = rom
                .arm9_overlays()
                .iter()
                .find(|o| o.id() == overlay.id)
                .with_context(|| format!("Failed to find overlay {} in ROM", overlay.id))?;

            let module_name = format!("OV{:03}", overlay.id);
            let file_name = format!("arm9_ov{:03}.bin", overlay.id);
            let ctor = delinks.sections.by_name(".ctor").unwrap();

            let mut info = rom_overlay.info().clone();
            info.base_address = self.section_ranges(&delinks.sections, &module_name, &object, |_| true)?.unwrap().start;
            info.code_size =
                self.section_ranges(&delinks.sections, &module_name, &object, |s| s.kind().is_initialized())?.unwrap().len()
                    as u32;
            info.bss_size =
                self.section_ranges(&delinks.sections, &module_name, &object, |s| !s.kind().is_initialized())?.unwrap().len()
                    as u32;
            info.ctor_start = ctor.start_address();
            info.ctor_end = ctor.end_address();
            overlay_configs.push(OverlayConfig { info, file_name });
        }

        let yaml_path = config_path.join(&config.main_module.object).parent().unwrap().join("arm9_overlays.yaml");
        serde_yml::to_writer(create_file(&yaml_path)?, &overlay_configs)?;

        rom_paths.arm9_overlays = Some(Self::make_path(rom_paths_path, yaml_path));

        Ok(())
    }

    fn config_autoloads(
        &self,
        object: &object::File<'_>,
        config: &Config,
        rom: &Rom<'_>,
        rom_paths: &mut RomConfig,
        rom_paths_path: &Path,
    ) -> Result<()> {
        let config_path = self.config.parent().unwrap();

        let rom_autoloads = rom.arm9().autoloads()?;
        for autoload in &config.autoloads {
            let delinks = Delinks::from_file(config_path.join(&autoload.module.delinks), ModuleKind::Autoload(autoload.kind))?;
            let base_address = delinks.sections.base_address().unwrap();
            let rom_autoload = rom_autoloads
                .iter()
                .find(|a| a.base_address() == base_address)
                .with_context(|| format!("Failed to find autoload {} in ROM", autoload.kind))?;

            let (module_name, file_name) = match autoload.kind {
                AutoloadKind::Itcm => ("ITCM", "itcm.yaml"),
                AutoloadKind::Dtcm => ("DTCM", "dtcm.yaml"),
                AutoloadKind::Unknown => panic!("Unknown autoload kind"),
            };

            let mut autoload_info = rom_autoload.info().clone();
            autoload_info.code_size = self
                .section_ranges(&delinks.sections, module_name, &object, |s| s.kind().is_initialized())?
                .map(|range| range.len() as u32)
                .unwrap_or(0);
            autoload_info.bss_size = self
                .section_ranges(&delinks.sections, module_name, &object, |s| !s.kind().is_initialized())?
                .map(|range| range.len() as u32)
                .unwrap_or(0);

            let binary_path = config_path.join(&autoload.module.object);
            let yaml_path = binary_path.parent().unwrap().join(file_name);
            serde_yml::to_writer(create_file(&yaml_path)?, &autoload_info)?;

            match autoload.kind {
                AutoloadKind::Itcm => {
                    rom_paths.itcm_bin = Self::make_path(rom_paths_path, binary_path);
                    rom_paths.itcm_config = Self::make_path(rom_paths_path, yaml_path);
                }
                AutoloadKind::Dtcm => {
                    rom_paths.dtcm_bin = Self::make_path(rom_paths_path, binary_path);
                    rom_paths.dtcm_config = Self::make_path(rom_paths_path, yaml_path);
                }
                AutoloadKind::Unknown => {}
            }
        }

        Ok(())
    }

    fn config_arm9(
        &self,
        object: &object::File<'_>,
        config: &Config,
        rom: &Rom<'_>,
        rom_paths: &mut RomConfig,
        rom_paths_path: &Path,
    ) -> Result<()> {
        let config_path = self.config.parent().unwrap();

        let arm9_section = object.section_by_name("ARM9").context("ARM9 section not found")?;
        let build_info_symbol = object.symbol_by_name("BuildInfo").context("BuildInfo symbol not found")?;
        let autoload_callback_symbol = object.symbol_by_name("AutoloadCallback").context("BuildInfo symbol not found")?;
        let delinks = Delinks::from_file(config_path.join(&config.main_module.delinks), ModuleKind::Arm9)?;
        let bss_range = self.section_ranges(&delinks.sections, "ARM9", object, |s| !s.kind().is_initialized())?.unwrap();

        let mut arm9_build_config = rom.arm9_build_config()?;
        arm9_build_config.offsets.base_address = arm9_section.address() as u32;
        arm9_build_config.offsets.entry_function = object.entry() as u32;
        arm9_build_config.offsets.build_info = build_info_symbol.address() as u32;
        arm9_build_config.offsets.autoload_callback = autoload_callback_symbol.address() as u32;
        arm9_build_config.build_info.bss_start = bss_range.start;
        arm9_build_config.build_info.bss_end = bss_range.end;

        let binary_path = config_path.join(&config.main_module.object);
        let yaml_path = binary_path.parent().unwrap().join("arm9.yaml");
        serde_yml::to_writer(create_file(&yaml_path)?, &arm9_build_config)?;

        rom_paths.arm9_bin = Self::make_path(rom_paths_path, binary_path);
        rom_paths.arm9_config = Self::make_path(rom_paths_path, yaml_path);

        Ok(())
    }

    fn section_ranges<F>(
        &self,
        sections: &Sections,
        module_name: &str,
        object: &object::File<'_>,
        predicate: F,
    ) -> Result<Option<Range<u32>>>
    where
        F: FnMut(&&Section) -> bool,
    {
        Ok(sections
            .iter()
            .filter(predicate)
            .map(|s| s.range_from_object(module_name, object))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .reduce(|a, b| a.start.min(b.start)..a.end.max(b.end)))
    }

    fn make_path<P: AsRef<Path>, B: AsRef<Path>>(path: P, base: B) -> PathBuf {
        PathBuf::from(diff_paths(path, &base).unwrap().to_slash_lossy().as_ref())
    }
}
