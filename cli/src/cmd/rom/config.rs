use std::{
    ops::Range,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::Args;
use ds_decomp::config::{
    config::Config,
    delinks::Delinks,
    module::ModuleKind,
    section::{Section, Sections},
};
use ds_rom::rom::{
    OverlayConfig, OverlayTableConfig, Rom, RomConfig, RomLoadOptions, raw::AutoloadKind,
};
use object::{ObjectSection, ObjectSymbol};
use path_slash::PathExt;
use pathdiff::diff_paths;

use crate::{
    config::section::SectionExt,
    util::{
        io::{create_file, open_file, read_file},
        object::ObjectCache,
    },
};

/// Creates a configuration to build a ROM from linked binaries.
#[derive(Args, Clone)]
pub struct ConfigRom {
    /// Path to linked ELF file
    #[arg(long, short = 'e')]
    pub elf: PathBuf,

    /// Path to config YAML
    #[arg(long, short = 'c')]
    pub config: PathBuf,
}

impl ConfigRom {
    pub fn run(&self) -> Result<()> {
        let config = Config::from_file(&self.config)?;
        let config_path = self.config.parent().unwrap();

        let old_rom_paths_path = config_path.join(&config.rom_config);
        let rom_extract_dir = old_rom_paths_path.parent().unwrap();

        let rom = Rom::load(&old_rom_paths_path, RomLoadOptions {
            key: None,
            compress: false,
            encrypt: false,
            load_files: false,
            load_header: false,
            load_banner: false,
            load_multiboot_signature: false,
        })?;

        let mut rom_paths = rom.config().clone();
        let main_module_path = config_path.join(&config.main_module.object);
        let new_rom_paths_dir = main_module_path.parent().unwrap();

        Self::update_relative_paths(&mut rom_paths, rom_extract_dir, new_rom_paths_dir);

        let file = read_file(&self.elf)?;
        let object = object::File::parse(&*file)?;
        let object_cache = ObjectCache::new(&object);

        self.config_arm9(&object_cache, &config, &rom, &mut rom_paths, new_rom_paths_dir)?;
        self.config_autoloads(&object_cache, &config, &rom, &mut rom_paths, new_rom_paths_dir)?;
        self.config_overlays(
            &object_cache,
            &config,
            &rom,
            &mut rom_paths,
            new_rom_paths_dir,
            rom_extract_dir,
        )?;

        serde_saphyr::to_io_writer(
            &mut create_file(new_rom_paths_dir.join("rom_config.yaml"))?,
            &rom_paths,
        )?;

        Ok(())
    }

    fn update_relative_paths(rom_paths: &mut RomConfig, old: &Path, new: &Path) {
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
            arm9_hmac_sha1_key,
            multiboot_signature,

            // These files will be remade
            arm9_bin: _,
            arm9_config: _,
            itcm: _,
            dtcm: _,
            unknown_autoloads: _,
            arm9_overlays: _,

            // Other non-path values
            file_image_padding_value: _,
            section_padding_value: _,
            alignment: _,
        } = rom_paths;

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
        if let Some(arm9_hmac_sha1_key) = arm9_hmac_sha1_key {
            rom_paths.arm9_hmac_sha1_key = Some(Self::make_path(old.join(arm9_hmac_sha1_key), new));
        }
        if let Some(multiboot_signature) = multiboot_signature {
            rom_paths.multiboot_signature =
                Some(Self::make_path(old.join(multiboot_signature), new));
        }
    }

    fn config_overlays(
        &self,
        object_cache: &ObjectCache<'_, '_>,
        config: &Config,
        rom: &Rom<'_>,
        rom_paths: &mut RomConfig,
        rom_paths_dir: &Path,
        rom_extract_dir: &Path,
    ) -> Result<()> {
        let config_path = self.config.parent().unwrap();

        let mut overlay_configs = vec![];
        for overlay in &config.overlays {
            let delinks = Delinks::from_file(
                config_path.join(&overlay.module.delinks),
                ModuleKind::Overlay(overlay.id),
            )?;
            let rom_overlay = rom
                .arm9_overlays()
                .iter()
                .find(|o| o.id() == overlay.id)
                .with_context(|| format!("Failed to find overlay {} in ROM", overlay.id))?;

            let module_name = format!("OV{:03}", overlay.id);
            let file_name =
                overlay.module.object.file_name().unwrap().to_string_lossy().to_string();

            let ctor_start = object_cache
                .symbols_by_name
                .get(&format!("{module_name}_CTOR_START"))
                .with_context(|| format!("No CTOR_START in overlay {}", overlay.id))?;
            let ctor_end = object_cache
                .symbols_by_name
                .get(&format!("{module_name}_CTOR_END"))
                .with_context(|| format!("No CTOR_END in overlay {}", overlay.id))?;

            let base_address =
                Self::section_ranges(&delinks.sections, &module_name, object_cache, |_| true)?
                    .unwrap()
                    .start;
            let mut info = rom_overlay.info().clone();
            info.base_address = base_address;

            let code_range =
                Self::section_ranges(&delinks.sections, &module_name, object_cache, |s| {
                    s.kind().is_initialized()
                })?;
            let bss_range =
                Self::section_ranges(&delinks.sections, &module_name, object_cache, |s| {
                    !s.kind().is_initialized()
                })?;

            let bss_range = bss_range
                .or(code_range.map(|r| r.end..r.end))
                .map(|r| r.start..r.end.next_multiple_of(32))
                .unwrap();

            info.code_size = bss_range.start - base_address;
            info.bss_size = bss_range.len() as u32;
            info.ctor_start = ctor_start.address() as u32;
            info.ctor_end = ctor_end.address() as u32;
            info.compressed = rom_overlay.originally_compressed();
            overlay_configs.push(OverlayConfig { info, signed: overlay.signed, file_name });
        }

        let original_config = if let Some(arm9_overlays_path) = &rom_paths.arm9_overlays {
            let original_config: OverlayTableConfig =
                serde_saphyr::from_reader(open_file(rom_extract_dir.join(arm9_overlays_path))?)?;
            Some(original_config)
        } else {
            None
        };

        let overlay_table_config = OverlayTableConfig {
            table_signed: original_config.as_ref().is_some_and(|c| c.table_signed),
            table_signature: original_config.map(|c| c.table_signature).unwrap_or_default(),
            overlays: overlay_configs,
        };

        let yaml_path = config_path
            .join(&config.main_module.object)
            .parent()
            .unwrap()
            .join("arm9_overlays.yaml");
        serde_saphyr::to_io_writer(&mut create_file(&yaml_path)?, &overlay_table_config)?;

        rom_paths.arm9_overlays = Some(Self::make_path(yaml_path, rom_paths_dir));

        Ok(())
    }

    fn config_autoloads(
        &self,
        object_cache: &ObjectCache<'_, '_>,
        config: &Config,
        rom: &Rom<'_>,
        rom_paths: &mut RomConfig,
        rom_paths_dir: &Path,
    ) -> Result<()> {
        let config_path = self.config.parent().unwrap();

        let rom_autoloads = rom.arm9().autoloads()?;
        for autoload in &config.autoloads {
            let delinks = Delinks::from_file(
                config_path.join(&autoload.module.delinks),
                ModuleKind::Autoload(autoload.kind),
            )?;
            let base_address = delinks.sections.base_address().unwrap();
            let rom_autoload = rom_autoloads
                .iter()
                .find(|a| a.base_address() == base_address)
                .with_context(|| format!("Failed to find autoload {} in ROM", autoload.kind))?;

            let module_name = match autoload.kind {
                AutoloadKind::Itcm => "ITCM".into(),
                AutoloadKind::Dtcm => "DTCM".into(),
                AutoloadKind::Unknown(index) => format!("AUTOLOAD_{index}"),
            };

            let mut autoload_info = *rom_autoload.info();
            autoload_info.list_entry.code_size =
                Self::section_ranges(&delinks.sections, &module_name, object_cache, |s| {
                    s.kind().is_initialized()
                })?
                .map_or(0, |range| range.len() as u32);
            autoload_info.list_entry.bss_size =
                Self::section_ranges(&delinks.sections, &module_name, object_cache, |s| {
                    !s.kind().is_initialized()
                })?
                .map_or(0, |range| range.len() as u32);

            if let Some((_, text_section)) = delinks.sections.by_name(".text") {
                autoload_info.list_entry.code_size =
                    autoload_info.list_entry.code_size.next_multiple_of(text_section.alignment());
            }

            let yaml_file_name = autoload
                .module
                .object
                .with_extension("yaml")
                .file_name()
                .unwrap()
                .to_string_lossy()
                .to_string();

            let binary_path = config_path.join(&autoload.module.object);
            let yaml_path = binary_path.parent().unwrap().join(yaml_file_name);
            serde_saphyr::to_io_writer(&mut create_file(&yaml_path)?, &autoload_info)?;

            if !binary_path.exists() {
                // Linker does not create binary file if module is completely empty
                create_file(&binary_path)?;
            }

            match autoload.kind {
                AutoloadKind::Itcm => {
                    rom_paths.itcm.bin = Self::make_path(binary_path, rom_paths_dir);
                    rom_paths.itcm.config = Self::make_path(yaml_path, rom_paths_dir);
                }
                AutoloadKind::Dtcm => {
                    rom_paths.dtcm.bin = Self::make_path(binary_path, rom_paths_dir);
                    rom_paths.dtcm.config = Self::make_path(yaml_path, rom_paths_dir);
                }
                AutoloadKind::Unknown(index) => {
                    let autoload = rom_paths
                        .unknown_autoloads
                        .iter_mut()
                        .find(|a| a.index == index)
                        .with_context(|| {
                            format!("Failed to find autoload {} in ROM config", index)
                        })?;
                    autoload.files.bin = Self::make_path(binary_path, rom_paths_dir);
                    autoload.files.config = Self::make_path(yaml_path, rom_paths_dir);
                }
            }
        }

        Ok(())
    }

    fn config_arm9(
        &self,
        object_cache: &ObjectCache<'_, '_>,
        config: &Config,
        rom: &Rom<'_>,
        rom_paths: &mut RomConfig,
        rom_paths_dir: &Path,
    ) -> Result<()> {
        let config_path = self.config.parent().unwrap();

        let arm9_section =
            object_cache.sections_by_name.get("ARM9").context("ARM9 section not found")?;
        let build_info_symbol =
            object_cache.symbols_by_name.get("BuildInfo").context("BuildInfo symbol not found")?;
        let autoload_callback_symbol = object_cache
            .symbols_by_name
            .get("AutoloadCallback")
            .context("BuildInfo symbol not found")?;
        let delinks =
            Delinks::from_file(config_path.join(&config.main_module.delinks), ModuleKind::Arm9)?;
        let bss_range = Self::section_ranges(&delinks.sections, "ARM9", object_cache, |s| {
            !s.kind().is_initialized()
        })?
        .unwrap();

        let mut arm9_build_config = rom.arm9_build_config()?;
        arm9_build_config.offsets.base_address = arm9_section.address() as u32;
        arm9_build_config.offsets.entry_function = object_cache.entry;
        arm9_build_config.offsets.build_info =
            (build_info_symbol.address() - arm9_section.address()) as u32;
        arm9_build_config.offsets.autoload_callback = autoload_callback_symbol.address() as u32;
        arm9_build_config.build_info.bss_start = bss_range.start;
        arm9_build_config.build_info.bss_end = bss_range.end;
        arm9_build_config.compressed = rom.arm9().originally_compressed();
        arm9_build_config.encrypted = rom.arm9().originally_encrypted();

        let binary_path = config_path.join(&config.main_module.object);
        let yaml_path = binary_path.parent().unwrap().join("arm9.yaml");
        serde_saphyr::to_io_writer(&mut create_file(&yaml_path)?, &arm9_build_config)?;

        rom_paths.arm9_bin = Self::make_path(binary_path, rom_paths_dir);
        rom_paths.arm9_config = Self::make_path(yaml_path, rom_paths_dir);

        Ok(())
    }

    fn section_ranges<F>(
        sections: &Sections,
        module_name: &str,
        object_cache: &ObjectCache<'_, '_>,
        predicate: F,
    ) -> Result<Option<Range<u32>>>
    where
        F: FnMut(&&Section) -> bool,
    {
        Ok(sections
            .iter()
            .filter(predicate)
            .map(|s| s.range_from_object(module_name, object_cache))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .reduce(|a, b| a.start.min(b.start)..a.end.max(b.end)))
    }

    fn make_path<P: AsRef<Path>, B: AsRef<Path>>(path: P, base: B) -> PathBuf {
        let diff = diff_paths(path, &base).unwrap();
        let diff_slash = diff.to_slash_lossy();
        let diff_str: &str = diff_slash.as_ref();
        PathBuf::from(diff_str)
    }
}
