use std::{
    borrow::Cow,
    fs::File,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::Result;
use clap::Args;
use ds_decomp::config::{
    config::{Config, ConfigModule},
    delinks::Delinks,
    module::ModuleKind,
};
use ds_rom::rom::{raw::AutoloadKind, Rom, RomLoadOptions};

use crate::{
    analysis::overlay_groups::OverlayGroups,
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

    /// Path to output LCF file.
    #[arg(long, short = 'l')]
    pub lcf_file: PathBuf,

    /// Path to object list file.
    #[arg(long, short = 'o')]
    pub objects_file: PathBuf,
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
        let delinks_path = config_dir.normalize_join(&config.delinks_path)?;

        let (static_end_address, last_static_module) = find_last_static_module(&rom)?;
        log::debug!("Static end address: {:#010x}", static_end_address);
        let overlay_groups = OverlayGroups::analyze(static_end_address, rom.arm9_overlays())?;

        let lcf_file = create_file_and_dirs(&self.lcf_file)?;
        let mut lcf = BufWriter::new(lcf_file);

        let objects_file = create_file_and_dirs(&self.objects_file)?;
        let mut objects = BufWriter::new(objects_file);

        self.write_memory_section(&mut lcf, rom, overlay_groups, &last_static_module, &config, &build_path)?;
        self.write_keep_section_section(&mut lcf)?;
        self.write_sections_section(&mut lcf, &mut objects, config_dir, &config, &build_path, &delinks_path)?;

        Ok(())
    }

    fn write_sections_section(
        &self,
        lcf: &mut BufWriter<File>,
        objects: &mut BufWriter<File>,
        config_dir: &Path,
        config: &Config,
        build_path: &Path,
        delinks_path: &Path,
    ) -> Result<(), anyhow::Error> {
        writeln!(lcf, "SECTIONS {{")?;
        self.write_module_section(lcf, objects, config_dir, &config.main_module, ModuleKind::Arm9, build_path, delinks_path)?;
        for autoload in &config.autoloads {
            self.write_module_section(
                lcf,
                objects,
                config_dir,
                &autoload.module,
                ModuleKind::Autoload(autoload.kind),
                build_path,
                delinks_path,
            )?;
        }
        for overlay in &config.overlays {
            self.write_module_section(
                lcf,
                objects,
                config_dir,
                &overlay.module,
                ModuleKind::Overlay(overlay.id),
                build_path,
                delinks_path,
            )?;
        }
        writeln!(lcf, "}}\n")?;
        Ok(())
    }

    fn write_keep_section_section(&self, lcf: &mut BufWriter<File>) -> Result<()> {
        writeln!(lcf, "KEEP_SECTION {{")?;
        writeln!(lcf, "    .init,")?;
        writeln!(lcf, "    .ctor")?;
        writeln!(lcf, "}}\n")?;
        Ok(())
    }

    fn write_memory_section(
        &self,
        lcf: &mut BufWriter<File>,
        rom: Rom<'_>,
        overlay_groups: OverlayGroups,
        last_static_module: &str,
        config: &Config,
        build_path: &Path,
    ) -> Result<()> {
        let config_dir = self.config_path.parent().unwrap();

        writeln!(lcf, "MEMORY {{")?;
        let arm9_bin = config_dir.normalize_join(&config.main_module.object)?;
        create_dir_all(arm9_bin.parent().unwrap())?; // Empty directory, but mwld doesn't create it by itself
        let arm9_bin = arm9_bin.strip_prefix_ext(build_path)?; // mwld expects memory files to be relative to the linked ELF binary
        writeln!(lcf, "    ARM9 : ORIGIN = {:#x} > {}", rom.arm9().base_address(), arm9_bin.display())?;
        for autoload in rom.arm9().autoloads()?.iter() {
            let memory_name = match autoload.kind() {
                AutoloadKind::Itcm => "ITCM".into(),
                AutoloadKind::Dtcm => "DTCM".into(),
                AutoloadKind::Unknown(index) => format!("AUTOLOAD_{index}"),
            };
            let config = config.autoloads.iter().find(|a| a.kind == autoload.kind()).unwrap();
            writeln!(
                lcf,
                "    {memory_name} : ORIGIN = {:#x} > {}",
                autoload.base_address(),
                config_dir.normalize_join(&config.module.object)?.strip_prefix_ext(build_path)?.display()
            )?;
        }
        for group in overlay_groups.iter() {
            for &overlay_id in &group.overlays {
                let overlay = &rom.arm9_overlays()[overlay_id as usize];

                let memory_name = format!("OV{:03}", overlay.id());

                write!(lcf, "    {memory_name} : ORIGIN = AFTER(")?;

                if group.after.is_empty() {
                    write!(lcf, "{last_static_module}")?;
                } else {
                    for (i, id) in group.after.iter().enumerate() {
                        if i > 0 {
                            write!(lcf, ",")?;
                        }
                        let memory_name = format!("OV{:03}", id);
                        write!(lcf, "{memory_name}")?;
                    }
                }

                let config = config.overlays.iter().find(|o| o.id == overlay_id).unwrap();
                writeln!(
                    lcf,
                    ") > {}",
                    config_dir.normalize_join(&config.module.object)?.strip_prefix_ext(build_path)?.display()
                )?;
            }
        }
        writeln!(lcf, "}}\n")?;
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn write_module_section(
        &self,
        lcf: &mut BufWriter<File>,
        objects: &mut BufWriter<File>,
        config_dir: &Path,
        module: &ConfigModule,
        module_kind: ModuleKind,
        build_path: &Path,
        delinks_path: &Path,
    ) -> Result<()> {
        let (module_name, memory_name): (Cow<str>, Cow<str>) = match module_kind {
            ModuleKind::Arm9 => (".arm9".into(), "ARM9".into()),
            ModuleKind::Overlay(id) => (format!(".ov{:03}", id).into(), format!("OV{:03}", id).into()),
            ModuleKind::Autoload(AutoloadKind::Itcm) => (".itcm".into(), "ITCM".into()),
            ModuleKind::Autoload(AutoloadKind::Dtcm) => (".dtcm".into(), "DTCM".into()),
            ModuleKind::Autoload(AutoloadKind::Unknown(index)) => {
                (format!(".autoload_{index}").into(), format!("AUTOLOAD_{index}").into())
            }
        };

        writeln!(lcf, "    {module_name} : {{")?;
        writeln!(lcf, "        ALIGNALL(4);")?;
        if let ModuleKind::Overlay(id) = module_kind {
            let overlay_id_symbol_name = Self::overlay_id_symbol_name(id);
            writeln!(lcf, "        {overlay_id_symbol_name} = {id};")?;
        }
        let delinks = Delinks::from_file_and_generate_gaps(config_dir.join(&module.delinks), module_kind)?;
        for section in delinks.sections.sorted_by_address() {
            writeln!(lcf, "        . = ALIGN({});", section.alignment())?;
            let section_boundary_name = section.boundary_name();
            writeln!(lcf, "        {memory_name}_{section_boundary_name}_START = .;")?;
            for file in &delinks.files {
                if file.sections.by_name(section.name()).is_none() {
                    continue;
                }
                let (file_path, _) = file.split_file_ext();
                let (_, file_name) = file_path.rsplit_once('/').unwrap_or(("", file_path));
                writeln!(lcf, "        {file_name}.o({})", section.name())?;
            }
            writeln!(lcf, "        {memory_name}_{section_boundary_name}_END = .;")?;
        }
        writeln!(lcf, "    }} > {memory_name}\n")?;

        for file in &delinks.files {
            let (file_path, _) = file.split_file_ext();
            let base_path = if file.complete { build_path } else { delinks_path };
            let file_path = base_path.join(file_path);
            writeln!(objects, "{}.o", file_path.display())?;
        }

        Ok(())
    }

    pub fn overlay_id_symbol_name(id: u16) -> String {
        format!("OVERLAY_{id}_ID")
    }
}

fn find_last_static_module(rom: &Rom<'_>) -> Result<(u32, String)> {
    // Find contiguous autoloads after the main program and return the end address of the last one
    let mut static_end_address = rom.arm9().end_address()?;
    let mut module_name = "ARM9".to_string();
    let mut sorted_autoloads = rom.arm9().autoloads()?;
    sorted_autoloads.sort_unstable_by_key(|a| a.base_address());
    for i in 0..sorted_autoloads.len() {
        let AutoloadKind::Unknown(autoload_index) = sorted_autoloads[i].kind() else {
            continue;
        };
        if sorted_autoloads[i].base_address() == static_end_address {
            static_end_address = sorted_autoloads[i].end_address();
            module_name = format!("AUTOLOAD_{autoload_index}");
        }
    }
    Ok((static_end_address, module_name))
}
