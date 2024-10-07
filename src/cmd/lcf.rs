use std::{
    borrow::Cow,
    fs::File,
    io::{BufWriter, Write},
    path::{Path, PathBuf},
};

use anyhow::{bail, Result};
use argp::FromArgs;
use ds_rom::rom::{raw::AutoloadKind, Rom, RomLoadOptions};

use crate::{
    analysis::overlay_groups::OverlayGroups,
    config::{config::Config, delinks::Delinks, module::ModuleKind},
    util::io::{create_dir_all, create_file_and_dirs, open_file},
};

/// Generates linker scripts for all modules in a dsd config.
#[derive(FromArgs)]
#[argp(subcommand, name = "lcf")]
pub struct Lcf {
    /// Path to config.yaml.
    #[argp(option, short = 'c')]
    config_path: PathBuf,

    /// Path to output LCF file.
    #[argp(option, short = 'l')]
    lcf_file: PathBuf,

    /// Path to object list file.
    #[argp(option, short = 'o')]
    objects_file: PathBuf,

    /// Path to compiled objects.
    #[argp(option, short = 'p')]
    objects_path: Option<PathBuf>,

    /// Path to build directory, where the linked binaries will go.
    #[argp(option, short = 'b')]
    build_path: PathBuf,
}

impl Lcf {
    pub fn run(&self) -> Result<()> {
        let config: Config = serde_yml::from_reader(open_file(&self.config_path)?)?;
        let config_dir = self.config_path.parent().unwrap();

        let rom = Rom::load(
            config_dir.join(&config.rom_config),
            RomLoadOptions { key: None, compress: false, encrypt: false, load_files: false },
        )?;

        let overlay_groups = OverlayGroups::analyze(rom.arm9().end_address()?, rom.arm9_overlays())?;

        let lcf_file = create_file_and_dirs(&self.lcf_file)?;
        let mut lcf = BufWriter::new(lcf_file);

        let objects_file = create_file_and_dirs(&self.objects_file)?;
        let mut objects = BufWriter::new(objects_file);

        self.write_memory_section(&mut lcf, rom, overlay_groups, &config)?;
        self.write_sections_section(&mut lcf, &mut objects, config_dir, &config)?;

        Ok(())
    }

    fn write_sections_section(
        &self,
        lcf: &mut BufWriter<File>,
        objects: &mut BufWriter<File>,
        config_dir: &Path,
        config: &Config,
    ) -> Result<(), anyhow::Error> {
        writeln!(lcf, "SECTIONS {{")?;
        self.write_module_section(lcf, objects, config_dir, &config.main_module.delinks, ModuleKind::Arm9)?;
        for autoload in &config.autoloads {
            self.write_module_section(
                lcf,
                objects,
                config_dir,
                &autoload.module.delinks,
                ModuleKind::Autoload(autoload.kind),
            )?;
        }
        for overlay in &config.overlays {
            self.write_module_section(lcf, objects, config_dir, &overlay.module.delinks, ModuleKind::Overlay(overlay.id))?;
        }
        writeln!(lcf, "}}\n")?;
        Ok(())
    }

    fn write_memory_section(
        &self,
        lcf: &mut BufWriter<File>,
        rom: Rom<'_>,
        overlay_groups: OverlayGroups,
        config: &Config,
    ) -> Result<()> {
        let config_dir = self.config_path.parent().unwrap();

        writeln!(lcf, "MEMORY {{")?;
        let arm9_bin = normalize_join(config_dir, &config.main_module.object)?;
        create_dir_all(arm9_bin.parent().unwrap())?; // Empty directory, but mwld doesn't create it by itself
        let arm9_bin = arm9_bin.strip_prefix(&self.build_path)?; // mwld expects memory files to be relative to the linked ELF binary
        writeln!(lcf, "    ARM9 : ORIGIN = {:#x} > {}", rom.arm9().base_address(), arm9_bin.display())?;
        for autoload in rom.arm9().autoloads()?.iter() {
            let memory_name = match autoload.kind() {
                AutoloadKind::Itcm => "ITCM",
                AutoloadKind::Dtcm => "DTCM",
                AutoloadKind::Unknown => bail!("Unknown autoload kind"),
            };
            let config = config.autoloads.iter().find(|a| a.kind == autoload.kind()).unwrap();
            writeln!(
                lcf,
                "    {memory_name} : ORIGIN = {:#x} > {}",
                autoload.base_address(),
                normalize_join(config_dir, &config.module.object)?.strip_prefix(&self.build_path)?.display()
            )?;
        }
        for group in overlay_groups.iter() {
            for &overlay_id in &group.overlays {
                let overlay = &rom.arm9_overlays()[overlay_id as usize];

                let memory_name = format!("OV{:03}", overlay.id());

                write!(lcf, "    {memory_name} : ORIGIN = AFTER(")?;

                if group.after.is_empty() {
                    write!(lcf, "ARM9")?;
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
                    normalize_join(config_dir, &config.module.object)?.strip_prefix(&self.build_path)?.display()
                )?;
            }
        }
        writeln!(lcf, "}}\n")?;
        Ok(())
    }

    fn write_module_section(
        &self,
        lcf: &mut BufWriter<File>,
        objects: &mut BufWriter<File>,
        config_dir: &Path,
        delinks_path: &Path,
        module_kind: ModuleKind,
    ) -> Result<()> {
        let (module_name, memory_name): (Cow<str>, Cow<str>) = match module_kind {
            ModuleKind::Arm9 => (".arm9".into(), "ARM9".into()),
            ModuleKind::Overlay(id) => (format!(".ov{:03}", id).into(), format!("OV{:03}", id).into()),
            ModuleKind::Autoload(AutoloadKind::Itcm) => (".itcm".into(), "ITCM".into()),
            ModuleKind::Autoload(AutoloadKind::Dtcm) => (".dtcm".into(), "DTCM".into()),
            ModuleKind::Autoload(_) => bail!("Unknown autoload kind"),
        };

        writeln!(lcf, "    {module_name} : {{")?;
        let delinks = Delinks::from_file(config_dir.join(delinks_path), module_kind)?;
        for section in delinks.sections.sorted_by_address() {
            writeln!(lcf, "        . = ALIGN({});", section.alignment())?;
            let section_boundary_name = section.boundary_name();
            writeln!(lcf, "        {memory_name}_{section_boundary_name}_START = .;")?;
            for file in &delinks.files {
                if file.sections.by_name(section.name()).is_none() {
                    continue;
                }
                let (file_path, _) = file.split_file_ext();
                let (_, file_name) = file_path.rsplit_once('/').unwrap_or(("", &file_path));
                writeln!(lcf, "        {file_name}.o({})", section.name())?;
            }
            writeln!(lcf, "        {memory_name}_{section_boundary_name}_END = .;")?;
        }
        writeln!(lcf, "    }} > {memory_name}\n")?;

        for file in &delinks.files {
            let (file_path, _) = file.split_file_ext();
            let file_path = self.objects_path.clone().map_or(file_path.into(), |base| base.join(&file_path));
            writeln!(objects, "{}.o", file_path.display())?;
        }

        Ok(())
    }
}

fn normalize_join<P: AsRef<Path>, Q: AsRef<Path>>(a: P, b: Q) -> Result<PathBuf> {
    Ok(std::path::absolute(a.as_ref().join(b))?.strip_prefix(std::env::current_dir()?)?.to_path_buf())
}
