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
    util::io::{create_file_and_dirs, open_file},
};

/// Generates linker scripts for all modules in a dsd config.
#[derive(FromArgs)]
#[argp(subcommand, name = "lcf")]
pub struct Lcf {
    /// Path to config.yaml.
    #[argp(option, short = 'c')]
    config_path: PathBuf,

    /// Path to output LCF file.
    #[argp(option, short = 'o')]
    output_path: PathBuf,
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

        let lcf_file = create_file_and_dirs(&self.output_path)?;
        let mut writer = BufWriter::new(lcf_file);

        self.write_memory_section(&mut writer, rom, overlay_groups)?;
        self.write_sections_section(&mut writer, config_dir, &config)?;

        Ok(())
    }

    fn write_sections_section(
        &self,
        writer: &mut BufWriter<File>,
        config_dir: &Path,
        config: &Config,
    ) -> Result<(), anyhow::Error> {
        writeln!(writer, "SECTIONS {{")?;
        self.write_module_section(writer, config_dir, &config.main_module.delinks, ModuleKind::Arm9)?;
        for autoload in &config.autoloads {
            self.write_module_section(writer, config_dir, &autoload.module.delinks, ModuleKind::Autoload(autoload.kind))?;
        }
        for overlay in &config.overlays {
            self.write_module_section(writer, config_dir, &overlay.module.delinks, ModuleKind::Overlay(overlay.id))?;
        }
        writeln!(writer, "}}\n")?;
        Ok(())
    }

    fn write_memory_section(&self, writer: &mut BufWriter<File>, rom: Rom<'_>, overlay_groups: OverlayGroups) -> Result<()> {
        writeln!(writer, "MEMORY {{")?;
        writeln!(writer, "    ARM9 : ORIGIN = {:#x} > arm9.bin", rom.arm9().base_address())?;
        for autoload in rom.arm9().autoloads()?.iter() {
            let (memory_name, file_name) = match autoload.kind() {
                AutoloadKind::Itcm => ("ITCM", "itcm.bin"),
                AutoloadKind::Dtcm => ("DTCM", "dtcm.bin"),
                AutoloadKind::Unknown => bail!("Unknown autoload kind"),
            };
            writeln!(writer, "    {memory_name} : ORIGIN = {:#x} > {file_name}", autoload.base_address())?;
        }
        for group in overlay_groups.iter() {
            for &overlay_id in &group.overlays {
                let overlay = &rom.arm9_overlays()[overlay_id as usize];

                let memory_name = format!("OV{:03}", overlay.id());
                let file_name = format!("ov{:03}.bin", overlay.id());

                write!(writer, "    {memory_name} : ORIGIN = AFTER(")?;

                if group.after.is_empty() {
                    write!(writer, "ARM9")?;
                } else {
                    for (i, id) in group.after.iter().enumerate() {
                        if i > 0 {
                            write!(writer, ",")?;
                        }
                        let memory_name = format!("OV{:03}", id);
                        write!(writer, "{memory_name}")?;
                    }
                }

                writeln!(writer, ") > {file_name}")?;
            }
        }
        writeln!(writer, "}}\n")?;
        Ok(())
    }

    fn write_module_section(
        &self,
        writer: &mut BufWriter<File>,
        config_dir: &Path,
        delinks_path: &Path,
        module_kind: ModuleKind,
    ) -> Result<()> {
        let (section_name, memory_name): (Cow<str>, Cow<str>) = match module_kind {
            ModuleKind::Arm9 => (".arm9".into(), "ARM9".into()),
            ModuleKind::Overlay(id) => (format!(".ov{:03}", id).into(), format!("OV{:03}", id).into()),
            ModuleKind::Autoload(AutoloadKind::Itcm) => (".itcm".into(), "ITCM".into()),
            ModuleKind::Autoload(AutoloadKind::Dtcm) => (".dtcm".into(), "DTCM".into()),
            ModuleKind::Autoload(_) => bail!("Unknown autoload kind"),
        };

        writeln!(writer, "    {section_name} : {{")?;
        let delinks = Delinks::from_file(config_dir.join(delinks_path), module_kind)?;
        for section in delinks.sections.sorted_by_address() {
            writeln!(writer, "        . = ALIGN({});", section.alignment())?;
            for file in &delinks.files {
                if file.sections.by_name(section.name()).is_none() {
                    continue;
                }
                let (_, file_name) = file.name.rsplit_once('/').unwrap_or(("", &file.name));
                writeln!(writer, "        {file_name}.o({})", section.name())?;
            }
        }
        writeln!(writer, "    }} > {memory_name}\n")?;
        Ok(())
    }
}
