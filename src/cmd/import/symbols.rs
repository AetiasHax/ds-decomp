use std::{borrow::Cow, path::PathBuf};

use anyhow::Result;
use argp::FromArgs;
use ds_rom::rom::raw::AutoloadKind;
use object::{Object, ObjectSection, ObjectSymbol};

use crate::{
    config::{config::Config, module::ModuleKind, symbol::SymbolMaps},
    util::io::{open_file, read_file},
};

/// Imports symbol names from a previously built ELF file.
#[derive(FromArgs)]
#[argp(subcommand, name = "symbols")]
pub struct ImportSymbols {
    /// Path to config.yaml.
    #[argp(option, short = 'c')]
    config_path: PathBuf,

    /// Path to built/linked ELF file.
    #[argp(option, short = 'x')]
    elf_path: PathBuf,

    /// Includes symbols with default names like `func_ov12_0211514c`.
    #[argp(switch, short = 'D')]
    include_default_names: bool,

    /// Dry run, do not write any files.
    #[argp(switch, short = 'd')]
    dry: bool,
}

impl ImportSymbols {
    pub fn run(&self) -> Result<()> {
        let config: Config = serde_yml::from_reader(open_file(&self.config_path)?)?;
        let config_path = self.config_path.parent().unwrap();

        let mut symbol_maps = SymbolMaps::from_config(config_path, &config)?;

        let file = read_file(&self.elf_path)?;
        let object = object::File::parse(&*file)?;

        for section in object.sections() {
            let section_name = section.name()?;
            log::debug!("Section: {section_name}");
            let Some(module_kind) = self.parse_module_kind(section_name)? else { continue };
            let symbol_map = symbol_maps.get_mut(module_kind);
            log::debug!("Module: {module_kind}");
            for symbol in object.symbols() {
                if symbol.section_index() != Some(section.index()) {
                    continue;
                };

                let name = symbol.name()?;
                if name.starts_with(".")
                    || name.starts_with("$")
                    || name.starts_with("ov")
                    || name.starts_with("arm9")
                    || name.starts_with("itcm")
                    || name.starts_with("dtcm")
                    || name.starts_with("@")
                {
                    continue;
                }

                let is_default_name = name.starts_with("func_") || name.starts_with("data_");

                let name = if is_default_name {
                    if !self.include_default_names {
                        continue;
                    } else {
                        self.pad_default_symbol(name)?
                    }
                } else {
                    name.into()
                };

                let address = symbol.address() as u32;
                if address == 0 {
                    continue;
                }

                let result = symbol_map.rename_by_address(address, &name);
                if !is_default_name {
                    log::debug!("{address:#x} {name}");
                    result?;
                }
            }
        }

        if !self.dry {
            symbol_maps.to_files(&config, &config_path)?;
        }

        Ok(())
    }

    fn parse_module_kind(&self, s: &str) -> Result<Option<ModuleKind>> {
        if s == "ARM9" {
            Ok(Some(ModuleKind::Arm9))
        } else if s == "ITCM" {
            Ok(Some(ModuleKind::Autoload(AutoloadKind::Itcm)))
        } else if s == "DTCM" {
            Ok(Some(ModuleKind::Autoload(AutoloadKind::Dtcm)))
        } else if let Some(overlay_number) = s.strip_prefix("ov") {
            let overlay_id = overlay_number.parse()?;
            Ok(Some(ModuleKind::Overlay(overlay_id)))
        } else {
            Ok(None)
        }
    }

    fn pad_default_symbol<'a>(&self, name: &'a str) -> Result<Cow<'a, str>> {
        let split = name.split('_').collect::<Vec<_>>();
        if split.len() <= 2 {
            return Ok(name.into());
        }

        let module_name = split[1];
        let Some(overlay_number) = module_name.strip_prefix("ov") else {
            return Ok(name.into());
        };

        if overlay_number.len() >= 3 || !overlay_number.chars().next().unwrap().is_ascii_digit() {
            return Ok(name.into());
        }

        let overlay_id: u16 = overlay_number.parse()?;

        let prefix = split[0];
        let suffix = split[2..].join("_");

        Ok(format!("{prefix}_ov{overlay_id:03}_{suffix}").into())
    }
}
