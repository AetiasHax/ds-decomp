use std::{
    io::{stdout, Write},
    path::PathBuf,
};

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
}

impl ImportSymbols {
    pub fn run(&self) -> Result<()> {
        let config: Config = serde_yml::from_reader(open_file(&self.config_path)?)?;
        let config_path = self.config_path.parent().unwrap();

        let mut symbol_maps = SymbolMaps::from_config(config_path, &config)?;

        let file = read_file(&self.elf_path)?;
        let object = object::File::parse(&*file)?;

        let mut stdout = stdout().lock();

        for section in object.sections() {
            let section_name = section.name()?;
            writeln!(stdout, "Section: {section_name}")?;
            let Some(module_kind) = self.parse_module_kind(section_name)? else { continue };
            let symbol_map = symbol_maps.get_mut(module_kind);
            writeln!(stdout, "Module: {module_kind}")?;
            for symbol in object.symbols() {
                if symbol.section_index() != Some(section.index()) {
                    continue;
                };

                let name = symbol.name()?;
                if name.starts_with("func")
                    || name.starts_with("data")
                    || name.starts_with(".")
                    || name.starts_with("$")
                    || name.starts_with("ov")
                    || name.starts_with("arm9")
                    || name.starts_with("itcm")
                    || name.starts_with("dtcm")
                    || name.starts_with("@")
                {
                    continue;
                }

                let address = symbol.address() as u32;
                if address == 0 {
                    continue;
                }

                writeln!(stdout, "{address:#x} {name}")?;

                symbol_map.rename_by_address(address, name)?;
            }
        }

        symbol_maps.to_files(&config, &self.config_path.parent().unwrap())?;

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
}
