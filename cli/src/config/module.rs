use anyhow::{Result, anyhow};
use ds_decomp::config::module::ModuleKind;
use ds_rom::rom::raw::AutoloadKind;

pub trait ModuleKindExt
where
    Self: Sized,
{
    fn from_linked_section_name(section_name: &str) -> Result<Option<Self>>;
}

impl ModuleKindExt for ModuleKind {
    fn from_linked_section_name(section_name: &str) -> Result<Option<Self>> {
        match section_name {
            "ARM9" => Ok(Some(ModuleKind::Arm9)),
            "ITCM" => Ok(Some(ModuleKind::Autoload(AutoloadKind::Itcm))),
            "DTCM" => Ok(Some(ModuleKind::Autoload(AutoloadKind::Dtcm))),
            name if name.starts_with("OV") => {
                let id = name[2..].parse::<u16>().map_err(|_| {
                    anyhow!("Invalid overlay ID in linked object section name '{section_name}'")
                })?;
                Ok(Some(ModuleKind::Overlay(id)))
            }
            name if name.starts_with("AUTOLOAD_") => {
                let index = name[9..].parse::<u32>().map_err(|_| {
                    anyhow!("Invalid autoload index in linked object section name '{section_name}'")
                })?;
                Ok(Some(ModuleKind::Autoload(AutoloadKind::Unknown(index))))
            }
            _ => Ok(None),
        }
    }
}
