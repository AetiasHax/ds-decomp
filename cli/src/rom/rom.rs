use std::borrow::Cow;

use anyhow::{Context, Result};
use ds_decomp::config::module::ModuleKind;
use ds_rom::rom::Rom;

pub trait RomExt {
    fn get_code(&self, kind: ModuleKind) -> Result<Cow<'_, [u8]>>;
}

impl RomExt for Rom<'_> {
    fn get_code(&self, kind: ModuleKind) -> Result<Cow<'_, [u8]>> {
        match kind {
            ModuleKind::Arm9 => Ok(self.arm9().code()?.into()),
            ModuleKind::Overlay(id) => Ok(self.arm9_overlays()[id as usize].code().into()),
            ModuleKind::Autoload(autoload_kind) => {
                let autoloads = self.arm9().autoloads()?;
                let autoload = autoloads.iter().find(|a| a.kind() == autoload_kind).context("Autoload not found")?;
                Ok(autoload.code().to_owned().into())
            }
        }
    }
}
