use std::borrow::Cow;

use ds_rom::rom::{Arm9AutoloadError, Rom, raw::RawBuildInfoError};
use snafu::Snafu;

use crate::config::module::ModuleKind;

#[derive(Debug, Snafu)]
pub enum RomGetCodeError {
    #[snafu(display("Module {} not found", module_kind))]
    ModuleNotFound { module_kind: ModuleKind },
    #[snafu(transparent)]
    RawBuildInfo { source: RawBuildInfoError },
    #[snafu(transparent)]
    Arm9Autoload { source: Arm9AutoloadError },
}

pub trait RomExt {
    fn get_code(&self, kind: ModuleKind) -> Result<Cow<'_, [u8]>, RomGetCodeError>;
}

impl RomExt for Rom<'_> {
    fn get_code(&self, kind: ModuleKind) -> Result<Cow<'_, [u8]>, RomGetCodeError> {
        match kind {
            ModuleKind::Arm9 => Ok(self.arm9().code()?.into()),
            ModuleKind::Overlay(id) => Ok(self
                .arm9_overlays()
                .get(id as usize)
                .ok_or_else(|| RomGetCodeError::ModuleNotFound { module_kind: kind })?
                .code()
                .into()),
            ModuleKind::Autoload(autoload_kind) => {
                let autoloads = self.arm9().autoloads()?;
                let autoload = autoloads
                    .iter()
                    .find(|a| a.kind() == autoload_kind)
                    .ok_or_else(|| RomGetCodeError::ModuleNotFound { module_kind: kind })?;
                Ok(autoload.code().to_owned().into())
            }
        }
    }
}
