use std::iter;

use anyhow::{bail, Result};
use ds_decomp_config::config::{
    module::ModuleKind,
    relocations::{RelocationKind, RelocationModule},
};
use ds_rom::rom::raw::AutoloadKind;
use object::elf::{R_ARM_ABS32, R_ARM_PC24, R_ARM_THM_PC22, R_ARM_XPC25};

use super::module::Module;

pub trait RelocationKindExt {
    fn as_obj_symbol_kind(&self) -> object::SymbolKind;
    fn as_elf_relocation_type(&self) -> u32;
}

impl RelocationKindExt for RelocationKind {
    fn as_obj_symbol_kind(&self) -> object::SymbolKind {
        match self {
            Self::ArmCall => object::SymbolKind::Text,
            Self::ThumbCall => object::SymbolKind::Text,
            Self::ArmCallThumb => object::SymbolKind::Text,
            Self::ThumbCallArm => object::SymbolKind::Text,
            Self::ArmBranch => object::SymbolKind::Text,
            Self::Load => object::SymbolKind::Data,
        }
    }

    fn as_elf_relocation_type(&self) -> u32 {
        match self {
            Self::ArmCall => R_ARM_PC24,
            Self::ThumbCall => R_ARM_THM_PC22,
            Self::ArmCallThumb => R_ARM_XPC25,
            // Bug in mwld thinks that the range of XPC22 is only +-2MB, but it should be +-4MB. Fortunately we can use PC22 as
            // it has the correct range, and the linker resolves BL instructions to BLX automatically anyway.
            Self::ThumbCallArm => R_ARM_THM_PC22,
            Self::ArmBranch => R_ARM_PC24,
            Self::Load => R_ARM_ABS32,
        }
    }
}

pub trait RelocationModuleExt
where
    Self: Sized,
{
    fn from_modules<'a, I>(modules: I) -> Result<Self>
    where
        I: Iterator<Item = &'a Module<'a>>;

    /// Returns the first (and possibly only) module this relocation is pointing to.
    fn first_module(&self) -> Option<ModuleKind>;

    /// Returns all modules other than the first that this relocation is pointing to.
    fn other_modules(&self) -> Option<impl Iterator<Item = ModuleKind> + '_>;
}

impl RelocationModuleExt for RelocationModule {
    fn from_modules<'a, I>(mut modules: I) -> Result<Self>
    where
        I: Iterator<Item = &'a Module<'a>>,
    {
        let Some(first) = modules.next() else { return Ok(Self::None) };

        match first.kind() {
            ModuleKind::Arm9 => {
                if modules.next().is_some() {
                    log::error!("Relocations to main should be unambiguous");
                    bail!("Relocations to main should be unambiguous");
                }
                Ok(Self::Main)
            }
            ModuleKind::Autoload(AutoloadKind::Itcm) => {
                if modules.next().is_some() {
                    log::error!("Relocations to ITCM should be unambiguous");
                    bail!("Relocations to ITCM should be unambiguous");
                }
                Ok(Self::Itcm)
            }
            ModuleKind::Autoload(AutoloadKind::Dtcm) => {
                if modules.next().is_some() {
                    log::error!("Relocations to DTCM should be unambiguous");
                    bail!("Relocations to DTCM should be unambiguous");
                }
                Ok(Self::Dtcm)
            }
            ModuleKind::Autoload(kind) => {
                log::error!("Unknown autoload kind '{kind}'");
                bail!("Unknown autoload kind '{kind}'");
            }
            ModuleKind::Overlay(id) => {
                let ids = iter::once(first)
                    .chain(modules)
                    .map(|module| {
                        if let ModuleKind::Overlay(id) = module.kind() {
                            Ok(id)
                        } else {
                            log::error!("Relocations to overlays should not go to other kinds of modules");
                            bail!("Relocations to overlays should not go to other kinds of modules");
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;
                if ids.len() > 1 {
                    Ok(Self::Overlays { ids })
                } else {
                    Ok(Self::Overlay { id })
                }
            }
        }
    }

    /// Returns the first (and possibly only) module this relocation is pointing to.
    fn first_module(&self) -> Option<ModuleKind> {
        match self {
            RelocationModule::None => None,
            RelocationModule::Overlays { ids } => Some(ModuleKind::Overlay(*ids.first().unwrap())),
            RelocationModule::Overlay { id } => Some(ModuleKind::Overlay(*id)),
            RelocationModule::Main => Some(ModuleKind::Arm9),
            RelocationModule::Itcm => Some(ModuleKind::Autoload(AutoloadKind::Itcm)),
            RelocationModule::Dtcm => Some(ModuleKind::Autoload(AutoloadKind::Dtcm)),
        }
    }

    /// Returns all modules other than the first that this relocation is pointing to.
    fn other_modules(&self) -> Option<impl Iterator<Item = ModuleKind> + '_> {
        match self {
            RelocationModule::Overlays { ids } => Some(ids[1..].iter().map(|&id| ModuleKind::Overlay(id))),
            RelocationModule::None => None,
            RelocationModule::Overlay { .. } => None,
            RelocationModule::Main => None,
            RelocationModule::Itcm => None,
            RelocationModule::Dtcm => None,
        }
    }
}
