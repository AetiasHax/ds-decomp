use std::{collections::BTreeMap, path::Path};

use anyhow::Result;
use ds_decomp::config::{
    config::Config,
    module::ModuleKind,
    relocations::{RelocationKind, RelocationModule, Relocations},
};
use ds_rom::rom::raw::AutoloadKind;
use object::elf::{R_ARM_ABS32, R_ARM_PC24, R_ARM_THM_PC22};

pub trait RelocationKindExt: Sized {
    fn as_obj_symbol_kind(&self) -> object::SymbolKind;
    fn as_elf_relocation_type(&self) -> u32;
    fn from_elf_relocation_type(r_type: u32, dest_thumb: bool, is_branch: bool) -> Option<Self>;
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
            Self::OverlayId => object::SymbolKind::Data,
            Self::LinkTimeConst(_) => object::SymbolKind::Data,
        }
    }

    fn as_elf_relocation_type(&self) -> u32 {
        match self {
            Self::ArmCall => R_ARM_PC24,
            Self::ThumbCall => R_ARM_THM_PC22,
            Self::ArmCallThumb => R_ARM_PC24,
            // Bug in mwld thinks that the range of XPC22 is only +-2MB, but it should be +-4MB. Fortunately we can use PC22 as
            // it has the correct range, and the linker resolves BL instructions to BLX automatically anyway.
            Self::ThumbCallArm => R_ARM_THM_PC22,
            Self::ArmBranch => R_ARM_PC24,
            Self::Load => R_ARM_ABS32,
            Self::OverlayId => R_ARM_ABS32,
            Self::LinkTimeConst(_) => R_ARM_ABS32,
        }
    }

    fn from_elf_relocation_type(r_type: u32, dest_thumb: bool, is_branch: bool) -> Option<Self> {
        match r_type {
            R_ARM_PC24 => {
                if is_branch {
                    Some(Self::ArmBranch)
                } else if dest_thumb {
                    Some(Self::ArmCallThumb)
                } else {
                    Some(Self::ArmCall)
                }
            }
            R_ARM_THM_PC22 => {
                if dest_thumb {
                    Some(Self::ThumbCall)
                } else {
                    Some(Self::ThumbCallArm)
                }
            }
            R_ARM_ABS32 => Some(Self::Load),
            _ => None,
        }
    }
}

pub trait RelocationModuleExt
where
    Self: Sized,
{
    /// Returns the first (and possibly only) module this relocation is pointing to.
    fn first_module(&self) -> Option<ModuleKind>;

    /// Returns all modules other than the first that this relocation is pointing to.
    fn other_modules(&self) -> Option<impl Iterator<Item = ModuleKind> + '_>;
}

impl RelocationModuleExt for RelocationModule {
    /// Returns the first (and possibly only) module this relocation is pointing to.
    fn first_module(&self) -> Option<ModuleKind> {
        match self {
            RelocationModule::None => None,
            RelocationModule::Overlays { ids } => Some(ModuleKind::Overlay(*ids.first().unwrap())),
            RelocationModule::Overlay { id } => Some(ModuleKind::Overlay(*id)),
            RelocationModule::Main => Some(ModuleKind::Arm9),
            RelocationModule::Itcm => Some(ModuleKind::Autoload(AutoloadKind::Itcm)),
            RelocationModule::Dtcm => Some(ModuleKind::Autoload(AutoloadKind::Dtcm)),
            RelocationModule::Autoload { index } => {
                Some(ModuleKind::Autoload(AutoloadKind::Unknown(*index)))
            }
        }
    }

    /// Returns all modules other than the first that this relocation is pointing to.
    fn other_modules(&self) -> Option<impl Iterator<Item = ModuleKind> + '_> {
        match self {
            RelocationModule::Overlays { ids } => {
                Some(ids[1..].iter().map(|&id| ModuleKind::Overlay(id)))
            }
            RelocationModule::None => None,
            RelocationModule::Overlay { .. } => None,
            RelocationModule::Main => None,
            RelocationModule::Itcm => None,
            RelocationModule::Dtcm => None,
            RelocationModule::Autoload { .. } => None,
        }
    }
}

pub struct RelocationsMap {
    map: BTreeMap<ModuleKind, Relocations>,
}

impl RelocationsMap {
    pub fn from_config(config: &Config, path: impl AsRef<Path>) -> Result<RelocationsMap> {
        let path = path.as_ref();
        let map = config
            .iter_modules()
            .map(|(kind, config)| {
                let relocations = Relocations::from_file(path.join(&config.relocations))?;
                Ok((kind, relocations))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        Ok(Self { map })
    }

    pub fn to_files(&self, config: &Config, config_path: impl AsRef<Path>) -> Result<()> {
        let config_path = config_path.as_ref();
        for (kind, module) in config.iter_modules() {
            let relocs = self.get(kind).unwrap();
            relocs.to_file(config_path.join(&module.relocations))?;
        }
        Ok(())
    }

    pub fn get(&self, kind: ModuleKind) -> Option<&Relocations> {
        self.map.get(&kind)
    }

    pub fn get_mut(&mut self, kind: ModuleKind) -> Option<&mut Relocations> {
        self.map.get_mut(&kind)
    }
}
