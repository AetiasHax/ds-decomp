use ds_decomp::config::{
    module::ModuleKind,
    relocations::{RelocationKind, RelocationModule},
};
use ds_rom::rom::raw::AutoloadKind;
use object::elf::{R_ARM_ABS32, R_ARM_PC24, R_ARM_THM_PC22};

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
            Self::ArmCallThumb => R_ARM_PC24,
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
            RelocationModule::Autoload { index } => Some(ModuleKind::Autoload(AutoloadKind::Unknown(*index))),
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
            RelocationModule::Autoload { .. } => None,
        }
    }
}
