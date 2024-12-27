use std::fmt::Display;

use ds_rom::rom::raw::AutoloadKind;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum ModuleKind {
    Arm9,
    Overlay(u16),
    Autoload(AutoloadKind),
}

impl ModuleKind {
    pub fn index(self) -> usize {
        match self {
            ModuleKind::Arm9 => 0,
            ModuleKind::Autoload(kind) => match kind {
                AutoloadKind::Itcm => 1,
                AutoloadKind::Dtcm => 2,
                AutoloadKind::Unknown(_) => 3,
            },
            ModuleKind::Overlay(id) => 4 + id as usize,
        }
    }
}

impl Display for ModuleKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModuleKind::Arm9 => write!(f, "ARM9 main"),
            ModuleKind::Overlay(index) => write!(f, "overlay {index}"),
            ModuleKind::Autoload(kind) => write!(f, "{kind}"),
        }
    }
}
