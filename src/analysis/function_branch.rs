use unarm::{
    args::{Argument, Reg, Register},
    Ins, ParsedIns,
};

/// Function branches refers to `b` instructions (not `bl`) which go to other functions. They are not typically possible with
/// C/C++, but is instead made in assembly code. Since the function boundary detector thinks all branches are within the same
/// function, we must tell it to ignore function branches.
///
/// The current implementation to detect function branches is completely arbitrary and relies on instruction patterns that is
/// hopefully (likely) not present in C/C++ code.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub enum FunctionBranchState {
    #[default]
    Start,
    Eors,
    MovgePcLr,
    MovFromSp,
    FunctionBranch,
}

impl FunctionBranchState {
    pub fn handle(self, ins: Ins, parsed_ins: &ParsedIns) -> Self {
        let args = &parsed_ins.args;
        match self {
            Self::Start => match (parsed_ins.mnemonic, args[0], args[1], args[2], args[3]) {
                ("eors", Argument::Reg(_), Argument::Reg(_), Argument::Reg(_), Argument::None) => Self::Eors,
                (
                    "movge",
                    Argument::Reg(Reg { reg: Register::Pc, .. }),
                    Argument::Reg(Reg { reg: Register::Lr, .. }),
                    Argument::None,
                    Argument::None,
                ) => Self::MovgePcLr,
                (
                    "mov",
                    Argument::Reg(Reg { .. }),
                    Argument::Reg(Reg { reg: Register::Sp, deref: false, .. }),
                    Argument::None,
                    Argument::None,
                ) => Self::MovFromSp,
                _ => Self::default(),
            },
            Self::Eors => match (parsed_ins.mnemonic, args[0], args[1]) {
                ("bmi", Argument::BranchDest(_), Argument::None) => Self::FunctionBranch,
                _ if ins.updates_condition_flags() => Self::default(),
                _ => self,
            },
            Self::MovgePcLr | Self::MovFromSp => match (parsed_ins.mnemonic, args[0], args[1]) {
                ("b", Argument::BranchDest(_), Argument::None) => Self::FunctionBranch,
                _ => Self::default(),
            },
            Self::FunctionBranch => Self::default(),
        }
    }

    pub fn is_function_branch(self) -> bool {
        self == Self::FunctionBranch
    }
}
