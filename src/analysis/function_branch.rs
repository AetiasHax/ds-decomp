use unarm::{args::Argument, Ins, ParsedIns};

/// Function branches refers to `b` instructions (not `bl`) which go to other functions. They are not typically possible with
/// C/C++, but is instead made in assembly code. Since the function boundary detector thinks all branches are within the same
/// function, we must tell it to ignore function branches.
///
/// The current implementation to detect function branches is completely arbitrary and relies on instruction patterns that is
/// hopefully but likely not present in C/C++ code.
#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub enum FunctionBranchState {
    #[default]
    Start,
    Eors,
    FunctionBranch,
}

impl FunctionBranchState {
    pub fn handle(self, ins: Ins, parsed_ins: &ParsedIns) -> Self {
        let args = &parsed_ins.args;
        match self {
            Self::Start => match (parsed_ins.mnemonic, args[0], args[1], args[2], args[3]) {
                ("eors", Argument::Reg(_), Argument::Reg(_), Argument::Reg(_), Argument::None) => Self::Eors,
                _ => Self::default(),
            },
            Self::Eors => match (parsed_ins.mnemonic, args[0], args[1]) {
                ("bmi", Argument::BranchDest(_), Argument::None) => Self::FunctionBranch,
                _ if ins.updates_condition_flags() => Self::default(),
                _ => self,
            },
            Self::FunctionBranch => Self::default(),
        }
    }

    pub fn is_function_branch(self) -> bool {
        self == Self::FunctionBranch
    }
}
