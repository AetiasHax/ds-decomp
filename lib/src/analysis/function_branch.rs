use unarm::{AddrLdrStr, Cond, Ins, Op2, Reg, ShiftImm};

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
    LdrIpPc,
    AddR0Ip,
    FunctionBranch,
}

impl FunctionBranchState {
    pub fn handle(self, ins: &Ins) -> Self {
        match self {
            Self::Start => match ins {
                // eors *, *, *
                Ins::Eor { s: true, cond: Cond::Al, .. } => Self::Eors,
                // movge pc, lr
                Ins::Mov {
                    s: false,
                    cond: Cond::Ge,
                    rd: Reg::Pc,
                    op2: Op2::ShiftImm(ShiftImm { rm: Reg::Lr, imm: 0, .. }),
                    ..
                } => Self::MovgePcLr,
                // mov *, sp
                Ins::Mov {
                    s: false,
                    cond: Cond::Al,
                    op2: Op2::ShiftImm(ShiftImm { rm: Reg::Sp, imm: 0, .. }),
                    ..
                } => Self::MovFromSp,
                // ldr ip, [pc, *]
                Ins::Ldr {
                    cond: Cond::Al,
                    rd: Reg::R12,
                    addr: AddrLdrStr::Pre { rn: Reg::Pc, .. },
                } => Self::LdrIpPc,
                _ => Self::default(),
            },
            Self::Eors => match ins {
                // bmi *
                Ins::B { cond: Cond::Mi, target: _ } => Self::FunctionBranch,
                _ if ins.updates_condition_flags() => Self::default(),
                _ => self,
            },
            Self::MovgePcLr | Self::MovFromSp | Self::AddR0Ip => match ins {
                // b *
                Ins::B { cond: Cond::Al, target: _ } => Self::FunctionBranch,
                _ => Self::default(),
            },
            Self::LdrIpPc => match ins {
                // add r0, r0, ip
                Ins::Add {
                    s: false,
                    cond: Cond::Al,
                    rd: Reg::R0,
                    rn: Reg::R0,
                    op2: Op2::ShiftImm(ShiftImm { rm: Reg::R12, imm: 0, .. }),
                    ..
                } => Self::AddR0Ip,
                _ => Self::default(),
            },
            Self::FunctionBranch => Self::default(),
        }
    }

    pub fn is_function_branch(self) -> bool {
        self == Self::FunctionBranch
    }
}
