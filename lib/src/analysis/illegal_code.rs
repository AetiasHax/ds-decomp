use unarm::{
    Ins, ParsedIns,
    args::{Argument as Arg, OffsetReg, Reg, Register},
};

/// Detects illegal code sequences that never appears in any game.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub enum IllegalCodeState {
    #[default]
    Start,
    ShiftedRegisterValue {
        reg: Register,
    },
    Illegal,
}

impl IllegalCodeState {
    pub fn handle(self, ins: Ins, parsed_ins: &ParsedIns) -> Self {
        if ins.is_illegal() || parsed_ins.is_illegal() {
            return Self::Illegal;
        }

        let args = &parsed_ins.args;
        match (self, ins.mnemonic(), args[0], args[1], args[2]) {
            // Find registers with shifted value
            (_, "lsl", Arg::Reg(Reg { reg, .. }), _, _)
            | (_, "lsls", Arg::Reg(Reg { reg, .. }), _, _)
            | (_, "lsr", Arg::Reg(Reg { reg, .. }), _, _)
            | (_, "lsrs", Arg::Reg(Reg { reg, .. }), _, _)
            | (_, "asr", Arg::Reg(Reg { reg, .. }), _, _)
            | (_, "asrs", Arg::Reg(Reg { reg, .. }), _, _)
            | (_, "ror", Arg::Reg(Reg { reg, .. }), _, _)
            | (_, "rors", Arg::Reg(Reg { reg, .. }), _, _) => Self::ShiftedRegisterValue { reg },

            // Dereferencing shifted registers
            (Self::ShiftedRegisterValue { reg }, "stm", Arg::Reg(Reg { reg: base, .. }), _, _)
            | (Self::ShiftedRegisterValue { reg }, "stmia", Arg::Reg(Reg { reg: base, .. }), _, _)
                if reg == base =>
            {
                Self::Illegal
            }

            // Dereferencing registers offset by the same register
            (_, "str", _, Arg::Reg(Reg { deref: true, reg: base, .. }), Arg::OffsetReg(OffsetReg { reg: offset, .. }))
                if base == offset =>
            {
                Self::Illegal
            }

            _ => Self::default(),
        }
    }

    pub fn is_illegal(self) -> bool {
        self == Self::Illegal
    }
}
