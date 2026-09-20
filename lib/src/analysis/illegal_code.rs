use unarm::{Ins, LdrStrOffset, Op2, Reg, ShiftImm};

/// Detects illegal code sequences that never appears in any game.
#[derive(Clone, Copy, Default, PartialEq, Eq, Debug)]
pub enum IllegalCodeState {
    #[default]
    Start,
    ShiftedRegisterValue {
        reg: Reg,
    },
    Illegal {
        reason: &'static str,
    },
}

impl IllegalCodeState {
    pub fn handle(self, ins: &Ins, thumb: bool) -> Self {
        if thumb
            && let Ins::Mov {
                rd: Reg::R0,
                op2: Op2::ShiftImm(ShiftImm { rm: Reg::R0, imm: 0, .. }),
                ..
            } = ins
        {
            // In Thumb with unified syntax, 0000 disassembles into movs r0, r0 and is a no-op
            return Self::Illegal { reason: "Thumb no-op 'lsl r0, r0, #0' or 0000 in hex" };
        }

        match (self, ins) {
            (_, Ins::Illegal) => Self::Illegal { reason: "illegal opcode" },

            // Find registers with shifted value
            (_, Ins::Lsl { s: _, thumb: _, cond: _, rd, rn: _, op2: _ })
            | (_, Ins::Lsr { s: _, thumb: _, cond: _, rd, rn: _, op2: _ })
            | (_, Ins::Asr { s: _, thumb: _, cond: _, rd, rn: _, op2: _ })
            | (_, Ins::Ror { s: _, thumb: _, cond: _, rd, rn: _, op2: _ }) => {
                Self::ShiftedRegisterValue { reg: *rd }
            }

            // Dereferencing shifted registers
            (
                Self::ShiftedRegisterValue { reg },
                Ins::Stm { mode: _, cond: _, rn, writeback: _, regs: _, user_mode: _ },
            ) if reg == *rn => Self::Illegal { reason: "dereferencing shifted registers" },

            // Dereferencing registers offset by the same register
            (_, Ins::Str { cond: _, rd: _, addr })
                if let LdrStrOffset::Reg { rm, .. } = addr.offset()
                    && addr.rn() == rm =>
            {
                Self::Illegal { reason: "dereferencing registers offset by itself" }
            }

            // Reading from PC into PC
            (_, Ins::Ldm { mode: _, cond: _, rn: Reg::Pc, writeback: _, regs, user_mode: _ })
                if regs.contains(Reg::Pc) =>
            {
                Self::Illegal { reason: "reading from PC into PC" }
            }

            _ => Self::default(),
        }
    }
}

pub const ILLEGAL_CODE_PATTERNS: &[&[u8]] = &[&[0x00, 0x02, 0x03, 0x00, 0x04, 0x00, 0x00, 0x00]];
