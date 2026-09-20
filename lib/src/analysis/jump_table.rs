use serde::{Deserialize, Serialize};
use unarm::{
    AddrLdrStr, AddrMiscLoad, Cond, Ins, LdrStrOffset, MiscLoadOffset, Op2, Op2Imm, Op2Shift, Reg,
    ShiftImm, ShiftOp,
};

use super::functions::JumpTables;
use crate::analysis::functions::RegValueSrc;

#[derive(Debug, Clone)]
pub struct JumpTable {
    pub address: u32,
    pub size: u32,
    pub kind: JumpTableKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum JumpTableKind {
    Arm,
    Thumb { kind: ThumbJumpTableKind, jump: ThumbJumpTableJump },
}

#[derive(Clone, Copy, Debug)]
pub enum JumpTableState {
    Arm(JumpTableStateArm),
    Thumb(JumpTableStateThumb),
}

impl JumpTableState {
    pub fn handle(
        self,
        address: u32,
        ins: &Ins,
        jump_tables: &mut JumpTables,
        register_values: &[Option<(u32, RegValueSrc)>; 16],
    ) -> Self {
        match self {
            Self::Arm(state) => Self::Arm(state.handle(address, ins, jump_tables)),
            Self::Thumb(state) => {
                Self::Thumb(state.handle(address, ins, jump_tables, register_values))
            }
        }
    }

    pub fn table_end_address(&self) -> Option<u32> {
        match self {
            Self::Arm(state) => state.table_end_address(),
            Self::Thumb(state) => state.table_end_address(),
        }
    }

    pub fn get_labels(&self, address: u32, ins_code: u16) -> Option<(u32, Option<u32>)> {
        match self {
            Self::Arm(_) => None,
            Self::Thumb(state) => state.get_labels(address, ins_code),
        }
    }

    pub fn is_numerical_jump_offset(&self) -> bool {
        match self {
            Self::Arm(_) => false,
            Self::Thumb(state) => state.is_numerical_jump_offset(),
        }
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub enum JumpTableStateArm {
    /// `cmp index, #size`              where `index` is the jump index and `size` is the size of the jump table
    #[default]
    CmpReg,

    /// `...`                           other non-comparing instructions
    /// `addls pc, pc, index, lsl #0x2` jump to nearby branch instruction, OR
    /// `bgt @skip`                     skip jump table if SIGNED index is out of bounds
    /// `pophi {...}`                   return if index is out of bounds
    JumpOrBranchSigned { index: Reg, limit: u32 },

    /// if index is signed:  
    /// `cmp index, #0x0`               check that the index is non-negative
    SignedBaseline { index: Reg, limit: u32 },

    /// if index is signed:  
    /// `addge pc, pc, index, lsl #0x2` jump to nearby branch instruction
    JumpSigned { index: Reg, limit: u32 },

    /// `add pc, pc, index, lsl #0x2`   jump to nearby branch instruction
    JumpAfterReturn { index: Reg, limit: u32 },

    /// valid table detected, starts from `table_address` with a size of `limit`
    ValidJumpTable { table_address: u32, limit: u32 },
}

impl JumpTableStateArm {
    fn check_start(self, ins: &Ins) -> Option<Self> {
        match ins {
            Ins::Cmp { cond: Cond::Al, rn, op2: Op2::Imm(Op2Imm { imm: limit, .. }) }
                if *limit > 0 =>
            {
                Some(Self::JumpOrBranchSigned { index: *rn, limit: *limit })
            }
            _ => None,
        }
    }

    fn handle(self, address: u32, ins: &Ins, jump_tables: &mut JumpTables) -> Self {
        if let Some(start) = self.check_start(ins) {
            return start;
        };

        match self {
            Self::CmpReg => match ins {
                Ins::Cmp { cond: Cond::Al, rn, op2: Op2::Imm(Op2Imm { imm: limit, .. }) } => {
                    Self::JumpOrBranchSigned { index: *rn, limit: *limit }
                }
                _ => Self::default(),
            },
            Self::JumpOrBranchSigned { index, limit } => match ins {
                Ins::Add {
                    s: false,
                    thumb: _,
                    cond: Cond::Ls,
                    rd: Reg::Pc,
                    rn: Reg::Pc,
                    op2: Op2::ShiftImm(ShiftImm { rm, shift_op: ShiftOp::Lsl, imm: 2 }),
                } if *rm == index => {
                    let table_address = address + 8;
                    let size = (limit + 1) * 4;
                    jump_tables.insert(table_address, JumpTable {
                        address: table_address,
                        size,
                        kind: JumpTableKind::Arm,
                    });
                    Self::ValidJumpTable { table_address: address + 8, limit }
                }
                Ins::B { cond: Cond::Gt, target: _ } => Self::SignedBaseline { index, limit },
                Ins::Pop { cond: Cond::Hi, regs: _ } => Self::JumpAfterReturn { index, limit },
                _ if ins.updates_condition_flags() => Self::default(),
                _ => self,
            },
            Self::SignedBaseline { index, limit } => match ins {
                Ins::Cmp { cond: Cond::Al, rn, op2: Op2::Imm(Op2Imm { imm: 0, .. }) }
                    if *rn == index =>
                {
                    Self::JumpSigned { index, limit }
                }
                _ => Self::default(),
            },
            Self::JumpSigned { index, limit } => match ins {
                Ins::Add {
                    s: false,
                    thumb: _,
                    cond: Cond::Ge,
                    rd: Reg::Pc,
                    rn: Reg::Pc,
                    op2: Op2::ShiftImm(ShiftImm { rm, shift_op: ShiftOp::Lsl, imm: 2 }),
                } if *rm == index => {
                    let table_address = address + 8;
                    let size = (limit + 1) * 4;
                    jump_tables.insert(table_address, JumpTable {
                        address: table_address,
                        size,
                        kind: JumpTableKind::Arm,
                    });
                    Self::ValidJumpTable { table_address: address + 8, limit }
                }
                _ if ins.updates_condition_flags() => Self::default(),
                _ => self,
            },
            Self::JumpAfterReturn { index, limit } => match ins {
                Ins::Add {
                    s: false,
                    thumb: _,
                    cond: Cond::Al,
                    rd: Reg::Pc,
                    rn: Reg::Pc,
                    op2: Op2::ShiftImm(ShiftImm { rm, shift_op: ShiftOp::Lsl, imm: 2 }),
                } if *rm == index => {
                    let table_address = address + 8;
                    let size = (limit + 1) * 4;
                    jump_tables.insert(table_address, JumpTable {
                        address: table_address,
                        size,
                        kind: JumpTableKind::Arm,
                    });
                    Self::ValidJumpTable { table_address: address + 8, limit }
                }
                _ if ins.updates_condition_flags() => Self::default(),
                _ => self,
            },
            Self::ValidJumpTable { table_address, limit } => {
                let end = table_address + limit * 4;
                if address > end { Self::default() } else { self }
            }
        }
    }

    pub fn table_end_address(&self) -> Option<u32> {
        match self {
            Self::ValidJumpTable { table_address, limit } => Some(table_address + (limit + 1) * 4),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Default, Debug)]
pub enum JumpTableStateThumb {
    /// `cmp index, #size`              where `index` is the jump index and `size` is the size of the jump table
    /// `cmp index, size`               when the table size is loaded from a pool constant
    #[default]
    CmpReg,

    /// `...`                           other non-comparing instructions before the branch  
    /// `bhi @skip`                     skip jump table if index is out of bounds, OR  
    /// `bgt @skip`                     same as above but signed, OR
    /// `bls @jump`                     go to jump table code
    BranchCond { index: Reg, limit: u32 },

    /// if [`JumpTableStateThumb::BranchCond`] was bls:
    /// or [`JumpTableStateThumb::BranchNegative`] was bge:
    /// `b @skip`                       skip jump table
    /// `bl @skip`                      skip jump table using long branch
    Branch { index: Reg, limit: u32 },

    /// if [`JumpTableStateThumb::BranchCond`] was bgt:
    /// `cmp index, #0`                 check that the index is non-negative, OR
    /// `mov new_index, index`          move index to another register and repeat this state, OR
    /// `sub index, #base`              subtract index to lowest case value
    SignedBaseline { index: Reg, limit: u32 },

    /// if [`JumpTableStateThumb::BranchCond`] was bgt:
    /// `blt @skip`                     skip jump table, OR
    /// `bmi @skip`                     same as above but for subtraction
    BranchNegative { index: Reg, limit: u32 },

    /// `add offset, index, index`      multiply index by 2 to calculate jump table offset
    /// `mov offset, index`             multiply index by 1 (8-bit table items)
    AddRegReg { index: Reg, limit: u32 },

    /// `add offset, pc`                turn jump table offset into a PC-relative address
    AddRegPc { offset: Reg, limit: u32 },

    /// `ldrh jump, [offset, #imm]`     load 16-bit jump value from table
    /// `ldrb jump, [offset, #imm]`     load 8-bit jump value from table
    LoadOffset { offset: Reg, limit: u32, pc_base: u32 },

    /// `lsl jump, jump, #0x10`         sign extend
    SignExtendLsl { jump: Reg, table_address: u32, limit: u32, kind: ThumbJumpTableKind },

    /// `asr jump, jump, #0x10`         sign extend
    SignExtendAsr { jump: Reg, table_address: u32, limit: u32, kind: ThumbJumpTableKind },

    /// `add pc, jump`                  do the jump
    /// `add jump, pc`                  calculate the jump destination
    AddPcReg { jump: Reg, table_address: u32, limit: u32, kind: ThumbJumpTableKind },

    /// `bx jump`                       jump to the destination
    BxJump { jump: Reg, table_address: u32, limit: u32, kind: ThumbJumpTableKind },

    /// valid table detected, starts from `table_address` with a size of `limit`
    ValidJumpTable {
        table_address: u32,
        limit: u32,
        kind: ThumbJumpTableKind,
        jump: ThumbJumpTableJump,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThumbJumpTableKind {
    Halfword,
    Byte,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ThumbJumpTableJump {
    AddPc,
    Bx,
}

impl JumpTableStateThumb {
    fn check_start(
        self,
        ins: &Ins,
        register_values: &[Option<(u32, RegValueSrc)>; 16],
    ) -> Option<Self> {
        match ins {
            Ins::Cmp { cond: Cond::Al, rn, op2: Op2::Imm(Op2Imm { imm: limit, .. }) }
                if *limit > 0 =>
            {
                Some(Self::BranchCond { index: *rn, limit: *limit })
            }
            Ins::Cmp { cond: Cond::Al, rn, op2: Op2::ShiftImm(ShiftImm { rm, imm: 0, .. }) } => {
                // If the jump table is large enough, the limit gets loaded from a pool constant
                let (limit, _) = register_values[*rm as usize]?;
                (limit > 0).then_some(Self::BranchCond { index: *rn, limit })
            }
            _ => None,
        }
    }

    fn handle(
        self,
        address: u32,
        ins: &Ins,
        jump_tables: &mut JumpTables,
        register_values: &[Option<(u32, RegValueSrc)>; 16],
    ) -> Self {
        if let Some(end_address) = self.table_end_address()
            && address < end_address
        {
        } else if let Some(start) = self.check_start(ins, register_values) {
            return start;
        }

        match self {
            Self::CmpReg => Self::default(),
            Self::BranchCond { index, limit } => match ins {
                Ins::B { cond: Cond::Hi, target: _ } => Self::AddRegReg { index, limit },
                Ins::B { cond: Cond::Ls, target: _ } => Self::Branch { index, limit },
                Ins::B { cond: Cond::Gt, target: _ } => Self::SignedBaseline { index, limit },
                _ if ins.updates_condition_flags() => Self::default(),
                _ => self,
            },
            Self::Branch { index, limit } => match ins {
                Ins::B { cond: Cond::Al, target: _ } => Self::AddRegReg { index, limit },
                // Long branch when `b` is out of range
                Ins::Bl { cond: Cond::Al, target: _ } => Self::AddRegReg { index, limit },
                _ => Self::default(),
            },
            Self::SignedBaseline { index, limit } => match ins {
                Ins::Cmp { cond: Cond::Al, rn, op2: Op2::Imm(Op2Imm { imm: 0, .. }) }
                    if *rn == index =>
                {
                    Self::BranchNegative { index: *rn, limit }
                }
                Ins::Mov {
                    s: _,
                    thumb: _,
                    cond: Cond::Al,
                    rd,
                    op2: Op2::ShiftImm(ShiftImm { rm: src_reg, shift_op: _, imm: 0 }),
                }
                | Ins::Add {
                    s: _,
                    thumb: _,
                    cond: Cond::Al,
                    rd,
                    rn: src_reg,
                    op2: Op2::Imm(Op2Imm { imm: 0, rotate_imm: _ }),
                } if *src_reg == index => Self::SignedBaseline { index: *rd, limit },
                Ins::Sub {
                    s: _,
                    thumb: _,
                    cond: Cond::Al,
                    rd,
                    rn,
                    op2: Op2::Imm(Op2Imm { imm: base, rotate_imm: _ }),
                } if *rd == *rn && *rn == index => {
                    Self::SignedBaseline { index, limit: limit - base }
                }
                _ => Self::default(),
            },
            Self::BranchNegative { index, limit } => match ins {
                Ins::B { cond: Cond::Lt, target: _ } => Self::AddRegReg { index, limit },
                Ins::B { cond: Cond::Mi, target: _ } => Self::AddRegReg { index, limit },
                Ins::B { cond: Cond::Ge, target: _ } => Self::Branch { index, limit },
                _ => Self::default(),
            },
            Self::AddRegReg { index, limit } => match ins {
                Ins::Add {
                    s: _,
                    thumb: _,
                    cond: Cond::Al,
                    rd,
                    rn,
                    op2: Op2::ShiftImm(ShiftImm { rm, shift_op: _, imm: 0 }),
                } => {
                    if *rn == index && *rn == *rm {
                        Self::AddRegPc { offset: *rd, limit }
                    } else {
                        Self::default()
                    }
                }
                Ins::Mov {
                    s: _,
                    thumb: _,
                    cond: Cond::Al,
                    rd,
                    op2: Op2::ShiftImm(ShiftImm { rm: src_reg, shift_op: _, imm: 0 }),
                }
                | Ins::Add {
                    s: _,
                    thumb: _,
                    cond: Cond::Al,
                    rd,
                    rn: src_reg,
                    op2: Op2::Imm(Op2Imm { imm: 0, rotate_imm: _ }),
                } => {
                    if *src_reg == index {
                        Self::AddRegPc { offset: *rd, limit }
                    } else {
                        Self::default()
                    }
                }
                _ => Self::default(),
            },
            Self::AddRegPc { offset, limit } => match ins {
                Ins::Add {
                    s: _,
                    thumb: _,
                    cond: Cond::Al,
                    rd,
                    rn,
                    op2: Op2::ShiftImm(ShiftImm { rm: Reg::Pc, shift_op: _, imm: 0 }),
                } if *rd == *rn => {
                    if *rn == offset {
                        Self::LoadOffset { offset, limit, pc_base: address }
                    } else {
                        Self::default()
                    }
                }
                _ => Self::default(),
            },
            Self::LoadOffset { offset, limit, pc_base } => match ins {
                Ins::Ldrh {
                    cond: Cond::Al,
                    rd,
                    addr:
                        AddrMiscLoad::Pre { rn, offset: MiscLoadOffset::Imm(value), writeback: false },
                } if *rd == *rn => {
                    let table_start = (pc_base as i32 - 2 + value * 2) as u32;
                    Self::SignExtendLsl {
                        jump: offset,
                        table_address: table_start,
                        limit,
                        kind: ThumbJumpTableKind::Halfword,
                    }
                }
                Ins::Ldrb {
                    cond: Cond::Al,
                    rd,
                    addr: AddrLdrStr::Pre { rn, offset: LdrStrOffset::Imm(value), writeback: false },
                } if *rd == *rn => {
                    let table_start = (pc_base as i32 - 2 + value * 2) as u32;
                    Self::SignExtendLsl {
                        jump: offset,
                        table_address: table_start,
                        limit,
                        kind: ThumbJumpTableKind::Byte,
                    }
                }
                _ => Self::default(),
            },
            Self::SignExtendLsl { jump, table_address, limit, kind } => match ins {
                Ins::Lsl { s: _, thumb: _, cond: Cond::Al, rd, rn, op2: Op2Shift::Imm(value) }
                    if *rd == *rn && *rd == jump && *value == 0x10 =>
                {
                    Self::SignExtendAsr { jump, table_address, limit, kind }
                }
                _ => Self::default(),
            },
            Self::SignExtendAsr { jump, table_address, limit, kind } => match ins {
                Ins::Asr { s: _, thumb: _, cond: Cond::Al, rd, rn, op2: Op2Shift::Imm(value) }
                    if *rd == *rn && *rd == jump && *value == 0x10 =>
                {
                    Self::AddPcReg { jump, table_address, limit, kind }
                }
                _ => Self::default(),
            },
            Self::AddPcReg { jump, table_address, limit, kind } => match ins {
                Ins::Add {
                    s: _,
                    thumb: _,
                    cond: Cond::Al,
                    rd: Reg::Pc,
                    rn: Reg::Pc,
                    op2: Op2::ShiftImm(ShiftImm { rm, shift_op: _, imm: 0 }),
                } if *rm == jump => {
                    let size = (limit + 1) * kind.item_size();
                    let jump = ThumbJumpTableJump::AddPc;
                    jump_tables.insert(table_address, JumpTable {
                        address: table_address,
                        size,
                        kind: JumpTableKind::Thumb { kind, jump },
                    });
                    Self::ValidJumpTable { table_address, limit, kind, jump }
                }
                Ins::Add {
                    s: _,
                    thumb: _,
                    cond: Cond::Al,
                    rd,
                    rn,
                    op2: Op2::ShiftImm(ShiftImm { rm: Reg::Pc, shift_op: _, imm: 0 }),
                } if *rd == *rn && *rn == jump => Self::BxJump { jump, table_address, limit, kind },
                _ => Self::default(),
            },
            Self::BxJump { jump, table_address, limit, kind } => match ins {
                Ins::Bx { cond: Cond::Al, rm } if *rm == jump => {
                    let table_address = table_address - 2;
                    let size = (limit + 1) * kind.item_size();
                    let jump = ThumbJumpTableJump::Bx;
                    jump_tables.insert(table_address, JumpTable {
                        address: table_address,
                        size,
                        kind: JumpTableKind::Thumb { kind, jump },
                    });
                    Self::ValidJumpTable { table_address, limit, kind, jump }
                }
                _ => Self::default(),
            },
            Self::ValidJumpTable { table_address, limit, kind, jump: _ } => {
                let end = table_address + (limit + 1) * kind.item_size();
                if address >= end { Self::default() } else { self }
            }
        }
    }

    pub fn table_end_address(&self) -> Option<u32> {
        match self {
            Self::ValidJumpTable { table_address, limit, kind, jump: _ } => {
                Some(table_address + (limit + 1) * kind.item_size())
            }
            _ => None,
        }
    }

    pub fn get_labels(&self, address: u32, ins_code: u16) -> Option<(u32, Option<u32>)> {
        match self {
            Self::ValidJumpTable { table_address, limit, kind, jump } => {
                let end = table_address + limit * kind.item_size();
                if address < *table_address || address > end {
                    None
                } else {
                    let pc_offset = match jump {
                        ThumbJumpTableJump::AddPc => 2,
                        ThumbJumpTableJump::Bx => 0,
                    };
                    let label_base = (table_address + pc_offset) as i32;
                    let jump_offset = ins_code as i16;
                    match kind {
                        ThumbJumpTableKind::Halfword => {
                            Some(((label_base + jump_offset as i32) as u32 & !1, None))
                        }
                        ThumbJumpTableKind::Byte => {
                            let [first_offset, second_offset] = jump_offset.to_le_bytes();
                            let first_value = first_offset as i8 as i32;
                            let second_value = second_offset as i8 as i32;
                            Some((
                                (label_base + first_value) as u32 & !1,
                                Some((label_base + second_value) as u32 & !1),
                            ))
                        }
                    }
                }
            }
            _ => None,
        }
    }

    pub fn is_numerical_jump_offset(&self) -> bool {
        matches!(self, JumpTableStateThumb::ValidJumpTable { .. })
    }
}

impl ThumbJumpTableKind {
    fn item_size(self) -> u32 {
        match self {
            ThumbJumpTableKind::Halfword => 2,
            ThumbJumpTableKind::Byte => 1,
        }
    }
}
