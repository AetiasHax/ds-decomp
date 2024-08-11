use unarm::{
    args::{Argument, OffsetImm, Reg, Register, Shift, ShiftImm},
    Ins, ParsedIns,
};

use super::functions::JumpTables;

#[derive(Debug, Clone)]
pub struct JumpTable {
    pub address: u32,
    pub size: u32,
    /// If true, the jump table entries are instructions. Otherwise, they are data.
    pub code: bool,
}

#[derive(Clone, Copy)]
pub enum JumpTableState {
    Arm(JumpTableStateArm),
    Thumb(JumpTableStateThumb),
}

impl JumpTableState {
    pub fn handle(self, address: u32, ins: Ins, parsed_ins: &ParsedIns, jump_tables: &mut JumpTables) -> Self {
        match self {
            Self::Arm(state) => Self::Arm(state.handle(address, ins, parsed_ins, jump_tables)),
            Self::Thumb(state) => Self::Thumb(state.handle(address, ins, parsed_ins, jump_tables)),
        }
    }

    pub fn table_end_address(&self) -> Option<u32> {
        match self {
            Self::Arm(state) => state.table_end_address(),
            Self::Thumb(state) => state.table_end_address(),
        }
    }

    pub fn get_label(&self, address: u32, ins: Ins) -> Option<u32> {
        match self {
            Self::Arm(_) => None,
            Self::Thumb(state) => state.get_label(address, ins),
        }
    }
}

#[derive(Clone, Copy, Default)]
pub enum JumpTableStateArm {
    /// `cmp index, #size`              where `index` is the jump index and `size` is the size of the jump table
    #[default]
    CmpReg,

    /// `...`                           other non-comparing instructions
    /// `addls pc, pc, index, lsl #0x2` jump to nearby branch instruction, OR
    /// `bgt @skip`                     skip jump table if SIGNED index is out of bounds
    JumpOrBranchSigned { index: Register, limit: u32 },

    /// if index is signed:  
    /// `cmp index, #0x0`                check that the index is non-negative
    SignedBaseline { index: Register, limit: u32 },

    /// if index is signed:  
    /// `addge pc, pc, index, lsl #0x2` jump to nearby branch instruction
    JumpSigned { index: Register, limit: u32 },

    /// valid table detected, starts from `table_address` with a size of `limit`
    ValidJumpTable { table_address: u32, limit: u32 },
}

impl JumpTableStateArm {
    fn check_start(self, parsed_ins: &ParsedIns) -> Option<Self> {
        let args = &parsed_ins.args;
        match (parsed_ins.mnemonic, args[0], args[1], args[2]) {
            ("cmp", Argument::Reg(Reg { reg, .. }), Argument::UImm(limit), Argument::None) if limit > 0 => {
                Some(Self::JumpOrBranchSigned { index: reg, limit })
            }
            _ => None,
        }
    }

    fn handle(self, address: u32, ins: Ins, parsed_ins: &ParsedIns, jump_tables: &mut JumpTables) -> Self {
        if let Some(start) = self.check_start(parsed_ins) {
            return start;
        };

        let args = &parsed_ins.args;
        match self {
            Self::CmpReg => match (parsed_ins.mnemonic, args[0], args[1], args[2]) {
                ("cmp", Argument::Reg(Reg { reg, .. }), Argument::UImm(limit), Argument::None) => {
                    Self::JumpOrBranchSigned { index: reg, limit }
                }
                _ => Self::default(),
            },
            Self::JumpOrBranchSigned { index, limit } => {
                match (parsed_ins.mnemonic, args[0], args[1], args[2], args[3], args[4]) {
                    (
                        "addls",
                        Argument::Reg(Reg { reg: Register::Pc, .. }),
                        Argument::Reg(Reg { reg: Register::Pc, .. }),
                        Argument::Reg(Reg { reg, .. }),
                        Argument::ShiftImm(ShiftImm { imm: 2, op: Shift::Lsl }),
                        Argument::None,
                    ) if reg == index => {
                        let table_address = address + 8;
                        let size = (limit + 1) * 4;
                        jump_tables.insert(table_address, JumpTable { address: table_address, size, code: true });
                        Self::ValidJumpTable { table_address: address + 8, limit }
                    }
                    ("bgt", Argument::BranchDest(_), Argument::None, Argument::None, Argument::None, Argument::None) => {
                        Self::SignedBaseline { index, limit }
                    }
                    _ if ins.updates_condition_flags() => Self::default(),
                    _ => self,
                }
            }
            Self::SignedBaseline { index, limit } => match (parsed_ins.mnemonic, args[0], args[1], args[2]) {
                ("cmp", Argument::Reg(Reg { reg, .. }), Argument::UImm(0), Argument::None) if reg == index => {
                    Self::JumpSigned { index, limit }
                }
                _ => Self::default(),
            },
            Self::JumpSigned { index, limit } => match (parsed_ins.mnemonic, args[0], args[1], args[2], args[3], args[4]) {
                (
                    "addge",
                    Argument::Reg(Reg { reg: Register::Pc, .. }),
                    Argument::Reg(Reg { reg: Register::Pc, .. }),
                    Argument::Reg(Reg { reg, .. }),
                    Argument::ShiftImm(ShiftImm { imm: 2, op: Shift::Lsl }),
                    Argument::None,
                ) if reg == index => {
                    let table_address = address + 8;
                    let size = (limit + 1) * 4;
                    jump_tables.insert(table_address, JumpTable { address: table_address, size, code: true });
                    Self::ValidJumpTable { table_address: address + 8, limit }
                }
                _ if ins.updates_condition_flags() => Self::default(),
                _ => self,
            },
            Self::ValidJumpTable { table_address, limit } => {
                let end = table_address + limit * 4;
                if address > end {
                    Self::default()
                } else {
                    self
                }
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
    #[default]
    CmpReg,

    /// `...`                           other non-comparing instructions before the branch  
    /// `bhi @skip`                     skip jump table if index is out of bounds, OR  
    /// `bgt @skip`                     same as above but signed, OR
    /// `bls @jump`                     go to jump table code
    BranchCond { index: Register, limit: u32 },

    /// if [`JumpTableStateThumb::BranchCond`] was bls:  
    /// `b @skip`                       skip jump table
    Branch { index: Register, limit: u32 },

    /// if [`JumpTableStateThumb::BranchCond`] was bgt:
    /// `cmp index, #0`                 check that the index is non-negative, OR
    /// `mov new_index, index`          move index to another register and repeat this state, OR
    /// `sub index, #base`              subtract index to lowest case value
    SignedBaseline { index: Register, limit: u32 },

    /// if [`JumpTableStateThumb::BranchCond`] was bgt:
    /// `blt @skip`                     skip jump table, OR
    /// `bmi @skip`                     same as above but for subtraction
    BranchNegative { index: Register, limit: u32 },

    /// `add offset, index, index`      multiply index by 2 to calculate jump table offset
    AddRegReg { index: Register, limit: u32 },

    /// `add offset, pc`                turn jump table offset into a PC-relative address
    AddRegPc { offset: Register, limit: u32 },

    /// `ldrh jump, [offset, #imm]`     load 16-bit jump value from table
    LoadOffset { offset: Register, limit: u32, pc_base: u32 },

    /// `lsl jump, jump, #0x10`         sign extend
    SignExtendLsl { jump: Register, table_address: u32, limit: u32 },

    /// `asr jump, jump, #0x10`         sign extend
    SignExtendAsr { jump: Register, table_address: u32, limit: u32 },

    /// `add pc, jump`                  do the jump
    AddPcReg { jump: Register, table_address: u32, limit: u32 },

    /// valid table detected, starts from `table_address` with a size of `limit`
    ValidJumpTable { table_address: u32, limit: u32 },
}

impl JumpTableStateThumb {
    fn check_start(self, parsed_ins: &ParsedIns) -> Option<Self> {
        let args = &parsed_ins.args;
        match (parsed_ins.mnemonic, args[0], args[1], args[2]) {
            ("cmp", Argument::Reg(Reg { reg: index, .. }), Argument::UImm(limit), Argument::None) if limit > 0 => {
                Some(Self::BranchCond { index, limit })
            }
            _ => None,
        }
    }

    fn handle(self, address: u32, ins: Ins, parsed_ins: &ParsedIns, jump_tables: &mut JumpTables) -> Self {
        if let Some(start) = self.check_start(parsed_ins) {
            return start;
        };

        let args = &parsed_ins.args;
        match self {
            Self::CmpReg => Self::default(),
            Self::BranchCond { index, limit } => match (parsed_ins.mnemonic, args[0], args[1]) {
                ("bhi", Argument::BranchDest(_), Argument::None) => Self::AddRegReg { index, limit },
                ("bls", Argument::BranchDest(_), Argument::None) => Self::Branch { index, limit },
                ("bgt", Argument::BranchDest(_), Argument::None) => Self::SignedBaseline { index, limit },
                (_, _, _) if ins.updates_condition_flags() => Self::CmpReg,
                _ => self,
            },
            Self::Branch { index, limit } => match (parsed_ins.mnemonic, args[0], args[1]) {
                ("b", Argument::BranchDest(_), Argument::None) => Self::AddRegReg { index, limit },
                _ => Self::default(),
            },
            Self::SignedBaseline { index, limit } => match (parsed_ins.mnemonic, args[0], args[1], args[2]) {
                ("cmp", Argument::Reg(Reg { reg, .. }), Argument::UImm(0), Argument::None) if reg == index => {
                    Self::BranchNegative { index, limit }
                }
                ("mov", Argument::Reg(Reg { reg: dest, .. }), Argument::Reg(Reg { reg: src, .. }), Argument::None)
                    if src == index =>
                {
                    Self::SignedBaseline { index: dest, limit }
                }
                ("sub", Argument::Reg(Reg { reg, .. }), Argument::UImm(base), Argument::None) if reg == index => {
                    Self::BranchNegative { index, limit: limit - base }
                }
                _ => Self::default(),
            },
            Self::BranchNegative { index, limit } => match (parsed_ins.mnemonic, args[0], args[1]) {
                ("blt", Argument::BranchDest(_), Argument::None) => Self::AddRegReg { index, limit },
                ("bmi", Argument::BranchDest(_), Argument::None) => Self::AddRegReg { index, limit },
                _ => Self::default(),
            },
            Self::AddRegReg { index, limit } => match (parsed_ins.mnemonic, args[0], args[1], args[2], args[3]) {
                (
                    "add",
                    Argument::Reg(Reg { reg: table_offset, .. }),
                    Argument::Reg(Reg { reg: a, .. }),
                    Argument::Reg(Reg { reg: b, .. }),
                    Argument::None,
                ) => {
                    if a == index && a == b {
                        Self::AddRegPc { offset: table_offset, limit }
                    } else {
                        Self::default()
                    }
                }
                _ => Self::default(),
            },
            Self::AddRegPc { offset, limit } => match (parsed_ins.mnemonic, args[0], args[1], args[2]) {
                ("add", Argument::Reg(Reg { reg, .. }), Argument::Reg(Reg { reg: Register::Pc, .. }), Argument::None) => {
                    if reg == offset {
                        Self::LoadOffset { offset, limit, pc_base: address }
                    } else {
                        Self::default()
                    }
                }
                _ => Self::default(),
            },
            Self::LoadOffset { offset, limit, pc_base } => match (parsed_ins.mnemonic, args[0], args[1], args[2], args[3]) {
                (
                    "ldrh",
                    Argument::Reg(Reg { reg, .. }),
                    Argument::Reg(Reg { reg: base_reg, deref: true, .. }),
                    Argument::OffsetImm(OffsetImm { post_indexed: false, value }),
                    Argument::None,
                ) if reg == base_reg => {
                    let table_start = (pc_base as i32 - 2 + value) as u32;
                    Self::SignExtendLsl { jump: offset, table_address: table_start, limit }
                }
                _ => Self::default(),
            },
            Self::SignExtendLsl { jump, table_address, limit } => {
                match (parsed_ins.mnemonic, args[0], args[1], args[2], args[3]) {
                    (
                        "lsl",
                        Argument::Reg(Reg { reg: dest_reg, .. }),
                        Argument::Reg(Reg { reg: src_reg, .. }),
                        Argument::UImm(value),
                        Argument::None,
                    ) if dest_reg == src_reg && dest_reg == jump && value == 0x10 => {
                        Self::SignExtendAsr { jump, table_address, limit }
                    }
                    _ => Self::default(),
                }
            }
            Self::SignExtendAsr { jump, table_address, limit } => {
                match (parsed_ins.mnemonic, args[0], args[1], args[2], args[3]) {
                    (
                        "asr",
                        Argument::Reg(Reg { reg: dest_reg, .. }),
                        Argument::Reg(Reg { reg: src_reg, .. }),
                        Argument::UImm(value),
                        Argument::None,
                    ) if dest_reg == src_reg && dest_reg == jump && value == 0x10 => {
                        Self::AddPcReg { jump, table_address, limit }
                    }
                    _ => Self::default(),
                }
            }
            Self::AddPcReg { jump, table_address, limit } => match (parsed_ins.mnemonic, args[0], args[1], args[2]) {
                ("add", Argument::Reg(Reg { reg: Register::Pc, .. }), Argument::Reg(Reg { reg, .. }), Argument::None)
                    if reg == jump =>
                {
                    let size = (limit + 1) * 2;
                    jump_tables.insert(table_address, JumpTable { address: table_address, size, code: false });
                    Self::ValidJumpTable { table_address, limit }
                }
                _ => Self::default(),
            },
            Self::ValidJumpTable { table_address, limit } => {
                let end = table_address + limit * 2;
                if address > end {
                    Self::default()
                } else {
                    self
                }
            }
        }
    }

    pub fn table_end_address(&self) -> Option<u32> {
        match self {
            Self::ValidJumpTable { table_address, limit } => Some(table_address + (limit + 1) * 2),
            _ => None,
        }
    }

    pub fn get_label(&self, address: u32, ins: Ins) -> Option<u32> {
        match self {
            Self::ValidJumpTable { table_address, limit } => {
                let end = table_address + limit * 2;
                if address < *table_address || address > end {
                    None
                } else {
                    Some((*table_address as i32 + ins.code() as i16 as i32 + 2) as u32)
                }
            }
            _ => None,
        }
    }
}
