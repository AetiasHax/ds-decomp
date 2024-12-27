use ds_decomp_config::config::symbol::SymData;
use unarm::{
    args::{Argument, Reg, Register, Shift, ShiftImm},
    ParsedIns,
};

/// Inline tables refer to data tables that exist within a function. They probably only exist for assembly functions and would
/// not be generated from C/C++. We need to detect them so the function boundary detector does not run into "illegal"
/// instructions within these tables.
///
/// This implementation is somewhat hardcoded, as it not always simple to calculate the size of the table. Instead, we're
/// assuming the table size based on unusual (assembly-like) instruction patterns associated with the inline tables.
#[derive(Clone, Copy, Default, Debug)]
pub enum InlineTableState {
    #[default]
    Start,
    SubPc {
        table_base: Register,
        table_address: u32,
        size: u32,
    },
    ValidTable(InlineTable),
}

impl InlineTableState {
    pub fn handle(self, thumb: bool, address: u32, parsed_ins: &ParsedIns) -> Self {
        let args = &parsed_ins.args;
        match self {
            Self::Start => match (parsed_ins.mnemonic, args[0], args[1], args[2], args[3]) {
                (
                    "sub",
                    Argument::Reg(Reg { reg, .. }),
                    Argument::Reg(Reg { reg: Register::Pc, .. }),
                    Argument::UImm(offset),
                    Argument::None,
                ) => Self::SubPc {
                    table_base: reg,
                    table_address: 0x100 + address - offset + if thumb { 4 } else { 8 },
                    size: 0x100,
                },
                _ => Self::default(),
            },
            Self::SubPc { table_base, table_address, size } => {
                match (parsed_ins.mnemonic, args[0], args[1], args[2], args[3], args[4]) {
                    (
                        "ldrb",
                        Argument::Reg(Reg { .. }),
                        Argument::Reg(Reg { deref: true, reg, .. }),
                        Argument::OffsetReg(_),
                        Argument::ShiftImm(ShiftImm { op: Shift::Lsr, .. }),
                        Argument::None,
                    ) if reg == table_base => {
                        Self::ValidTable(InlineTable { address: table_address, size, kind: InlineTableKind::Byte })
                    }
                    _ => Self::default(),
                }
            }
            Self::ValidTable(_) => Self::default(),
        }
    }

    pub fn get_table(self) -> Option<InlineTable> {
        let Self::ValidTable(table) = self else { return None };
        Some(table)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct InlineTable {
    pub address: u32,
    pub size: u32,
    pub kind: InlineTableKind,
}

impl InlineTable {
    pub fn count(&self) -> u32 {
        self.size / self.kind.size()
    }
}

impl From<InlineTable> for SymData {
    fn from(val: InlineTable) -> Self {
        match val.kind {
            InlineTableKind::Byte => SymData::Byte { count: Some(val.count()) },
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum InlineTableKind {
    Byte,
}

impl InlineTableKind {
    pub fn size(self) -> u32 {
        match self {
            Self::Byte => 1,
        }
    }
}
