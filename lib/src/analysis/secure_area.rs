use snafu::Snafu;
use unarm::{Cond, Ins, Op2, Op2Imm, Reg};

#[derive(Clone, Copy, Default, Debug)]
pub enum SecureAreaState {
    #[default]
    Start,
    Arg {
        start: u32,
    },
    Return {
        start: u32,
        function: SwiFunction,
        return_reg: Reg,
    },
    ValidFunction(SecureAreaFunction),
}

impl SecureAreaState {
    pub fn handle(self, address: u32, ins: &Ins) -> Self {
        match self {
            Self::Start => match ins {
                Ins::Svc { cond: Cond::Al, imm: interrupt } => {
                    if let Ok(function) = SwiFunction::try_from(*interrupt) {
                        Self::Return { start: address, function, return_reg: Reg::R0 }
                    } else {
                        Self::default()
                    }
                }
                Ins::Mov { s: _, thumb: _, cond: Cond::Al, rd: _, op2: Op2::Imm(_) } => {
                    Self::Arg { start: address }
                }
                _ => Self::default(),
            },
            Self::Arg { start } => match ins {
                Ins::Svc { cond: Cond::Al, imm: interrupt } => {
                    if let Ok(function) = SwiFunction::try_from(*interrupt) {
                        if function.allows_arg() {
                            Self::Return { start, function, return_reg: Reg::R0 }
                        } else {
                            // Ignore the mov
                            Self::Return { start: address, function, return_reg: Reg::R0 }
                        }
                    } else {
                        Self::default()
                    }
                }
                _ => Self::default(),
            },
            Self::Return { start, function, return_reg } => match ins {
                Ins::Add {
                    s: _,
                    thumb: _,
                    cond: Cond::Al,
                    rd,
                    rn,
                    op2: Op2::Imm(Op2Imm { imm: 0, rotate_imm: _ }),
                } if *rd == return_reg => Self::Return { start, function, return_reg: *rn },
                Ins::Bx { cond: Cond::Al, rm: Reg::Lr } => {
                    Self::ValidFunction(SecureAreaFunction {
                        function,
                        return_reg,
                        start,
                        end: address + 2,
                    })
                }
                _ => Self::default(),
            },
            Self::ValidFunction { .. } => Self::default(),
        }
    }

    pub fn get_function(self) -> Option<SecureAreaFunction> {
        let Self::ValidFunction(function) = self else { return None };
        Some(function)
    }
}

#[derive(Clone, Copy, Debug)]
pub enum SwiFunction {
    SoftReset,
    WaitByLoop,
    IntrWait,
    VBlankIntrWait,
    Halt,
    Div,
    Mod,
    CpuSet,
    CpuFastSet,
    Sqrt,
    GetCRC16,
    IsDebugger,
    BitUnPack,
    LZ77UnCompReadNormalWrite8bit,
    LZ77UnCompReadByCallbackWrite16bit,
    HuffUnCompReadByCallback,
    RLUnCompReadNormalWrite8bit,
    RLUnCompReadByCallbackWrite16bit,
}

impl SwiFunction {
    pub fn interrupt_value(self) -> u32 {
        match self {
            Self::SoftReset => 0x0,
            Self::WaitByLoop => 0x3,
            Self::IntrWait => 0x4,
            Self::VBlankIntrWait => 0x5,
            Self::Halt => 0x6,
            Self::Div | Self::Mod => 0x9,
            Self::CpuSet => 0xb,
            Self::CpuFastSet => 0xc,
            Self::Sqrt => 0xd,
            Self::GetCRC16 => 0xe,
            Self::IsDebugger => 0xf,
            Self::BitUnPack => 0x10,
            Self::LZ77UnCompReadNormalWrite8bit => 0x11,
            Self::LZ77UnCompReadByCallbackWrite16bit => 0x12,
            Self::HuffUnCompReadByCallback => 0x13,
            Self::RLUnCompReadNormalWrite8bit => 0x14,
            Self::RLUnCompReadByCallbackWrite16bit => 0x15,
        }
    }

    pub fn name(self, return_reg: Reg) -> &'static str {
        match (self, return_reg) {
            (Self::SoftReset, _) => "SoftReset",
            (Self::WaitByLoop, _) => "WaitByLoop",
            (Self::IntrWait, _) => "IntrWait",
            (Self::VBlankIntrWait, _) => "VBlankIntrWait",
            (Self::Halt, _) => "Halt",
            (Self::Div, Reg::R1) => "Mod",
            (Self::Div, _) => "Div",
            (Self::Mod, _) => "Mod",
            (Self::CpuSet, _) => "CpuSet",
            (Self::CpuFastSet, _) => "CpuFastSet",
            (Self::Sqrt, _) => "Sqrt",
            (Self::GetCRC16, _) => "GetCRC16",
            (Self::IsDebugger, _) => "IsDebugger",
            (Self::BitUnPack, _) => "BitUnPack",
            (Self::LZ77UnCompReadNormalWrite8bit, _) => "LZ77UnCompReadNormalWrite8bit",
            (Self::LZ77UnCompReadByCallbackWrite16bit, _) => "LZ77UnCompReadByCallbackWrite16bit",
            (Self::HuffUnCompReadByCallback, _) => "HuffUnCompReadByCallback",
            (Self::RLUnCompReadNormalWrite8bit, _) => "RLUnCompReadNormalWrite8bit",
            (Self::RLUnCompReadByCallbackWrite16bit, _) => "RLUnCompReadByCallbackWrite16bit",
        }
    }

    pub fn allows_arg(self) -> bool {
        matches!(self, Self::VBlankIntrWait)
    }
}

#[derive(Debug, Snafu)]
pub enum IntoSwiFunctionError {
    #[snafu(display("unknown interrupt value {value:#x}"))]
    UnknownInterrupt { value: u32 },
}

impl TryFrom<u32> for SwiFunction {
    type Error = IntoSwiFunctionError;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            0x0 => Ok(Self::SoftReset),
            0x3 => Ok(Self::WaitByLoop),
            0x4 => Ok(Self::IntrWait),
            0x5 => Ok(Self::VBlankIntrWait),
            0x6 => Ok(Self::Halt),
            0x9 => Ok(Self::Div),
            0xb => Ok(Self::CpuSet),
            0xc => Ok(Self::CpuFastSet),
            0xd => Ok(Self::Sqrt),
            0xe => Ok(Self::GetCRC16),
            0xf => Ok(Self::IsDebugger),
            0x10 => Ok(Self::BitUnPack),
            0x11 => Ok(Self::LZ77UnCompReadNormalWrite8bit),
            0x12 => Ok(Self::LZ77UnCompReadByCallbackWrite16bit),
            0x13 => Ok(Self::HuffUnCompReadByCallback),
            0x14 => Ok(Self::RLUnCompReadNormalWrite8bit),
            0x15 => Ok(Self::RLUnCompReadByCallbackWrite16bit),
            _ => UnknownInterruptSnafu { value }.fail(),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SecureAreaFunction {
    function: SwiFunction,
    return_reg: Reg,
    start: u32,
    end: u32,
}

impl SecureAreaFunction {
    pub fn name(&self) -> &'static str {
        self.function.name(self.return_reg)
    }

    pub fn start(&self) -> u32 {
        self.start
    }

    pub fn end(&self) -> u32 {
        self.end
    }
}
