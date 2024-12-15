use anyhow::{bail, Result};
use unarm::{
    args::{Argument, Reg, Register},
    ParsedIns,
};

#[derive(Clone, Copy, Default, Debug)]
pub enum SecureAreaState {
    #[default]
    Swi,
    Return {
        start: u32,
        function: SwiFunction,
        return_reg: Register,
    },
    ValidFunction(SecureAreaFunction),
}

impl SecureAreaState {
    pub fn handle(self, address: u32, parsed_ins: &ParsedIns) -> Self {
        let args = &parsed_ins.args;
        match self {
            Self::Swi => match (parsed_ins.mnemonic, args[0], args[1]) {
                ("swi", Argument::UImm(interrupt), Argument::None) | ("svc", Argument::UImm(interrupt), Argument::None) => {
                    if let Ok(function) = interrupt.try_into() {
                        Self::Return { start: address, function, return_reg: Register::R0 }
                    } else {
                        Self::default()
                    }
                }
                _ => Self::default(),
            },
            Self::Return { start, function, return_reg } => match (parsed_ins.mnemonic, args[0], args[1], args[2]) {
                ("mov", Argument::Reg(Reg { reg: dest, .. }), Argument::Reg(Reg { reg: src, .. }), Argument::None)
                    if dest == return_reg =>
                {
                    Self::Return { start, function, return_reg: src }
                }
                ("bx", Argument::Reg(Reg { reg: Register::Lr, .. }), Argument::None, Argument::None) => {
                    Self::ValidFunction(SecureAreaFunction { function, return_reg, start, end: address + 2 })
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

    pub fn name(self, return_reg: Register) -> &'static str {
        match (self, return_reg) {
            (Self::SoftReset, _) => "SoftReset",
            (Self::WaitByLoop, _) => "WaitByLoop",
            (Self::IntrWait, _) => "IntrWait",
            (Self::VBlankIntrWait, _) => "VBlankIntrWait",
            (Self::Halt, _) => "Halt",
            (Self::Div, Register::R1) => "Mod",
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
}

impl TryFrom<u32> for SwiFunction {
    type Error = anyhow::Error;

    fn try_from(value: u32) -> Result<Self> {
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
            _ => bail!("unknown interrupt value {value:#x}"),
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct SecureAreaFunction {
    function: SwiFunction,
    return_reg: Register,
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
