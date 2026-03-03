use std::{backtrace::Backtrace, fmt::Display};

use serde::{Deserialize, Serialize};
use snafu::Snafu;
use strum_macros::EnumIter;

use crate::config::ParseContext;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, EnumIter)]
pub enum LinkerVar {
    DtcmLo,
    ItcmHi,
    CodeHi,
    OverlayCount,
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum LinkerVarParseError {
    #[snafu(display(
        "{context}: unknown linker variable '{value}', must be one of:
        __DTCM_LO, __ITCM_HI, __CODE_HI, __OVERLAY_COUNT:
        {backtrace}"
    ))]
    UnknownKind { context: ParseContext, value: String, backtrace: Backtrace },
}

impl LinkerVar {
    pub(crate) fn parse(value: &str, context: &ParseContext) -> Result<Self, LinkerVarParseError> {
        match value {
            "__DTCM_LO" => Ok(Self::DtcmLo),
            "__ITCM_HI" => Ok(Self::ItcmHi),
            "__CODE_HI" => Ok(Self::CodeHi),
            "__OVERLAY_COUNT" => Ok(Self::OverlayCount),
            _ => linker_var_parse_error::UnknownKindSnafu { context, value }.fail(),
        }
    }
}

impl Display for LinkerVar {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkerVar::DtcmLo => write!(f, "__DTCM_LO"),
            LinkerVar::ItcmHi => write!(f, "__ITCM_HI"),
            LinkerVar::CodeHi => write!(f, "__CODE_HI"),
            LinkerVar::OverlayCount => write!(f, "__OVERLAY_COUNT"),
        }
    }
}
