use std::{backtrace::Backtrace, fmt::Display};

use serde::{Deserialize, Serialize};
use snafu::Snafu;
use strum_macros::EnumIter;

use crate::config::ParseContext;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, EnumIter)]
pub enum LinkTimeConst {
    DtcmLo,
    ItcmHi,
    CodeHi,
    OverlayCount,
}

#[derive(Debug, Snafu)]
pub enum LinkTimeConstParseError {
    #[snafu(display(
        "{context}: unknown link-time constant '{value}', must be one of:
        __DTCM_LO, __ITCM_HI, __CODE_HI, __OVERLAY_COUNT:
        {backtrace}"
    ))]
    UnknownKind { context: ParseContext, value: String, backtrace: Backtrace },
}

impl LinkTimeConst {
    pub(crate) fn parse(value: &str, context: &ParseContext) -> Result<Self, LinkTimeConstParseError> {
        match value {
            "__DTCM_LO" => Ok(Self::DtcmLo),
            "__ITCM_HI" => Ok(Self::ItcmHi),
            "__CODE_HI" => Ok(Self::CodeHi),
            "__OVERLAY_COUNT" => Ok(Self::OverlayCount),
            _ => UnknownKindSnafu { context, value }.fail(),
        }
    }
}

impl Display for LinkTimeConst {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkTimeConst::DtcmLo => write!(f, "__DTCM_LO"),
            LinkTimeConst::ItcmHi => write!(f, "__ITCM_HI"),
            LinkTimeConst::CodeHi => write!(f, "__CODE_HI"),
            LinkTimeConst::OverlayCount => write!(f, "__OVERLAY_COUNT"),
        }
    }
}
