use std::backtrace::Backtrace;

use bytemuck::{Pod, Zeroable};
use ds_rom::rom::{Arm9, Autoload, raw::RawBuildInfoError};
use snafu::Snafu;

use crate::{config::section::SectionCodeError, util::bytes::FromSlice};

pub struct ExceptionData {
    exception_start: Option<u32>,
    exceptix_start: u32,
    exceptix_end: u32,
}

struct GetExceptixFunction {
    code: &'static [u8],
    // Offset of pool constants to the start and end of .exceptix
    start_offset: u32,
    end_offset: u32,
}

const GET_EXCEPTIX_FUNCTIONS: [GetExceptixFunction; 1] = [GetExceptixFunction {
    code: &[
        0x10, 0x20, 0x9f, 0xe5, // ldr r2, [pc, #0x10]
        0x10, 0x10, 0x9f, 0xe5, // ldr r1, [pc, #0x10]
        0x0c, 0x20, 0x80, 0xe5, // str r2, [r0, #0xc]
        0x10, 0x10, 0x80, 0xe5, // str r1, [r0, #0x10]
        0x01, 0x00, 0xa0, 0xe3, // mov r0, #1
        0x1e, 0xff, 0x2f, 0xe1, // bx lr
    ],
    start_offset: 0x18,
    end_offset: 0x1c,
}];

#[repr(C)]
#[derive(Zeroable, Pod, Clone, Copy)]
struct ExceptionTableEntry {
    function_start: u32,
    function_length: u32,
    /// This is a pointer if `(function_length & 1) == 0`, otherwise it's the whole exception record.
    exception_record: u32,
}

impl ExceptionTableEntry {
    pub fn has_long_exception_record(&self) -> bool {
        self.function_length & 1 == 0
    }

    pub fn exception_record_pointer(&self) -> Option<u32> {
        self.has_long_exception_record().then_some(self.exception_record)
    }
}

#[derive(Debug, Snafu)]
pub enum ExceptionDataError {
    #[snafu(display("Failed to cast data to exception table entry: {}\n{}", error, backtrace))]
    PodCastError { error: bytemuck::PodCastError, backtrace: Backtrace },
    #[snafu(transparent)]
    SectionCode { source: SectionCodeError },
    #[snafu(transparent)]
    DsRomBuildInfo { source: RawBuildInfoError },
}

impl ExceptionData {
    pub fn analyze(arm9: &Arm9, unknown_autoloads: &[&Autoload]) -> Result<Option<Self>, ExceptionDataError> {
        let arm9_code = arm9.code()?;

        let mut exceptix_result = Self::find_get_exceptix_function(arm9_code, arm9.base_address())?;
        if exceptix_result.is_none() {
            for autoload in unknown_autoloads {
                exceptix_result = Self::find_get_exceptix_function(autoload.code(), autoload.base_address())?;
                if exceptix_result.is_some() {
                    break;
                }
            }
        }

        let Some((exceptix_start, exceptix_end)) = exceptix_result else {
            return Ok(None);
        };

        let base_address = arm9.base_address();
        let start = (exceptix_start - base_address) as usize;
        let end = (exceptix_end - base_address) as usize;
        let exception_table: &[ExceptionTableEntry] =
            bytemuck::try_cast_slice(&arm9_code[start..end]).map_err(|error| PodCastSnafu { error }.build())?;

        let exception_start = exception_table.iter().filter_map(|entry| entry.exception_record_pointer()).min();

        Ok(Some(ExceptionData { exception_start, exceptix_start, exceptix_end }))
    }

    fn find_get_exceptix_function(module_code: &[u8], base_address: u32) -> Result<Option<(u32, u32)>, ExceptionDataError> {
        let end_address = base_address + module_code.len() as u32;
        log::debug!("Searching for exception table in {:#010x}..{:#010x}", base_address, end_address);

        for address in (base_address..end_address).step_by(4) {
            let code = &module_code[(address - base_address) as usize..];
            let Some(get_exceptix) = GET_EXCEPTIX_FUNCTIONS.iter().find(|get_exceptix| code.starts_with(get_exceptix.code))
            else {
                continue;
            };

            let exceptix_start =
                u32::from_le_slice(&code[get_exceptix.start_offset as usize..get_exceptix.start_offset as usize + 4]);
            let exceptix_end =
                u32::from_le_slice(&code[get_exceptix.end_offset as usize..get_exceptix.end_offset as usize + 4]);

            log::debug!(
                "Found get_exceptix function at {:#010x} with exceptix start {:#010x} and end {:#010x}",
                address,
                exceptix_start,
                exceptix_end
            );

            return Ok(Some((exceptix_start, exceptix_end)));
        }
        Ok(None)
    }

    pub fn exception_start(&self) -> Option<u32> {
        self.exception_start
    }

    pub fn exceptix_start(&self) -> u32 {
        self.exceptix_start
    }

    pub fn exceptix_end(&self) -> u32 {
        self.exceptix_end
    }
}
