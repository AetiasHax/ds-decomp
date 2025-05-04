use std::backtrace::Backtrace;

use bytemuck::{Pod, Zeroable};
use snafu::Snafu;

use crate::{
    config::section::{Section, SectionCodeError},
    util::bytes::FromSlice,
};

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
}

impl ExceptionData {
    pub fn analyze(module_code: &[u8], base_address: u32, text_section: &Section) -> Result<Option<Self>, ExceptionDataError> {
        let Some(text_code) = text_section.code(module_code, base_address)? else {
            return Ok(None);
        };

        let Some((exceptix_start, exceptix_end)) = text_section.functions().values().find_map(|function| {
            if function.start_address() == 0x020844c0 {
                log::debug!("Function: {:#x}", function.start_address());
            }
            let code = function.code(text_code, text_section.start_address());
            let get_exceptix = GET_EXCEPTIX_FUNCTIONS.iter().find(|get_exceptix| code.starts_with(get_exceptix.code))?;
            let p_exceptix_start = function.start_address() + get_exceptix.start_offset;
            let p_exceptix_end = function.start_address() + get_exceptix.end_offset;
            let exceptix_start = u32::from_le_slice(
                &module_code[(p_exceptix_start - base_address) as usize..(p_exceptix_start - base_address + 4) as usize],
            );
            let exceptix_end = u32::from_le_slice(
                &module_code[(p_exceptix_end - base_address) as usize..(p_exceptix_end - base_address + 4) as usize],
            );
            Some((exceptix_start, exceptix_end))
        }) else {
            return Ok(None);
        };

        let start = (exceptix_start - base_address) as usize;
        let end = (exceptix_end - base_address) as usize;
        let exception_table: &[ExceptionTableEntry] =
            bytemuck::try_cast_slice(&module_code[start..end]).map_err(|error| PodCastSnafu { error }.build())?;

        let exception_start = exception_table.iter().filter_map(|entry| entry.exception_record_pointer()).min();

        Ok(Some(ExceptionData { exception_start, exceptix_start, exceptix_end }))
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
