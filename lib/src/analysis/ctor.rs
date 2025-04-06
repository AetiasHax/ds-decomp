use std::backtrace::Backtrace;

use ds_rom::rom::{raw::RawBuildInfoError, Arm9, Autoload};
use snafu::Snafu;
use unarm::args::Argument;

use crate::config::module::ModuleKind;

use super::functions::{Function, FunctionAnalysisError, FunctionParseOptions, ParseFunctionResult};

#[derive(Debug)]
pub struct CtorRange {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Snafu)]
pub enum CtorRangeError {
    #[snafu(transparent)]
    RawBuildInfo { source: RawBuildInfoError },
    #[snafu(transparent)]
    FunctionAnalysis { source: FunctionAnalysisError },
    #[snafu(display("failed to analyze entrypoint function: {parse_result:x?}:\n{backtrace}"))]
    EntryAnalysisFailed { parse_result: ParseFunctionResult, backtrace: Backtrace },
    #[snafu(display("no function calls in entrypoint:\n{backtrace}"))]
    NoEntryFunctionCalls { backtrace: Backtrace },
    #[snafu(display("failed to parse static initializer function: {parse_result:x?}:\n{backtrace}"))]
    InitFunctionAnalysisFailed { parse_result: ParseFunctionResult, backtrace: Backtrace },
    #[snafu(display("no pool constants found in static initializer function:\n{backtrace}"))]
    NoInitPoolConstants { backtrace: Backtrace },
    #[snafu(display(".ctor runner at {address:#010x} not in range of module '{module_kind}:\n{backtrace}'"))]
    CtorRunnerNotInRange { address: u32, module_kind: ModuleKind, backtrace: Backtrace },
}

impl CtorRange {
    fn find_last_function_call(function: &Function, module_code: &[u8], base_address: u32) -> Option<u32> {
        let mut last_called_function = None;
        for (address, _ins, parsed_ins) in function.parser(module_code, base_address) {
            if !parsed_ins.mnemonic.starts_with("bl") {
                continue;
            }
            let Argument::BranchDest(offset) = parsed_ins.args[0] else {
                continue;
            };
            let dest = (address as i32 + offset) as u32;
            last_called_function = Some(dest);
        }
        last_called_function
    }

    pub fn find_in_arm9(arm9: &Arm9, unknown_autoloads: &[&Autoload]) -> Result<Self, CtorRangeError> {
        let code = arm9.code()?;

        let entry_addr = arm9.entry_function();
        let entry_code = &code[(entry_addr - arm9.base_address()) as usize..];
        let parse_result = Function::parse_function(FunctionParseOptions {
            name: "entry".to_string(),
            start_address: arm9.entry_function(),
            base_address: entry_addr,
            module_code: entry_code,
            known_end_address: None,
            module_start_address: arm9.base_address(),
            module_end_address: arm9.end_address()?,
            parse_options: Default::default(),
            ..Default::default()
        })?;
        let entry_func = match parse_result {
            ParseFunctionResult::Found(ref function) => function,
            _ => return EntryAnalysisFailedSnafu { parse_result }.fail(),
        };

        let run_inits_addr = Self::find_last_function_call(entry_func, entry_code, entry_addr)
            .ok_or_else(|| NoEntryFunctionCallsSnafu.build())?;

        let run_inits_offset = (run_inits_addr - arm9.base_address()) as usize;
        let (run_inits_module_start, run_inits_module_end, run_inits_code) = if run_inits_offset < code.len() {
            (arm9.base_address(), arm9.end_address()?, &code[run_inits_offset..])
        } else {
            // .ctor is in one of the unknown autoloads
            let run_inits_autoload = unknown_autoloads.iter().find(|autoload| {
                let run_inits_offset = (run_inits_addr - autoload.base_address()) as usize;
                run_inits_offset < autoload.code().len()
            });
            let Some(run_inits_autoload) = run_inits_autoload else {
                return CtorRunnerNotInRangeSnafu { address: run_inits_addr, module_kind: ModuleKind::Arm9 }.fail();
            };

            let base_address = run_inits_autoload.base_address();
            let run_inits_offset = (run_inits_addr - base_address) as usize;
            let code = &run_inits_autoload.code()[run_inits_offset..];
            (base_address, base_address + run_inits_autoload.code().len() as u32 + run_inits_autoload.bss_size(), code)
        };
        let parse_result = Function::parse_function(FunctionParseOptions {
            name: "run_inits".to_string(),
            start_address: run_inits_addr,
            base_address: run_inits_addr,
            module_code: run_inits_code,
            known_end_address: None,
            module_start_address: run_inits_module_start,
            module_end_address: run_inits_module_end,
            parse_options: Default::default(),
            ..Default::default()
        })?;
        let run_inits_func = match parse_result {
            ParseFunctionResult::Found(function) => function,
            _ => return InitFunctionAnalysisFailedSnafu { parse_result }.fail(),
        };

        let p_ctor_start = run_inits_func.pool_constants().first().ok_or_else(|| NoInitPoolConstantsSnafu.build())?;
        let ctor_start_data = &run_inits_code[(p_ctor_start - run_inits_addr) as usize..];
        let ctor_start = u32::from_le_bytes([ctor_start_data[0], ctor_start_data[1], ctor_start_data[2], ctor_start_data[3]]);

        let num_ctors = code[(ctor_start - arm9.base_address()) as usize..]
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .position(|ctor| ctor == 0)
            .unwrap();

        let ctor_end = ctor_start + num_ctors as u32 * 4 + 4;

        Ok(Self { start: ctor_start, end: ctor_end })
    }
}
