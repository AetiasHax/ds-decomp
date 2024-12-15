use anyhow::{bail, Context, Result};
use ds_rom::rom::Arm9;
use unarm::args::Argument;

use crate::config::section::Sections;

use super::functions::{Function, FunctionParseOptions, ParseFunctionResult};

#[derive(Debug)]
pub struct CtorRange {
    pub start: u32,
    pub end: u32,
}

impl CtorRange {
    fn find_last_function_call(function: Function, module_code: &[u8], base_address: u32) -> Option<u32> {
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

    pub fn find_in_arm9(arm9: &Arm9) -> Result<Self> {
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
        })?;
        let entry_func = match parse_result {
            ParseFunctionResult::Found(function) => function,
            _ => bail!("failed to analyze entrypoint function: {:?}", parse_result),
        };

        let run_inits_addr =
            Self::find_last_function_call(entry_func, entry_code, entry_addr).context("no function calls in entrypoint")?;
        let run_inits_code = &code[(run_inits_addr - arm9.base_address()) as usize..];
        let parse_result = Function::parse_function(FunctionParseOptions {
            name: "run_inits".to_string(),
            start_address: run_inits_addr,
            base_address: run_inits_addr,
            module_code: run_inits_code,
            known_end_address: None,
            module_start_address: arm9.base_address(),
            module_end_address: arm9.end_address()?,
            parse_options: Default::default(),
        })?;
        let run_inits_func = match parse_result {
            ParseFunctionResult::Found(function) => function,
            _ => bail!("failed to parse static initializer function: {:?}", parse_result),
        };

        let p_ctor_start =
            run_inits_func.pool_constants().first().context("no pool constants found in static initializer function")?;
        let ctor_start_data = &code[(p_ctor_start - arm9.base_address()) as usize..];
        let ctor_start = u32::from_le_bytes([ctor_start_data[0], ctor_start_data[1], ctor_start_data[2], ctor_start_data[3]]);

        let num_ctors = code[(ctor_start - arm9.base_address()) as usize..]
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .position(|ctor| ctor == 0)
            .unwrap();

        let ctor_end = ctor_start + num_ctors as u32 * 4 + 4;

        Ok(Self { start: ctor_start, end: ctor_end })
    }

    pub fn try_from_sections(sections: &Sections) -> Result<Self> {
        let ctor = sections.by_name(".ctor").context("no .ctor section to get range")?;
        Ok(Self { start: ctor.start_address(), end: ctor.end_address() })
    }
}
