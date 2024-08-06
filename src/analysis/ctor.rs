use anyhow::{Context, Result};
use ds_rom::rom::Arm9;
use unarm::args::Argument;

use super::functions::Function;

pub struct CtorRange {
    pub start: u32,
    pub end: u32,
}

impl CtorRange {
    fn find_last_function_call(function: Function) -> Option<u32> {
        let mut last_called_function = None;
        for (address, _ins, parsed_ins) in function.parser() {
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
        let entry_func = Function::parse_function("entry".to_string(), arm9.entry_function(), entry_code)
            .context("failed to analyze entrypoint function")?;

        let run_inits_addr = Self::find_last_function_call(entry_func).context("no function calls in entrypoint")?;
        let run_inits_code = &code[(run_inits_addr - arm9.base_address()) as usize..];
        let run_inits_func = Function::parse_function("run_inits".to_string(), run_inits_addr, run_inits_code)
            .context("failed to parse static initializer function")?;

        let p_ctor_start =
            run_inits_func.pool_constants().first().context("no pool constants found in static initializer function")?;
        let ctor_start_data = &code[(p_ctor_start - arm9.base_address()) as usize..];
        let ctor_start = u32::from_le_bytes([ctor_start_data[0], ctor_start_data[1], ctor_start_data[2], ctor_start_data[3]]);

        let num_ctors = code[(ctor_start - arm9.base_address()) as usize..]
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .position(|ctor| ctor == 0)
            .unwrap();

        let ctor_end = ctor_start + num_ctors as u32 * 4;

        Ok(Self { start: ctor_start, end: ctor_end })
    }
}
