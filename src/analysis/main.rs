use anyhow::{bail, Context, Result};
use ds_rom::rom::Arm9;
use unarm::args::{Argument, OffsetImm, Reg, Register};

use super::functions::{Function, FunctionParseOptions, ParseFunctionResult};

#[derive(Clone, Copy)]
pub struct MainFunction {
    pub address: u32,
}

impl MainFunction {
    fn find_tail_call(function: Function, module_code: &[u8], base_address: u32) -> Result<u32> {
        let mut parser = function.parser(module_code, base_address);

        let ins_size = parser.mode.instruction_size(0) as u32;
        let last_ins_addr =
            function.pool_constants().first().context("Expected entry function to contain pool constants")? - ins_size;

        parser.seek_forward(last_ins_addr);
        let (_, _, last_ins) = parser.next().unwrap();

        let tail_call_reg = match (last_ins.mnemonic, last_ins.args[0], last_ins.args[1]) {
            ("bx", Argument::Reg(Reg { reg, .. }), Argument::None) => reg,
            _ => bail!("Expected last instruction of entry function to be 'bx <reg>'"),
        };

        let mut p_tail_call = None;
        for (address, _ins, parsed_ins) in function.parser(module_code, base_address) {
            if function.pool_constants().contains(&address) {
                break;
            }
            let args = &parsed_ins.args;
            p_tail_call = match (parsed_ins.mnemonic, args[0], args[1], args[2], args[3]) {
                (
                    "ldr",
                    Argument::Reg(Reg { reg, .. }),
                    Argument::Reg(Reg { reg: pc, deref: true, .. }),
                    Argument::OffsetImm(OffsetImm { post_indexed: false, value: offset }),
                    Argument::None,
                ) if reg == tail_call_reg && pc == Register::Pc => {
                    Some(((address as i32 + offset) & !3) as u32 + if function.is_thumb() { 4 } else { 8 })
                }
                _ => continue,
            };
        }
        let p_tail_call = p_tail_call.context("No tail call found in entry function")?;

        let function_code = function.code(module_code, base_address);
        let tail_call_data = &function_code[(p_tail_call - function.start_address()) as usize..];
        let tail_call = u32::from_le_bytes([tail_call_data[0], tail_call_data[1], tail_call_data[2], tail_call_data[3]]);
        Ok(tail_call & !1)
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

        let main = Self::find_tail_call(entry_func, entry_code, entry_addr)?;
        Ok(Self { address: main })
    }
}
