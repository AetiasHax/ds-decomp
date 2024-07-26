use std::{collections::HashMap, fmt::Display};

use unarm::{
    args::{Argument, Register},
    ArmVersion, Endian, Ins, ParseFlags, ParseMode, ParsedIns, Parser,
};

#[derive(Debug)]
pub struct Function<'a> {
    name: String,
    start_address: u32,
    end_address: u32,
    code_end_address: u32,
    thumb: bool,
    labels: HashMap<u32, FunctionLabel>,
    code: &'a [u8],
}

#[derive(Debug)]
pub struct FunctionLabel {
    name: String,
}

impl<'a> Function<'a> {
    pub fn size(&self) -> u32 {
        self.end_address - self.start_address
    }

    fn is_thumb_function(code: &[u8]) -> bool {
        if code.len() < 4 {
            // Can't contain a full ARM instruction
            true
        } else if code[3] & 0xf0 == 0xe0 {
            // First instruction has the AL condition code, must be ARM
            false
        } else {
            // Thumb otherwise
            true
        }
    }

    fn is_return(ins: Ins, parsed_ins: &ParsedIns) -> bool {
        if ins.is_conditional() {
            return false;
        }

        let mnemonic = ins.mnemonic();
        if mnemonic == "bx" {
            // bx *
            true
        } else if mnemonic == "mov" && parsed_ins.registers().nth(0).unwrap() == Register::Pc {
            // mov pc, *
            true
        } else if ins.loads_multiple() {
            // PC can't be used in Thumb LDM, hence the difference between register_list() and register_list_pc()
            if mnemonic == "ldm" && ins.register_list().contains(Register::Pc) {
                // ldm* *, {..., pc}
                true
            } else if mnemonic == "pop" && ins.register_list_pc().contains(Register::Pc) {
                // pop {..., pc}
                true
            } else {
                false
            }
        } else {
            false
        }
    }

    fn is_branch(ins: Ins, parsed_ins: &ParsedIns, address: u32) -> Option<u32> {
        if ins.mnemonic() != "b" {
            return None;
        }
        let dest = parsed_ins.branch_destination().unwrap();
        Some((address as i32 + dest).try_into().unwrap())
    }

    fn is_pool_load(ins: Ins, parsed_ins: &ParsedIns, address: u32) -> Option<u32> {
        if ins.mnemonic() != "ldr" {
            return None;
        }
        match (parsed_ins.args[0], parsed_ins.args[1], parsed_ins.args[2]) {
            (Argument::Reg(dest), Argument::Reg(base), Argument::OffsetImm(offset)) => {
                if dest.reg == Register::Pc {
                    None
                } else if !base.deref || base.reg != Register::Pc {
                    None
                } else if offset.post_indexed {
                    None
                } else {
                    // ldr *, [pc + *]
                    let load_address = (address as i32 + offset.value) as u32;
                    let load_address = (load_address + 1).next_multiple_of(4); // +1 to guarantee next multiple of 4
                    Some(load_address)
                }
            }
            _ => None,
        }
    }

    fn parse_function(name: String, start_address: u32, thumb: bool, parser: Parser, code: &'a [u8]) -> Function<'a> {
        let mut end_address = None;
        let mut labels = HashMap::new();

        // Address of last conditional instruction, so we can detect the final return instruction
        let mut last_conditional_destination = None;

        // Address of last pool constant, to get the function's true end address
        let mut last_pool_address = None;

        for (address, ins, parsed_ins) in parser {
            if address == 0x0207762e {
                println!();
            }

            if Some(address) >= last_conditional_destination && Self::is_return(ins, &parsed_ins) {
                // We're not inside a conditional code block, so this is the final return instruction
                end_address = Some(address + parser.mode.instruction_size(address) as u32);
                break;
            }

            if let Some(destination) = Self::is_branch(ins, &parsed_ins, address) {
                let name = format!("_{destination:08x}");
                labels.insert(destination, FunctionLabel { name });

                last_conditional_destination = last_conditional_destination.max(Some(destination));
            }

            if let Some(pool_address) = Self::is_pool_load(ins, &parsed_ins, address) {
                let name = format!("_{pool_address:08x}");
                labels.insert(pool_address, FunctionLabel { name });

                last_pool_address = last_pool_address.max(Some(pool_address));
            }
        }

        let code_end_address = end_address.unwrap();
        let end_address = code_end_address.max(last_pool_address.map(|a| a + 4).unwrap_or(0)).next_multiple_of(4);
        let size = end_address - start_address;
        let code = &code[..size as usize];
        Function { name, start_address, end_address, code_end_address, thumb, labels, code }
    }

    pub fn iter_from_code(code: &'a [u8], base_addr: u32, start_address: Option<u32>) -> FunctionIter {
        let offset = start_address.map(|a| a - base_addr).unwrap_or(0);
        let start_address = base_addr + offset;
        let code = &code[offset as usize..];
        FunctionIter { start_address, code }
    }
}

pub struct FunctionIter<'a> {
    start_address: u32,
    code: &'a [u8],
}

impl<'a> Iterator for FunctionIter<'a> {
    type Item = Function<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.code.is_empty() {
            return None;
        }

        let thumb = Function::is_thumb_function(self.code);

        let parse_mode = if thumb { ParseMode::Thumb } else { ParseMode::Arm };
        let parser = Parser::new(
            parse_mode,
            self.start_address,
            Endian::Little,
            ParseFlags { version: ArmVersion::V5Te, ual: false },
            self.code,
        );

        let name = format!("func_{:08x}", self.start_address);
        let function = Function::parse_function(name, self.start_address, thumb, parser, self.code);

        self.start_address = function.end_address;
        self.code = &self.code[function.size() as usize..];

        Some(function)
    }
}

impl<'a> Display for Function<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mode = if self.thumb { ParseMode::Thumb } else { ParseMode::Arm };
        let mut parser = Parser::new(
            mode,
            self.start_address,
            Endian::Little,
            ParseFlags { ual: false, version: ArmVersion::V5Te },
            &self.code,
        );

        writeln!(f, "    .global {}", self.name)?;
        if self.thumb {
            writeln!(f, "    thumb_func_start {}", self.name)?;
        } else {
            writeln!(f, "    arm_func_start {}", self.name)?;
        }
        writeln!(f, "{}: ; 0x{:08x}", self.name, self.start_address)?;

        while let Some((address, _ins, parsed_ins)) = parser.next() {
            if let Some(label) = self.labels.get(&address) {
                writeln!(f, "{}:", label.name)?;
            }

            writeln!(f, "    {}", parsed_ins.display(Default::default()))?;

            if address + parser.mode.instruction_size(address) as u32 >= self.code_end_address {
                parser.mode = ParseMode::Data;
            }
        }

        if self.thumb {
            writeln!(f, "    thumb_func_end {}", self.name)?;
        } else {
            writeln!(f, "    arm_func_end {}", self.name)?;
        }

        Ok(())
    }
}
