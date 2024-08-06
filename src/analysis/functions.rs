use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
};

use unarm::{
    args::{Argument, Register},
    ArmVersion, Endian, Ins, ParseFlags, ParseMode, ParsedIns, Parser,
};

use crate::config::symbol::SymbolMap;

use super::{
    jump_table::{JumpTable, JumpTableState},
    secure_area::SecureAreaState,
};

pub type Labels = BTreeSet<u32>;
pub type PoolConstants = BTreeSet<u32>;
pub type JumpTables = BTreeMap<u32, JumpTable>;

#[derive(Debug, Clone)]
pub struct Function<'a> {
    name: String,
    start_address: u32,
    end_address: u32,
    thumb: bool,
    labels: Labels,
    pool_constants: PoolConstants,
    jump_tables: JumpTables,
    code: &'a [u8],
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

    fn is_pool_load(ins: Ins, parsed_ins: &ParsedIns, address: u32, thumb: bool) -> Option<u32> {
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
                    let load_address = (address as i32 + offset.value) as u32 & !3;
                    let load_address = load_address + if thumb { 4 } else { 8 };
                    Some(load_address)
                }
            }
            _ => None,
        }
    }

    fn parse_function_impl(
        name: String,
        start_address: u32,
        thumb: bool,
        mut parser: Parser,
        code: &'a [u8],
    ) -> Option<Function<'a>> {
        let mut end_address = None;
        let mut labels = Labels::new();
        let mut pool_constants = PoolConstants::new();
        let mut jump_tables = JumpTables::new();

        // Address of last conditional instruction, so we can detect the final return instruction
        let mut last_conditional_destination = None;

        // Address of last pool constant, to get the function's true end address
        let mut last_pool_address = None;

        // State machine for detecting jump tables and adding them as symbols
        let mut jump_table_state =
            if thumb { JumpTableState::Thumb(Default::default()) } else { JumpTableState::Arm(Default::default()) };

        while let Some((address, ins, parsed_ins)) = parser.next() {
            if pool_constants.contains(&address) {
                parser.seek_forward(address + 4);
                continue;
            }

            if address >= 0x02001a9c && address < 0x204f48c {
                eprintln!("{:#x}: {:x?} {}", address, last_conditional_destination, parsed_ins.display(Default::default()));
            }

            if ins.is_illegal() {
                return None;
            }

            if Some(address) >= last_conditional_destination && Self::is_return(ins, &parsed_ins) {
                // We're not inside a conditional code block, so this is the final return instruction
                end_address = Some(address + parser.mode.instruction_size(address) as u32);
                break;
            }

            if let Some(destination) = Self::is_branch(ins, &parsed_ins, address) {
                labels.insert(destination);
                last_conditional_destination = last_conditional_destination.max(Some(destination));
            }

            if let Some(pool_address) = Self::is_pool_load(ins, &parsed_ins, address, thumb) {
                pool_constants.insert(pool_address);
                last_pool_address = last_pool_address.max(Some(pool_address));
            }

            jump_table_state = jump_table_state.handle(address, ins, &parsed_ins, &mut jump_tables);
            last_conditional_destination = last_conditional_destination.max(jump_table_state.table_end_address());
            if let Some(label) = jump_table_state.get_label(address, ins) {
                labels.insert(label);
                last_conditional_destination = last_conditional_destination.max(Some(label));
            }
        }

        let Some(end_address) = end_address else {
            return None;
        };
        let end_address = end_address.max(last_pool_address.map(|a| a + 4).unwrap_or(0)).next_multiple_of(4);
        let size = end_address - start_address;
        let code = &code[..size as usize];
        Some(Function { name, start_address, end_address, thumb, labels, pool_constants, jump_tables, code })
    }

    pub fn parse_function(name: String, start_address: u32, code: &'a [u8]) -> Option<Self> {
        let thumb = Function::is_thumb_function(code);
        let parse_mode = if thumb { ParseMode::Thumb } else { ParseMode::Arm };
        let parser =
            Parser::new(parse_mode, start_address, Endian::Little, ParseFlags { version: ArmVersion::V5Te, ual: false }, code);

        Self::parse_function_impl(name, start_address, thumb, parser, code)
    }

    pub fn find_functions(
        code: &'a [u8],
        base_addr: u32,
        default_name_prefix: &str,
        symbol_map: &mut SymbolMap,
        start_address: Option<u32>,
        end_address: Option<u32>,
        num_functions: Option<usize>,
    ) -> Vec<Function<'a>> {
        let mut functions = vec![];

        let start_offset = start_address.map(|a| a - base_addr).unwrap_or(0);
        let mut start_address = start_offset + base_addr;
        let mut code = &code[start_offset as usize..];
        let end_address = end_address.unwrap_or(code.len() as u32);

        while !code.is_empty() && start_address <= end_address && num_functions.map(|n| functions.len() < n).unwrap_or(true) {
            let thumb = Function::is_thumb_function(code);

            let parse_mode = if thumb { ParseMode::Thumb } else { ParseMode::Arm };
            let parser = Parser::new(
                parse_mode,
                start_address,
                Endian::Little,
                ParseFlags { version: ArmVersion::V5Te, ual: false },
                code,
            );

            let (name, new) = if let Some((_, symbol)) = symbol_map.by_address(start_address) {
                (symbol.name.clone(), false)
            } else {
                (format!("{}{:08x}", default_name_prefix, start_address), true)
            };
            let Some(function) = Function::parse_function_impl(name, start_address, thumb, parser, code) else { break };

            if new {
                symbol_map.add_function(&function).unwrap();
            }
            for address in function.labels.iter() {
                symbol_map.add_label(*address).unwrap();
            }
            for address in function.pool_constants.iter() {
                symbol_map.add_pool_constant(*address).unwrap();
            }
            for jump_table in function.jump_tables() {
                symbol_map.add_jump_table(&jump_table).unwrap();
            }

            start_address = function.end_address;
            code = &code[function.size() as usize..];

            functions.push(function);
        }
        functions
    }

    pub fn find_secure_area_functions(code: &'a [u8], base_addr: u32, symbol_map: &mut SymbolMap) -> Vec<Function<'a>> {
        let mut functions = vec![];

        let mut parser = Parser::new(
            ParseMode::Thumb,
            base_addr,
            Endian::Little,
            ParseFlags { ual: false, version: ArmVersion::V5Te },
            code,
        );
        let mut state = SecureAreaState::default();
        while let Some((address, _ins, parsed_ins)) = parser.next() {
            state = state.handle(address, &parsed_ins);
            if let Some(function) = state.get_function() {
                let start = (function.start() - base_addr) as usize;
                let end = (function.end() - base_addr) as usize;
                let code = &code[start..end];

                let function = Function {
                    name: function.name().to_string(),
                    start_address: function.start(),
                    end_address: function.end(),
                    thumb: true,
                    labels: Labels::new(),
                    pool_constants: PoolConstants::new(),
                    jump_tables: JumpTables::new(),
                    code,
                };
                symbol_map.add_function(&function).unwrap();
                functions.push(function);
            }
        }

        functions
    }

    pub fn parser(&self) -> Parser {
        Parser::new(
            if self.thumb { ParseMode::Thumb } else { ParseMode::Arm },
            self.start_address,
            Endian::Little,
            ParseFlags { ual: false, version: ArmVersion::V5Te },
            &self.code,
        )
    }

    pub fn display(&self, symbol_map: &'a SymbolMap) -> DisplayFunction<'_> {
        DisplayFunction { function: self, symbol_map }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn start_address(&self) -> u32 {
        self.start_address
    }

    pub fn end_address(&self) -> u32 {
        self.end_address
    }

    pub fn is_thumb(&self) -> bool {
        self.thumb
    }

    pub fn labels(&self) -> impl Iterator<Item = &u32> {
        self.labels.iter()
    }

    pub fn jump_tables(&self) -> impl Iterator<Item = &JumpTable> {
        self.jump_tables.values()
    }

    pub fn code(&self) -> &[u8] {
        self.code
    }

    pub fn pool_constants(&self) -> &PoolConstants {
        &self.pool_constants
    }
}

pub struct DisplayFunction<'a> {
    function: &'a Function<'a>,
    symbol_map: &'a SymbolMap,
}

impl<'a> Display for DisplayFunction<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let function = self.function;

        let mode = if function.thumb { ParseMode::Thumb } else { ParseMode::Arm };
        let mut parser = Parser::new(
            mode,
            function.start_address,
            Endian::Little,
            ParseFlags { ual: false, version: ArmVersion::V5Te },
            &function.code,
        );

        // declare function
        writeln!(f, "    .global {}", function.name)?;
        if function.thumb {
            writeln!(f, "    thumb_func_start {}", function.name)?;
        } else {
            writeln!(f, "    arm_func_start {}", function.name)?;
        }
        writeln!(f, "{}: ; 0x{:08x}", function.name, function.start_address)?;

        let mut jump_table = None;

        while let Some((address, ins, parsed_ins)) = parser.next() {
            let ins_size = parser.mode.instruction_size(0) as u32;

            // write label
            if let Some(label) = self.symbol_map.get_label(address) {
                writeln!(f, "{}:", label.name)?;
            }
            if let Some(pool_const) = self.symbol_map.get_pool_constant(address) {
                write!(f, "{}: ", pool_const.name)?;
            }
            if let Some((table, sym)) = self.symbol_map.get_jump_table(address) {
                jump_table = Some((table, sym));
                writeln!(f, "{}: ; jump table", sym.name)?;
            }

            // possibly terminate jump table
            if jump_table.map_or(false, |(table, sym)| address >= sym.addr + table.size) {
                jump_table = None;
            }

            // write instruction
            match jump_table {
                Some((table, sym)) if !table.code => {
                    let (directive, value) =
                        if function.thumb { (".short", ins.code() as i16 as i32) } else { (".word", ins.code() as i32) };
                    let label_address = (sym.addr as i32 + value + 2) as u32;
                    let label = self
                        .symbol_map
                        .get_label(label_address)
                        .unwrap_or_else(|| panic!("expected label for jump table desination 0x{:08x}", label_address));
                    write!(f, "    {directive} {} - {} - 2", label.name, sym.name)?;
                }
                _ => {
                    if parser.mode != ParseMode::Data {
                        write!(f, "    ")?;
                    }
                    write!(
                        f,
                        "{}",
                        parsed_ins.display_with_symbols(
                            Default::default(),
                            unarm::Symbols {
                                lookup: self.symbol_map,
                                program_counter: address,
                                pc_load_offset: if function.thumb { 4 } else { 8 }
                            }
                        )
                    )?
                }
            }

            // write jump table case
            if let Some((_table, sym)) = jump_table {
                let case = (address - sym.addr) / ins_size;
                writeln!(f, " ; case {case}")?;
            } else {
                writeln!(f)?;
            }

            // possibly start writing pool constants
            let next_address = address + ins_size;
            if function.pool_constants.contains(&next_address) {
                parser.mode = ParseMode::Data;
            } else {
                parser.mode = mode;
            }
        }

        if function.thumb {
            writeln!(f, "    thumb_func_end {}", function.name)?;
        } else {
            writeln!(f, "    arm_func_end {}", function.name)?;
        }

        Ok(())
    }
}
