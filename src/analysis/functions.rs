use std::{
    collections::{BTreeMap, BTreeSet},
    io,
};

use anyhow::{bail, Result};
use bon::bon;
use unarm::{
    args::{Argument, Reg, Register},
    arm, thumb, ArmVersion, DisplayOptions, Endian, Ins, ParseFlags, ParseMode, ParsedIns, Parser, RegNames,
};

use crate::{
    analysis::function_start::is_valid_function_start,
    config::symbol::{SymbolLookup, SymbolMap},
    util::bytes::FromSlice,
};

use super::{
    function_branch::FunctionBranchState,
    illegal_code::IllegalCodeState,
    inline_table::{InlineTable, InlineTableState},
    jump_table::{JumpTable, JumpTableState},
    secure_area::SecureAreaState,
};

// All keys in the types below are instruction addresses
pub type Labels = BTreeSet<u32>;
pub type PoolConstants = BTreeSet<u32>;
pub type JumpTables = BTreeMap<u32, JumpTable>;
pub type InlineTables = BTreeMap<u32, InlineTable>;
pub type FunctionCalls = BTreeMap<u32, CalledFunction>;
pub type DataLoads = BTreeMap<u32, u32>;

#[derive(Debug, Clone)]
pub struct Function {
    name: String,
    start_address: u32,
    end_address: u32,
    first_instruction_address: u32,
    thumb: bool,
    labels: Labels,
    pool_constants: PoolConstants,
    jump_tables: JumpTables,
    inline_tables: InlineTables,
    function_calls: FunctionCalls,
}

#[bon]
impl Function {
    pub fn size(&self) -> u32 {
        self.end_address - self.start_address
    }

    fn is_thumb_function(address: u32, code: &[u8]) -> bool {
        if (address & 3) != 0 {
            // Not 4-aligned, must be Thumb
            true
        } else if code.len() < 4 {
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

    fn is_push(ins: Ins) -> bool {
        match ins {
            Ins::Arm(op) => op.op == arm::Opcode::StmW && op.modifier_addr_ldm_stm() == arm::AddrLdmStm::Db,
            Ins::Thumb(op) => op.op == thumb::Opcode::Push,
            Ins::Data => false,
        }
    }

    fn is_entry_instruction(ins: Ins, parsed_ins: &ParsedIns) -> bool {
        if ins.is_conditional() {
            return false;
        }

        let args = &parsed_ins.args;
        match (parsed_ins.mnemonic, args[0], args[1], args[2]) {
            (
                "stmdb",
                Argument::Reg(Reg { reg: Register::Sp, writeback: true, deref: false }),
                Argument::RegList(regs),
                Argument::None,
            )
            | ("push", Argument::RegList(regs), Argument::None, Argument::None)
                if regs.contains(Register::Lr) =>
            {
                true
            }
            _ => false,
        }
    }

    fn is_return(ins: Ins, parsed_ins: &ParsedIns, address: u32, function_start: u32) -> bool {
        if ins.is_conditional() {
            return false;
        }

        let args = &parsed_ins.args;
        match (parsed_ins.mnemonic, args[0], args[1]) {
            // bx *
            ("bx", _, _) => true,
            // mov pc, *
            ("mov", Argument::Reg(Reg { reg: Register::Pc, .. }), _) => true,
            // ldmia *, {..., pc}
            ("ldmia", _, Argument::RegList(reg_list)) if reg_list.contains(Register::Pc) => true,
            // pop {..., pc}
            ("pop", Argument::RegList(reg_list), _) if reg_list.contains(Register::Pc) => true,
            // backwards branch
            ("b", Argument::BranchDest(offset), _) if offset < 0 => {
                // Branch must be within current function
                Self::is_branch(ins, parsed_ins, address).map(|destination| destination >= function_start).unwrap_or(false)
            }
            // subs pc, lr, *
            ("subs", Argument::Reg(Reg { reg: Register::Pc, .. }), Argument::Reg(Reg { reg: Register::Lr, .. })) => true,
            // ldr pc, *
            ("ldr", Argument::Reg(Reg { reg: Register::Pc, .. }), _) => true,
            _ => false,
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

    fn is_function_call(ins: Ins, parsed_ins: &ParsedIns, address: u32, thumb: bool) -> Option<CalledFunction> {
        let args = &parsed_ins.args;
        match (ins.mnemonic(), args[0], args[1]) {
            ("bl", Argument::BranchDest(offset), Argument::None) => {
                let destination = (address as i32 + offset) as u32;
                Some(CalledFunction { ins, address: destination, thumb })
            }
            ("blx", Argument::BranchDest(offset), Argument::None) => {
                let destination = (address as i32 + offset) as u32;
                let destination = if thumb { destination & !3 } else { destination };
                Some(CalledFunction { ins, address: destination, thumb: !thumb })
            }
            _ => None,
        }
    }

    #[builder]
    fn function_parser_loop<'a>(
        name: String,
        start_address: u32,
        thumb: bool,
        mut parser: Parser<'a>,
        known_end_address: Option<u32>,
        module_start_address: u32,
        module_end_address: u32,
    ) -> Result<ParseFunctionResult> {
        let mut context =
            ParseFunctionContext::new(start_address, thumb, known_end_address, module_start_address, module_end_address);

        let Some((address, ins, parsed_ins)) = parser.next() else { return Ok(ParseFunctionResult::NoEpilogue) };
        if !is_valid_function_start(address, ins, &parsed_ins) {
            return Ok(ParseFunctionResult::InvalidStart { address, ins, parsed_ins });
        }

        let state = context.handle_ins(&mut parser, address, ins, &parsed_ins);
        let result = if state.ended() {
            return context.into_function(state, name);
        } else {
            loop {
                let Some((address, ins, parsed_ins)) = parser.next() else {
                    break context.into_function(ParseFunctionState::Done, name);
                };
                let state = context.handle_ins(&mut parser, address, ins, &parsed_ins);
                if state.ended() {
                    break context.into_function(state, name);
                }
            }
        };

        let result = result?;
        let ParseFunctionResult::Found(mut function) = result else {
            return Ok(result);
        };

        if let Some(first_pool_address) = function.pool_constants.first() {
            if *first_pool_address < function.start_address {
                log::info!(
                    "Function at {:#010x} was adjusted to include pre-code constant pool at {:#010x}",
                    function.start_address,
                    first_pool_address
                );

                function.first_instruction_address = function.start_address;
                function.start_address = *first_pool_address;
            }
        }

        Ok(ParseFunctionResult::Found(function))
    }

    #[builder]
    fn run_function_parser_loop(
        name: String,
        start_address: u32,
        base_address: u32,
        first_instruction_offset: Option<u32>,
        module_code: &[u8],
        options: ParseFunctionOptions,
        known_end_address: Option<u32>,
        module_start_address: u32,
        module_end_address: u32,
    ) -> Result<ParseFunctionResult> {
        let thumb = options.thumb.unwrap_or(Function::is_thumb_function(start_address, module_code));
        let parse_mode = if thumb { ParseMode::Thumb } else { ParseMode::Arm };
        let offset = first_instruction_offset.unwrap_or(0);
        let start = (start_address - base_address + offset) as usize;
        let function_code = &module_code[start..];
        let parser = Parser::new(
            parse_mode,
            start_address,
            Endian::Little,
            ParseFlags { version: ArmVersion::V5Te, ual: false },
            function_code,
        );

        Self::function_parser_loop()
            .name(name)
            .start_address(start_address)
            .thumb(thumb)
            .parser(parser)
            .maybe_known_end_address(known_end_address)
            .module_start_address(module_start_address)
            .module_end_address(module_end_address)
            .call()
    }

    #[builder]
    pub fn parse_function(
        name: String,
        start_address: u32,
        base_address: u32,
        module_code: &[u8],
        options: Option<ParseFunctionOptions>,
        module_start_address: u32,
        module_end_address: u32,
    ) -> Result<ParseFunctionResult> {
        Self::run_function_parser_loop()
            .name(name)
            .start_address(start_address)
            .module_code(module_code)
            .options(options.unwrap_or_default())
            .base_address(base_address)
            .module_start_address(module_start_address)
            .module_end_address(module_end_address)
            .call()
    }

    #[builder]
    pub fn parse_known_function(
        name: String,
        start_address: u32,
        first_instruction_offset: u32,
        known_end_address: u32,
        code: &[u8],
        options: ParseFunctionOptions,
        module_start_address: u32,
        module_end_address: u32,
    ) -> Result<ParseFunctionResult> {
        Self::run_function_parser_loop()
            .name(name)
            .start_address(start_address)
            .module_code(code)
            .first_instruction_offset(first_instruction_offset)
            .options(options)
            .known_end_address(known_end_address)
            .base_address(start_address)
            .module_start_address(module_start_address)
            .module_end_address(module_end_address)
            .call()
    }

    #[builder]
    pub fn find_functions(
        module_code: &[u8],
        base_addr: u32,
        default_name_prefix: &str,
        symbol_map: &mut SymbolMap,
        options: FindFunctionsOptions,
        module_start_address: u32,
        module_end_address: u32,
    ) -> Result<BTreeMap<u32, Function>> {
        let mut functions = BTreeMap::new();

        let start_address = options.start_address.unwrap_or(base_addr);
        let start_offset = start_address - base_addr;
        let end_address = options.end_address.unwrap_or(base_addr + module_code.len() as u32);
        let end_offset = end_address - base_addr;
        let module_code = &module_code[..end_offset as usize];
        let mut function_code = &module_code[start_offset as usize..end_offset as usize];

        log::debug!("Searching for functions from {:#010x} to {:#010x}", start_address, end_address);

        let mut last_function_address = options.last_function_address.unwrap_or(end_address);
        let mut address = start_address;

        while !function_code.is_empty() && address <= last_function_address {
            let thumb = Function::is_thumb_function(address, function_code);

            let parse_mode = if thumb { ParseMode::Thumb } else { ParseMode::Arm };
            let parser = Parser::new(
                parse_mode,
                address,
                Endian::Little,
                ParseFlags { version: ArmVersion::V5Te, ual: false },
                function_code,
            );

            let (name, new) = if let Some((_, symbol)) = symbol_map.by_address(address)? {
                (symbol.name.clone(), false)
            } else {
                (format!("{}{:08x}", default_name_prefix, address), true)
            };

            let function_result = Function::function_parser_loop()
                .name(name)
                .start_address(address)
                .thumb(thumb)
                .parser(parser)
                .module_start_address(module_start_address)
                .module_end_address(module_end_address)
                .call()?;
            let function = match function_result {
                ParseFunctionResult::Found(function) => function,
                ParseFunctionResult::IllegalIns { address: illegal_address, ins, .. } => {
                    if options.keep_searching_for_valid_function_start {
                        // It's possible that we've attempted to analyze pool constants as code, which can happen if the
                        // function has a constant pool ahead of its code.
                        if thumb {
                            while !function_code.is_empty()
                                && address <= last_function_address
                                && Function::is_thumb_function(address, function_code)
                            {
                                address = (address + 1).next_multiple_of(4);
                                function_code = &module_code[(address - base_addr) as usize..];
                            }
                        } else {
                            while !function_code.is_empty()
                                && address <= last_function_address
                                && !Function::is_thumb_function(address, function_code)
                            {
                                address = (address + 1).next_multiple_of(2);
                                function_code = &module_code[(address - base_addr) as usize..];
                            }
                        }
                        continue;
                    } else {
                        if thumb {
                            log::debug!(
                                "Terminating function analysis due to illegal instruction at {:#010x}: {:04x}",
                                illegal_address,
                                ins.code()
                            );
                        } else {
                            log::debug!(
                                "Terminating function analysis due to illegal instruction at {:#010x}: {:08x}",
                                illegal_address,
                                ins.code()
                            );
                        }
                        break;
                    }
                }
                ParseFunctionResult::NoEpilogue => {
                    log::debug!(
                        "Terminating function analysis due to no epilogue in function starting from {:#010x}",
                        address
                    );
                    break;
                }
                ParseFunctionResult::InvalidStart { address: start_address, ins, parsed_ins } => {
                    if options.keep_searching_for_valid_function_start {
                        let ins_size = parse_mode.instruction_size(0);
                        address += ins_size as u32;
                        function_code = &function_code[ins_size..];
                        continue;
                    } else {
                        if thumb {
                            log::debug!(
                                "Terminating function analysis due to invalid function start at {:#010x}: {:04x} {}",
                                start_address,
                                ins.code(),
                                parsed_ins.display(Default::default())
                            );
                        } else {
                            log::debug!(
                                "Terminating function analysis due to invalid function start at {:#010x}: {:08x} {}",
                                start_address,
                                ins.code(),
                                parsed_ins.display(Default::default())
                            );
                        }
                        break;
                    }
                }
            };

            if new {
                symbol_map.add_function(&function);
            }
            function.add_local_symbols_to_map(symbol_map)?;

            address = function.end_address;
            function_code = &module_code[(address - base_addr) as usize..];

            // Look for pointers to data in this module, to use as an upper bound for finding functions
            if options.use_data_as_upper_bound {
                for pool_constant in function.iter_pool_constants(module_code, base_addr) {
                    let pointer_value = pool_constant.value & !1;
                    if pointer_value >= last_function_address {
                        continue;
                    }
                    if pointer_value >= start_address && pointer_value >= address {
                        let offset = (pointer_value - base_addr) as usize;
                        if offset < module_code.len() {
                            let thumb = Function::is_thumb_function(pointer_value, &module_code[offset..]);
                            let mut parser = Parser::new(
                                if thumb { ParseMode::Thumb } else { ParseMode::Arm },
                                pointer_value,
                                Endian::Little,
                                ParseFlags { ual: false, version: ArmVersion::V5Te },
                                &module_code[offset..],
                            );
                            let (address, ins, parsed_ins) = parser.next().unwrap();
                            if !is_valid_function_start(address, ins, &parsed_ins) {
                                // The pool constant points to data, limit the upper bound
                                last_function_address = pointer_value;
                                log::debug!(
                                    "Upper bound found: address to data at {:#010x} from pool constant at {:#010x} from function {}",
                                    pool_constant.value,
                                    pool_constant.address,
                                    function.name
                                );
                            }
                        }
                    }
                }
            }

            functions.insert(function.start_address, function);
        }
        Ok(functions)
    }

    pub fn add_local_symbols_to_map(&self, symbol_map: &mut SymbolMap) -> Result<()> {
        for address in self.labels.iter() {
            symbol_map.add_label(*address, self.thumb)?;
        }
        for address in self.pool_constants.iter() {
            symbol_map.add_pool_constant(*address)?;
        }
        for jump_table in self.jump_tables() {
            symbol_map.add_jump_table(&jump_table)?;
        }
        for inline_table in self.inline_tables().values() {
            symbol_map.add_data(None, inline_table.address, inline_table.clone().into())?;
        }
        Ok(())
    }

    pub fn find_secure_area_functions(
        module_code: &[u8],
        base_addr: u32,
        symbol_map: &mut SymbolMap,
    ) -> BTreeMap<u32, Function> {
        let mut functions = BTreeMap::new();

        let mut parser = Parser::new(
            ParseMode::Thumb,
            base_addr,
            Endian::Little,
            ParseFlags { ual: false, version: ArmVersion::V5Te },
            module_code,
        );
        let mut state = SecureAreaState::default();
        while let Some((address, _ins, parsed_ins)) = parser.next() {
            state = state.handle(address, &parsed_ins);
            if let Some(function) = state.get_function() {
                let function = Function {
                    name: function.name().to_string(),
                    start_address: function.start(),
                    end_address: function.end(),
                    first_instruction_address: function.start(),
                    thumb: true,
                    labels: Labels::new(),
                    pool_constants: PoolConstants::new(),
                    jump_tables: JumpTables::new(),
                    inline_tables: InlineTables::new(),
                    function_calls: FunctionCalls::new(),
                };
                symbol_map.add_function(&function);
                functions.insert(function.start_address, function);
            }
        }

        functions
    }

    pub fn parser<'a>(&'a self, module_code: &'a [u8], base_address: u32) -> Parser {
        Parser::new(
            if self.thumb { ParseMode::Thumb } else { ParseMode::Arm },
            self.start_address,
            Endian::Little,
            ParseFlags { ual: false, version: ArmVersion::V5Te },
            self.code(module_code, base_address),
        )
    }

    pub fn code<'a>(&self, module_code: &'a [u8], base_address: u32) -> &'a [u8] {
        let start = (self.start_address - base_address) as usize;
        let end = (self.end_address - base_address) as usize;
        &module_code[start..end]
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

    pub fn first_instruction_address(&self) -> u32 {
        self.first_instruction_address
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

    pub fn inline_tables(&self) -> &InlineTables {
        &self.inline_tables
    }

    pub fn get_inline_table_at(&self, address: u32) -> Option<&InlineTable> {
        Self::inline_table_at(&self.inline_tables, address)
    }

    fn inline_table_at(inline_tables: &InlineTables, address: u32) -> Option<&InlineTable> {
        inline_tables.values().find(|table| address >= table.address && address < table.address + table.size)
    }

    pub fn pool_constants(&self) -> &PoolConstants {
        &self.pool_constants
    }

    pub fn iter_pool_constants<'a>(
        &'a self,
        module_code: &'a [u8],
        base_address: u32,
    ) -> impl Iterator<Item = PoolConstant> + '_ {
        self.pool_constants.iter().map(move |&address| {
            let start = (address - base_address) as usize;
            let bytes = &module_code[start as usize..];
            PoolConstant { address, value: u32::from_le_slice(bytes) }
        })
    }

    pub fn function_calls(&self) -> &FunctionCalls {
        &self.function_calls
    }

    pub fn write_assembly<W: io::Write>(
        &self,
        w: &mut W,
        symbols: &SymbolLookup,
        module_code: &[u8],
        base_address: u32,
        ual: bool,
    ) -> Result<()> {
        let mode = if self.thumb { ParseMode::Thumb } else { ParseMode::Arm };
        let mut parser = Parser::new(
            mode,
            self.start_address,
            Endian::Little,
            ParseFlags { ual, version: ArmVersion::V5Te },
            self.code(module_code, base_address),
        );

        // declare self
        writeln!(w, "    .global {}", self.name)?;
        if self.thumb {
            writeln!(w, "    thumb_func_start {}", self.name)?;
        } else {
            writeln!(w, "    arm_func_start {}", self.name)?;
        }
        writeln!(w, "{}: ; {:#010x}", self.name, self.start_address)?;

        let mut jump_table = None;

        while let Some((address, ins, parsed_ins)) = parser.next() {
            let ins_size = parser.mode.instruction_size(0) as u32;

            // write label
            if let Some(label) = symbols.symbol_map.get_label(address)? {
                writeln!(w, "{}:", label.name)?;
            }
            if let Some((table, sym)) = symbols.symbol_map.get_jump_table(address)? {
                jump_table = Some((table, sym));
                writeln!(w, "{}: ; jump table", sym.name)?;
            }

            // write data
            if let Some((data, sym)) = symbols.symbol_map.get_data(address)? {
                let Some(size) = data.size() else {
                    log::error!("Inline tables must have a known size");
                    bail!("Inline tables must have a known size");
                };
                parser.seek_forward(address + size as u32);

                writeln!(w, "{}: ; inline table", sym.name)?;

                let start = (sym.addr - base_address) as usize;
                let end = start + size as usize;
                let bytes = &module_code[start..end];
                data.write_assembly(w, sym, bytes, &symbols)?;
                continue;
            }

            // possibly terminate jump table
            if jump_table.map_or(false, |(table, sym)| address >= sym.addr + table.size) {
                jump_table = None;
            }

            // write instruction
            match jump_table {
                Some((table, sym)) if !table.code => {
                    let (directive, value) =
                        if self.thumb { (".short", ins.code() as i16 as i32) } else { (".word", ins.code() as i32) };
                    let label_address = (sym.addr as i32 + value + 2) as u32;
                    let Some(label) = symbols.symbol_map.get_label(label_address)? else {
                        log::error!("Expected label for jump table destination {:#010x}", label_address);
                        bail!("Expected label for jump table destination {:#010x}", label_address);
                    };
                    write!(w, "    {directive} {} - {} - 2", label.name, sym.name)?;
                }
                _ => {
                    if parser.mode != ParseMode::Data {
                        write!(w, "    ")?;
                    }
                    let pc_load_offset = if self.thumb { 4 } else { 8 };
                    write!(
                        w,
                        "{}",
                        parsed_ins.display_with_symbols(
                            DisplayOptions { reg_names: RegNames { ip: true, ..Default::default() } },
                            unarm::Symbols { lookup: symbols, program_counter: address, pc_load_offset }
                        )
                    )?;
                    if let Some(reference) = parsed_ins.pc_relative_reference(address, pc_load_offset) {
                        symbols.write_ambiguous_symbols_comment(w, address, reference)?;
                    }
                }
            }

            // write jump table case
            if let Some((_table, sym)) = jump_table {
                let case = (address - sym.addr) / ins_size;
                writeln!(w, " ; case {case}")?;
            } else {
                writeln!(w)?;
            }

            // write pool constants
            let next_address = address + ins_size;
            for i in 0.. {
                let pool_address = next_address + i * 4;
                if self.pool_constants.contains(&pool_address) {
                    let start = pool_address - base_address;
                    let bytes = &module_code[start as usize..];
                    let const_value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

                    let Some(pool_symbol) = symbols.symbol_map.get_pool_constant(pool_address)? else {
                        log::error!("Pool constant at {:#010x} in function {} has no symbol", pool_address, self.name);
                        bail!("Pool constant at {:#010x} in function {} has no symbol", pool_address, self.name);
                    };
                    write!(w, "{}: ", pool_symbol.name)?;

                    if !symbols.write_symbol(w, pool_address, const_value, &mut false, "")? {
                        writeln!(w, ".word {const_value:#x}")?;
                    }
                } else {
                    if pool_address > parser.address {
                        parser.seek_forward(pool_address);
                    }
                    break;
                }
            }
        }

        if self.thumb {
            writeln!(w, "    thumb_func_end {}", self.name)?;
        } else {
            writeln!(w, "    arm_func_end {}", self.name)?;
        }

        writeln!(w)?;

        Ok(())
    }
}

struct ParseFunctionContext {
    start_address: u32,
    thumb: bool,
    end_address: Option<u32>,
    known_end_address: Option<u32>,
    labels: Labels,
    pool_constants: PoolConstants,
    jump_tables: JumpTables,
    inline_tables: InlineTables,
    function_calls: FunctionCalls,

    module_start_address: u32,
    module_end_address: u32,

    /// Address of last conditional instruction, so we can detect the final return instruction
    last_conditional_destination: Option<u32>,
    /// Address of last pool constant, to get the function's true end address
    last_pool_address: Option<u32>,
    /// State machine for detecting jump tables and adding them as symbols
    jump_table_state: JumpTableState,
    /// State machine for detecting branches (B, not BL) to other functions
    function_branch_state: FunctionBranchState,
    /// State machine for detecting inline data tables within the function
    inline_table_state: InlineTableState,
    /// State machine for detecting illegal code sequences
    illegal_code_state: IllegalCodeState,

    prev_ins: Option<Ins>,
}

impl ParseFunctionContext {
    pub fn new(
        start_address: u32,
        thumb: bool,
        known_end_address: Option<u32>,
        module_start_address: u32,
        module_end_address: u32,
    ) -> Self {
        Self {
            start_address,
            thumb,
            end_address: None,
            known_end_address,
            labels: Labels::new(),
            pool_constants: PoolConstants::new(),
            jump_tables: JumpTables::new(),
            inline_tables: InlineTables::new(),
            function_calls: FunctionCalls::new(),

            module_start_address,
            module_end_address,

            last_conditional_destination: None,
            last_pool_address: None,
            jump_table_state: if thumb {
                JumpTableState::Thumb(Default::default())
            } else {
                JumpTableState::Arm(Default::default())
            },
            function_branch_state: Default::default(),
            inline_table_state: Default::default(),
            illegal_code_state: Default::default(),

            prev_ins: None,
        }
    }

    fn handle_ins_inner(&mut self, parser: &mut Parser, address: u32, ins: Ins, parsed_ins: &ParsedIns) -> ParseFunctionState {
        if self.pool_constants.contains(&address) {
            parser.seek_forward(address + 4);
            return ParseFunctionState::Continue;
        }
        if let Some(inline_table) = Function::inline_table_at(&self.inline_tables, address) {
            parser.seek_forward(inline_table.address + inline_table.size);
            return ParseFunctionState::Continue;
        }

        self.jump_table_state = self.jump_table_state.handle(address, ins, &parsed_ins, &mut self.jump_tables);
        self.last_conditional_destination = self.last_conditional_destination.max(self.jump_table_state.table_end_address());
        if let Some(label) = self.jump_table_state.get_label(address, ins) {
            self.labels.insert(label);
            self.last_conditional_destination = self.last_conditional_destination.max(Some(label));
        }

        if self.jump_table_state.is_numerical_jump_offset() {
            // Not an instruction, continue
            return ParseFunctionState::Continue;
        }

        let ins_size = if let Ins::Thumb(thumb_ins) = ins {
            if thumb_ins.op != thumb::Opcode::Bl && thumb_ins.op != thumb::Opcode::BlxI {
                // Typical Thumb instruction
                2
            } else if matches!(parsed_ins.args[0], Argument::BranchDest(_)) {
                // Combined BL/BLX instruction
                4
            } else {
                // Not combined
                return ParseFunctionState::IllegalIns { address, ins, parsed_ins: parsed_ins.clone() };
            }
        } else {
            // ARM instruction
            4
        };

        self.illegal_code_state = self.illegal_code_state.handle(ins, parsed_ins);
        if self.illegal_code_state.is_illegal() {
            return ParseFunctionState::IllegalIns { address, ins, parsed_ins: parsed_ins.clone() };
        }

        let in_conditional_block = Some(address) < self.last_conditional_destination;
        if !in_conditional_block {
            if Function::is_return(ins, &parsed_ins, address, self.start_address) {
                // We're not inside a conditional code block, so this is the final return instruction
                self.end_address = Some(address + ins_size);
                return ParseFunctionState::Done;
            }
        }

        if address > self.start_address
            && Function::is_entry_instruction(ins, &parsed_ins)
            && !self.prev_ins.map_or(false, Function::is_push)
        {
            // This instruction marks the start of a new function, so we must end the current one
            self.end_address = Some(address);
            return ParseFunctionState::Done;
        }

        self.function_branch_state = self.function_branch_state.handle(ins, &parsed_ins);
        if let Some(destination) = Function::is_branch(ins, &parsed_ins, address) {
            let in_current_module = destination >= self.module_start_address && destination < self.module_end_address;
            if !in_current_module {
                // Tail call
                self.function_calls.insert(address, CalledFunction { ins, address: destination, thumb: self.thumb });
            } else if self.function_branch_state.is_function_branch() {
                if !ins.is_conditional() && !in_conditional_block {
                    // This is an unconditional backwards function branch, which means this function has ended
                    self.end_address = Some(address + ins_size);
                    return ParseFunctionState::Done;
                } else {
                    // TODO: Always run this (move it outside of else block)
                    // mwldarm manages to relocate conditional branches, but not unconditional ones like the if block above
                    self.function_calls.insert(address, CalledFunction { ins, address: destination, thumb: self.thumb });
                }
            } else {
                // Normal branch instruction, insert a label
                if let Some(state) = self.handle_label(destination, address, parser, ins_size) {
                    return state;
                }
            }
        }

        if let Some(pool_address) = Function::is_pool_load(ins, &parsed_ins, address, self.thumb) {
            self.pool_constants.insert(pool_address);
            self.last_pool_address = self.last_pool_address.max(Some(pool_address));
        }

        self.inline_table_state = self.inline_table_state.handle(self.thumb, address, &parsed_ins);
        if let Some(table) = self.inline_table_state.get_table() {
            log::debug!("Inline table found at {:#x}, size {:#x}", table.address, table.size);
            self.inline_tables.insert(table.address, table);
        }

        if let Some(called_function) = Function::is_function_call(ins, parsed_ins, address, self.thumb) {
            self.function_calls.insert(address, called_function);
        }

        ParseFunctionState::Continue
    }

    pub fn handle_ins(&mut self, parser: &mut Parser, address: u32, ins: Ins, parsed_ins: &ParsedIns) -> ParseFunctionState {
        let state = self.handle_ins_inner(parser, address, ins, parsed_ins);
        self.prev_ins = Some(ins);
        state
    }

    fn handle_label(
        &mut self,
        destination: u32,
        address: u32,
        parser: &mut Parser,
        ins_size: u32,
    ) -> Option<ParseFunctionState> {
        self.labels.insert(destination);
        self.last_conditional_destination = self.last_conditional_destination.max(Some(destination));

        let next_address = address + ins_size;
        if self.pool_constants.contains(&next_address) {
            let branch_backwards = destination <= address;

            // Load instructions in ARM mode can have an offset of up to ±4kB. Therefore, some functions must
            // emit pool constants in the middle so they can all be accessed by PC-relative loads. There will
            // also be branch instruction right before, so that the pool constants don't get executed.

            // Sometimes, the pre-pool branch is conveniently placed at an actual branch in the code, and
            // leads even further than the end of the pool constants. In that case we should already have found
            // a label at a lower address.
            if let Some(after_pools) = self.labels.range(address + 1..).next().map(|&x| x) {
                if after_pools > address + 0x1000 {
                    log::warn!("Massive gap from constant pool at {:#x} to next label at {:#x}", next_address, after_pools);
                }
                parser.seek_forward(after_pools);
            } else if !branch_backwards {
                // Backwards branch with no further branch labels. This type of function contains some kind of infinite loop,
                // hence the lack of return instruction as the final instruction.
                self.end_address = Some(next_address);
                return Some(ParseFunctionState::Done);
            } else {
                let after_pools = (next_address..).step_by(4).find(|addr| !self.pool_constants.contains(addr)).unwrap();
                log::warn!(
                    "No label past constant pool at {:#x}, jumping to first address not occupied by a pool constant ({:#x})",
                    next_address,
                    after_pools
                );
                parser.seek_forward(after_pools);
            }
        }

        None
    }

    fn into_function(self, state: ParseFunctionState, name: String) -> Result<ParseFunctionResult> {
        match state {
            ParseFunctionState::Continue => {
                log::error!("Cannot turn parse context into function before parsing is done");
                bail!("Cannot turn parse context into function before parsing is done");
            }
            ParseFunctionState::IllegalIns { address, ins, parsed_ins } => {
                return Ok(ParseFunctionResult::IllegalIns { address, ins, parsed_ins })
            }
            ParseFunctionState::Done => {}
        };
        let Some(end_address) = self.end_address else {
            return Ok(ParseFunctionResult::NoEpilogue);
        };

        let end_address = self
            .known_end_address
            .unwrap_or(end_address.max(self.last_pool_address.map(|a| a + 4).unwrap_or(0)).next_multiple_of(4));
        if end_address > self.module_end_address {
            return Ok(ParseFunctionResult::NoEpilogue);
        }

        Ok(ParseFunctionResult::Found(Function {
            name,
            start_address: self.start_address,
            end_address,
            first_instruction_address: self.start_address,
            thumb: self.thumb,
            labels: self.labels,
            pool_constants: self.pool_constants,
            jump_tables: self.jump_tables,
            inline_tables: self.inline_tables,
            function_calls: self.function_calls,
        }))
    }
}

#[derive(Default)]
pub struct ParseFunctionOptions {
    /// Whether the function is in Thumb or ARM mode, or None if it should be detected automatically.
    pub thumb: Option<bool>,
}

enum ParseFunctionState {
    Continue,
    IllegalIns { address: u32, ins: Ins, parsed_ins: ParsedIns },
    Done,
}

impl ParseFunctionState {
    pub fn ended(&self) -> bool {
        match self {
            Self::Continue => false,
            Self::IllegalIns { .. } | Self::Done => true,
        }
    }
}

#[derive(Debug)]
pub enum ParseFunctionResult {
    Found(Function),
    IllegalIns { address: u32, ins: Ins, parsed_ins: ParsedIns },
    NoEpilogue,
    InvalidStart { address: u32, ins: Ins, parsed_ins: ParsedIns },
}

#[derive(Default)]
pub struct FindFunctionsOptions {
    /// Address to start searching from. Defaults to the base address.
    pub start_address: Option<u32>,
    /// Last address that a function can start from. Defaults to [`Self::end_address`].
    pub last_function_address: Option<u32>,
    /// Address to end the search. Defaults to the base address plus code size.
    pub end_address: Option<u32>,
    /// If false, end the search when an illegal starting instruction is found.
    pub keep_searching_for_valid_function_start: bool,
    /// If true, pointers to data will be used to limit the upper bound address.
    pub use_data_as_upper_bound: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct CalledFunction {
    pub ins: Ins,
    pub address: u32,
    pub thumb: bool,
}

pub struct PoolConstant {
    pub address: u32,
    pub value: u32,
}
