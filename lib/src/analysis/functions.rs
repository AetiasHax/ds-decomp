use std::{
    backtrace::Backtrace,
    collections::{BTreeMap, BTreeSet},
    fmt::{Display, Formatter},
};

use snafu::Snafu;
use unarm::{
    args::{Argument, Reg, Register},
    arm, thumb, ArmVersion, Endian, Ins, ParseFlags, ParseMode, ParsedIns, Parser,
};

use crate::{
    config::symbol::{SymbolMap, SymbolMapError},
    util::bytes::FromSlice,
};

use super::{
    function_branch::FunctionBranchState,
    function_start::is_valid_function_start,
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

#[derive(Debug, Snafu)]
pub enum FunctionAnalysisError {
    #[snafu(transparent)]
    IntoFunction { source: IntoFunctionError },
    #[snafu(transparent)]
    SymbolMap { source: SymbolMapError },
}

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

    #[allow(clippy::match_like_matches_macro)]
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

    fn function_parser_loop(
        mut parser: Parser<'_>,
        options: FunctionParseOptions,
    ) -> Result<ParseFunctionResult, FunctionAnalysisError> {
        let thumb = parser.mode == ParseMode::Thumb;
        let mut context = ParseFunctionContext::new(thumb, options);

        let Some((address, ins, parsed_ins)) = parser.next() else { return Ok(ParseFunctionResult::NoEpilogue) };
        if !is_valid_function_start(address, ins, &parsed_ins) {
            return Ok(ParseFunctionResult::InvalidStart { address, ins, parsed_ins });
        }

        let state = context.handle_ins(&mut parser, address, ins, parsed_ins);
        let result = if state.ended() {
            return Ok(context.into_function(state)?);
        } else {
            loop {
                let Some((address, ins, parsed_ins)) = parser.next() else {
                    break context.into_function(ParseFunctionState::Done);
                };
                let state = context.handle_ins(&mut parser, address, ins, parsed_ins);
                if state.ended() {
                    break context.into_function(state);
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

    pub fn parse_function(options: FunctionParseOptions) -> Result<ParseFunctionResult, FunctionAnalysisError> {
        let FunctionParseOptions { start_address, base_address, module_code, parse_options, .. } = &options;

        let thumb = parse_options.thumb.unwrap_or(Function::is_thumb_function(*start_address, module_code));
        let parse_mode = if thumb { ParseMode::Thumb } else { ParseMode::Arm };
        let start = (start_address - base_address) as usize;
        let function_code = &module_code[start..];
        let parser = Parser::new(
            parse_mode,
            *start_address,
            Endian::Little,
            ParseFlags { version: ArmVersion::V5Te, ual: false },
            function_code,
        );

        Self::function_parser_loop(parser, options)
    }

    pub fn find_functions(options: FindFunctionsOptions) -> Result<BTreeMap<u32, Function>, FunctionAnalysisError> {
        let FindFunctionsOptions {
            default_name_prefix,
            base_address,
            module_code,
            symbol_map,
            module_start_address,
            module_end_address,
            search_options,
        } = options;

        let mut functions = BTreeMap::new();

        let start_address = search_options.start_address.unwrap_or(base_address);
        assert!((start_address & 1) == 0);
        let start_offset = start_address - base_address;
        let end_address = search_options.end_address.unwrap_or(base_address + module_code.len() as u32);
        let end_offset = end_address - base_address;
        let module_code = &module_code[..end_offset as usize];
        let mut function_code = &module_code[start_offset as usize..end_offset as usize];

        log::debug!("Searching for functions from {:#010x} to {:#010x}", start_address, end_address);

        // Upper bound for function search
        let last_function_address = search_options.last_function_address.unwrap_or(end_address);
        let mut upper_bounds = BTreeSet::new();

        // Used to limit how far to search for valid function starts, see `max_function_start_search_distance`
        let mut prev_valid_address = start_address;
        let mut address = start_address;

        while !function_code.is_empty() && address <= *upper_bounds.first().unwrap_or(&last_function_address) {
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

            let function_result = Function::function_parser_loop(
                parser,
                FunctionParseOptions {
                    name,
                    start_address: address,
                    base_address,
                    module_code,
                    known_end_address: None,
                    module_start_address,
                    module_end_address,
                    existing_functions: search_options.existing_functions,
                    check_defs_uses: search_options.check_defs_uses,
                    parse_options: Default::default(),
                },
            )?;
            let function = match function_result {
                ParseFunctionResult::Found(function) => function,
                ParseFunctionResult::IllegalIns { address: illegal_address, ins, .. } => {
                    let search_limit = prev_valid_address.saturating_add(search_options.max_function_start_search_distance);
                    let limit_reached = address >= search_limit;

                    if !limit_reached {
                        // It's possible that we've attempted to analyze pool constants as code, which can happen if the
                        // function has a constant pool ahead of its code.
                        let mut next_address = (address + 1).next_multiple_of(4);
                        if let Some(function_addresses) = search_options.function_addresses.as_ref() {
                            if let Some(&next_function) = function_addresses.range(address + 1..).next() {
                                next_address = next_function;
                            }
                        }
                        address = next_address;
                        function_code = &module_code[(address - base_address) as usize..];
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
                    let search_limit = prev_valid_address.saturating_add(search_options.max_function_start_search_distance);
                    let limit_reached = address >= search_limit;

                    if !limit_reached {
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

            // A function was found
            if new {
                symbol_map.add_function(&function);
            }
            function.add_local_symbols_to_map(symbol_map)?;

            address = function.end_address.next_multiple_of(4); // align by 4 in case of Thumb function ending on 2-byte boundary
            prev_valid_address = function.end_address;
            function_code = &module_code[(address - base_address) as usize..];

            // Invalidate upper bounds if they are inside the function
            let invalid_upper_bounds: Vec<u32> = upper_bounds.range(..=function.end_address).copied().collect();
            for invalid_upper_bound in invalid_upper_bounds {
                upper_bounds.remove(&invalid_upper_bound);
                log::debug!(
                    "Invalidating upper bound {:#010x} inside function {:#010x}",
                    invalid_upper_bound,
                    function.start_address
                );
            }

            // Look for pointers to data in this module, to use as an upper bound for finding functions
            if search_options.use_data_as_upper_bound {
                for pool_constant in function.iter_pool_constants(module_code, base_address) {
                    let pointer_value = pool_constant.value & !1;
                    if upper_bounds.contains(&pointer_value) {
                        continue;
                    }
                    if pointer_value < address {
                        continue;
                    }

                    let offset = (pointer_value - base_address) as usize;
                    if offset >= module_code.len() {
                        continue;
                    }

                    let thumb = Function::is_thumb_function(pointer_value, &module_code[offset..]);
                    let mut parser = Parser::new(
                        if thumb { ParseMode::Thumb } else { ParseMode::Arm },
                        pointer_value,
                        Endian::Little,
                        ParseFlags { ual: false, version: ArmVersion::V5Te },
                        &module_code[offset..],
                    );
                    let (address, ins, parsed_ins) = parser.next().unwrap();
                    if is_valid_function_start(address, ins, &parsed_ins) {
                        continue;
                    }

                    // The pool constant points to data, limit the upper bound
                    upper_bounds.insert(pointer_value);
                    log::debug!(
                        "Upper bound found: address to data at {:#010x} from pool constant at {:#010x} from function {}",
                        pool_constant.value,
                        pool_constant.address,
                        function.name
                    );
                }
            }

            functions.insert(function.first_instruction_address, function);
        }
        Ok(functions)
    }

    pub fn add_local_symbols_to_map(&self, symbol_map: &mut SymbolMap) -> Result<(), SymbolMapError> {
        for address in self.labels.iter() {
            symbol_map.add_label(*address, self.thumb)?;
        }
        for address in self.pool_constants.iter() {
            symbol_map.add_pool_constant(*address)?;
        }
        for jump_table in self.jump_tables() {
            symbol_map.add_jump_table(jump_table)?;
        }
        for inline_table in self.inline_tables().values() {
            symbol_map.add_data(None, inline_table.address, (*inline_table).into())?;
        }
        Ok(())
    }

    pub fn find_secure_area_functions(
        module_code: &[u8],
        base_addr: u32,
        symbol_map: &mut SymbolMap,
    ) -> BTreeMap<u32, Function> {
        let mut functions = BTreeMap::new();

        let parse_flags = ParseFlags { ual: false, version: ArmVersion::V5Te };

        let mut address = base_addr;
        let mut state = SecureAreaState::default();
        for ins_code in module_code.chunks_exact(2) {
            let ins_code = u16::from_le_slice(ins_code);
            let ins = thumb::Ins::new(ins_code as u32, &parse_flags);
            let parsed_ins = ins.parse(&parse_flags);

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
                functions.insert(function.first_instruction_address, function);
            }

            address += 2;
        }

        functions
    }

    pub fn parser<'a>(&'a self, module_code: &'a [u8], base_address: u32) -> Parser<'a> {
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
    ) -> impl Iterator<Item = PoolConstant> + 'a {
        self.pool_constants.iter().map(move |&address| {
            let start = (address - base_address) as usize;
            let bytes = &module_code[start..];
            PoolConstant { address, value: u32::from_le_slice(bytes) }
        })
    }

    pub fn function_calls(&self) -> &FunctionCalls {
        &self.function_calls
    }
}

#[derive(Default)]
pub struct FunctionParseOptions<'a> {
    pub name: String,
    pub start_address: u32,
    pub base_address: u32,
    pub module_code: &'a [u8],
    pub known_end_address: Option<u32>,
    pub module_start_address: u32,
    pub module_end_address: u32,
    pub existing_functions: Option<&'a BTreeMap<u32, Function>>,

    /// Whether to check that all registers used in the instruction are defined
    pub check_defs_uses: bool,

    pub parse_options: ParseFunctionOptions,
}

pub struct FindFunctionsOptions<'a> {
    pub default_name_prefix: &'a str,
    pub base_address: u32,
    pub module_code: &'a [u8],
    pub symbol_map: &'a mut SymbolMap,
    pub module_start_address: u32,
    pub module_end_address: u32,

    pub search_options: FunctionSearchOptions<'a>,
}

struct ParseFunctionContext<'a> {
    name: String,
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
    existing_functions: Option<&'a BTreeMap<u32, Function>>,

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

    /// Whether to check that all registers used in the instruction are defined
    check_defs_uses: bool,
    defined_registers: BTreeSet<Register>,

    prev_ins: Option<Ins>,
    prev_parsed_ins: Option<ParsedIns>,
    prev_address: Option<u32>,
}

#[derive(Debug, Snafu)]
pub enum IntoFunctionError {
    #[snafu(display("Cannot turn parse context into function before parsing is done"))]
    NotDone { backtrace: Backtrace },
}

impl<'a> ParseFunctionContext<'a> {
    pub fn new(thumb: bool, options: FunctionParseOptions<'a>) -> Self {
        let FunctionParseOptions {
            name,
            start_address,
            known_end_address,
            module_start_address,
            module_end_address,
            existing_functions,
            check_defs_uses,
            ..
        } = options;

        let mut defined_registers = BTreeSet::new();
        // Could be arguments
        defined_registers.insert(Register::R0);
        defined_registers.insert(Register::R1);
        defined_registers.insert(Register::R2);
        defined_registers.insert(Register::R3);
        // Always defined
        defined_registers.insert(Register::Sp);
        defined_registers.insert(Register::Lr);
        defined_registers.insert(Register::Pc);

        Self {
            name,
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
            existing_functions,

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

            check_defs_uses,
            defined_registers,

            prev_ins: None,
            prev_parsed_ins: None,
            prev_address: None,
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

        self.jump_table_state = self.jump_table_state.handle(address, ins, parsed_ins, &mut self.jump_tables);
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
        let is_return =
            self.is_return(ins, parsed_ins, address, self.start_address, self.module_start_address, self.module_end_address);
        if !in_conditional_block && is_return {
            let end_address = address + ins_size;
            if let Some(destination) = Function::is_branch(ins, parsed_ins, address) {
                let outside_function = destination < self.start_address || destination >= end_address;
                if outside_function {
                    // Tail call
                    self.function_calls.insert(address, CalledFunction { ins, address: destination, thumb: self.thumb });
                }
            }

            // We're not inside a conditional code block, so this is the final return instruction
            self.end_address = Some(address + ins_size);
            return ParseFunctionState::Done;
        }

        if address > self.start_address && Function::is_entry_instruction(ins, parsed_ins) {
            'check_tail_call: {
                let Some(prev_ins) = self.prev_ins else {
                    break 'check_tail_call;
                };
                let Some(prev_parsed_ins) = self.prev_parsed_ins.as_ref() else {
                    break 'check_tail_call;
                };
                let Some(prev_address) = self.prev_address else {
                    break 'check_tail_call;
                };
                if Function::is_branch(prev_ins, prev_parsed_ins, prev_address).is_some() {
                    let is_conditional = in_conditional_block || prev_ins.is_conditional();
                    if is_conditional {
                        // Tail call
                        self.end_address = Some(address);
                        return ParseFunctionState::Done;
                    }
                }
            };
        }

        self.function_branch_state = self.function_branch_state.handle(ins, parsed_ins);
        if let Some(destination) = Function::is_branch(ins, parsed_ins, address) {
            let in_current_module = destination >= self.module_start_address && destination < self.module_end_address;
            if !in_current_module {
                // Tail call
                self.function_calls.insert(address, CalledFunction { ins, address: destination, thumb: self.thumb });
            } else if self.function_branch_state.is_function_branch()
                || self.existing_functions.map(|functions| functions.contains_key(&destination)).unwrap_or(false)
            {
                if !ins.is_conditional() && !in_conditional_block {
                    // This is an unconditional backwards function branch, which means this function has ended
                    self.end_address = Some(address + ins_size);
                    return ParseFunctionState::Done;
                } else {
                    // TODO: Always run this (move it outside of else block). SectionExt::relocatable_code must take condition
                    // code into account so the game matches after linking
                    self.function_calls.insert(address, CalledFunction { ins, address: destination, thumb: self.thumb });
                }
            } else {
                // Normal branch instruction, insert a label
                if let Some(state) = self.handle_label(destination, address, parser, ins_size) {
                    return state;
                }
            }
        }

        if let Some(pool_address) = Function::is_pool_load(ins, parsed_ins, address, self.thumb) {
            self.pool_constants.insert(pool_address);
            self.last_pool_address = self.last_pool_address.max(Some(pool_address));
        }

        self.inline_table_state = self.inline_table_state.handle(self.thumb, address, parsed_ins);
        if let Some(table) = self.inline_table_state.get_table() {
            log::debug!("Inline table found at {:#x}, size {:#x}", table.address, table.size);
            self.inline_tables.insert(table.address, table);
        }

        if let Some(called_function) = Function::is_function_call(ins, parsed_ins, address, self.thumb) {
            self.function_calls.insert(address, called_function);
        }

        if self.check_defs_uses && !Self::is_nop(ins, parsed_ins) {
            if Self::is_push(ins) {
                // Add all caller-saved registers to the defined set
                ins.register_list().iter().for_each(|reg| {
                    self.defined_registers.insert(reg);
                });
            }

            // Verify that all registers used in the instruction are defined
            let defs_uses = match ins {
                Ins::Arm(ins) => Some((ins.defs(&Default::default()), ins.uses(&Default::default()))),
                Ins::Thumb(ins) => Some((ins.defs(&Default::default()), ins.uses(&Default::default()))),
                Ins::Data => None,
            };
            if let Some((defs, uses)) = defs_uses {
                for usage in uses {
                    let legal = match usage {
                        Argument::Reg(reg) => {
                            if let Ins::Arm(ins) = ins {
                                if ins.op == arm::Opcode::Str && ins.field_rn_deref().reg == Register::Sp {
                                    // There are instance of `str Rd, [sp, #imm]` where Rd is not defined.
                                    // Potential UB bug in mwccarm.
                                    self.defined_registers.insert(reg.reg);
                                    continue;
                                }
                            }

                            self.defined_registers.contains(&reg.reg)
                        }
                        Argument::RegList(reg_list) => reg_list.iter().all(|reg| self.defined_registers.contains(&reg)),
                        Argument::ShiftReg(shift_reg) => self.defined_registers.contains(&shift_reg.reg),
                        Argument::OffsetReg(offset_reg) => self.defined_registers.contains(&offset_reg.reg),
                        _ => continue,
                    };
                    if !legal {
                        return ParseFunctionState::IllegalIns { address, ins, parsed_ins: parsed_ins.clone() };
                    }
                }
                if !is_return {
                    for def in defs {
                        match def {
                            Argument::Reg(reg) => {
                                self.defined_registers.insert(reg.reg);
                            }
                            Argument::RegList(reg_list) => {
                                for reg in reg_list.iter() {
                                    self.defined_registers.insert(reg);
                                }
                            }
                            Argument::ShiftReg(shift_reg) => {
                                self.defined_registers.insert(shift_reg.reg);
                            }
                            Argument::OffsetReg(offset_reg) => {
                                self.defined_registers.insert(offset_reg.reg);
                            }
                            _ => continue,
                        };
                    }
                }
            }
        }

        ParseFunctionState::Continue
    }

    pub fn handle_ins(&mut self, parser: &mut Parser, address: u32, ins: Ins, parsed_ins: ParsedIns) -> ParseFunctionState {
        let state = self.handle_ins_inner(parser, address, ins, &parsed_ins);
        self.prev_ins = Some(ins);
        self.prev_parsed_ins = Some(parsed_ins);
        self.prev_address = Some(address);
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
            if let Some(after_pools) = self.labels.range(address + 1..).next().copied() {
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

    fn into_function(self, state: ParseFunctionState) -> Result<ParseFunctionResult, IntoFunctionError> {
        match state {
            ParseFunctionState::Continue => {
                return NotDoneSnafu.fail();
            }
            ParseFunctionState::IllegalIns { address, ins, parsed_ins } => {
                return Ok(ParseFunctionResult::IllegalIns { address, ins, parsed_ins })
            }
            ParseFunctionState::Done => {}
        };
        let Some(end_address) = self.end_address else {
            return Ok(ParseFunctionResult::NoEpilogue);
        };

        let end_address =
            self.known_end_address.unwrap_or(end_address.max(self.last_pool_address.map(|a| a + 4).unwrap_or(0)));
        if end_address > self.module_end_address {
            return Ok(ParseFunctionResult::NoEpilogue);
        }

        Ok(ParseFunctionResult::Found(Function {
            name: self.name,
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

    fn is_return(
        &self,
        ins: Ins,
        parsed_ins: &ParsedIns,
        address: u32,
        function_start: u32,
        module_start_address: u32,
        module_end_address: u32,
    ) -> bool {
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
                // Branch must be within current function (infinite loop) or outside current module (tail call)
                Function::is_branch(ins, parsed_ins, address)
                    .map(|destination| {
                        destination >= function_start
                            || destination < module_start_address
                            || destination >= module_end_address
                    })
                    .unwrap_or(false)
            }
            // subs pc, lr, *
            ("subs", Argument::Reg(Reg { reg: Register::Pc, .. }), Argument::Reg(Reg { reg: Register::Lr, .. })) => true,
            // ldr pc, *
            ("ldr", Argument::Reg(Reg { reg: Register::Pc, .. }), _) => true,
            _ => false,
        }
    }

    fn is_nop(ins: Ins, parsed_ins: &ParsedIns) -> bool {
        match (ins.mnemonic(), parsed_ins.args[0], parsed_ins.args[1], parsed_ins.args[2]) {
            ("nop", _, _, _) => true,
            ("mov", Argument::Reg(Reg { reg: dest, .. }), Argument::Reg(Reg { reg: src, .. }), Argument::None) => dest == src,
            _ => false,
        }
    }

    fn is_push(ins: Ins) -> bool {
        match ins {
            Ins::Arm(arm_ins) => {
                if arm_ins.op == arm::Opcode::StmW && arm_ins.field_rn_wb().reg == Register::Sp {
                    true
                } else {
                    matches!(arm_ins.op, arm::Opcode::PushM | arm::Opcode::PushR)
                }
            }
            Ins::Thumb(thumb_ins) => thumb_ins.op == thumb::Opcode::Push,
            _ => false,
        }
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

impl Display for ParseFunctionResult {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Found(function) => write!(f, "Found function: {}", function.name()),
            Self::IllegalIns { address, parsed_ins, .. } => {
                write!(f, "Illegal instruction at {:#010x}: {}", address, parsed_ins.display(Default::default()))
            }
            Self::NoEpilogue => write!(f, "No epilogue found"),
            Self::InvalidStart { address, parsed_ins, .. } => {
                write!(f, "Invalid function start at {:#010x}: {}", address, parsed_ins.display(Default::default()))
            }
        }
    }
}

#[derive(Default)]
pub struct FunctionSearchOptions<'a> {
    /// Address to start searching from. Defaults to the base address.
    pub start_address: Option<u32>,
    /// Last address that a function can start from. Defaults to [`Self::end_address`].
    pub last_function_address: Option<u32>,
    /// Address to end the search. Defaults to the base address plus code size.
    pub end_address: Option<u32>,
    /// If zero, end the search when an illegal starting instruction is found. Otherwise, continue searching for a valid
    /// function start for up to this many bytes. Set to [`u32::MAX`] to search until the end of the module.
    pub max_function_start_search_distance: u32,
    /// If true, pointers to data will be used to limit the upper bound address.
    pub use_data_as_upper_bound: bool,
    /// Guarantees that all these addresses will be analyzed, even if the function analysis would terminate before they are
    /// reached. Used for .init functions.
    /// Note: This will override `keep_searching_for_valid_function_start`, they are not intended to be used together.
    pub function_addresses: Option<BTreeSet<u32>>,
    /// If a branch instruction branches into one of these functions, it will be treated as a function branch instead of
    /// inserting a label at the branch destination.
    /// If the function branch is unconditional, it will also be treated as a tail call and terminate the analysis of the
    /// current function.
    pub existing_functions: Option<&'a BTreeMap<u32, Function>>,
    /// Whether to treat instructions using undefined registers as illegal.
    pub check_defs_uses: bool,
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
