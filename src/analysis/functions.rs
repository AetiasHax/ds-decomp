use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
};

use unarm::{
    args::{Argument, Reg, Register},
    ArmVersion, Endian, Ins, ParseFlags, ParseMode, ParsedIns, Parser,
};

use crate::{analysis::function_start::is_valid_function_start, config::symbol::SymbolMap, util::ds::is_ram_address};

use super::{
    function_branch::FunctionBranchState,
    inline_table::{InlineTable, InlineTableState},
    jump_table::{JumpTable, JumpTableState},
    secure_area::SecureAreaState,
};

pub type Labels = BTreeSet<u32>;
pub type PoolConstants = BTreeSet<u32>;
pub type JumpTables = BTreeMap<u32, JumpTable>;
pub type InlineTables = BTreeMap<u32, InlineTable>;

#[derive(Debug, Clone)]
pub struct Function<'a> {
    name: String,
    start_address: u32,
    end_address: u32,
    thumb: bool,
    labels: Labels,
    pool_constants: PoolConstants,
    jump_tables: JumpTables,
    inline_tables: InlineTables,
    code: &'a [u8],
}

impl<'a> Function<'a> {
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
    ) -> ParseFunctionResult<'a> {
        let mut context = ParseFunctionContext::new(start_address, code, thumb);

        let Some((address, ins, parsed_ins)) = parser.next() else { return ParseFunctionResult::NoEpilogue };
        if !is_valid_function_start(address, ins, &parsed_ins) {
            return ParseFunctionResult::InvalidStart;
        }

        let state = context.handle_ins(&mut parser, address, ins, &parsed_ins);
        if state.ended() {
            return context.into_function(state, name);
        }

        while let Some((address, ins, parsed_ins)) = parser.next() {
            let state = context.handle_ins(&mut parser, address, ins, &parsed_ins);
            if state.ended() {
                return context.into_function(state, name);
            }
        }

        context.into_function(ParseFunctionState::Done, name)
    }

    pub fn parse_function(
        name: String,
        start_address: u32,
        code: &'a [u8],
        options: ParseFunctionOptions,
    ) -> ParseFunctionResult {
        let thumb = options.thumb.unwrap_or(Function::is_thumb_function(start_address, code));
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
        options: FindFunctionsOptions,
    ) -> BTreeMap<u32, Function<'a>> {
        let mut functions = BTreeMap::new();

        let start_address = options.start_address.unwrap_or(base_addr);
        let start_offset = start_address - base_addr;
        let end_address = options.end_address.unwrap_or(base_addr + code.len() as u32);
        let end_offset = end_address - base_addr;
        let mut code = &code[start_offset as usize..end_offset as usize];

        let last_function_address = options.last_function_address.unwrap_or(end_address);
        let mut address = start_address;

        while !code.is_empty() && address <= last_function_address {
            let thumb = Function::is_thumb_function(address, code);

            let parse_mode = if thumb { ParseMode::Thumb } else { ParseMode::Arm };
            let parser =
                Parser::new(parse_mode, address, Endian::Little, ParseFlags { version: ArmVersion::V5Te, ual: false }, code);

            let (name, new) = if let Some((_, symbol)) = symbol_map.by_address(address) {
                (symbol.name.clone(), false)
            } else {
                (format!("{}{:08x}", default_name_prefix, address), true)
            };
            let function = match Function::parse_function_impl(name, address, thumb, parser, code) {
                ParseFunctionResult::Found(function) => function,
                ParseFunctionResult::IllegalIns | ParseFunctionResult::NoEpilogue => break,
                ParseFunctionResult::InvalidStart => {
                    if options.keep_searching_for_valid_function_start {
                        let ins_size = parse_mode.instruction_size(0);
                        address += ins_size as u32;
                        code = &code[ins_size..];
                        continue;
                    } else {
                        break;
                    }
                }
            };

            if new {
                symbol_map.add_function(&function).unwrap();
            }
            function.add_local_symbols_to_map(symbol_map);

            address = function.end_address;
            code = &code[function.size() as usize..];

            functions.insert(function.start_address, function);
        }
        functions
    }

    pub fn add_local_symbols_to_map(&self, symbol_map: &mut SymbolMap) {
        for address in self.labels.iter() {
            symbol_map.add_label(*address).unwrap();
        }
        for address in self.pool_constants.iter() {
            symbol_map.add_pool_constant(*address).unwrap();
        }
        for jump_table in self.jump_tables() {
            symbol_map.add_jump_table(&jump_table).unwrap();
        }
        for inline_table in self.inline_tables().values() {
            symbol_map.add_data(None, inline_table.address, inline_table.clone().into()).unwrap();
        }
    }

    pub fn find_secure_area_functions(
        code: &'a [u8],
        base_addr: u32,
        symbol_map: &mut SymbolMap,
    ) -> BTreeMap<u32, Function<'a>> {
        let mut functions = BTreeMap::new();

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
                    inline_tables: InlineTables::new(),
                    code,
                };
                symbol_map.add_function(&function).unwrap();
                functions.insert(function.start_address, function);
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

    pub fn inline_tables(&self) -> &InlineTables {
        &self.inline_tables
    }

    pub fn get_inline_table_at(&self, address: u32) -> Option<&InlineTable> {
        Self::inline_table_at(&self.inline_tables, address)
    }

    fn inline_table_at(inline_tables: &InlineTables, address: u32) -> Option<&InlineTable> {
        inline_tables.values().find(|table| address >= table.address && address < table.address + table.size)
    }

    pub fn code(&self) -> &[u8] {
        self.code
    }

    pub fn pool_constants(&self) -> &PoolConstants {
        &self.pool_constants
    }
}

struct ParseFunctionContext<'a> {
    start_address: u32,
    code: &'a [u8],
    thumb: bool,
    end_address: Option<u32>,
    labels: Labels,
    pool_constants: PoolConstants,
    jump_tables: JumpTables,
    inline_tables: InlineTables,
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
}

impl<'a> ParseFunctionContext<'a> {
    pub fn new(start_address: u32, code: &'a [u8], thumb: bool) -> Self {
        Self {
            start_address,
            code,
            thumb,
            end_address: None,
            labels: Labels::new(),
            pool_constants: PoolConstants::new(),
            jump_tables: JumpTables::new(),
            inline_tables: InlineTables::new(),
            last_conditional_destination: None,
            last_pool_address: None,
            jump_table_state: if thumb {
                JumpTableState::Thumb(Default::default())
            } else {
                JumpTableState::Arm(Default::default())
            },
            function_branch_state: Default::default(),
            inline_table_state: Default::default(),
        }
    }

    pub fn handle_ins(&mut self, parser: &mut Parser, address: u32, ins: Ins, parsed_ins: &ParsedIns) -> ParseFunctionState {
        if self.pool_constants.contains(&address) {
            parser.seek_forward(address + 4);
            return ParseFunctionState::Continue;
        }
        if let Some(inline_table) = Function::inline_table_at(&self.inline_tables, address) {
            parser.seek_forward(inline_table.address + inline_table.size);
            return ParseFunctionState::Continue;
        }

        if ins.is_illegal() || parsed_ins.is_illegal() {
            return ParseFunctionState::IllegalIns;
        }

        if Some(address) >= self.last_conditional_destination && Function::is_return(ins, &parsed_ins) {
            // We're not inside a conditional code block, so this is the final return instruction
            self.end_address = Some(address + parser.mode.instruction_size(address) as u32);
            return ParseFunctionState::Done;
        }

        if address > self.start_address && Function::is_entry_instruction(ins, &parsed_ins) {
            // This instruction marks the start of a new function, so we must end the current one
            self.end_address = Some(address);
            return ParseFunctionState::Done;
        }

        self.function_branch_state = self.function_branch_state.handle(ins, &parsed_ins);
        if !self.function_branch_state.is_function_branch() {
            if let Some(destination) = Function::is_branch(ins, &parsed_ins, address) {
                self.labels.insert(destination);
                self.last_conditional_destination = self.last_conditional_destination.max(Some(destination));

                let next_address = (address & !3) + 4;
                if self.pool_constants.contains(&next_address) {
                    let branch_forwards = destination > address;
                    if branch_forwards {
                        // Load instructions in ARM mode can have an offset of up to ±4kB. Therefore, some functions must
                        // emit pool constants in the middle so they can all be accessed by PC-relative loads. There will
                        // also be branch instruction right before, so that the pool constants don't get executed.

                        // Sometimes, the pre-pool branch is conveniently placed at an actual branch in the code, and
                        // leads even further than the end of the pool constants. In that case we should already have found
                        // a label at a lower address.
                        let after_pools =
                            self.labels.range(address + 1..destination).next_back().map(|&x| x).unwrap_or(destination);

                        parser.seek_forward(after_pools);
                    } else {
                        // Pool constant coming up next, which doesn't necessarily mean that the function is over, since long
                        // functions have to emit multiple pools and branch past them. However, this branch is backwards, so
                        // we're not branching past these pool constants and this function must end here. This type of function
                        // contains some kind of infinite loop, hence the lack of return instruction as the final instruction.
                        self.end_address = Some(next_address);
                        return ParseFunctionState::Done;
                    }
                }
            }
        }

        if let Some(pool_address) = Function::is_pool_load(ins, &parsed_ins, address, self.thumb) {
            self.pool_constants.insert(pool_address);
            self.last_pool_address = self.last_pool_address.max(Some(pool_address));
        }

        self.jump_table_state = self.jump_table_state.handle(address, ins, &parsed_ins, &mut self.jump_tables);
        self.last_conditional_destination = self.last_conditional_destination.max(self.jump_table_state.table_end_address());
        if let Some(label) = self.jump_table_state.get_label(address, ins) {
            self.labels.insert(label);
            self.last_conditional_destination = self.last_conditional_destination.max(Some(label));
        }

        self.inline_table_state = self.inline_table_state.handle(self.thumb, address, &parsed_ins);
        if let Some(table) = self.inline_table_state.get_table() {
            self.inline_tables.insert(table.address, table);
        }

        ParseFunctionState::Continue
    }

    pub fn into_function(self, state: ParseFunctionState, name: String) -> ParseFunctionResult<'a> {
        match state {
            ParseFunctionState::Continue => panic!("cannot turn parse context into function before parsing is done"),
            ParseFunctionState::IllegalIns => return ParseFunctionResult::IllegalIns,
            ParseFunctionState::Done => {}
        };
        let Some(end_address) = self.end_address else {
            return ParseFunctionResult::NoEpilogue;
        };

        let end_address = end_address.max(self.last_pool_address.map(|a| a + 4).unwrap_or(0)).next_multiple_of(4);
        let size = end_address - self.start_address;
        let code = &self.code[..size as usize];
        ParseFunctionResult::Found(Function {
            name,
            start_address: self.start_address,
            end_address,
            thumb: self.thumb,
            labels: self.labels,
            pool_constants: self.pool_constants,
            jump_tables: self.jump_tables,
            inline_tables: self.inline_tables,
            code,
        })
    }
}

#[derive(Default)]
pub struct ParseFunctionOptions {
    /// Whether the function is in Thumb or ARM mode, or None if it should be detected automatically.
    pub thumb: Option<bool>,
}

enum ParseFunctionState {
    Continue,
    IllegalIns,
    Done,
}

impl ParseFunctionState {
    pub fn ended(&self) -> bool {
        match self {
            Self::Continue => false,
            Self::IllegalIns | Self::Done => true,
        }
    }
}

#[derive(Debug)]
pub enum ParseFunctionResult<'a> {
    Found(Function<'a>),
    IllegalIns,
    NoEpilogue,
    InvalidStart,
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

            // write data
            if let Some((data, sym)) = self.symbol_map.get_data(address) {
                let Some(size) = data.size() else {
                    panic!("inline tables must have a known size");
                };
                parser.seek_forward(address + size as u32);

                writeln!(f, "{}: ; inline table", sym.name)?;

                let start = (sym.addr - function.start_address) as usize;
                let end = start + size;
                let bytes = &function.code[start..end];
                write!(f, "{}", data.display_assembly(sym, bytes, self.symbol_map))?;
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

            // write pool constants
            let next_address = address + ins_size;
            for i in 0.. {
                let pool_address = next_address + i * 4;
                if function.pool_constants.contains(&pool_address) {
                    let start = pool_address - function.start_address();
                    let bytes = &function.code[start as usize..];
                    let const_value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

                    // Check if constant could be a pointer to RAM or TCM
                    if !is_ram_address(const_value) {
                        writeln!(f, "    .word {const_value:#x}")?;
                        continue;
                    }

                    let Some((_, symbol)) = self.symbol_map.by_address(const_value) else {
                        writeln!(f, "    .word {const_value:#x}")?;
                        continue;
                    };

                    writeln!(f, "    .word {}", symbol.name)?;
                } else {
                    if pool_address > parser.address {
                        parser.seek_forward(pool_address);
                    }
                    break;
                }
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
