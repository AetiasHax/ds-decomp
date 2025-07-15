use crate::{
    analysis::{
        code::{
            block_map::{BasicBlock, Block, BlockMap, FunctionCall},
            functions::{Function, FunctionAddress, FunctionKind, FunctionMap},
            range_set::RangeSet,
        },
        function_branch::FunctionBranchState,
    },
    util::bytes::FromSlice,
};
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet, BinaryHeap},
    ops::Range,
};

use ds_rom::rom::raw::AutoloadKind;
use snafu::Snafu;
use unarm::{
    ParseFlags, Parser,
    args::{Argument, OffsetImm, OffsetReg, Reg, Register},
};

use crate::{
    analysis::jump_table::JumpTableState,
    config::{module::ModuleKind, symbol::InstructionMode},
};

pub struct ModuleOptions {
    pub base_address: u32,
    pub end_address: u32,
    pub kind: ModuleKind,
    pub code: Vec<u8>,
    /// Regions of data that shall not be interpreted as code
    pub data_regions: Vec<(u32, u32)>,
    /// Prevents detecting new data regions that are outside this range
    pub data_required_range: Range<u32>,
}

#[derive(Debug)]
pub struct Module {
    base_address: u32,
    end_address: u32,
    kind: ModuleKind,
    code: Vec<u8>,
    /// Regions of data that shall not be interpreted as code
    data_regions: RangeSet<u32>,
    /// Prevents detecting new data regions that are outside this range
    data_required_range: Range<u32>,
}

pub struct Modules {
    main: Option<Module>,
    overlays: BTreeMap<u16, Module>,
    autoloads: BTreeMap<AutoloadKind, Module>,
}

pub struct BlockAnalyzer {
    modules: Modules,
    function_map: FunctionMap,
    queue: AnalysisQueue,
    block_map: BlockMap,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnalysisLocation {
    address: u32,
    module: ModuleKind,
    mode: InstructionMode,
    conditional: bool,
    kind: AnalysisLocationKind,
    jump_table_state: JumpTableState,
    function_branch_state: FunctionBranchState,
    registers: Registers,
    stack: Stack,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnalysisLocationKind {
    Function,
    Label { function: FunctionAddress },
}

pub struct AnalysisQueue {
    queue: BinaryHeap<Reverse<AnalysisLocation>>, // reverse for min-heap
    visited: BTreeSet<(ModuleKind, u32)>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Registers {
    values: [Option<u32>; 16],
}

#[derive(Default, Clone, Debug, PartialEq, Eq)]
struct Stack {
    values: BTreeMap<i32, u32>,
}

#[derive(Debug, Snafu)]
pub enum BlockAnalysisError {
    ModuleNotFound { module: ModuleKind },
    FunctionNotFound { address: FunctionAddress },
    PendingBlock { address: u32, module: ModuleKind },
    EmptyFunction { address: u32, module: ModuleKind },
}

impl BlockAnalyzer {
    pub fn new() -> Self {
        Self {
            modules: Modules::new(),
            function_map: FunctionMap::new(),
            queue: AnalysisQueue::new(),
            block_map: BlockMap::new(),
        }
    }

    pub fn add_module(&mut self, options: ModuleOptions) {
        self.modules.add(Module::new(options));
    }

    pub fn add_function_location(&mut self, address: u32, module: ModuleKind, mode: InstructionMode, kind: FunctionKind) {
        let location = AnalysisLocation {
            address,
            module,
            mode,
            conditional: false,
            kind: AnalysisLocationKind::Function,
            jump_table_state: JumpTableState::new(mode == InstructionMode::Thumb),
            function_branch_state: FunctionBranchState::default(),
            registers: Registers::new(),
            stack: Stack::default(),
        };
        self.function_map.add(Function::new(&location, kind));
        self.queue.push(location);
    }

    pub fn analyze(&mut self) -> Result<(), BlockAnalysisError> {
        loop {
            while let Some(location) = self.queue.pop() {
                let Some(module) = self.modules.get(&location.module) else {
                    return ModuleNotFoundSnafu { module: location.module }.fail();
                };

                let function_address = match location.kind {
                    AnalysisLocationKind::Function => FunctionAddress(location.address),
                    AnalysisLocationKind::Label { function } => FunctionAddress(function.0),
                };
                let mut function = self
                    .function_map
                    .remove(location.module, function_address)
                    .unwrap_or_else(|| Function::new(&location, FunctionKind::Default));
                if function.has_analyzed_block(&self.block_map, location.address) {
                    continue; // Block already analyzed
                }

                let new_locations =
                    function.analyze_block(module, &location, &self.modules, &mut self.function_map, &mut self.block_map);

                let mut data_addresses = if let Some(block) = self.block_map.get(location.module, location.address) {
                    let Block::Analyzed(analyzed_block) = block else {
                        log::error!("Expected analyzed block at {:#010x} in module {:?}", location.address, location.module);
                        return PendingBlockSnafu { address: location.address, module: location.module }.fail();
                    };
                    analyzed_block.data_reads.values().copied().collect::<Vec<_>>()
                } else {
                    vec![]
                };

                if let Some(new_locations) = new_locations {
                    self.function_map.add(function);
                    self.queue.extend(new_locations.into_values());
                } else {
                    data_addresses.push(location.address);
                }

                for data_address in data_addresses {
                    self.add_data_region(data_address, &location);
                }
            }

            for function in self.function_map.iter() {
                if function.is_empty(&self.block_map) {
                    log::error!("Function at {:#010x} in module {:?} is empty", function.address(), function.module());
                    return EmptyFunctionSnafu { address: function.address(), module: function.module() }.fail();
                }
            }
            if let Some(block) = self.block_map.first_pending_block() {
                log::error!("Pending blocks found in block map");
                return PendingBlockSnafu { address: block.address(), module: block.module() }.fail();
            }

            for function in self.function_map.iter_mut() {
                function.update_end_address(&self.block_map);
            }

            let Some((module, start_address)) = self.find_function_gap() else {
                break;
            };
            let Some(module_code) = self.modules.get(&module) else {
                return ModuleNotFoundSnafu { module }.fail();
            };
            let code_slice = module_code.slice_from(start_address);
            let is_thumb = Self::is_thumb_function(start_address, code_slice);
            let mode = if is_thumb { InstructionMode::Thumb } else { InstructionMode::Arm };

            self.add_function_location(start_address, module, mode, FunctionKind::Default);
        }

        Ok(())
    }

    fn add_data_region(&mut self, static_pointer: u32, location: &AnalysisLocation) {
        let module_mut = self.modules.get_mut(&location.module).unwrap();
        if !module_mut.contains_address(static_pointer) {
            return;
        }
        if !module_mut.data_required_range.contains(&static_pointer) {
            return;
        }
        let end = module_mut.end_address.min(module_mut.data_required_range.end);

        if module_mut.data_regions.insert(static_pointer, end) {
            log::debug!(
                "Inserted static data region {:#010x} - {:#010x} for module {:?}",
                static_pointer,
                end,
                location.module
            );
        }
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

    fn find_function_gap(&self) -> Option<(ModuleKind, u32)> {
        for module in self.modules.iter() {
            let mut end_address = module.skip_data_region(module.base_address).next_multiple_of(4);
            for function in self.function_map.for_module(module.kind) {
                let start_address = module.skip_data_region(function.address());
                if end_address < start_address {
                    return Some((module.kind, end_address));
                }
                end_address = module.skip_data_region(function.end_address(&self.block_map).unwrap()).next_multiple_of(4);
            }
            if end_address < module.end_address {
                return Some((module.kind, end_address));
            }
        }
        None
    }

    pub fn functions(&self) -> &FunctionMap {
        &self.function_map
    }

    pub fn block_map(&self) -> &BlockMap {
        &self.block_map
    }
}

impl Function {
    fn new(location: &AnalysisLocation, kind: FunctionKind) -> Self {
        Self {
            entry_block: location.address,
            pool_constants: BTreeSet::new(),
            address: location.address,
            module: location.module,
            mode: location.mode,
            kind,
            end_address: None,
        }
    }

    fn has_analyzed_block(&self, block_map: &BlockMap, address: u32) -> bool {
        block_map.get(self.module, address).map(|block| block.is_analyzed()).unwrap_or(false)
    }

    fn analyze_block(
        &mut self,
        module: &Module,
        location: &AnalysisLocation,
        modules: &Modules,
        functions: &mut FunctionMap,
        block_map: &mut BlockMap,
    ) -> Option<BTreeMap<u32, AnalysisLocation>> {
        if self.try_split_block(block_map, location.address, location.conditional, location.mode, location.address) {
            return Some(BTreeMap::new()); // Block was split, no new locations to analyze
        }

        let mut next: BTreeMap<u32, Vec<u32>> = BTreeMap::new();
        let mut calls = BTreeMap::new();
        let mut data_reads = BTreeMap::new();
        let mut returns = false;

        let parse_flags = ParseFlags { ual: true, version: unarm::ArmVersion::V5Te };
        let mut parser = Parser::new(
            location.mode.into(),
            location.address,
            unarm::Endian::Little,
            parse_flags,
            module.slice_from(location.address),
        );

        let mut jump_table_state = location.jump_table_state;
        let mut function_branch_state = location.function_branch_state;

        let mut registers = location.registers;
        let mut stack = location.stack.clone();

        for (address, ins, parsed_ins) in &mut parser {
            if module.data_regions.contains(address) && !matches!(self.kind, FunctionKind::SecureArea(_)) {
                // Not code
                return None;
            }

            if self.has_analyzed_block(block_map, address) {
                // Traversed into an existing block
                next.entry(address).or_default().push(address);
                break;
            }

            jump_table_state = jump_table_state.handle(address, ins, &parsed_ins);
            function_branch_state = function_branch_state.handle(ins, &parsed_ins);

            if jump_table_state.is_in_table(address) {
                if let Some(dest) = jump_table_state.get_branch_dest(address, ins, &parsed_ins) {
                    block_map.add_if_absent(Block::Pending(AnalysisLocation {
                        address: dest,
                        module: self.module,
                        mode: self.mode,
                        conditional: true,
                        kind: AnalysisLocationKind::Label { function: FunctionAddress(self.address) },
                        jump_table_state: jump_table_state.reset(),
                        function_branch_state,
                        registers,
                        stack: stack.clone(),
                    }));
                    next.entry(address).or_default().push(dest);
                    if jump_table_state.is_last_instruction(address) {
                        break;
                    }
                }
                continue;
            }

            // Dereferencing
            if let (
                "ldr" | "ldrh" | "ldrsh" | "ldrb" | "ldrsb",
                Argument::Reg(Reg { .. }),
                Argument::Reg(Reg { reg, deref: true, .. }),
                offset,
            ) = (ins.mnemonic(), parsed_ins.args[0], parsed_ins.args[1], parsed_ins.args[2])
                && reg != Register::Pc
                && !matches!(offset, Argument::OffsetReg(OffsetReg { reg: Register::R12, .. }))
            {
                if let Some(value) = registers.get(reg) {
                    data_reads.insert(address, value);
                };
            }

            let defs = match ins {
                unarm::Ins::Arm(ins) => ins.defs(&parse_flags),
                unarm::Ins::Thumb(ins) => ins.defs(&parse_flags),
                unarm::Ins::Data => [Argument::None; 6],
            };
            for def in defs {
                match def {
                    Argument::Reg(reg) => registers.clear(reg.reg),
                    Argument::RegList(reg_list) => {
                        for reg in reg_list.iter() {
                            registers.clear(reg);
                        }
                    }
                    _ => {}
                }
            }

            match (ins.mnemonic(), parsed_ins.args[0], parsed_ins.args[1], parsed_ins.args[2]) {
                // Branches
                ("b", Argument::BranchDest(dest), Argument::None, Argument::None) => {
                    let dest = ((address as i32) + dest) as u32;

                    let steps_into_function =
                        functions.for_address(FunctionAddress(parser.address)).any(|f| f.module == self.module);

                    let existing_function =
                        functions.get_mut_by_contained_address(self.module, FunctionAddress(dest), block_map);
                    let is_existing_function = existing_function.is_some();
                    if let Some(existing_function) = existing_function
                        && existing_function.address != dest
                    {
                        existing_function.try_split_block(block_map, dest, location.conditional, location.mode, address);
                    }

                    if function_branch_state.is_function_branch() || is_existing_function {
                        calls.insert(
                            address,
                            FunctionCall {
                                address: dest,
                                mode: self.mode,
                                module: modules.get_solo_module(dest, module),
                            },
                        );

                        let conditional_branch = ins.is_conditional();
                        if conditional_branch {
                            if !steps_into_function {
                                block_map.add_if_absent(Block::Pending(AnalysisLocation {
                                    address: parser.address,
                                    module: self.module,
                                    mode: self.mode,
                                    conditional: true,
                                    kind: AnalysisLocationKind::Label { function: FunctionAddress(self.address) },
                                    jump_table_state,
                                    function_branch_state,
                                    registers,
                                    stack: stack.clone(),
                                }));
                                next.entry(address).or_default().push(parser.address);
                            } else {
                                calls.insert(
                                    parser.address,
                                    FunctionCall { address: dest, mode: self.mode, module: Some(self.module) },
                                );
                            }
                        } else if !location.conditional {
                            // This branch is a tail call
                            returns = true;
                        }
                        break;
                    }

                    let module = modules.get_solo_module(dest, module);
                    if let Some(module) = module
                        && module == self.module
                    {
                        block_map.add_if_absent(Block::Pending(AnalysisLocation {
                            address: dest,
                            module: self.module,
                            mode: self.mode,
                            conditional: location.conditional,
                            kind: AnalysisLocationKind::Label { function: FunctionAddress(self.address) },
                            jump_table_state,
                            function_branch_state,
                            registers,
                            stack: stack.clone(),
                        }));
                        let next_vec = next.entry(address).or_default();
                        next_vec.push(dest);

                        let conditional_branch = ins.is_conditional();
                        if conditional_branch {
                            if !steps_into_function {
                                block_map.add_if_absent(Block::Pending(AnalysisLocation {
                                    address: parser.address,
                                    module: self.module,
                                    mode: self.mode,
                                    conditional: true,
                                    kind: AnalysisLocationKind::Label { function: FunctionAddress(self.address) },
                                    jump_table_state,
                                    function_branch_state,
                                    registers,
                                    stack: stack.clone(),
                                }));
                                next_vec.push(parser.address);
                            } else {
                                calls.insert(address, FunctionCall { address: dest, mode: self.mode, module: Some(module) });
                            }
                        }
                    } else if module.is_some() {
                        log::error!("Branch to {dest:#010x} from {address:#010x} in different module {module:?}");
                    } else {
                        log::error!("Branch to unknown address {dest:#010x} from {address:#010x}");
                    }

                    break;
                }
                // Calls
                ("bl", Argument::BranchDest(dest), Argument::None, Argument::None) => {
                    let dest = ((address as i32) + dest) as u32;
                    let module = modules.get_solo_module(dest, module);
                    calls.insert(address, FunctionCall { address: dest, mode: self.mode, module });
                    continue;
                }
                ("blx", Argument::BranchDest(dest), Argument::None, Argument::None) => {
                    let dest = ((address as i32) + dest) as u32;
                    let dest = if self.mode == InstructionMode::Thumb { dest & !3 } else { dest };
                    let module = modules.get_solo_module(dest, module);
                    calls.insert(address, FunctionCall { address: dest, mode: self.mode.exchange(), module });
                    continue;
                }
                // Returns
                ("bx", Argument::Reg(Reg { reg, .. }), _, _) => {
                    if let Some(value) = registers.get(reg) {
                        let dest = value & !1;
                        let mode = if value & 1 != 0 {
                            InstructionMode::Thumb
                        } else {
                            InstructionMode::Arm
                        };
                        calls.insert(
                            address,
                            FunctionCall { address: dest, mode, module: modules.get_solo_module(dest, module) },
                        );
                    }
                    returns = true;
                    if !ins.is_conditional() {
                        break;
                    }
                }
                ("mov", Argument::Reg(Reg { reg: Register::Pc, .. }), _, _) => {
                    returns = true;
                    if !ins.is_conditional() {
                        break;
                    }
                }
                ("pop", Argument::RegList(reg_list), _, _) if reg_list.contains(Register::Pc) => {
                    returns = true;
                    if !ins.is_conditional() {
                        break;
                    }
                }
                ("subs", Argument::Reg(Reg { reg: Register::Pc, .. }), Argument::Reg(Reg { reg: Register::Lr, .. }), _) => {
                    returns = true;
                    if !ins.is_conditional() {
                        break;
                    }
                }
                ("ldr", Argument::Reg(Reg { reg: Register::Pc, .. }), _, _) => {
                    returns = true;
                    if !ins.is_conditional() {
                        break;
                    }
                }
                // Pool loads
                (
                    "ldr",
                    Argument::Reg(Reg { reg, .. }),
                    Argument::Reg(Reg { reg: Register::Pc, deref: true, .. }),
                    Argument::OffsetImm(OffsetImm { value, .. }),
                ) => {
                    let load_address = (address as i32 + value) as u32 & !3;
                    let load_address = load_address + if self.mode == InstructionMode::Thumb { 4 } else { 8 };
                    let load_value = u32::from_le_slice(module.slice_from(load_address));
                    registers.set(reg, load_value);

                    self.pool_constants.insert(load_address);
                }
                // Stack allocation
                (
                    "str",
                    Argument::Reg(Reg { reg, .. }),
                    Argument::Reg(Reg { reg: Register::Sp, deref: true, .. }),
                    Argument::OffsetImm(OffsetImm { value: offset, .. }),
                ) => {
                    if let Some(value) = registers.get(reg) {
                        stack.values.insert(offset, value);
                    }
                }
                (
                    "ldr",
                    Argument::Reg(Reg { reg, .. }),
                    Argument::Reg(Reg { reg: Register::Sp, deref: true, .. }),
                    Argument::OffsetImm(OffsetImm { value: offset, .. }),
                ) => {
                    if let Some(value) = stack.values.get(&offset) {
                        registers.set(reg, *value);
                    }
                }
                _ => continue,
            };
        }

        let end_address = parser.address;
        let block = BasicBlock {
            module: self.module,
            start_address: location.address,
            end_address,
            next,
            calls,
            data_reads,
            conditional: location.conditional,
            returns,
        };

        let analysis_locations = block.get_analysis_locations(self, block_map);
        block_map.insert(Block::Analyzed(block));
        Some(analysis_locations)
    }

    fn get_block<'a>(&'a self, block_map: &'a BlockMap, address: u32) -> Option<&'a Block> {
        block_map.get(self.module, address)
    }

    fn try_split_block(
        &mut self,
        block_map: &mut BlockMap,
        address: u32,
        conditional: bool,
        mode: InstructionMode,
        from: u32,
    ) -> bool {
        if self.mode != mode {
            log::warn!(
                "Cannot split block at {:#010x} in function at {:#010x} in module {:?}: mode mismatch from {:#010x}",
                address,
                self.address,
                self.module,
                from
            );
            return false; // Mode mismatch
        }
        let Some(block_to_split) = block_map.get_by_contained_address(self.module, address) else {
            return false; // No block to split
        };
        let Block::Analyzed(block_to_split) = block_to_split else {
            return false; // Cannot split a pending block
        };
        if address >= block_to_split.end_address {
            return false; // Address is not within the block
        }

        let mut first_next = block_to_split.next.range(..address).map(|(&k, v)| (k, v.clone())).collect::<BTreeMap<_, _>>();
        first_next.entry(address).or_default().push(address);
        let first_block = BasicBlock {
            module: self.module,
            start_address: block_to_split.start_address,
            end_address: address,
            next: first_next,
            calls: block_to_split.calls.range(..address).map(|(&k, &v)| (k, v)).collect(),
            data_reads: block_to_split.data_reads.range(..address).map(|(&k, &v)| (k, v)).collect(),
            conditional: block_to_split.conditional,
            returns: false,
        };
        let second_block = BasicBlock {
            module: self.module,
            start_address: address,
            end_address: block_to_split.end_address,
            next: block_to_split.next.range(address..).map(|(&k, v)| (k, v.clone())).collect(),
            calls: block_to_split.calls.range(address..).map(|(&k, &v)| (k, v)).collect(),
            data_reads: block_to_split.data_reads.range(address..).map(|(&k, &v)| (k, v)).collect(),
            conditional: block_to_split.conditional && conditional,
            returns: block_to_split.returns,
        };

        block_map.insert(Block::Analyzed(first_block));
        block_map.insert(Block::Analyzed(second_block));

        true
    }

    fn is_empty(&self, block_map: &BlockMap) -> bool {
        let Some(block) = block_map.get(self.module, self.entry_block) else {
            return true;
        };
        match block {
            Block::Analyzed(b) => b.start_address == b.end_address,
            Block::Pending(_) => true,
        }
    }

    pub fn update_end_address(&mut self, block_map: &BlockMap) -> Option<u32> {
        if let Some(end_address) = self.end_address {
            return Some(end_address);
        }
        self.end_address = self.calculate_end_address(block_map);
        self.end_address
    }

    pub fn end_address(&self, block_map: &BlockMap) -> Option<u32> {
        if let Some(end_address) = self.end_address {
            return Some(end_address);
        }
        self.calculate_end_address(block_map)
    }

    fn calculate_end_address(&self, block_map: &BlockMap) -> Option<u32> {
        let last_block_end = self
            .blocks(block_map)
            .last_key_value()
            .or_else(|| {
                log::error!("No blocks found in function at {:#010x} in module {:?}", self.address, self.module);
                None
            })
            .and_then(|(_, block)| match block {
                Block::Analyzed(b) => Some(b.end_address),
                Block::Pending(_) => None,
            })?;
        let last_pool_constant_end = self.pool_constants.iter().last().map(|&addr| addr + 4).unwrap_or(0);
        Some(last_block_end.max(last_pool_constant_end))
    }
}

impl BasicBlock {
    pub fn get_analysis_locations(&self, function: &Function, block_map: &BlockMap) -> BTreeMap<u32, AnalysisLocation> {
        let mut analysis_locations = BTreeMap::new();
        for next_addresses in self.next.values() {
            for &next_address in next_addresses {
                let next_block = function.get_block(block_map, next_address).unwrap();
                let Block::Pending(location) = next_block else {
                    continue;
                };
                analysis_locations.insert(location.address, location.clone());
            }
        }
        for call in self.calls.values() {
            let Some(module) = call.module else {
                continue;
            };
            analysis_locations.insert(
                call.address,
                AnalysisLocation {
                    address: call.address,
                    module,
                    mode: call.mode,
                    conditional: false,
                    kind: AnalysisLocationKind::Function,
                    jump_table_state: JumpTableState::new(call.mode == InstructionMode::Thumb),
                    function_branch_state: FunctionBranchState::default(),
                    registers: Registers::new(),
                    stack: Stack::default(),
                },
            );
        }
        analysis_locations
    }
}

impl Module {
    pub fn new(options: ModuleOptions) -> Self {
        Self {
            base_address: options.base_address,
            end_address: options.end_address,
            kind: options.kind,
            code: options.code,
            data_regions: RangeSet::from_ranges(options.data_regions),
            data_required_range: options.data_required_range,
        }
    }

    pub fn contains_address(&self, address: u32) -> bool {
        address >= self.base_address && address < self.end_address
    }

    pub fn slice_from(&self, start: u32) -> &[u8] {
        let start_index = (start - self.base_address) as usize;
        &self.code[start_index..]
    }

    pub fn skip_data_region(&self, mut address: u32) -> u32 {
        // TODO: Sort and combine data_regions and use binary search
        'outer: loop {
            for &(start, end) in self.data_regions.iter() {
                if address >= start && address < end {
                    address = end;
                    continue 'outer;
                }
            }
            return address;
        }
    }
}

impl Modules {
    fn new() -> Self {
        Self { main: None, overlays: BTreeMap::new(), autoloads: BTreeMap::new() }
    }

    fn add(&mut self, module: Module) {
        match module.kind {
            ModuleKind::Arm9 => self.main = Some(module),
            ModuleKind::Autoload(autoload_kind) => {
                self.autoloads.insert(autoload_kind, module);
            }
            ModuleKind::Overlay(id) => {
                self.overlays.insert(id, module);
            }
        }
    }

    fn get(&self, kind: &ModuleKind) -> Option<&Module> {
        match kind {
            ModuleKind::Arm9 => self.main.as_ref(),
            ModuleKind::Autoload(autoload_kind) => self.autoloads.get(autoload_kind),
            ModuleKind::Overlay(id) => self.overlays.get(id),
        }
    }

    fn get_mut(&mut self, module: &ModuleKind) -> Option<&mut Module> {
        match module {
            ModuleKind::Arm9 => self.main.as_mut(),
            ModuleKind::Autoload(autoload_kind) => self.autoloads.get_mut(autoload_kind),
            ModuleKind::Overlay(id) => self.overlays.get_mut(id),
        }
    }

    fn iter(&self) -> impl Iterator<Item = &Module> {
        self.overlays.values().chain(self.autoloads.values()).chain(self.main.as_ref())
    }

    fn get_solo_module(&self, address: u32, current_module: &Module) -> Option<ModuleKind> {
        if current_module.contains_address(address) {
            return Some(current_module.kind);
        }

        let modules =
            self.iter().filter(|module| module.contains_address(address)).map(|module| module.kind).collect::<Vec<_>>();
        if modules.len() == 1 { Some(modules[0]) } else { None }
    }
}

impl AnalysisQueue {
    pub fn new() -> Self {
        Self { queue: BinaryHeap::new(), visited: BTreeSet::new() }
    }

    pub fn push(&mut self, location: AnalysisLocation) {
        let key = (location.module, location.address);
        if !self.visited.contains(&key) {
            self.queue.push(Reverse(location));
            self.visited.insert(key);
        }
    }

    pub fn pop(&mut self) -> Option<AnalysisLocation> {
        self.queue.pop().map(|Reverse(location)| location)
    }

    pub fn extend(&mut self, locations: impl IntoIterator<Item = AnalysisLocation>) {
        for location in locations {
            self.push(location);
        }
    }
}

impl PartialOrd for AnalysisLocation {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for AnalysisLocation {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.address.cmp(&other.address)
    }
}

impl Registers {
    pub fn new() -> Self {
        Self { values: [None; 16] }
    }

    pub fn set(&mut self, reg: Register, value: u32) {
        self.values[reg as usize] = Some(value);
    }

    pub fn clear(&mut self, reg: Register) {
        self.values[reg as usize] = None;
    }

    pub fn get(&self, reg: Register) -> Option<u32> {
        self.values[reg as usize]
    }
}

impl AnalysisLocation {
    pub fn address(&self) -> u32 {
        self.address
    }

    pub fn module(&self) -> ModuleKind {
        self.module
    }

    pub fn mode(&self) -> InstructionMode {
        self.mode
    }
}
