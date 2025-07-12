use crate::util::bytes::FromSlice;
use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet, BinaryHeap},
};

use snafu::Snafu;
use unarm::{
    ParseFlags, Parser,
    args::{Argument, OffsetImm, Reg, Register},
};

use crate::{
    analysis::jump_table::JumpTableState,
    config::{module::ModuleKind, symbol::InstructionMode},
};

#[derive(Debug)]
pub struct Module {
    pub base_address: u32,
    pub end_address: u32,
    pub kind: ModuleKind,
    pub code: Vec<u8>,
}

struct Modules(BTreeMap<ModuleKind, Module>);

pub struct BlockAnalyzer {
    modules: Modules,
    functions: BTreeMap<FunctionAddress, Function>,
    queue: AnalysisQueue,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct FunctionAddress(u32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AnalysisLocation {
    address: u32,
    module: ModuleKind,
    mode: InstructionMode,
    conditional: bool,
    kind: AnalysisLocationKind,
    jump_table_state: JumpTableState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnalysisLocationKind {
    Function,
    Label { function: FunctionAddress },
}

pub struct AnalysisQueue {
    queue: BinaryHeap<Reverse<AnalysisLocation>>, // reverse for min-heap
    visited: BTreeSet<u32>,
}

#[derive(Debug)]
pub struct Function {
    blocks: BTreeMap<u32, Block>,
    address: u32,
    module: ModuleKind,
    mode: InstructionMode,
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
struct BlockAddress(u32);

#[derive(Debug)]
enum Block {
    Analyzed(BasicBlock),
    Pending(AnalysisLocation),
}

#[derive(Debug)]
struct BasicBlock {
    start_address: u32,
    end_address: u32,
    next: BTreeMap<u32, Vec<BlockAddress>>,
    calls: BTreeMap<u32, FunctionCall>,
    conditional: bool,
    returns: bool,
}

#[derive(Clone, Copy, Debug)]
struct FunctionCall {
    address: u32,
    mode: InstructionMode,
    module: Option<ModuleKind>,
}

struct Registers {
    values: [Option<u32>; 16],
}

#[derive(Debug, Snafu)]
pub enum BlockAnalysisError {
    ModuleNotFound { module: ModuleKind },
    FunctionNotFound { address: FunctionAddress },
}

impl BlockAnalyzer {
    pub fn new() -> Self {
        Self {
            modules: Modules(BTreeMap::new()),
            functions: BTreeMap::new(),
            queue: AnalysisQueue::new(),
        }
    }

    pub fn add_module(&mut self, module: Module) {
        self.modules.0.insert(module.kind, module);
    }

    pub fn add_function_location(&mut self, address: u32, module: ModuleKind, mode: InstructionMode) {
        let location = AnalysisLocation {
            address,
            module,
            mode,
            conditional: false,
            kind: AnalysisLocationKind::Function,
            jump_table_state: JumpTableState::new(mode == InstructionMode::Thumb),
        };
        self.functions.insert(FunctionAddress(address), Function::new(&location));
        self.queue.push(location);
    }

    pub fn analyze(&mut self) -> Result<(), BlockAnalysisError> {
        while let Some(location) = self.queue.pop() {
            let Some(module_code) = self.modules.0.get(&location.module) else {
                return ModuleNotFoundSnafu { module: location.module }.fail();
            };

            let function_address = match location.kind {
                AnalysisLocationKind::Function => FunctionAddress(location.address),
                AnalysisLocationKind::Label { function } => FunctionAddress(function.0),
            };
            let mut function = self.functions.remove(&function_address).unwrap_or_else(|| Function::new(&location));
            if function.has_analyzed_block(location.address) {
                continue; // Block already analyzed
            }

            let new_locations = function.analyze_block(module_code, &location, &self.modules, &self.functions);

            self.functions.insert(function_address, function);

            self.queue.extend(new_locations.into_values());
        }

        Ok(())
    }

    pub fn functions(&self) -> &BTreeMap<FunctionAddress, Function> {
        &self.functions
    }
}

impl Function {
    fn new(location: &AnalysisLocation) -> Self {
        Self {
            blocks: BTreeMap::new(),
            address: location.address,
            module: location.module,
            mode: location.mode,
        }
    }

    fn has_analyzed_block(&self, address: u32) -> bool {
        self.blocks.get(&address).map(|block| matches!(block, Block::Analyzed(_))).unwrap_or(false)
    }

    fn analyze_block(
        &mut self,
        module: &Module,
        location: &AnalysisLocation,
        modules: &Modules,
        functions: &BTreeMap<FunctionAddress, Function>,
    ) -> BTreeMap<u32, AnalysisLocation> {
        if self.try_split_block(location) {
            return BTreeMap::new(); // Block was split, no new locations to analyze
        }

        let mut next = BTreeMap::new();
        let mut calls = BTreeMap::new();
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

        let mut registers = Registers::new();

        for (address, ins, parsed_ins) in &mut parser {
            if self.has_analyzed_block(address) {
                // Traversed into an existing block
                next.entry(address).or_insert_with(Vec::new).push(BlockAddress(address));
                break;
            }

            jump_table_state = jump_table_state.handle(address, ins, &parsed_ins);

            if let Some(dest) = jump_table_state.get_branch_dest(address, ins, &parsed_ins) {
                self.get_or_create_block(dest, true, JumpTableState::new(location.mode == InstructionMode::Thumb));
                next.entry(address).or_insert_with(Vec::new).push(BlockAddress(dest));
                if jump_table_state.is_last_instruction(address) {
                    break;
                }
                continue;
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

                    if functions.contains_key(&FunctionAddress(dest)) {
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
                            self.get_or_create_block(parser.address, true, jump_table_state);
                            next.entry(address).or_insert_with(Vec::new).push(BlockAddress(parser.address));
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
                        self.get_or_create_block(dest, location.conditional, jump_table_state);
                        let next_vec = next.entry(address).or_insert_with(Vec::new);
                        next_vec.push(BlockAddress(dest));

                        let conditional_branch = ins.is_conditional();
                        if conditional_branch {
                            self.get_or_create_block(parser.address, true, jump_table_state);
                            next_vec.push(BlockAddress(parser.address));
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
                ("ldmia", _, Argument::RegList(reg_list), _) if reg_list.contains(Register::Pc) => {
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
                }
                _ => continue,
            };
        }

        let end_address = parser.address;
        let block = BasicBlock {
            start_address: location.address,
            end_address,
            next,
            calls,
            conditional: location.conditional,
            returns,
        };

        let analysis_locations = block.get_analysis_locations(self);
        self.blocks.insert(location.address, Block::Analyzed(block));
        analysis_locations
    }

    fn get_or_create_block(&mut self, address: u32, conditional: bool, jump_table_state: JumpTableState) -> &mut Block {
        self.blocks.entry(address).or_insert_with(|| {
            Block::Pending(AnalysisLocation {
                address,
                module: self.module,
                mode: self.mode,
                conditional,
                kind: AnalysisLocationKind::Label { function: FunctionAddress(self.address) },
                jump_table_state,
            })
        })
    }

    fn try_split_block(&mut self, location: &AnalysisLocation) -> bool {
        let address = location.address;
        let Some((_, block_to_split)) = self.blocks.range(..address).last() else {
            return false; // No block to split
        };
        let Block::Analyzed(block_to_split) = block_to_split else {
            return false; // Cannot split a pending block
        };
        if address >= block_to_split.end_address {
            return false; // Address is not within the block
        }

        let mut first_next = block_to_split.next.range(..address).map(|(&k, v)| (k, v.clone())).collect::<BTreeMap<_, _>>();
        first_next.entry(address).or_insert_with(Vec::new).push(BlockAddress(address));
        let first_block = BasicBlock {
            start_address: block_to_split.start_address,
            end_address: address,
            next: first_next,
            calls: block_to_split.calls.range(..address).map(|(&k, &v)| (k, v)).collect(),
            conditional: block_to_split.conditional,
            returns: false,
        };
        let second_block = BasicBlock {
            start_address: address,
            end_address: block_to_split.end_address,
            next: block_to_split.next.range(address..).map(|(&k, v)| (k, v.clone())).collect(),
            calls: block_to_split.calls.range(address..).map(|(&k, &v)| (k, v)).collect(),
            conditional: block_to_split.conditional && location.conditional,
            returns: block_to_split.returns,
        };

        self.blocks.insert(block_to_split.start_address, Block::Analyzed(first_block));
        self.blocks.insert(address, Block::Analyzed(second_block));

        true
    }
}

impl BasicBlock {
    pub fn get_analysis_locations(&self, function: &Function) -> BTreeMap<u32, AnalysisLocation> {
        let mut analysis_locations = BTreeMap::new();
        for next_addresses in self.next.values() {
            for next_address in next_addresses {
                let next_block = function.blocks.get(&next_address.0).unwrap();
                let Block::Pending(location) = next_block else {
                    continue;
                };
                analysis_locations.insert(location.address, *location);
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
                    jump_table_state: JumpTableState::new(function.mode == InstructionMode::Thumb),
                },
            );
        }
        analysis_locations
    }
}

impl Module {
    pub fn contains_address(&self, address: u32) -> bool {
        address >= self.base_address && address < self.end_address
    }

    pub fn slice_from(&self, start: u32) -> &[u8] {
        let start_index = (start - self.base_address) as usize;
        &self.code[start_index..]
    }
}

impl Modules {
    pub fn get_solo_module(&self, address: u32, current_module: &Module) -> Option<ModuleKind> {
        if current_module.contains_address(address) {
            return Some(current_module.kind);
        }

        let modules =
            self.0.iter().filter(|(_, module)| module.contains_address(address)).map(|(kind, _)| *kind).collect::<Vec<_>>();
        if modules.len() == 1 { Some(modules[0]) } else { None }
    }
}

impl AnalysisQueue {
    pub fn new() -> Self {
        Self { queue: BinaryHeap::new(), visited: BTreeSet::new() }
    }

    pub fn push(&mut self, location: AnalysisLocation) {
        if !self.visited.contains(&location.address) {
            self.queue.push(Reverse(location));
            self.visited.insert(location.address);
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
