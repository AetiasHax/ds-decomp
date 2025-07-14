use std::{collections::BTreeMap, fmt::Display};

use crate::{
    analysis::code::blocks::AnalysisLocation,
    config::{module::ModuleKind, symbol::InstructionMode},
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct BlockAddress(pub u32);

#[derive(Debug)]
pub enum Block {
    Analyzed(BasicBlock),
    Pending(AnalysisLocation),
}

#[derive(Debug)]
pub struct BasicBlock {
    pub module: ModuleKind,
    pub start_address: u32,
    pub end_address: u32,
    pub next: BTreeMap<u32, Vec<BlockAddress>>,
    pub calls: BTreeMap<u32, FunctionCall>,
    pub data_reads: BTreeMap<u32, u32>,
    pub conditional: bool,
    pub returns: bool,
}

#[derive(Clone, Copy, Debug)]
pub struct FunctionCall {
    pub address: u32,
    pub mode: InstructionMode,
    pub module: Option<ModuleKind>,
}

pub struct BlockMap {
    blocks: BTreeMap<(ModuleKind, BlockAddress), Block>,
}

impl BlockMap {
    pub fn new() -> Self {
        Self { blocks: BTreeMap::new() }
    }

    pub fn insert(&mut self, block: Block) {
        let module = block.module();
        let address = block.address();
        self.blocks.insert((module, address), block);
    }

    pub fn remove(&mut self, module: ModuleKind, address: BlockAddress) -> Option<Block> {
        self.blocks.remove(&(module, address))
    }

    pub fn get(&self, module: ModuleKind, address: u32) -> Option<&Block> {
        self.blocks.get(&(module, BlockAddress(address)))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Block> {
        self.blocks.values()
    }

    pub fn add_if_absent(&mut self, block: Block) {
        self.blocks.entry((block.module(), block.address())).or_insert(block);
    }
}

impl Block {
    pub fn address(&self) -> BlockAddress {
        match self {
            Block::Analyzed(basic_block) => BlockAddress(basic_block.start_address),
            Block::Pending(location) => BlockAddress(location.address()),
        }
    }

    pub fn module(&self) -> ModuleKind {
        match self {
            Block::Analyzed(basic_block) => basic_block.module,
            Block::Pending(location) => location.module(),
        }
    }

    pub fn is_analyzed(&self) -> bool {
        matches!(self, Block::Analyzed(_))
    }

    pub fn display(&self, indent: usize) -> DisplayBlock {
        DisplayBlock { block: self, indent }
    }
}

pub struct DisplayBlock<'a> {
    block: &'a Block,
    indent: usize,
}

impl Display for DisplayBlock<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = " ".repeat(self.indent);
        match self.block {
            Block::Analyzed(basic_block) => {
                writeln!(f, "Block {{")?;
                writeln!(f, "{i}  module: {:?}", basic_block.module)?;
                writeln!(f, "{i}  start_address: {:#010x}", basic_block.start_address)?;
                writeln!(f, "{i}  end_address: {:#010x}", basic_block.end_address)?;
                writeln!(f, "{i}  next: [")?;
                for (address, targets) in &basic_block.next {
                    write!(f, "{i}    {address:#010x}: [")?;
                    for target in targets {
                        write!(f, "{:#010x},", target.0)?;
                    }
                    writeln!(f, "]")?;
                }
                writeln!(f, "{i}  ]")?;
                writeln!(f, "{i}  calls: [")?;
                for (address, call) in &basic_block.calls {
                    writeln!(
                        f,
                        "{i}    {:#010x}: FunctionCall {{ address: {:#010x}, mode: {:?}, module: {:?} }}",
                        address, call.address, call.mode, call.module
                    )?;
                }
                writeln!(f, "{i}  ]")?;
                writeln!(f, "{i}  data_reads: [")?;
                for (address, data) in &basic_block.data_reads {
                    writeln!(f, "{i}    {address:#010x}: {data:#010x}")?;
                }
                writeln!(f, "{i}  ]")?;
                writeln!(f, "{i}  conditional: {}", basic_block.conditional)?;
                writeln!(f, "{i}  returns: {}", basic_block.returns)?;
                write!(f, "{i}}}")?;
                Ok(())
            }
            Block::Pending(location) => {
                write!(f, "{i}PendingBlock {{ module: {:?}, address: {:#010x} }}", location.module(), location.address())
            }
        }
    }
}
