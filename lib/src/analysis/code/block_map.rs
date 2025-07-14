use std::collections::BTreeMap;

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
}
