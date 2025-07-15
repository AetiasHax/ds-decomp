use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
};

use crate::{
    analysis::{
        code::block_map::{Block, BlockMap},
        secure_area::SecureAreaFunction,
    },
    config::{module::ModuleKind, symbol::InstructionMode},
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct FunctionAddress(pub u32);

#[derive(Debug)]
pub struct Function {
    pub(super) entry_block: u32,
    pub(super) pool_constants: BTreeSet<u32>,
    pub(super) address: u32,
    pub(super) module: ModuleKind,
    pub(super) mode: InstructionMode,
    pub(super) kind: FunctionKind,
    pub(super) end_address: Option<u32>,
}

#[derive(Debug)]
pub enum FunctionKind {
    Default,
    SecureArea(SecureAreaFunction),
}

pub struct FunctionMap {
    functions: BTreeMap<(ModuleKind, FunctionAddress), Function>,
    functions_by_address: BTreeMap<FunctionAddress, Vec<ModuleKind>>,
    functions_by_module: BTreeMap<ModuleKind, BTreeSet<FunctionAddress>>,
}

impl FunctionMap {
    pub fn new() -> Self {
        Self {
            functions: BTreeMap::new(),
            functions_by_address: BTreeMap::new(),
            functions_by_module: BTreeMap::new(),
        }
    }

    pub fn add(&mut self, function: Function) {
        let module = function.module;
        let address = FunctionAddress(function.address);
        self.functions.insert((module, address), function);
        self.functions_by_address.entry(address).or_default().push(module);
        self.functions_by_module.entry(module).or_default().insert(address);
    }

    pub fn remove(&mut self, module: ModuleKind, address: FunctionAddress) -> Option<Function> {
        let function = self.functions.remove(&(module, address))?;

        let by_address = self.functions_by_address.get_mut(&address).unwrap();
        by_address.retain(|&m| m != module);
        if by_address.is_empty() {
            self.functions_by_address.remove(&address);
        }

        let by_module = self.functions_by_module.get_mut(&module).unwrap();
        by_module.retain(|&addr| addr != address);
        if by_module.is_empty() {
            self.functions_by_module.remove(&module);
        }

        Some(function)
    }

    pub fn for_address(&self, address: FunctionAddress) -> impl Iterator<Item = &Function> {
        self.functions_by_address
            .get(&address)
            .map(|modules| modules.iter().filter_map(move |&module| self.functions.get(&(module, address))))
            .into_iter()
            .flatten()
    }

    pub fn for_module(&self, module: ModuleKind) -> impl Iterator<Item = &Function> {
        self.functions_by_module
            .get(&module)
            .map(|addresses| addresses.iter().filter_map(move |&address| self.functions.get(&(module, address))))
            .into_iter()
            .flatten()
    }

    pub fn get(&self, module: ModuleKind, address: FunctionAddress) -> Option<&Function> {
        self.functions.get(&(module, address))
    }

    pub fn get_mut_by_contained_address(
        &mut self,
        module: ModuleKind,
        address: FunctionAddress,
        block_map: &BlockMap,
    ) -> Option<&mut Function> {
        let (module, start_address) = self
            .functions_by_address
            .range(..=address)
            .rev()
            .filter_map(|(&start_address, modules)| {
                let module = modules.iter().find(|&&m| m.is_static() || m == module)?;
                let function = self.functions.get(&(*module, start_address)).unwrap();
                let end_address = function.end_address(block_map).unwrap_or(start_address.0 + 1);
                (address.0 < end_address).then_some((*module, start_address))
            })
            .next()?;
        self.functions.get_mut(&(module, start_address))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Function> {
        self.functions.values()
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = &mut Function> {
        self.functions.values_mut()
    }
}

impl Function {
    pub fn address(&self) -> u32 {
        self.address
    }

    pub fn module(&self) -> ModuleKind {
        self.module
    }

    pub fn mode(&self) -> InstructionMode {
        self.mode
    }

    pub fn display<'a>(&'a self, block_map: &'a BlockMap, indent: usize) -> DisplayFunction<'a> {
        DisplayFunction { function: self, block_map, indent }
    }

    pub fn blocks<'a>(&self, block_map: &'a BlockMap) -> BTreeMap<u32, &'a Block> {
        let mut blocks = BTreeMap::new();
        let Some(block) = block_map.get(self.module, self.entry_block) else {
            log::error!("Entry block for function {:#010x} in module {} not found", self.address, self.module);
            return blocks;
        };
        blocks.insert(self.entry_block, block);

        let mut queue = vec![block];
        while let Some(block) = queue.pop() {
            let Block::Analyzed(basic_block) = block else {
                continue;
            };

            for nexts in basic_block.next.values() {
                for &next in nexts {
                    if let Some(next_block) = block_map.get(self.module, next) {
                        if !blocks.contains_key(&next_block.address()) {
                            blocks.insert(next, next_block);
                            queue.push(next_block);
                        }
                    } else {
                        log::warn!(
                            "Next block {:#010x} for function {:#010x} in module {} not found",
                            next,
                            self.address,
                            self.module
                        );
                    }
                }
            }
        }

        blocks
    }
}

pub struct DisplayFunction<'a> {
    function: &'a Function,
    block_map: &'a BlockMap,
    indent: usize,
}

impl Display for DisplayFunction<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let i = " ".repeat(self.indent);
        writeln!(f, "Function {{")?;
        writeln!(f, "{i}  address: {:#010x}", self.function.address)?;
        writeln!(f, "{i}  module: {:?}", self.function.module)?;
        writeln!(f, "{i}  mode: {:?}", self.function.mode)?;
        writeln!(f, "{i}  pool_constants: [")?;
        for constant in &self.function.pool_constants {
            writeln!(f, "{i}    {constant:#010x},")?;
        }
        writeln!(f, "{i}  ]")?;
        writeln!(f, "{i}  blocks: [")?;
        for block in self.function.blocks(self.block_map).values() {
            writeln!(f, "{i}    {:#010x}: {}", block.address(), block.display(self.indent + 4))?;
        }
        writeln!(f, "{i}  ]")?;
        write!(f, "{i}}}")?;
        Ok(())
    }
}
