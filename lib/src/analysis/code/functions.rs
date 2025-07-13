use std::collections::{BTreeMap, BTreeSet};

use crate::{
    analysis::code::blocks::Block,
    config::{module::ModuleKind, symbol::InstructionMode},
};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct FunctionAddress(pub u32);

#[derive(Debug)]
pub struct Function {
    pub(super) blocks: BTreeMap<u32, Block>,
    pub(super) pool_constants: BTreeSet<u32>,
    pub(super) address: u32,
    pub(super) module: ModuleKind,
    pub(super) mode: InstructionMode,
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

    pub fn get_mut_by_contained_address(&mut self, module: ModuleKind, address: FunctionAddress) -> Option<&mut Function> {
        let (module, start_address) = self
            .functions_by_address
            .range(..=address)
            .rev()
            .filter_map(|(&start_address, modules)| {
                let module = modules.iter().find(|&&m| m.is_static() || m == module)?;
                let function = self.functions.get(&(*module, start_address)).unwrap();
                let end_address = function.end_address().unwrap_or(start_address.0 + 1);
                (address.0 < end_address).then_some((*module, start_address))
            })
            .next()?;
        self.functions.get_mut(&(module, start_address))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Function> {
        self.functions.values()
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
}
