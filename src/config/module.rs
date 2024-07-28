use std::path::Path;

use anyhow::Result;
use ds_rom::rom::Overlay;

use crate::analysis::functions::Function;

use super::symbol::{Symbol, SymbolMap};

pub struct Module<'a> {
    symbol_map: SymbolMap,
    functions: Vec<Function<'a>>,
    code: &'a [u8],
    base_address: u32,
    default_name_prefix: String,
}

impl<'a> Module<'a> {
    pub fn new_overlay<P: AsRef<Path>>(symbols: P, overlay: &'a Overlay) -> Result<Self> {
        Ok(Self {
            symbol_map: SymbolMap::from_file(symbols)?,
            functions: vec![],
            code: overlay.code(),
            base_address: overlay.base_address(),
            default_name_prefix: format!("func_ov{:03}_", overlay.id()),
        })
    }

    pub fn find_functions(&mut self, start_address: Option<u32>, end_address: Option<u32>, num_functions: Option<usize>) {
        self.functions = Function::find_functions(
            &self.code,
            self.base_address,
            &self.default_name_prefix,
            &mut self.symbol_map,
            start_address,
            end_address,
            num_functions,
        );
    }

    pub fn add_symbol(&mut self, symbol: Symbol) -> Result<()> {
        self.symbol_map.add(symbol)
    }

    pub fn symbol_map(&self) -> &SymbolMap {
        &self.symbol_map
    }

    pub fn functions(&self) -> &[Function<'a>] {
        &self.functions
    }
}
