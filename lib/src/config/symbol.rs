use std::{
    backtrace::Backtrace,
    collections::{BTreeMap, HashMap, btree_map, hash_map},
    fmt::Display,
    io::{self, BufRead, BufReader, BufWriter, Write},
    num::ParseIntError,
    ops::Range,
    path::Path,
    slice,
};

use snafu::{Snafu, ensure};

use crate::{
    analysis::{functions::Function, jump_table::JumpTable},
    util::{
        io::{FileError, create_file, open_file},
        parse::parse_u32,
    },
};

use super::{ParseContext, config::Config, iter_attributes, module::ModuleKind};

pub struct SymbolMaps {
    symbol_maps: BTreeMap<ModuleKind, SymbolMap>,
}

#[derive(Debug, Snafu)]
pub enum SymbolMapsParseError {
    #[snafu(transparent)]
    SymbolMapParse { source: SymbolMapParseError },
}

#[derive(Debug, Snafu)]
pub enum SymbolMapsWriteError {
    #[snafu(display("Symbol map not found for {module}:\n{backtrace}"))]
    SymbolMapNotFound { module: ModuleKind, backtrace: Backtrace },
    #[snafu(transparent)]
    SymbolMapWrite { source: SymbolMapWriteError },
}

impl SymbolMaps {
    pub fn new() -> Self {
        Self { symbol_maps: BTreeMap::new() }
    }

    pub fn get(&self, module: ModuleKind) -> Option<&SymbolMap> {
        self.symbol_maps.get(&module)
    }

    pub fn get_mut(&mut self, module: ModuleKind) -> &mut SymbolMap {
        self.symbol_maps.entry(module).or_insert_with(SymbolMap::new)
    }

    pub fn from_config<P: AsRef<Path>>(config_path: P, config: &Config) -> Result<Self, SymbolMapsParseError> {
        let config_path = config_path.as_ref();

        let mut symbol_maps = SymbolMaps::new();
        symbol_maps.get_mut(ModuleKind::Arm9).load(config_path.join(&config.main_module.symbols))?;
        for autoload in &config.autoloads {
            symbol_maps.get_mut(ModuleKind::Autoload(autoload.kind)).load(config_path.join(&autoload.module.symbols))?;
        }
        for overlay in &config.overlays {
            symbol_maps.get_mut(ModuleKind::Overlay(overlay.id)).load(config_path.join(&overlay.module.symbols))?;
        }

        Ok(symbol_maps)
    }

    pub fn to_files<P: AsRef<Path>>(&self, config: &Config, config_path: P) -> Result<(), SymbolMapsWriteError> {
        let config_path = config_path.as_ref();
        self.get(ModuleKind::Arm9)
            .ok_or_else(|| SymbolMapNotFoundSnafu { module: ModuleKind::Arm9 }.build())?
            .to_file(config_path.join(&config.main_module.symbols))?;
        for autoload in &config.autoloads {
            let module = ModuleKind::Autoload(autoload.kind);
            self.get(module)
                .ok_or_else(|| SymbolMapNotFoundSnafu { module }.build())?
                .to_file(config_path.join(&autoload.module.symbols))?;
        }
        for overlay in &config.overlays {
            let module = ModuleKind::Overlay(overlay.id);
            self.get(module)
                .ok_or_else(|| SymbolMapNotFoundSnafu { module }.build())?
                .to_file(config_path.join(&overlay.module.symbols))?;
        }

        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = (ModuleKind, &'_ SymbolMap)> {
        self.symbol_maps.iter().map(|(module, symbol_map)| (*module, symbol_map))
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = (ModuleKind, &'_ mut SymbolMap)> {
        self.symbol_maps.iter_mut().map(|(module, symbol_map)| (*module, symbol_map))
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SymbolIndex(usize);

pub struct SymbolMap {
    symbols: Vec<Symbol>,
    symbols_by_address: BTreeMap<u32, Vec<SymbolIndex>>,
    symbols_by_name: HashMap<String, Vec<SymbolIndex>>,
}

#[derive(Debug, Snafu)]
pub enum SymbolMapParseError {
    #[snafu(transparent)]
    File { source: FileError },
    #[snafu(transparent)]
    Io { source: io::Error },
    #[snafu(transparent)]
    SymbolParse { source: SymbolParseError },
}

#[derive(Debug, Snafu)]
pub enum SymbolMapWriteError {
    #[snafu(transparent)]
    File { source: FileError },
    #[snafu(transparent)]
    Io { source: io::Error },
}

#[derive(Debug, Snafu)]
pub enum SymbolMapError {
    #[snafu(display("multiple symbols at {address:#010x}: {name}, {other_name}:\n{backtrace}"))]
    MultipleSymbols { address: u32, name: String, other_name: String, backtrace: Backtrace },
    #[snafu(display("multiple symbols with name '{name}': {old_address:#010x}, {new_address:#010x}:\n{backtrace}"))]
    DuplicateName { name: String, new_address: u32, old_address: u32, backtrace: Backtrace },
    #[snafu(display("no symbol at {address:#010x} to rename to '{new_name}':\n{backtrace}"))]
    NoSymbolToRename { address: u32, new_name: String, backtrace: Backtrace },
    #[snafu(display("there must be exactly one symbol at {address:#010x} to rename to '{new_name}':\n{backtrace}"))]
    RenameMultiple { address: u32, new_name: String, backtrace: Backtrace },
}

impl SymbolMap {
    pub fn new() -> Self {
        Self::from_symbols(vec![])
    }

    pub fn from_symbols(symbols: Vec<Symbol>) -> Self {
        let mut symbols_by_address = BTreeMap::<u32, Vec<_>>::new();
        let mut symbols_by_name = HashMap::<String, Vec<_>>::new();

        for (index, symbol) in symbols.iter().enumerate() {
            symbols_by_address.entry(symbol.addr).or_default().push(SymbolIndex(index));
            symbols_by_name.entry(symbol.name.clone()).or_default().push(SymbolIndex(index));
        }

        Self { symbols, symbols_by_address, symbols_by_name }
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, SymbolMapParseError> {
        let mut symbol_map = Self::new();
        symbol_map.load(path)?;
        Ok(symbol_map)
    }

    pub fn load<P: AsRef<Path>>(&mut self, path: P) -> Result<(), SymbolMapParseError> {
        let path = path.as_ref();
        let mut context = ParseContext { file_path: path.to_str().unwrap().to_string(), row: 0 };

        let file = open_file(path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            context.row += 1;

            let line = line?;
            let comment_start = line.find("//").unwrap_or(line.len());
            let line = &line[..comment_start];

            let Some(symbol) = Symbol::parse(line, &context)? else { continue };
            self.add(symbol);
        }
        Ok(())
    }

    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), SymbolMapWriteError> {
        let path = path.as_ref();

        let file = create_file(path)?;
        let mut writer = BufWriter::new(file);

        for indices in self.symbols_by_address.values() {
            for &index in indices {
                let symbol = &self.symbols[index.0];
                if symbol.should_write() {
                    writeln!(writer, "{symbol}")?;
                }
            }
        }

        Ok(())
    }

    pub fn for_address(&self, address: u32) -> Option<impl DoubleEndedIterator<Item = (SymbolIndex, &Symbol)>> {
        Some(self.symbols_by_address.get(&address)?.iter().map(|&i| (i, &self.symbols[i.0])))
    }

    pub fn by_address(&self, address: u32) -> Result<Option<(SymbolIndex, &Symbol)>, SymbolMapError> {
        let Some(mut symbols) = self.for_address(address) else {
            return Ok(None);
        };
        let (index, symbol) = symbols.next().unwrap();
        if let Some((_, other)) = symbols.next() {
            return MultipleSymbolsSnafu { address, name: symbol.name.clone(), other_name: other.name.clone() }.fail();
        }
        Ok(Some((index, symbol)))
    }

    pub fn first_at_address(&self, address: u32) -> Option<(SymbolIndex, &Symbol)> {
        self.for_address(address)?.next()
    }

    pub fn for_name(&self, name: &str) -> Option<impl DoubleEndedIterator<Item = (SymbolIndex, &Symbol)>> {
        Some(self.symbols_by_name.get(name)?.iter().map(|&i| (i, &self.symbols[i.0])))
    }

    pub fn by_name(&self, name: &str) -> Result<Option<(SymbolIndex, &Symbol)>, SymbolMapError> {
        let Some(mut symbols) = self.for_name(name) else {
            return Ok(None);
        };
        let (index, symbol) = symbols.next().unwrap();
        if let Some((_, other)) = symbols.next() {
            return DuplicateNameSnafu { name, new_address: symbol.addr, old_address: other.addr }.fail();
        }
        Ok(Some((index, symbol)))
    }

    pub fn iter_by_address(&self, range: Range<u32>) -> SymbolIterator {
        SymbolIterator { symbols_by_address: self.symbols_by_address.range(range), indices: [].iter(), symbols: &self.symbols }
    }

    /// Returns the first symbol before the given address, or multiple symbols if they are at the same address.
    pub fn first_symbol_before(&self, max_address: u32) -> Option<Vec<(SymbolIndex, &Symbol)>> {
        self.symbols_by_address.range(0..=max_address).rev().find_map(|(_, indices)| {
            let symbols = indices
                .iter()
                .filter_map(|&i| {
                    let symbol = &self.symbols[i.0];
                    symbol.is_external().then_some((i, symbol))
                })
                .collect::<Vec<_>>();
            (!symbols.is_empty()).then_some(symbols)
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = &'_ Symbol> {
        self.symbols_by_address.values().flat_map(|indices| indices.iter()).map(|&i| &self.symbols[i.0])
    }

    pub fn indices_by_address(&self) -> impl Iterator<Item = &SymbolIndex> {
        self.symbols_by_address.values().flat_map(|indices| indices.iter())
    }

    pub fn get(&self, index: SymbolIndex) -> Option<&Symbol> {
        self.symbols.get(index.0)
    }

    pub fn get_mut(&mut self, index: SymbolIndex) -> Option<&mut Symbol> {
        self.symbols.get_mut(index.0)
    }

    pub fn add(&mut self, symbol: Symbol) -> (SymbolIndex, &Symbol) {
        let index = SymbolIndex(self.symbols.len());
        self.symbols_by_address.entry(symbol.addr).or_default().push(index);
        self.symbols_by_name.entry(symbol.name.clone()).or_default().push(index);
        self.symbols.push(symbol);

        (index, self.symbols.last().unwrap())
    }

    pub fn add_if_new_address(&mut self, symbol: Symbol) -> Result<(SymbolIndex, &Symbol), SymbolMapError> {
        if self.symbols_by_address.contains_key(&symbol.addr) {
            Ok(self.by_address(symbol.addr)?.unwrap())
        } else {
            Ok(self.add(symbol))
        }
    }

    pub fn get_function(&self, address: u32) -> Result<Option<(SymFunction, &Symbol)>, SymbolMapError> {
        let Some(symbols) = self.for_address(address & !1) else {
            return Ok(None);
        };
        let mut symbols = symbols.filter(|(_, sym)| matches!(sym.kind, SymbolKind::Function(_)));
        let Some((_, symbol)) = symbols.next() else {
            return Ok(None);
        };
        if let Some((_, other)) = symbols.next() {
            return MultipleSymbolsSnafu { address, name: symbol.name.clone(), other_name: other.name.clone() }.fail();
        }

        Ok(match symbol.kind {
            SymbolKind::Function(function) => Some((function, symbol)),
            _ => None,
        })
    }

    pub fn get_function_mut(&mut self, address: u32) -> Result<Option<&mut Symbol>, SymbolMapError> {
        let Some(symbols) = self.symbols_by_address.get_mut(&(address & !1)) else {
            return Ok(None);
        };

        let mut symbols = symbols.iter().filter(|i| matches!(self.symbols[i.0].kind, SymbolKind::Function(_)));
        let Some(index) = symbols.next() else {
            return Ok(None);
        };
        if let Some(other_index) = symbols.next() {
            let symbol = &self.symbols[index.0];
            let other = &self.symbols[other_index.0];
            return MultipleSymbolsSnafu { address, name: symbol.name.clone(), other_name: other.name.clone() }.fail();
        }
        let symbol = &mut self.symbols[index.0];

        Ok(Some(symbol))
    }

    pub fn get_function_containing(&self, addr: u32) -> Option<(SymFunction, &Symbol)> {
        self.symbols_by_address
            .range(0..=addr)
            .rev()
            .filter_map(|(_, indices)| {
                let index = indices.first()?;
                let symbol = &self.symbols[index.0];
                if let SymbolKind::Function(func) = symbol.kind {
                    Some((func, symbol))
                } else {
                    None
                }
            })
            .take_while(|(func, sym)| func.contains(sym, addr))
            .next()
    }

    pub fn functions(&self) -> impl Iterator<Item = (SymFunction, &'_ Symbol)> {
        FunctionSymbolIterator {
            symbols_by_address: self.symbols_by_address.values(),
            indices: [].iter(),
            symbols: &self.symbols,
        }
    }

    pub fn clone_functions(&self) -> Vec<(SymFunction, Symbol)> {
        self.functions().map(|(function, symbol)| (function, symbol.clone())).collect()
    }

    pub fn data_symbols(&self) -> impl Iterator<Item = (SymData, &'_ Symbol)> {
        self.symbols.iter().filter_map(|symbol| {
            if let SymbolKind::Data(sym_data) = symbol.kind {
                Some((sym_data, symbol))
            } else {
                None
            }
        })
    }

    pub fn bss_symbols(&self) -> impl Iterator<Item = (SymBss, &'_ Symbol)> {
        self.symbols.iter().filter_map(|symbol| {
            if let SymbolKind::Bss(sym_bss) = symbol.kind {
                Some((sym_bss, symbol))
            } else {
                None
            }
        })
    }

    pub fn label_name(addr: u32) -> String {
        format!(".L_{addr:08x}")
    }

    pub fn add_label(&mut self, addr: u32, thumb: bool) -> Result<(SymbolIndex, &Symbol), SymbolMapError> {
        let name = Self::label_name(addr);
        self.add_if_new_address(Symbol::new_label(name, addr, thumb))
    }

    /// See [SymLabel::external].
    pub fn add_external_label(&mut self, addr: u32, thumb: bool) -> Result<(SymbolIndex, &Symbol), SymbolMapError> {
        let name = Self::label_name(addr);
        self.add_if_new_address(Symbol::new_external_label(name, addr, thumb))
    }

    pub fn get_label(&self, addr: u32) -> Result<Option<&Symbol>, SymbolMapError> {
        Ok(self.by_address(addr)?.and_then(|(_, s)| (matches!(s.kind, SymbolKind::Label { .. })).then_some(s)))
    }

    pub fn add_pool_constant(&mut self, addr: u32) -> Result<(SymbolIndex, &Symbol), SymbolMapError> {
        let name = Self::label_name(addr);
        self.add_if_new_address(Symbol::new_pool_constant(name, addr))
    }

    pub fn get_pool_constant(&self, addr: u32) -> Result<Option<&Symbol>, SymbolMapError> {
        Ok(self.by_address(addr)?.and_then(|(_, s)| (s.kind == SymbolKind::PoolConstant).then_some(s)))
    }

    pub fn get_jump_table(&self, addr: u32) -> Result<Option<(SymJumpTable, &Symbol)>, SymbolMapError> {
        Ok(self.by_address(addr)?.and_then(|(_, s)| match s.kind {
            SymbolKind::JumpTable(jump_table) => Some((jump_table, s)),
            _ => None,
        }))
    }

    fn make_unambiguous(&mut self, addr: u32) -> Result<(), SymbolMapError> {
        if let Some(index) = self
            .by_address(addr)?
            .filter(|(_, symbol)| matches!(symbol.kind, SymbolKind::Data(_) | SymbolKind::Bss(_)))
            .map(|(index, _)| index)
        {
            self.symbols[index.0].ambiguous = false;
        }
        Ok(())
    }

    pub fn add_function(&mut self, function: &Function) -> (SymbolIndex, &Symbol) {
        self.add(Symbol::from_function(function))
    }

    pub fn add_unknown_function(&mut self, name: String, addr: u32, thumb: bool) -> (SymbolIndex, &Symbol) {
        self.add(Symbol::new_unknown_function(name, addr & !1, thumb))
    }

    pub fn add_jump_table(&mut self, table: &JumpTable) -> Result<(SymbolIndex, &Symbol), SymbolMapError> {
        let name = Self::label_name(table.address);
        self.add_if_new_address(Symbol::new_jump_table(name, table.address, table.size, table.code))
    }

    pub fn add_data(
        &mut self,
        name: Option<String>,
        addr: u32,
        data: SymData,
    ) -> Result<(SymbolIndex, &Symbol), SymbolMapError> {
        let name = name.unwrap_or_else(|| Self::label_name(addr));
        self.make_unambiguous(addr)?;
        self.add_if_new_address(Symbol::new_data(name, addr, data, false))
    }

    pub fn add_ambiguous_data(
        &mut self,
        name: Option<String>,
        addr: u32,
        data: SymData,
    ) -> Result<(SymbolIndex, &Symbol), SymbolMapError> {
        let name = name.unwrap_or_else(|| Self::label_name(addr));
        self.add_if_new_address(Symbol::new_data(name, addr, data, true))
    }

    pub fn get_data(&self, addr: u32) -> Result<Option<(SymData, &Symbol)>, SymbolMapError> {
        Ok(self.by_address(addr)?.and_then(|(_, s)| match s.kind {
            SymbolKind::Data(data) => Some((data, s)),
            _ => None,
        }))
    }

    pub fn add_bss(
        &mut self,
        name: Option<String>,
        addr: u32,
        data: SymBss,
    ) -> Result<(SymbolIndex, &Symbol), SymbolMapError> {
        let name = name.unwrap_or_else(|| Self::label_name(addr));
        self.make_unambiguous(addr)?;
        self.add_if_new_address(Symbol::new_bss(name, addr, data, false))
    }

    pub fn add_ambiguous_bss(
        &mut self,
        name: Option<String>,
        addr: u32,
        data: SymBss,
    ) -> Result<(SymbolIndex, &Symbol), SymbolMapError> {
        let name = name.unwrap_or_else(|| Self::label_name(addr));
        self.add_if_new_address(Symbol::new_bss(name, addr, data, true))
    }

    /// Renames a symbol at the given address to the new name.
    ///
    /// Returns true if the symbol was renamed, or false if it was already named the same.
    pub fn rename_by_address(&mut self, address: u32, new_name: &str) -> Result<bool, SymbolMapError> {
        let symbol_indices =
            self.symbols_by_address.get(&address).ok_or_else(|| NoSymbolToRenameSnafu { address, new_name }.build())?;
        ensure!(symbol_indices.len() == 1, RenameMultipleSnafu { address, new_name });

        let symbol_index = symbol_indices[0];
        let name = &self.symbols[symbol_index.0].name;
        if name == new_name {
            return Ok(false);
        }

        match self.symbols_by_name.entry(name.clone()) {
            hash_map::Entry::Occupied(mut entry) => {
                let symbol_indices = entry.get_mut();
                if symbol_indices.len() == 1 {
                    entry.remove();
                } else {
                    // Remove the to-be-renamed symbol's index from the list of indices of symbols with the same name
                    let pos = symbol_indices.iter().position(|&i| i == symbol_index).unwrap();
                    symbol_indices.remove(pos);
                }
            }
            hash_map::Entry::Vacant(_) => {
                panic!("No symbol name entry found for '{name}' when trying to rename to '{new_name}'");
            }
        }

        match self.symbols_by_name.entry(new_name.to_string()) {
            hash_map::Entry::Occupied(mut entry) => {
                entry.get_mut().push(symbol_index);
            }
            hash_map::Entry::Vacant(entry) => {
                entry.insert(vec![symbol_index]);
            }
        }

        self.symbols[symbol_index.0].name = new_name.to_string();

        Ok(true)
    }
}

pub struct SymbolIterator<'a> {
    symbols_by_address: btree_map::Range<'a, u32, Vec<SymbolIndex>>,
    indices: slice::Iter<'a, SymbolIndex>,
    symbols: &'a [Symbol],
}

impl<'a> Iterator for SymbolIterator<'a> {
    type Item = &'a Symbol;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(&index) = self.indices.next() {
            Some(&self.symbols[index.0])
        } else if let Some((_, indices)) = self.symbols_by_address.next() {
            self.indices = indices.iter();
            self.next()
        } else {
            None
        }
    }
}

pub struct FunctionSymbolIterator<'a, I: Iterator<Item = &'a Vec<SymbolIndex>>> {
    symbols_by_address: I, //btree_map::Values<'a, u32, Vec<SymbolIndex>>,
    indices: slice::Iter<'a, SymbolIndex>,
    symbols: &'a [Symbol],
}

impl<'a, I: Iterator<Item = &'a Vec<SymbolIndex>>> FunctionSymbolIterator<'a, I> {
    fn next_function(&mut self) -> Option<(SymFunction, &'a Symbol)> {
        for &index in self.indices.by_ref() {
            let symbol = &self.symbols[index.0];
            if let SymbolKind::Function(function) = symbol.kind {
                return Some((function, symbol));
            }
        }
        None
    }
}

impl<'a, I: Iterator<Item = &'a Vec<SymbolIndex>>> Iterator for FunctionSymbolIterator<'a, I> {
    type Item = (SymFunction, &'a Symbol);

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(function) = self.next_function() {
            return Some(function);
        }
        while let Some(indices) = self.symbols_by_address.next() {
            self.indices = indices.iter();
            if let Some(function) = self.next_function() {
                return Some(function);
            }
        }
        None
    }
}

#[derive(Clone)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub addr: u32,
    /// If true, this symbol is involved in an ambiguous external reference to one of many overlays
    pub ambiguous: bool,
    /// If true, this symbol is local to its translation unit and will not cause duplicate symbol definitions in the linker
    pub local: bool,
}

#[derive(Debug, Snafu)]
pub enum SymbolParseError {
    #[snafu(transparent)]
    SymbolKindParse { source: SymbolKindParseError },
    #[snafu(display("{context}: failed to parse address '{value}': {error}\n{backtrace}"))]
    ParseAddress { context: ParseContext, value: String, error: ParseIntError, backtrace: Backtrace },
    #[snafu(display("{context}: expected symbol attribute 'kind' or 'addr' but got '{key}':\n{backtrace}"))]
    UnknownAttribute { context: ParseContext, key: String, backtrace: Backtrace },
    #[snafu(display("{context}: missing '{attribute}' attribute:\n{backtrace}"))]
    MissingAttribute { context: ParseContext, attribute: String, backtrace: Backtrace },
}

impl Symbol {
    fn parse(line: &str, context: &ParseContext) -> Result<Option<Self>, SymbolParseError> {
        let mut words = line.split_whitespace();
        let Some(name) = words.next() else { return Ok(None) };

        let mut kind = None;
        let mut addr = None;
        let mut ambiguous = false;
        let mut local = false;
        for (key, value) in iter_attributes(words) {
            match key {
                "kind" => kind = Some(SymbolKind::parse(value, context)?),
                "addr" => addr = Some(parse_u32(value).map_err(|error| ParseAddressSnafu { context, value, error }.build())?),
                "ambiguous" => ambiguous = true,
                "local" => local = true,
                _ => return UnknownAttributeSnafu { context, key }.fail(),
            }
        }

        let name = name.to_string();
        let kind = kind.ok_or_else(|| MissingAttributeSnafu { context, attribute: "kind" }.build())?;
        let addr = addr.ok_or_else(|| MissingAttributeSnafu { context, attribute: "addr" }.build())?;

        Ok(Some(Symbol { name, kind, addr, ambiguous, local }))
    }

    fn should_write(&self) -> bool {
        self.kind.should_write()
    }

    pub fn from_function(function: &Function) -> Self {
        Self {
            name: function.name().to_string(),
            kind: SymbolKind::Function(SymFunction {
                mode: InstructionMode::from_thumb(function.is_thumb()),
                size: function.size(),
                unknown: false,
            }),
            addr: function.first_instruction_address() & !1,
            ambiguous: false,
            local: false,
        }
    }

    pub fn new_unknown_function(name: String, addr: u32, thumb: bool) -> Self {
        Self {
            name,
            kind: SymbolKind::Function(SymFunction { mode: InstructionMode::from_thumb(thumb), size: 0, unknown: true }),
            addr,
            ambiguous: false,
            local: false,
        }
    }

    pub fn new_label(name: String, addr: u32, thumb: bool) -> Self {
        Self {
            name,
            kind: SymbolKind::Label(SymLabel { external: false, mode: InstructionMode::from_thumb(thumb) }),
            addr,
            ambiguous: false,
            local: true,
        }
    }

    pub fn new_external_label(name: String, addr: u32, thumb: bool) -> Self {
        Self {
            name,
            kind: SymbolKind::Label(SymLabel { external: true, mode: InstructionMode::from_thumb(thumb) }),
            addr,
            ambiguous: false,
            local: false,
        }
    }

    pub fn new_pool_constant(name: String, addr: u32) -> Self {
        Self { name, kind: SymbolKind::PoolConstant, addr, ambiguous: false, local: true }
    }

    pub fn new_jump_table(name: String, addr: u32, size: u32, code: bool) -> Self {
        Self { name, kind: SymbolKind::JumpTable(SymJumpTable { size, code }), addr, ambiguous: false, local: true }
    }

    pub fn new_data(name: String, addr: u32, data: SymData, ambiguous: bool) -> Symbol {
        Self { name, kind: SymbolKind::Data(data), addr, ambiguous, local: false }
    }

    pub fn new_bss(name: String, addr: u32, data: SymBss, ambiguous: bool) -> Symbol {
        Self { name, kind: SymbolKind::Bss(data), addr, ambiguous, local: false }
    }

    pub fn size(&self, max_address: u32) -> u32 {
        self.kind.size(max_address - self.addr)
    }

    pub fn is_external(&self) -> bool {
        match self.kind {
            SymbolKind::Label(SymLabel { external, .. }) => external,
            SymbolKind::PoolConstant => false,
            SymbolKind::JumpTable(_) => false,
            _ => true,
        }
    }
}

impl Display for Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} kind:{} addr:{:#010x}", self.name, self.kind, self.addr)?;
        if self.local {
            write!(f, " local")?;
        }
        if self.ambiguous {
            write!(f, " ambiguous")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SymbolKind {
    Undefined,
    Function(SymFunction),
    Label(SymLabel),
    PoolConstant,
    JumpTable(SymJumpTable),
    Data(SymData),
    Bss(SymBss),
}

#[derive(Debug, Snafu)]
pub enum SymbolKindParseError {
    #[snafu(transparent)]
    SymFunctionParse { source: SymFunctionParseError },
    #[snafu(transparent)]
    SymDataParse { source: SymDataParseError },
    #[snafu(transparent)]
    SymBssParse { source: SymBssParseError },
    #[snafu(transparent)]
    SymLabelParse { source: SymLabelParseError },
    #[snafu(display("{context}: unknown symbol kind '{kind}', must be one of: function, data, bss, label:\n{backtrace}"))]
    UnknownKind { context: ParseContext, kind: String, backtrace: Backtrace },
}

impl SymbolKind {
    fn parse(text: &str, context: &ParseContext) -> Result<Self, SymbolKindParseError> {
        let (kind, options) = text.split_once('(').unwrap_or((text, ""));
        let options = options.strip_suffix(')').unwrap_or(options);

        match kind {
            "function" => Ok(Self::Function(SymFunction::parse(options, context)?)),
            "data" => Ok(Self::Data(SymData::parse(options, context)?)),
            "bss" => Ok(Self::Bss(SymBss::parse(options, context)?)),
            "label" => Ok(Self::Label(SymLabel::parse(options, context)?)),
            _ => UnknownKindSnafu { context, kind }.fail(),
        }
    }

    fn should_write(&self) -> bool {
        match self {
            SymbolKind::Undefined => false,
            SymbolKind::Function(_) => true,
            SymbolKind::Label(label) => label.external,
            SymbolKind::PoolConstant => false,
            SymbolKind::JumpTable(_) => false,
            SymbolKind::Data(_) => true,
            SymbolKind::Bss(_) => true,
        }
    }

    pub fn size(&self, max_size: u32) -> u32 {
        match self {
            SymbolKind::Undefined => 0,
            SymbolKind::Function(function) => function.size,
            SymbolKind::Label(_) => 0,
            SymbolKind::PoolConstant => 0, // actually 4, but pool constants are just labels
            SymbolKind::JumpTable(_) => 0,
            SymbolKind::Data(data) => data.size().unwrap_or(max_size),
            SymbolKind::Bss(bss) => bss.size.unwrap_or(max_size),
        }
    }
}

impl Display for SymbolKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SymbolKind::Undefined => {}
            SymbolKind::Function(function) => write!(f, "function({function})")?,
            SymbolKind::Data(data) => write!(f, "data({data})")?,
            SymbolKind::Bss(bss) => write!(f, "bss{bss}")?,
            SymbolKind::Label(label) => write!(f, "label({label})")?,
            SymbolKind::PoolConstant => {}
            SymbolKind::JumpTable(_) => {}
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SymFunction {
    pub mode: InstructionMode,
    pub size: u32,
    /// Is `true` for functions that were not found during function analysis, but are being called from somewhere. This can
    /// happen if the function is encrypted.
    pub unknown: bool,
}

#[derive(Debug, Snafu)]
pub enum SymFunctionParseError {
    #[snafu(display("{context}: failed to parse size '{value}': {error}\n{backtrace}"))]
    ParseFunctionSize { context: ParseContext, value: String, error: ParseIntError, backtrace: Backtrace },
    #[snafu(display(
        "{context}: unknown function attribute '{key}', must be one of: size, unknown, arm, thumb:\n{backtrace}"
    ))]
    UnknownFunctionAttribute { context: ParseContext, key: String, backtrace: Backtrace },
    #[snafu(transparent)]
    InstructionModeParse { source: InstructionModeParseError },
    #[snafu(display("{context}: function must have an instruction mode: arm or thumb"))]
    MissingInstructionMode { context: ParseContext, backtrace: Backtrace },
    #[snafu(display("{context}: missing '{attribute}' attribute:\n{backtrace}"))]
    MissingFunctionAttribute { context: ParseContext, attribute: String, backtrace: Backtrace },
}

impl SymFunction {
    fn parse(options: &str, context: &ParseContext) -> Result<Self, SymFunctionParseError> {
        let mut size = None;
        let mut mode = None;
        let mut unknown = false;
        for option in options.split(',') {
            if let Some((key, value)) = option.split_once('=') {
                match key {
                    "size" => {
                        size =
                            Some(parse_u32(value).map_err(|error| ParseFunctionSizeSnafu { context, value, error }.build())?)
                    }
                    _ => return UnknownFunctionAttributeSnafu { context, key }.fail(),
                }
            } else {
                match option {
                    "unknown" => unknown = true,
                    _ => mode = Some(InstructionMode::parse(option, context)?),
                }
            }
        }

        Ok(Self {
            mode: mode.ok_or_else(|| MissingInstructionModeSnafu { context }.build())?,
            size: size.ok_or_else(|| MissingFunctionAttributeSnafu { context, attribute: "size" }.build())?,
            unknown,
        })
    }

    fn contains(&self, sym: &Symbol, addr: u32) -> bool {
        if !self.unknown {
            let start = sym.addr;
            let end = start + self.size;
            addr >= start && addr < end
        } else {
            // Unknown functions have no size
            sym.addr == addr
        }
    }
}

impl Display for SymFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{},size={:#x}", self.mode, self.size)?;
        if self.unknown {
            write!(f, ",unknown")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SymLabel {
    /// If true, the label is not used by the function itself, but accessed externally. Such labels are only discovered
    /// during relocation analysis, which is not performed by the dis/delink subcommands. External label symbols are
    /// therefore included in symbols.txt, hence this boolean.
    pub external: bool,
    pub mode: InstructionMode,
}

#[derive(Debug, Snafu)]
pub enum SymLabelParseError {
    #[snafu(transparent)]
    InstructionModeParse { source: InstructionModeParseError },
}

impl SymLabel {
    fn parse(options: &str, context: &ParseContext) -> Result<Self, SymLabelParseError> {
        Ok(Self { external: true, mode: InstructionMode::parse(options, context)? })
    }
}

impl Display for SymLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.mode)
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InstructionMode {
    Arm,
    Thumb,
}

#[derive(Debug, Snafu)]
pub enum InstructionModeParseError {
    #[snafu(display("{context}: expected instruction mode 'arm' or 'thumb' but got '{value}':\n{backtrace}"))]
    UnknownInstructionMode { context: ParseContext, value: String, backtrace: Backtrace },
}

impl InstructionMode {
    fn parse(value: &str, context: &ParseContext) -> Result<Self, InstructionModeParseError> {
        match value {
            "arm" => Ok(Self::Arm),
            "thumb" => Ok(Self::Thumb),
            _ => UnknownInstructionModeSnafu { context, value }.fail(),
        }
    }

    pub fn from_thumb(thumb: bool) -> Self {
        if thumb { Self::Thumb } else { Self::Arm }
    }

    pub fn into_thumb(self) -> Option<bool> {
        match self {
            Self::Arm => Some(false),
            Self::Thumb => Some(true),
        }
    }
}

impl Display for InstructionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Arm => write!(f, "arm"),
            Self::Thumb => write!(f, "thumb"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SymJumpTable {
    pub size: u32,
    pub code: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum SymData {
    Any,
    Byte { count: Option<u32> },
    Short { count: Option<u32> },
    Word { count: Option<u32> },
}

#[derive(Debug, Snafu)]
pub enum SymDataParseError {
    #[snafu(display("{context}: expected data kind 'any', 'byte', 'short' or 'word' but got nothing:\n{backtrace}"))]
    EmptyData { context: ParseContext, backtrace: Backtrace },
    #[snafu(display("{context}: failed to parse count '{value}': {error}\n{backtrace}"))]
    ParseCount { context: ParseContext, value: String, error: ParseIntError, backtrace: Backtrace },
    #[snafu(display("{context}: unexpected characters after ']':\n{backtrace}"))]
    CharacterAfterArray { context: ParseContext, backtrace: Backtrace },
    #[snafu(display("{context}: data type 'any' cannot be an array:\n{backtrace}"))]
    ArrayOfAny { context: ParseContext, backtrace: Backtrace },
    #[snafu(display("{context}: expected data kind 'any', 'byte', 'short' or 'word' but got '{kind}':\n{backtrace}"))]
    UnknownDataKind { context: ParseContext, kind: String, backtrace: Backtrace },
}

impl SymData {
    fn parse(kind: &str, context: &ParseContext) -> Result<Self, SymDataParseError> {
        if kind.is_empty() {
            return EmptyDataSnafu { context }.fail();
        }

        let (kind, rest) = kind.split_once('[').unwrap_or((kind, ""));
        let (count, rest) = rest
            .split_once(']')
            .map(|(count, rest)| {
                let count = if count.is_empty() {
                    Ok(None)
                } else {
                    parse_u32(count).map(Some).map_err(|error| ParseCountSnafu { context, value: count, error }.build())
                };
                (count, rest)
            })
            .unwrap_or((Ok(Some(1)), rest));
        let count = count?;

        if !rest.is_empty() {
            return CharacterAfterArraySnafu { context }.fail();
        }

        match kind {
            "any" => {
                if count != Some(1) {
                    ArrayOfAnySnafu { context }.fail()
                } else {
                    Ok(Self::Any)
                }
            }
            "short" => Ok(Self::Short { count }),
            "byte" => Ok(Self::Byte { count }),
            "word" => Ok(Self::Word { count }),
            kind => UnknownDataKindSnafu { context, kind }.fail(),
        }
    }

    pub fn count(self) -> Option<u32> {
        match self {
            Self::Any => None,
            Self::Byte { count } => count,
            Self::Short { count } => count,
            Self::Word { count } => count,
        }
    }

    pub fn element_size(self) -> u32 {
        match self {
            Self::Any => 1,
            Self::Byte { .. } => 1,
            Self::Short { .. } => 2,
            Self::Word { .. } => 4,
        }
    }

    pub fn size(&self) -> Option<u32> {
        self.count().map(|count| self.element_size() * count)
    }
}

impl Display for SymData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Any => write!(f, "any"),
            Self::Byte { count: Some(1) } => write!(f, "byte"),
            Self::Short { count: Some(1) } => write!(f, "short"),
            Self::Word { count: Some(1) } => write!(f, "word"),
            Self::Byte { count: Some(count) } => write!(f, "byte[{count}]"),
            Self::Short { count: Some(count) } => write!(f, "short[{count}]"),
            Self::Word { count: Some(count) } => write!(f, "word[{count}]"),
            Self::Byte { count: None } => write!(f, "byte[]"),
            Self::Short { count: None } => write!(f, "short[]"),
            Self::Word { count: None } => write!(f, "word[]"),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SymBss {
    pub size: Option<u32>,
}

#[derive(Debug, Snafu)]
pub enum SymBssParseError {
    #[snafu(display("{context}: failed to parse size '{value}': {error}\n{backtrace}"))]
    ParseBssSize { context: ParseContext, value: String, error: ParseIntError, backtrace: Backtrace },
    #[snafu(display("{context}: unknown attribute '{key}', must be one of: size:\n{backtrace}'"))]
    UnknownBssAttribute { context: ParseContext, key: String, backtrace: Backtrace },
}

impl SymBss {
    fn parse(options: &str, context: &ParseContext) -> Result<Self, SymBssParseError> {
        let mut size = None;
        if !options.trim().is_empty() {
            for option in options.split(',') {
                if let Some((key, value)) = option.split_once('=') {
                    match key {
                        "size" => {
                            size = Some(parse_u32(value).map_err(|error| ParseBssSizeSnafu { context, value, error }.build())?)
                        }
                        _ => return UnknownBssAttributeSnafu { context, key }.fail(),
                    }
                } else {
                    return UnknownBssAttributeSnafu { context, key: option }.fail();
                }
            }
        }
        Ok(Self { size })
    }
}

impl Display for SymBss {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(size) = self.size {
            write!(f, "(size={size:#x})")?;
        }
        Ok(())
    }
}
