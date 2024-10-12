use anyhow::{bail, ensure, Context, Result};
use std::{
    collections::{btree_map, hash_map, BTreeMap, HashMap},
    fmt::Display,
    io::{self, BufRead, BufReader, BufWriter, Write},
    ops::Range,
    path::Path,
    slice,
};
use unarm::LookupSymbol;

use crate::{
    analysis::{functions::Function, jump_table::JumpTable},
    util::{
        bytes::FromSlice,
        io::{create_file, open_file},
        parse::parse_u32,
    },
};

use super::{config::Config, iter_attributes, module::ModuleKind, relocation::Relocations, ParseContext};

pub struct SymbolMaps {
    symbol_maps: Vec<SymbolMap>,
}

impl SymbolMaps {
    pub fn new() -> Self {
        Self { symbol_maps: vec![] }
    }

    pub fn get(&self, module: ModuleKind) -> Option<&SymbolMap> {
        self.symbol_maps.get(module.index())
    }

    pub fn get_mut(&mut self, module: ModuleKind) -> &mut SymbolMap {
        let index = module.index();
        if index >= self.symbol_maps.len() {
            assert!(index < 1000, "sanity check");
            self.symbol_maps.resize_with(index + 1, || SymbolMap::new());
        }
        &mut self.symbol_maps[index]
    }

    pub fn from_config<P: AsRef<Path>>(config_path: P, config: &Config) -> Result<Self> {
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

    pub fn to_files<P: AsRef<Path>>(&self, config: &Config, config_path: P) -> Result<()> {
        let config_path = config_path.as_ref();
        self.get(ModuleKind::Arm9)
            .context("Symbol map not found for ARM9")?
            .to_file(config_path.join(&config.main_module.symbols))?;
        for autoload in &config.autoloads {
            self.get(ModuleKind::Autoload(autoload.kind))
                .with_context(|| format!("Symbol map not found for autoload {}", autoload.kind))?
                .to_file(config_path.join(&autoload.module.symbols))?;
        }
        for overlay in &config.overlays {
            self.get(ModuleKind::Overlay(overlay.id))
                .with_context(|| format!("Symbol map not found for overlay {}", overlay.id))?
                .to_file(config_path.join(&overlay.module.symbols))?;
        }

        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SymbolIndex(usize);

pub struct SymbolMap {
    symbols: Vec<Symbol>,
    symbols_by_address: BTreeMap<u32, Vec<SymbolIndex>>,
    symbols_by_name: HashMap<String, Vec<SymbolIndex>>,
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

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut symbol_map = Self::new();
        symbol_map.load(path)?;
        Ok(symbol_map)
    }

    pub fn load<P: AsRef<Path>>(&mut self, path: P) -> Result<()> {
        let path = path.as_ref();
        let mut context = ParseContext { file_path: path.to_str().unwrap().to_string(), row: 0 };

        let file = open_file(path)?;
        let reader = BufReader::new(file);

        for line in reader.lines() {
            context.row += 1;
            let Some(symbol) = Symbol::parse(line?.as_str(), &context)? else { continue };
            self.add(symbol);
        }
        Ok(())
    }

    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
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

    pub fn by_address(&self, address: u32) -> Result<Option<(SymbolIndex, &Symbol)>> {
        let Some(mut symbols) = self.for_address(address) else {
            return Ok(None);
        };
        let (index, symbol) = symbols.next().unwrap();
        if let Some((_, other)) = symbols.next() {
            log::error!("multiple symbols at 0x{:08x}: {}, {}", address, symbol.name, other.name);
            bail!("multiple symbols at 0x{:08x}: {}, {}", address, symbol.name, other.name);
        }
        Ok(Some((index, symbol)))
    }

    pub fn for_name(&self, name: &str) -> Option<impl DoubleEndedIterator<Item = (SymbolIndex, &Symbol)>> {
        Some(self.symbols_by_name.get(name)?.iter().map(|&i| (i, &self.symbols[i.0])))
    }

    pub fn by_name(&self, name: &str) -> Result<Option<(SymbolIndex, &Symbol)>> {
        let Some(mut symbols) = self.for_name(name) else {
            return Ok(None);
        };
        let (index, symbol) = symbols.next().unwrap();
        if let Some((_, other)) = symbols.next() {
            bail!("multiple symbols with name '{}': 0x{:08x}, 0x{:08x}", name, symbol.addr, other.addr);
        }
        Ok(Some((index, symbol)))
    }

    pub fn iter_by_address(&self, range: Range<u32>) -> SymbolIterator {
        SymbolIterator { symbols_by_address: self.symbols_by_address.range(range), indices: [].iter(), symbols: &self.symbols }
    }

    pub fn add(&mut self, symbol: Symbol) -> (SymbolIndex, &Symbol) {
        let index = SymbolIndex(self.symbols.len());
        self.symbols_by_address.entry(symbol.addr).or_default().push(index);
        self.symbols_by_name.entry(symbol.name.clone()).or_default().push(index);
        self.symbols.push(symbol);

        (index, self.symbols.last().unwrap())
    }

    pub fn add_if_new_address(&mut self, symbol: Symbol) -> Result<(SymbolIndex, &Symbol)> {
        if self.symbols_by_address.contains_key(&symbol.addr) {
            Ok(self.by_address(symbol.addr)?.unwrap())
        } else {
            Ok(self.add(symbol))
        }
    }

    pub fn add_function(&mut self, function: &Function) -> (SymbolIndex, &Symbol) {
        self.add(Symbol::from_function(function))
    }

    pub fn get_function(&self, addr: u32) -> Result<Option<(SymFunction, &Symbol)>> {
        Ok(self.by_address(addr & !1)?.map_or(None, |(_, s)| match s.kind {
            SymbolKind::Function(function) => Some((function, s)),
            _ => None,
        }))
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

    pub fn functions<'a>(&'a self) -> impl Iterator<Item = (SymFunction, &'a Symbol)> {
        FunctionSymbolIterator {
            symbols_by_address: self.symbols_by_address.values(),
            indices: [].iter(),
            symbols: &self.symbols,
        }
    }

    pub fn clone_functions(&self) -> Vec<(SymFunction, Symbol)> {
        self.functions().map(|(function, symbol)| (function, symbol.clone())).collect()
    }

    fn label_name(addr: u32) -> String {
        format!("_{:08x}", addr)
    }

    pub fn add_label(&mut self, addr: u32, thumb: bool) -> Result<(SymbolIndex, &Symbol)> {
        let name = Self::label_name(addr);
        self.add_if_new_address(Symbol::new_label(name, addr, thumb))
    }

    /// See [SymLabel::external].
    pub fn add_external_label(&mut self, addr: u32, thumb: bool) -> Result<(SymbolIndex, &Symbol)> {
        let name = Self::label_name(addr);
        self.add_if_new_address(Symbol::new_external_label(name, addr, thumb))
    }

    pub fn get_label(&self, addr: u32) -> Result<Option<&Symbol>> {
        Ok(self.by_address(addr)?.map_or(None, |(_, s)| (matches!(s.kind, SymbolKind::Label { .. })).then_some(s)))
    }

    pub fn add_pool_constant(&mut self, addr: u32) -> Result<(SymbolIndex, &Symbol)> {
        let name = Self::label_name(addr);
        self.add_if_new_address(Symbol::new_pool_constant(name, addr))
    }

    pub fn get_pool_constant(&self, addr: u32) -> Result<Option<&Symbol>> {
        Ok(self.by_address(addr)?.map_or(None, |(_, s)| (s.kind == SymbolKind::PoolConstant).then_some(s)))
    }

    pub fn add_jump_table(&mut self, table: &JumpTable) -> Result<(SymbolIndex, &Symbol)> {
        let name = Self::label_name(table.address);
        self.add_if_new_address(Symbol::new_jump_table(name, table.address, table.size, table.code))
    }

    pub fn get_jump_table(&self, addr: u32) -> Result<Option<(SymJumpTable, &Symbol)>> {
        Ok(self.by_address(addr)?.map_or(None, |(_, s)| match s.kind {
            SymbolKind::JumpTable(jump_table) => Some((jump_table, s)),
            _ => None,
        }))
    }

    fn make_unambiguous(&mut self, addr: u32) -> Result<()> {
        if let Some(index) = self
            .by_address(addr)?
            .filter(|(_, symbol)| matches!(symbol.kind, SymbolKind::Data(_) | SymbolKind::Bss(_)))
            .map(|(index, _)| index)
        {
            self.symbols[index.0].ambiguous = false;
        }
        Ok(())
    }

    pub fn add_data(&mut self, name: Option<String>, addr: u32, data: SymData) -> Result<(SymbolIndex, &Symbol)> {
        let name = name.unwrap_or_else(|| Self::label_name(addr));
        self.make_unambiguous(addr)?;
        self.add_if_new_address(Symbol::new_data(name, addr, data, false))
    }

    pub fn add_ambiguous_data(&mut self, name: Option<String>, addr: u32, data: SymData) -> Result<(SymbolIndex, &Symbol)> {
        let name = name.unwrap_or_else(|| Self::label_name(addr));
        self.add_if_new_address(Symbol::new_data(name, addr, data, true))
    }

    pub fn get_data(&self, addr: u32) -> Result<Option<(SymData, &Symbol)>> {
        Ok(self.by_address(addr)?.map_or(None, |(_, s)| match s.kind {
            SymbolKind::Data(data) => Some((data, s)),
            _ => None,
        }))
    }

    pub fn add_bss(&mut self, name: Option<String>, addr: u32, data: SymBss) -> Result<(SymbolIndex, &Symbol)> {
        let name = name.unwrap_or_else(|| Self::label_name(addr));
        self.make_unambiguous(addr)?;
        self.add_if_new_address(Symbol::new_bss(name, addr, data, false))
    }

    pub fn add_ambiguous_bss(&mut self, name: Option<String>, addr: u32, data: SymBss) -> Result<(SymbolIndex, &Symbol)> {
        let name = name.unwrap_or_else(|| Self::label_name(addr));
        self.add_if_new_address(Symbol::new_bss(name, addr, data, true))
    }

    pub fn rename_by_address(&mut self, address: u32, new_name: &str) -> Result<()> {
        let symbol_indices = self
            .symbols_by_address
            .get(&address)
            .with_context(|| format!("No symbol at {address:#x} to rename to '{new_name}'"))?;
        ensure!(symbol_indices.len() == 1, "There must be exactly one symbol at {address:#x} to rename to '{new_name}'");

        let symbol_index = symbol_indices[0];
        let name = &self.symbols[symbol_index.0].name;

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
                bail!("No symbol name entry found for '{name}' when trying to rename to '{new_name}'")
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

        Ok(())
    }
}

impl LookupSymbol for SymbolMap {
    fn lookup_symbol_name(&self, _source: u32, destination: u32) -> Option<&str> {
        match self.by_address(destination) {
            Ok(Some((_, symbol))) => Some(&symbol.name),
            Ok(None) => None,
            Err(e) => {
                log::error!("SymbolMap::lookup_symbol_name aborted due to error: {e}");
                panic!("SymbolMap::lookup_symbol_name aborted due to error: {e}");
            }
        }
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

impl<'a, I: Iterator<Item = &'a Vec<SymbolIndex>>> Iterator for FunctionSymbolIterator<'a, I> {
    type Item = (SymFunction, &'a Symbol);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(&index) = self.indices.next() {
            let symbol = &self.symbols[index.0];
            if let SymbolKind::Function(function) = symbol.kind {
                return Some((function, symbol));
            }
        }
        if let Some(indices) = self.symbols_by_address.next() {
            self.indices = indices.iter();
            self.next()
        } else {
            None
        }
    }
}

#[derive(Clone)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub addr: u32,
    /// If true, this symbol is involved in an ambiguous external reference to one of many overlays
    pub ambiguous: bool,
}

impl Symbol {
    fn parse(line: &str, context: &ParseContext) -> Result<Option<Self>> {
        let mut words = line.split_whitespace();
        let Some(name) = words.next() else { return Ok(None) };

        let mut kind = None;
        let mut addr = None;
        let mut ambiguous = false;
        for (key, value) in iter_attributes(words) {
            match key {
                "kind" => kind = Some(SymbolKind::parse(value, context)?),
                "addr" => {
                    addr = Some(parse_u32(value).with_context(|| format!("{context}: failed to parse address '{value}'"))?)
                }
                "ambiguous" => ambiguous = true,
                _ => bail!("{context}: expected symbol attribute 'kind' or 'addr' but got '{key}'"),
            }
        }

        let name = name.to_string().into();
        let kind = kind.with_context(|| format!("{context}: missing 'kind' attribute"))?;
        let addr = addr.with_context(|| format!("{context}: missing 'addr' attribute"))?;

        Ok(Some(Symbol { name, kind, addr, ambiguous }))
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
            }),
            addr: function.start_address() & !1,
            ambiguous: false,
        }
    }

    pub fn new_label(name: String, addr: u32, thumb: bool) -> Self {
        Self {
            name,
            kind: SymbolKind::Label(SymLabel { external: false, mode: InstructionMode::from_thumb(thumb) }),
            addr,
            ambiguous: false,
        }
    }

    pub fn new_external_label(name: String, addr: u32, thumb: bool) -> Self {
        Self {
            name,
            kind: SymbolKind::Label(SymLabel { external: true, mode: InstructionMode::from_thumb(thumb) }),
            addr,
            ambiguous: false,
        }
    }

    pub fn new_pool_constant(name: String, addr: u32) -> Self {
        Self { name, kind: SymbolKind::PoolConstant, addr, ambiguous: false }
    }

    pub fn new_jump_table(name: String, addr: u32, size: u32, code: bool) -> Self {
        Self { name, kind: SymbolKind::JumpTable(SymJumpTable { size, code }), addr, ambiguous: false }
    }

    pub fn new_data(name: String, addr: u32, data: SymData, ambiguous: bool) -> Symbol {
        Self { name, kind: SymbolKind::Data(data), addr, ambiguous }
    }

    pub fn new_bss(name: String, addr: u32, data: SymBss, ambiguous: bool) -> Symbol {
        Self { name, kind: SymbolKind::Bss(data), addr, ambiguous }
    }

    pub fn size(&self, max_address: u32) -> u32 {
        self.kind.size(max_address - self.addr)
    }

    pub fn mapping_symbol_name(&self) -> Option<&str> {
        match self.kind {
            SymbolKind::Function(SymFunction { mode, .. }) | SymbolKind::Label(SymLabel { mode, .. }) => match mode {
                InstructionMode::Arm => Some("$a"),
                InstructionMode::Thumb => Some("$t"),
            },
            SymbolKind::PoolConstant => Some("$d"),
            SymbolKind::JumpTable(jump_table) => {
                if jump_table.code {
                    Some("$a")
                } else {
                    Some("$d")
                }
            }
            SymbolKind::Data(_) => Some("$d"),
            SymbolKind::Bss(_) => None,
        }
    }
}

impl Display for Symbol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} kind:{} addr:{:#x}", self.name, self.kind, self.addr)?;
        if self.ambiguous {
            write!(f, " ambiguous")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Function(SymFunction),
    Label(SymLabel),
    PoolConstant,
    JumpTable(SymJumpTable),
    Data(SymData),
    Bss(SymBss),
}

impl SymbolKind {
    fn parse(text: &str, context: &ParseContext) -> Result<Self> {
        let (kind, options) = text.split_once('(').unwrap_or((text, ""));
        let options = options.strip_suffix(')').unwrap_or(options);

        match kind {
            "function" => Ok(Self::Function(SymFunction::parse(options, context)?)),
            "data" => Ok(Self::Data(SymData::parse(options, context)?)),
            "bss" => Ok(Self::Bss(SymBss::parse(options, context)?)),
            "label" => Ok(Self::Label(SymLabel::parse(options, context)?)),
            _ => bail!("{context}: unknown symbol kind '{kind}', must be one of: function, data, bss, label"),
        }
    }

    fn should_write(&self) -> bool {
        match self {
            SymbolKind::Function(_) => true,
            SymbolKind::Label(label) => label.external,
            SymbolKind::PoolConstant => false,
            SymbolKind::JumpTable(_) => false,
            SymbolKind::Data(_) => true,
            SymbolKind::Bss(_) => true,
        }
    }

    pub fn into_obj_symbol_kind(&self) -> object::SymbolKind {
        match self {
            Self::Function(_) => object::SymbolKind::Text,
            Self::Label { .. } => object::SymbolKind::Label,
            Self::PoolConstant => object::SymbolKind::Data,
            Self::JumpTable(_) => object::SymbolKind::Label,
            Self::Data(_) => object::SymbolKind::Data,
            Self::Bss(_) => object::SymbolKind::Data,
        }
    }

    pub fn into_obj_symbol_scope(&self) -> object::SymbolScope {
        match self {
            SymbolKind::Function(_) => object::SymbolScope::Dynamic,
            SymbolKind::Label(_) => object::SymbolScope::Compilation,
            SymbolKind::PoolConstant => object::SymbolScope::Compilation,
            SymbolKind::JumpTable(_) => object::SymbolScope::Compilation,
            SymbolKind::Data(_) => object::SymbolScope::Dynamic,
            SymbolKind::Bss(_) => object::SymbolScope::Dynamic,
        }
    }

    pub fn size(&self, max_size: u32) -> u32 {
        match self {
            SymbolKind::Function(function) => function.size,
            SymbolKind::Label { .. } => 0,
            SymbolKind::PoolConstant => 0, // actually 4, but pool constants are just labels
            SymbolKind::JumpTable(_) => 0,
            SymbolKind::Data(data) => data.size().unwrap_or(max_size) as u32,
            SymbolKind::Bss(bss) => bss.size.unwrap_or(max_size),
        }
    }
}

impl Display for SymbolKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SymFunction {
    pub mode: InstructionMode,
    pub size: u32,
}

impl SymFunction {
    fn parse(options: &str, context: &ParseContext) -> Result<Self> {
        let mut size = None;
        let mut mode = None;
        for option in options.split(',') {
            if let Some((key, value)) = option.split_once('=') {
                match key {
                    "size" => size = Some(parse_u32(value)?),
                    _ => bail!("{context}: unknown function attribute '{key}', must be one of: size, arm, thumb"),
                }
            } else {
                mode = Some(InstructionMode::parse(option, context)?);
            }
        }

        Ok(Self {
            mode: mode.with_context(|| format!("{context}: function must have an instruction mode"))?,
            size: size.with_context(|| format!("{context}: function must have a size"))?,
        })
    }

    fn contains(&self, sym: &Symbol, addr: u32) -> bool {
        let start = sym.addr;
        let end = start + self.size;
        addr >= start && addr < end
    }
}

impl Display for SymFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{},size={:#x}", self.mode, self.size)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SymLabel {
    /// If true, the label is not used by the function itself, but accessed externally. Such labels are only discovered
    /// during relocation analysis, which is not performed by the dis/delink subcommands. External label symbols are
    /// therefore included in symbols.txt, hence this boolean.
    pub external: bool,
    pub mode: InstructionMode,
}

impl SymLabel {
    fn parse(options: &str, context: &ParseContext) -> Result<Self> {
        Ok(Self { external: true, mode: InstructionMode::parse(options, context)? })
    }
}

impl Display for SymLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.mode)
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum InstructionMode {
    Arm,
    Thumb,
}

impl InstructionMode {
    fn parse(text: &str, context: &ParseContext) -> Result<Self> {
        match text {
            "arm" => Ok(Self::Arm),
            "thumb" => Ok(Self::Thumb),
            _ => bail!("{context}: expected instruction mode 'arm' or 'thumb' but got '{text}'"),
        }
    }

    pub fn from_thumb(thumb: bool) -> Self {
        if thumb {
            Self::Thumb
        } else {
            Self::Arm
        }
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SymJumpTable {
    pub size: u32,
    pub code: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SymData {
    Any,
    Byte { count: Option<u32> },
    Short { count: Option<u32> },
    Word { count: Option<u32> },
}

impl SymData {
    fn parse(kind: &str, context: &ParseContext) -> Result<Self> {
        if kind.is_empty() {
            bail!("{context}: expected data kind 'any', 'byte' or 'word' but got nothing");
        }

        let (kind, rest) = kind.split_once('[').unwrap_or((kind, ""));
        let (count, rest) = rest
            .split_once(']')
            .map(|(count, rest)| (if count.is_empty() { Ok(None) } else { parse_u32(count).map(|c| Some(c)) }, rest))
            .unwrap_or((Ok(Some(1)), rest));
        let count = count?;

        if !rest.is_empty() {
            bail!("{context}: unexpected characters after ']'");
        }

        match kind {
            "any" => {
                if count != Some(1) {
                    bail!("{context}: data type 'any' cannot be an array");
                } else {
                    Ok(Self::Any)
                }
            }
            "short" => Ok(Self::Short { count }),
            "byte" => Ok(Self::Byte { count }),
            "word" => Ok(Self::Word { count }),
            kind => bail!("{context}: expected data kind 'any', 'byte', 'short' or 'word' but got '{kind}'"),
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

    pub fn write_assembly<W: io::Write>(
        &self,
        w: &mut W,
        symbol: &Symbol,
        bytes: &[u8],
        symbols: &SymbolLookup,
    ) -> Result<()> {
        if let Some(size) = self.size() {
            if bytes.len() < size as usize {
                log::error!("Not enough bytes to write raw data directive");
                bail!("Not enough bytes to write raw data directive");
            }
        }

        let mut offset = 0;
        while offset < bytes.len() {
            let mut data_directive = false;

            let mut column = 0;
            while column < 16 {
                let offset = offset + column;
                if offset >= bytes.len() {
                    break;
                }
                let bytes = &bytes[offset..];

                let address = symbol.addr + offset as u32;

                // Try write symbol
                if bytes.len() >= 4 && (address & 3) == 0 {
                    let pointer = u32::from_le_slice(bytes);

                    if symbols.write_symbol(w, address, pointer, &mut data_directive, "    ")? {
                        column += 4;
                        continue;
                    }
                }

                // If no symbol, write data literals
                if !data_directive {
                    match self {
                        SymData::Any => write!(w, "    .byte 0x{:02x}", bytes[0])?,
                        SymData::Byte { .. } => write!(w, "    .byte 0x{:02x}", bytes[0])?,
                        SymData::Short { .. } => write!(w, "    .short {:#x}", bytes[0])?,
                        SymData::Word { .. } => write!(w, "    .word {:#x}", u32::from_le_slice(bytes))?,
                    }
                    data_directive = true;
                } else {
                    match self {
                        SymData::Any => write!(w, ", 0x{:02x}", bytes[0])?,
                        SymData::Byte { .. } => write!(w, ", 0x{:02x}", bytes[0])?,
                        SymData::Short { .. } => write!(w, ", {:#x}", u16::from_le_slice(bytes))?,
                        SymData::Word { .. } => write!(w, ", {:#x}", u32::from_le_slice(bytes))?,
                    }
                }
                column += self.element_size() as usize;
            }
            if data_directive {
                writeln!(w)?;
            }

            offset += 16;
        }

        Ok(())
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

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SymBss {
    pub size: Option<u32>,
}
impl SymBss {
    fn parse(options: &str, context: &ParseContext) -> Result<Self> {
        let mut size = None;
        if !options.trim().is_empty() {
            for option in options.split(',') {
                if let Some((key, value)) = option.split_once('=') {
                    match key {
                        "size" => size = Some(parse_u32(value)?),
                        _ => bail!("{context}: expected 'size=...' but got '{key}={value}'"),
                    }
                } else {
                    bail!("{context}: expected 'key=value' but got '{option}'");
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

pub struct SymbolLookup<'a> {
    pub module_kind: ModuleKind,
    /// Local symbol map
    pub symbol_map: &'a SymbolMap,
    /// All symbol maps, including external modules
    pub symbol_maps: &'a SymbolMaps,
    pub relocations: &'a Relocations,
}

impl<'a> SymbolLookup<'a> {
    pub fn write_symbol<W: io::Write>(
        &self,
        w: &mut W,
        source: u32,
        destination: u32,
        new_line: &mut bool,
        indent: &str,
    ) -> Result<bool> {
        if let Some(relocation) = self.relocations.get(source) {
            let relocation_to = relocation.module();
            if let Some(module_kind) = relocation_to.first_module() {
                let Some(external_symbol_map) = self.symbol_maps.get(module_kind) else {
                    log::error!(
                        "Relocation from 0x{source:08x} in {} to {module_kind} has no symbol map, does that module exist?",
                        self.module_kind
                    );
                    bail!("Relocation has no symbol map");
                };
                let symbol = if let Some((_, symbol)) = external_symbol_map.by_address(destination)? {
                    symbol
                } else if let Some((_, symbol)) = external_symbol_map.get_function(destination)? {
                    symbol
                } else {
                    log::error!(
                        "Symbol not found for relocation from 0x{source:08x} in {} to 0x{destination:08x} in {module_kind}",
                        self.module_kind
                    );
                    bail!("Symbol not found for relocation");
                };

                if *new_line {
                    writeln!(w)?;
                    *new_line = false;
                }
                write!(w, "{indent}.word {}", symbol.name)?;

                self.write_ambiguous_symbols_comment(w, source, destination)?;

                writeln!(w)?;
                Ok(true)
            } else {
                Ok(false)
            }
        } else {
            if let Some((_, symbol)) = self.symbol_map.by_address(destination)? {
                if *new_line {
                    writeln!(w)?;
                    *new_line = false;
                }

                writeln!(w, "{indent}.word {}", symbol.name)?;
                Ok(true)
            } else {
                Ok(false)
            }
        }
    }

    pub fn write_ambiguous_symbols_comment<W: io::Write>(&self, w: &mut W, source: u32, destination: u32) -> Result<()> {
        let Some(relocation) = self.relocations.get(source) else { return Ok(()) };

        if let Some(overlays) = relocation.module().other_modules() {
            write!(w, " ; ")?;
            for (i, overlay) in overlays.enumerate() {
                let Some(external_symbol_map) = self.symbol_maps.get(overlay) else {
                    log::warn!(
                        "Ambiguous relocation from 0x{source:08x} in {} to {overlay} has no symbol map, does that module exist?",
                        self.module_kind
                    );
                    continue;
                };
                let symbol = if let Some((_, symbol)) = external_symbol_map.by_address(destination)? {
                    symbol
                } else if let Some((_, symbol)) = external_symbol_map.get_function(destination)? {
                    symbol
                } else {
                    log::warn!(
                        "Ambiguous relocation from 0x{source:08x} in {} to 0x{destination:08x} in {overlay} has no symbol",
                        self.module_kind
                    );
                    continue;
                };
                if i > 0 {
                    write!(w, ", ")?;
                }
                write!(w, "{}", symbol.name)?;
            }
        }
        Ok(())
    }
}

impl<'a> LookupSymbol for SymbolLookup<'a> {
    fn lookup_symbol_name(&self, source: u32, destination: u32) -> Option<&str> {
        let symbol = match self.symbol_map.by_address(destination) {
            Ok(s) => s.map(|(_, symbol)| symbol),
            Err(e) => {
                log::error!("SymbolLookup::lookup_symbol_name aborted due to error: {e}");
                panic!("SymbolLookup::lookup_symbol_name aborted due to error: {e}");
            }
        };
        if let Some(symbol) = symbol {
            return Some(&symbol.name);
        }
        if let Some(relocation) = self.relocations.get(source) {
            let module_kind = relocation.module().first_module().unwrap();
            let external_symbol_map = self.symbol_maps.get(module_kind).unwrap();

            let symbol = match external_symbol_map.by_address(destination) {
                Ok(s) => s.map(|(_, symbol)| symbol),
                Err(e) => {
                    log::error!("SymbolLookup::lookup_symbol_name aborted due to error: {e}");
                    panic!("SymbolLookup::lookup_symbol_name aborted due to error: {e}");
                }
            };

            if let Some(symbol) = symbol {
                Some(&symbol.name)
            } else {
                None
            }
        } else {
            None
        }
    }
}
