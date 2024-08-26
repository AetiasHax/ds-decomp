use anyhow::{bail, Context, Result};
use std::{
    collections::{btree_map, BTreeMap, HashMap},
    fmt::Display,
    io::{BufRead, BufReader, BufWriter, Write},
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

use super::{config::Config, iter_attributes, module::ModuleKind, xref::Xrefs, ParseContext};

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
        symbol_maps.get_mut(ModuleKind::Arm9).load(config_path.join(&config.module.symbols))?;
        for autoload in &config.autoloads {
            symbol_maps.get_mut(ModuleKind::Autoload(autoload.kind)).load(config_path.join(&autoload.module.symbols))?;
        }
        for overlay in &config.overlays {
            symbol_maps.get_mut(ModuleKind::Overlay(overlay.id)).load(config_path.join(&overlay.module.symbols))?;
        }

        Ok(symbol_maps)
    }
}

type SymbolIndex = usize;

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
            symbols_by_address.entry(symbol.addr).or_default().push(index);
            symbols_by_name.entry(symbol.name.clone()).or_default().push(index);
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
            self.add(symbol)?;
        }
        Ok(())
    }

    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();

        let file = create_file(path)?;
        let mut writer = BufWriter::new(file);

        for indices in self.symbols_by_address.values() {
            for &index in indices {
                let symbol = &self.symbols[index];
                if symbol.should_write() {
                    writeln!(writer, "{symbol}")?;
                }
            }
        }

        Ok(())
    }

    pub fn for_address(&self, address: u32) -> Option<impl DoubleEndedIterator<Item = (SymbolIndex, &Symbol)>> {
        Some(self.symbols_by_address.get(&address)?.iter().map(|&i| (i, &self.symbols[i])))
    }

    pub fn by_address(&self, address: u32) -> Option<(SymbolIndex, &Symbol)> {
        let Some(mut symbols) = self.for_address(address) else {
            return None;
        };
        let (index, symbol) = symbols.next().unwrap();
        if let Some((_, other)) = symbols.next() {
            panic!("multiple symbols at 0x{:08x}: {}, {}", address, symbol.name, other.name);
        }
        Some((index, symbol))
    }

    pub fn for_name(&self, name: &str) -> Option<impl DoubleEndedIterator<Item = (SymbolIndex, &Symbol)>> {
        Some(self.symbols_by_name.get(name)?.iter().map(|&i| (i, &self.symbols[i])))
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

    pub fn iter_by_address(&self) -> SymbolIterator {
        SymbolIterator { symbols_by_address: self.symbols_by_address.values(), indices: [].iter(), symbols: &self.symbols }
    }

    pub fn add(&mut self, symbol: Symbol) -> Result<()> {
        let index = self.symbols.len();
        self.symbols_by_address.entry(symbol.addr).or_default().push(index);
        self.symbols_by_name.entry(symbol.name.clone()).or_default().push(index);
        self.symbols.push(symbol);

        Ok(())
    }

    pub fn add_if_new_address(&mut self, symbol: Symbol) -> Result<()> {
        if self.symbols_by_address.contains_key(&symbol.addr) {
            Ok(())
        } else {
            self.add(symbol)
        }
    }

    pub fn add_function(&mut self, function: &Function) -> Result<()> {
        self.add(Symbol::from_function(function))
    }

    pub fn get_function(&self, addr: u32) -> Option<(SymFunction, &Symbol)> {
        self.by_address(addr & !1).map_or(None, |(_, s)| match s.kind {
            SymbolKind::Function(function) => Some((function, s)),
            _ => None,
        })
    }

    pub fn functions(&self) -> FunctionSymbolIterator {
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

    pub fn add_label(&mut self, addr: u32) -> Result<()> {
        let name = Self::label_name(addr);
        self.add_if_new_address(Symbol::new_label(name, addr))
    }

    pub fn get_label(&self, addr: u32) -> Option<&Symbol> {
        self.by_address(addr).map_or(None, |(_, s)| (s.kind == SymbolKind::Label).then_some(s))
    }

    pub fn add_pool_constant(&mut self, addr: u32) -> Result<()> {
        let name = Self::label_name(addr);
        self.add_if_new_address(Symbol::new_pool_constant(name, addr))
    }

    pub fn get_pool_constant(&self, addr: u32) -> Option<&Symbol> {
        self.by_address(addr).map_or(None, |(_, s)| (s.kind == SymbolKind::PoolConstant).then_some(s))
    }

    pub fn add_jump_table(&mut self, table: &JumpTable) -> Result<()> {
        let name = Self::label_name(table.address);
        self.add_if_new_address(Symbol::new_jump_table(name, table.address, table.size, table.code))
    }

    pub fn get_jump_table(&self, addr: u32) -> Option<(SymJumpTable, &Symbol)> {
        self.by_address(addr).map_or(None, |(_, s)| match s.kind {
            SymbolKind::JumpTable(jump_table) => Some((jump_table, s)),
            _ => None,
        })
    }

    fn make_unambiguous(&mut self, addr: u32) {
        if let Some(index) = self
            .by_address(addr)
            .filter(|(_, symbol)| matches!(symbol.kind, SymbolKind::Data(_) | SymbolKind::Bss(_)))
            .map(|(index, _)| index)
        {
            self.symbols[index].ambiguous = false;
        }
    }

    pub fn add_data(&mut self, name: Option<String>, addr: u32, data: SymData) -> Result<()> {
        let name = name.unwrap_or_else(|| Self::label_name(addr));
        self.make_unambiguous(addr);
        self.add_if_new_address(Symbol::new_data(name, addr, data, false))
    }

    pub fn add_ambiguous_data(&mut self, name: Option<String>, addr: u32, data: SymData) -> Result<()> {
        let name = name.unwrap_or_else(|| Self::label_name(addr));
        self.add_if_new_address(Symbol::new_data(name, addr, data, true))
    }

    pub fn get_data(&self, addr: u32) -> Option<(SymData, &Symbol)> {
        self.by_address(addr).map_or(None, |(_, s)| match s.kind {
            SymbolKind::Data(data) => Some((data, s)),
            _ => None,
        })
    }

    pub fn add_bss(&mut self, name: Option<String>, addr: u32, data: SymBss) -> Result<()> {
        let name = name.unwrap_or_else(|| Self::label_name(addr));
        self.make_unambiguous(addr);
        self.add_if_new_address(Symbol::new_bss(name, addr, data, false))
    }

    pub fn add_ambiguous_bss(&mut self, name: Option<String>, addr: u32, data: SymBss) -> Result<()> {
        let name = name.unwrap_or_else(|| Self::label_name(addr));
        self.add_if_new_address(Symbol::new_bss(name, addr, data, true))
    }
}

impl LookupSymbol for SymbolMap {
    fn lookup_symbol_name(&self, _source: u32, destination: u32) -> Option<&str> {
        let Some((_, symbol)) = self.by_address(destination) else {
            return None;
        };
        Some(&symbol.name)
    }
}

pub struct SymbolIterator<'a> {
    symbols_by_address: btree_map::Values<'a, u32, Vec<SymbolIndex>>,
    indices: slice::Iter<'a, SymbolIndex>,
    symbols: &'a [Symbol],
}

impl<'a> Iterator for SymbolIterator<'a> {
    type Item = &'a Symbol;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(&index) = self.indices.next() {
            Some(&self.symbols[index])
        } else if let Some(indices) = self.symbols_by_address.next() {
            self.indices = indices.iter();
            self.next()
        } else {
            None
        }
    }
}

pub struct FunctionSymbolIterator<'a> {
    symbols_by_address: btree_map::Values<'a, u32, Vec<SymbolIndex>>,
    indices: slice::Iter<'a, SymbolIndex>,
    symbols: &'a [Symbol],
}

impl<'a> Iterator for FunctionSymbolIterator<'a> {
    type Item = (SymFunction, &'a Symbol);

    fn next(&mut self) -> Option<Self::Item> {
        while let Some(&index) = self.indices.next() {
            let symbol = &self.symbols[index];
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
                    addr = Some(parse_u32(value).with_context(|| format!("{}: failed to parse address '{}'", context, value))?)
                }
                "ambiguous" => ambiguous = true,
                _ => bail!("{}: expected symbol attribute 'kind' or 'addr' but got '{}'", context, key),
            }
        }

        let name = name.to_string().into();
        let kind = kind.with_context(|| format!("{}: missing 'kind' attribute", context))?;
        let addr = addr.with_context(|| format!("{}: missing 'addr' attribute", context))?;

        Ok(Some(Symbol { name, kind, addr, ambiguous }))
    }

    fn should_write(&self) -> bool {
        self.kind.should_write()
    }

    pub fn from_function(function: &Function) -> Self {
        Self {
            name: function.name().to_string(),
            kind: SymbolKind::Function(SymFunction { mode: InstructionMode::from_thumb(function.is_thumb()) }),
            addr: function.start_address() & !1,
            ambiguous: false,
        }
    }

    pub fn new_label(name: String, addr: u32) -> Self {
        Self { name, kind: SymbolKind::Label, addr, ambiguous: false }
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
    Label,
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
            _ => bail!("{}: unknown symbol kind '{}', must be one of: function, data, bss", context, kind),
        }
    }

    fn should_write(&self) -> bool {
        matches!(self, SymbolKind::Function(_) | SymbolKind::Data(_) | SymbolKind::Bss(_))
    }
}

impl Display for SymbolKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SymbolKind::Function(function) => write!(f, "function({function})")?,
            SymbolKind::Data(data) => write!(f, "data({data})")?,
            SymbolKind::Bss(bss) => write!(f, "bss{bss}")?,
            _ => {}
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SymFunction {
    pub mode: InstructionMode,
}

impl SymFunction {
    fn parse(options: &str, context: &ParseContext) -> Result<Self> {
        let mode = InstructionMode::parse(options, context)?;
        Ok(Self { mode })
    }
}

impl Display for SymFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.mode)
    }
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub enum InstructionMode {
    #[default]
    Auto,
    Arm,
    Thumb,
}

impl InstructionMode {
    fn parse(text: &str, context: &ParseContext) -> Result<Self> {
        match text {
            "" | "auto" => Ok(Self::Auto),
            "arm" => Ok(Self::Arm),
            "thumb" => Ok(Self::Thumb),
            _ => bail!("{}: expected instruction mode 'auto', 'arm' or 'thumb' but got '{}'", context, text),
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
            Self::Auto => None,
            Self::Arm => Some(false),
            Self::Thumb => Some(true),
        }
    }
}

impl Display for InstructionMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
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

    pub fn element_size(self) -> usize {
        match self {
            Self::Any => 1,
            Self::Byte { .. } => 1,
            Self::Short { .. } => 2,
            Self::Word { .. } => 4,
        }
    }

    pub fn size(&self) -> Option<usize> {
        self.count().map(|count| self.element_size() * count as usize)
    }

    pub fn display_assembly<'a>(
        &'a self,
        symbol: &'a Symbol,
        bytes: &'a [u8],
        module_kind: ModuleKind,
        symbol_map: &'a SymbolMap,
        symbol_maps: &'a SymbolMaps,
        xrefs: &'a Xrefs,
    ) -> DisplayDataAssembly {
        if let Some(size) = self.size() {
            if bytes.len() < size {
                panic!("not enough bytes to write raw data directive");
            }
        }

        DisplayDataAssembly { data: self, symbol, bytes, module_kind, symbol_map, symbol_maps, xrefs }
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

pub struct DisplayDataAssembly<'a> {
    symbol: &'a Symbol,
    data: &'a SymData,
    bytes: &'a [u8],
    module_kind: ModuleKind,
    symbol_map: &'a SymbolMap,
    symbol_maps: &'a SymbolMaps,
    xrefs: &'a Xrefs,
}

impl<'a> Display for DisplayDataAssembly<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut offset = 0;
        while offset < self.bytes.len() {
            let mut data_directive = false;

            let mut column = 0;
            while column < 16 {
                let offset = offset + column;
                if offset >= self.bytes.len() {
                    break;
                }
                let bytes = &self.bytes[offset..];

                let address = self.symbol.addr + offset as u32;

                // Try write symbol
                if bytes.len() >= 4 && (address & 3) == 0 {
                    let pointer = u32::from_le_slice(bytes);

                    if let Some(xref) = self.xrefs.get(address) {
                        let xref_to = xref.to();
                        if let Some(module_kind) = xref_to.first_module() {
                            let external_symbol_map = self.symbol_maps.get(module_kind).unwrap_or_else(|| {
                                panic!(
                                    "Xref from 0x{address:08x} in {} to {module_kind} has no symbol map, does that module exist?"
                                , self.module_kind)
                            });
                            let (_, symbol) = external_symbol_map.by_address(pointer).unwrap_or_else(|| {
                                panic!(
                                    "Symbol not found for xref from 0x{address:08x} in {} to 0x{pointer:08x} in {module_kind}",
                                    self.module_kind
                                )
                            });

                            if data_directive {
                                writeln!(f)?;
                                data_directive = false;
                            }
                            write!(f, "    .word {}", symbol.name)?;
                            column += 4;

                            if let Some(overlays) = xref_to.other_modules() {
                                write!(f, " ; ")?;
                                for (i, overlay) in overlays.enumerate() {
                                    let Some(external_symbol_map) = self.symbol_maps.get(overlay) else {
                                        eprintln!("Ambiguous xref from 0x{address:08x} in {} to {module_kind} has no symbol map, does that module exist?", self.module_kind);
                                        continue;
                                    };
                                    let Some((_, symbol)) = external_symbol_map.by_address(pointer) else {
                                        eprintln!("Ambiguous xref from 0x{address:08x} in {} to 0x{pointer:08x} in {module_kind} has no symbol", self.module_kind);
                                        continue;
                                    };
                                    if i > 0 {
                                        write!(f, ", ")?;
                                    }
                                    write!(f, "{}", symbol.name)?;
                                }
                            }

                            writeln!(f)?;
                            continue;
                        }
                    } else {
                        let symbol = self
                            .symbol_map
                            .get_data(pointer)
                            .map(|(_, sym)| sym)
                            .or_else(|| self.symbol_map.get_function(pointer).map(|(_, sym)| sym));

                        if let Some(symbol) = symbol {
                            if data_directive {
                                writeln!(f)?;
                                data_directive = false;
                            }

                            writeln!(f, "    .word {}", symbol.name)?;
                            column += 4;
                            continue;
                        }
                    }
                }

                // If no symbol, write data literals
                if !data_directive {
                    match self.data {
                        SymData::Any => write!(f, "    .byte 0x{:02x}", bytes[0])?,
                        SymData::Byte { .. } => write!(f, "    .byte 0x{:02x}", bytes[0])?,
                        SymData::Short { .. } => write!(f, "    .short {:#x}", bytes[0])?,
                        SymData::Word { .. } => write!(f, "    .word {:#x}", u32::from_le_slice(bytes))?,
                    }
                    data_directive = true;
                } else {
                    match self.data {
                        SymData::Any => write!(f, ", 0x{:02x}", bytes[0])?,
                        SymData::Byte { .. } => write!(f, ", 0x{:02x}", bytes[0])?,
                        SymData::Short { .. } => write!(f, ", {:#x}", u16::from_le_slice(bytes))?,
                        SymData::Word { .. } => write!(f, ", {:#x}", u32::from_le_slice(bytes))?,
                    }
                }
                column += self.data.element_size();
            }
            if data_directive {
                writeln!(f)?;
            }

            offset += 16;
        }

        Ok(())
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
