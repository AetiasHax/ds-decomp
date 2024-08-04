use anyhow::{bail, Context, Result};
use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};
use unarm::LookupSymbol;

use crate::{
    analysis::{functions::Function, jump_table::JumpTable},
    util::parse::parse_u32,
};

use super::{parse_attributes, ParseContext};

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
        let path = path.as_ref();
        let mut context = ParseContext { file_path: path.to_str().unwrap().to_string(), row: 0 };

        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut symbol_map = Self::from_symbols(vec![]);
        for line in reader.lines() {
            context.row += 1;
            let Some(symbol) = Symbol::parse(line?.as_str(), &context)? else { continue };
            symbol_map.add(symbol)?;
        }
        Ok(symbol_map)
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
        self.add(Symbol::new_jump_table(name, table.address, table.size, table.code))
    }

    pub fn get_jump_table(&self, addr: u32) -> Option<(SymJumpTable, &Symbol)> {
        self.by_address(addr).map_or(None, |(_, s)| match s.kind {
            SymbolKind::JumpTable(jump_table) => Some((jump_table, s)),
            _ => None,
        })
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

#[derive(Clone)]
pub struct Symbol {
    pub name: String,
    pub kind: SymbolKind,
    pub addr: u32,
}

impl Symbol {
    pub fn parse(line: &str, context: &ParseContext) -> Result<Option<Self>> {
        let Some(attributes) = parse_attributes(line, context)? else {
            return Ok(None);
        };
        let name = attributes.name;

        let mut kind = None;
        let mut addr = None;
        for pair in attributes {
            let (key, value) = pair?;
            match key {
                "kind" => kind = Some(SymbolKind::parse(value, context)?),
                "addr" => {
                    addr = Some(parse_u32(value).with_context(|| format!("{}: failed to parse address '{}'", context, value))?)
                }
                _ => bail!("{}: expected symbol attribute 'kind' or 'addr' but got '{}'", context, key),
            }
        }

        let name = name.to_string().into();
        let kind = kind.with_context(|| format!("{}: missing 'kind' attribute", context))?;
        let addr = addr.with_context(|| format!("{}: missing 'addr' attribute", context))?;

        Ok(Some(Symbol { name, kind, addr }))
    }

    pub fn from_function(function: &Function) -> Self {
        Self {
            name: function.name().to_string(),
            kind: SymbolKind::Function(SymFunction { mode: InstructionMode::from_thumb(function.is_thumb()) }),
            addr: function.start_address(),
        }
    }

    pub fn new_label(name: String, addr: u32) -> Self {
        Self { name, kind: SymbolKind::Label, addr }
    }

    pub fn new_pool_constant(name: String, addr: u32) -> Self {
        Self { name, kind: SymbolKind::PoolConstant, addr }
    }

    pub fn new_jump_table(name: String, addr: u32, size: u32, code: bool) -> Self {
        Self { name, kind: SymbolKind::JumpTable(SymJumpTable { size, code }), addr }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    Function(SymFunction),
    Label,
    PoolConstant,
    JumpTable(SymJumpTable),
    Data,
    Bss,
}

impl SymbolKind {
    pub fn parse(text: &str, context: &ParseContext) -> Result<Self> {
        let (kind, options) = text.split_once('(').unwrap_or((text, ""));
        let options = options.strip_suffix(')').unwrap_or(options);

        match kind {
            "function" => {
                let mode = InstructionMode::parse(options, context)?;
                Ok(Self::Function(SymFunction { mode }))
            }
            "data" => Ok(Self::Data),
            "bss" => Ok(Self::Bss),
            _ => bail!("{}: unknown symbol kind '{}', must be one of: function, data, bss", context, kind),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SymFunction {
    pub mode: InstructionMode,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
pub enum InstructionMode {
    #[default]
    Auto,
    Arm,
    Thumb,
}

impl InstructionMode {
    pub fn parse(text: &str, context: &ParseContext) -> Result<Self> {
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
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SymJumpTable {
    pub size: u32,
    pub code: bool,
}
