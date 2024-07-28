use anyhow::{bail, Context, Result};
use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};
use unarm::LookupSymbol;

use crate::{analysis::functions::Function, util::parse::parse_u32};

use super::ParseContext;

type SymbolIndex = usize;

pub struct SymbolMap {
    symbols: Vec<Symbol>,
    symbols_by_address: BTreeMap<u32, Vec<SymbolIndex>>,
    symbols_by_name: HashMap<String, Vec<SymbolIndex>>,
}

impl SymbolMap {
    pub fn new(symbols: Vec<Symbol>) -> Self {
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

        let mut symbol_map = Self::new(vec![]);
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

    pub fn by_address(&self, address: u32) -> Result<Option<(SymbolIndex, &Symbol)>> {
        let Some(mut symbols) = self.for_address(address) else {
            return Ok(None);
        };
        let (index, symbol) = symbols.next().unwrap();
        if let Some((_, other)) = symbols.next() {
            bail!("multiple symbols at 0x{:08x}: {}, {}", address, symbol.name, other.name);
        }
        Ok(Some((index, symbol)))
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

    pub fn add_function(&mut self, function: &Function) -> Result<()> {
        self.add(Symbol::from_function(function))
    }
}

impl LookupSymbol for SymbolMap {
    fn lookup_symbol_name(&self, _source: u32, destination: u32) -> Option<&str> {
        let Some((_, symbol)) = self.by_address(destination).unwrap() else {
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
        let mut words = line.split_whitespace();
        let Some(name) = words.next() else { return Ok(None) };

        let mut kind = None;
        let mut addr = None;
        for word in words {
            let (key, value) = word
                .split_once(':')
                .with_context(|| format!("{}:{}: expected 'key:value' but got '{}'", context.file_path, context.row, word))?;
            match key {
                "kind" => kind = Some(SymbolKind::parse(value, context)?),
                "addr" => {
                    addr = Some(parse_u32(value).with_context(|| {
                        format!("{}:{}: failed to parse address '{}'", context.file_path, context.row, value)
                    })?)
                }
                _ => bail!(
                    "{}:{}: expected symbol attribute 'kind' or 'addr' but got '{}'",
                    context.file_path,
                    context.row,
                    key
                ),
            }
        }

        let name = name.to_string().into();
        let kind = kind.with_context(|| format!("{}:{}: missing 'kind' attribute", context.file_path, context.row))?;
        let addr = addr.with_context(|| format!("{}:{}: missing 'addr' attribute", context.file_path, context.row))?;

        Ok(Some(Symbol { name, kind, addr }))
    }

    pub fn from_function(function: &Function) -> Self {
        Self {
            name: function.name().into(),
            kind: SymbolKind::Function { mode: InstructionMode::from_thumb(function.is_thumb()) },
            addr: function.start_address(),
        }
    }
}

#[derive(Clone, Copy)]
pub enum SymbolKind {
    Function { mode: InstructionMode },
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
                Ok(Self::Function { mode })
            }
            "data" => Ok(Self::Data),
            "bss" => Ok(Self::Bss),
            _ => bail!(
                "{}:{}: expected symbol kind 'function', 'data', or 'bss' but got '{}'",
                context.file_path,
                context.row,
                kind
            ),
        }
    }
}

#[derive(Default, Clone, Copy)]
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
            _ => bail!(
                "{}:{}: expected instruction mode 'auto', 'arm' or 'thumb' but got '{}'",
                context.file_path,
                context.row,
                text
            ),
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
