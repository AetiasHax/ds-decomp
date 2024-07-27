use anyhow::{bail, Context, Result};
use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader},
    path::Path,
};
use unarm::LookupSymbol;

use crate::util::parse::parse_u32;

use super::ParseContext;

pub struct SymbolMap {
    symbols: HashMap<u32, Symbol>,
}

impl SymbolMap {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let mut context = ParseContext { file_path: path.to_str().unwrap().to_string(), row: 0 };

        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut symbols = HashMap::new();
        for line in reader.lines() {
            context.row += 1;
            let Some(symbol) = Symbol::parse(line?.as_str(), &context)? else { continue };
            symbols.insert(symbol.addr, symbol);
        }

        Ok(Self { symbols })
    }

    pub fn get(&self, address: u32) -> Option<&Symbol> {
        self.symbols.get(&address)
    }

    pub fn add(&mut self, symbol: Symbol) {
        self.symbols.insert(symbol.addr, symbol);
    }
}

impl LookupSymbol for SymbolMap {
    fn lookup_symbol_name(&self, _source: u32, destination: u32) -> Option<&str> {
        let Some(symbol) = self.symbols.get(&destination) else {
            return None;
        };
        Some(&symbol.name)
    }
}

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

        let name = name.to_string();
        let kind = kind.with_context(|| format!("{}:{}: missing 'kind' attribute", context.file_path, context.row))?;
        let addr = addr.with_context(|| format!("{}:{}: missing 'addr' attribute", context.file_path, context.row))?;

        Ok(Some(Symbol { name, kind, addr }))
    }
}

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

#[derive(Default)]
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
}
