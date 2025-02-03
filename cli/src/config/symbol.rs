use std::io;

use anyhow::{bail, Result};
use ds_decomp::config::{
    module::ModuleKind,
    relocations::Relocations,
    symbol::{InstructionMode, SymData, SymFunction, SymLabel, Symbol, SymbolKind, SymbolMap, SymbolMaps},
};
use object::{Object, ObjectSymbol};
use unarm::LookupSymbol;

use crate::util::bytes::FromSlice;

use super::relocation::RelocationModuleExt;

pub struct LookupSymbolMap(SymbolMap);

impl LookupSymbol for LookupSymbolMap {
    fn lookup_symbol_name(&self, _source: u32, destination: u32) -> Option<&str> {
        match self.0.by_address(destination) {
            Ok(Some((_, symbol))) => Some(&symbol.name),
            Ok(None) => None,
            Err(e) => {
                log::error!("SymbolMap::lookup_symbol_name aborted due to error: {e}");
                panic!("SymbolMap::lookup_symbol_name aborted due to error: {e}");
            }
        }
    }
}

pub trait SymbolMapExt
where
    Self: Sized,
{
    fn from_object(object: &object::File) -> Result<Self>;
}

impl SymbolMapExt for SymbolMap {
    fn from_object(object: &object::File) -> Result<Self> {
        let mut symbol_map = Self::new();

        for symbol in object.symbols() {
            symbol_map.add(Symbol {
                name: symbol.name()?.to_string(),
                kind: SymbolKind::Undefined,
                addr: symbol.address() as u32,
                ambiguous: false,
                local: symbol.is_local(),
            });
        }

        Ok(symbol_map)
    }
}

pub enum SymbolMapContainsError {}

pub trait SymbolExt {
    fn mapping_symbol_name(&self) -> Option<&str>;

    fn get_obj_symbol_scope(&self) -> object::SymbolScope;
}

impl SymbolExt for Symbol {
    fn mapping_symbol_name(&self) -> Option<&str> {
        match self.kind {
            SymbolKind::Undefined => None,
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

    fn get_obj_symbol_scope(&self) -> object::SymbolScope {
        if self.local {
            object::SymbolScope::Compilation
        } else {
            object::SymbolScope::Dynamic
        }
    }
}

pub trait SymbolKindExt {
    fn as_obj_symbol_kind(&self) -> object::SymbolKind;
}

impl SymbolKindExt for SymbolKind {
    fn as_obj_symbol_kind(&self) -> object::SymbolKind {
        match self {
            Self::Undefined => object::SymbolKind::Unknown,
            Self::Function(_) => object::SymbolKind::Text,
            Self::Label { .. } => object::SymbolKind::Label,
            Self::PoolConstant => object::SymbolKind::Data,
            Self::JumpTable(_) => object::SymbolKind::Label,
            Self::Data(_) => object::SymbolKind::Data,
            Self::Bss(_) => object::SymbolKind::Data,
        }
    }
}

pub trait SymDataExt {
    fn write_assembly<W: io::Write>(&self, w: &mut W, symbol: &Symbol, bytes: &[u8], symbols: &SymbolLookup) -> Result<()>;
}

impl SymDataExt for SymData {
    fn write_assembly<W: io::Write>(&self, w: &mut W, symbol: &Symbol, bytes: &[u8], symbols: &SymbolLookup) -> Result<()> {
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
                let symbol_address = (destination as i64 - relocation.addend()) as u32;
                assert!(symbol_address == relocation.to_address());

                let Some(external_symbol_map) = self.symbol_maps.get(module_kind) else {
                    log::error!(
                        "Relocation from {source:#010x} in {} to {module_kind} has no symbol map, does that module exist?",
                        self.module_kind
                    );
                    bail!("Relocation has no symbol map");
                };
                let symbol = if let Some((_, symbol)) = external_symbol_map.by_address(symbol_address)? {
                    symbol
                } else if let Some((_, symbol)) = external_symbol_map.get_function(symbol_address)? {
                    symbol
                } else {
                    log::error!(
                        "Symbol not found for relocation from {source:#010x} in {} to {symbol_address:#010x} in {module_kind}",
                        self.module_kind
                    );
                    bail!("Symbol not found for relocation");
                };

                if *new_line {
                    writeln!(w)?;
                    *new_line = false;
                }
                write!(w, "{indent}.word {}", symbol.name)?;

                if relocation.addend() > 0 {
                    write!(w, "+{:#x}", relocation.addend())?;
                } else if relocation.addend() < 0 {
                    write!(w, "-{:#x}", relocation.addend().abs())?;
                }

                self.write_ambiguous_symbols_comment(w, source, symbol_address)?;

                writeln!(w)?;
                Ok(true)
            } else {
                Ok(false)
            }
        } else if let Some((_, symbol)) = self.symbol_map.by_address(destination)? {
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

    pub fn write_ambiguous_symbols_comment<W: io::Write>(&self, w: &mut W, source: u32, destination: u32) -> Result<()> {
        let Some(relocation) = self.relocations.get(source) else { return Ok(()) };

        if let Some(overlays) = relocation.module().other_modules() {
            write!(w, " ; ")?;
            for (i, overlay) in overlays.enumerate() {
                let Some(external_symbol_map) = self.symbol_maps.get(overlay) else {
                    log::warn!(
                        "Ambiguous relocation from {source:#010x} in {} to {overlay} has no symbol map, does that module exist?",
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
                        "Ambiguous relocation from {source:#010x} in {} to {destination:#010x} in {overlay} has no symbol",
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
