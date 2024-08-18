use anyhow::Result;

use crate::{
    config::{
        section::{Section, SectionKind, Sections},
        symbol::{SymBss, SymData, SymbolMap},
    },
    util::bytes::FromSlice,
};

use super::functions::Function;

pub fn find_data_from_pools(
    function: &Function,
    sections: &Sections,
    symbol_map: &mut SymbolMap,
    name_prefix: &str,
) -> Result<()> {
    let code = function.code();
    for &address in function.pool_constants() {
        let start = address - function.start_address();
        let bytes = &code[start as usize..];
        let pointer = u32::from_le_slice(bytes);

        let Some(section) = sections.get_by_contained_address(pointer) else {
            // Not a pointer, or points to a different module
            continue;
        };
        add_symbol_from_pointer(section, pointer, symbol_map, name_prefix)?;
    }

    Ok(())
}

pub fn find_data_from_section(
    sections: &Sections,
    section: &Section,
    code: &[u8],
    symbol_map: &mut SymbolMap,
    name_prefix: &str,
) -> Result<()> {
    find_pointers(sections, section, code, symbol_map, name_prefix)?;
    Ok(())
}

fn find_pointers(
    sections: &Sections,
    section: &Section,
    code: &[u8],
    symbol_map: &mut SymbolMap,
    name_prefix: &str,
) -> Result<()> {
    let start = section.start_address.next_multiple_of(4);
    let end = section.end_address & !3;
    for address in (start..end).step_by(4) {
        let offset = address - section.start_address;
        let bytes = &code[offset as usize..];
        let pointer = u32::from_le_slice(bytes);

        let Some(section) = sections.get_by_contained_address(pointer) else {
            continue;
        };
        add_symbol_from_pointer(section, pointer, symbol_map, name_prefix)?;
    }
    Ok(())
}

fn add_symbol_from_pointer(section: &Section, pointer: u32, symbol_map: &mut SymbolMap, name_prefix: &str) -> Result<()> {
    let name = format!("{}{:08x}", name_prefix, pointer);

    match section.kind {
        SectionKind::Code => {}
        SectionKind::Data => symbol_map.add_data(Some(name), pointer, SymData::Any)?,
        SectionKind::Bss => symbol_map.add_bss(Some(name), pointer, SymBss { size: None })?,
    }

    Ok(())
}
