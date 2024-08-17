use anyhow::Result;

use crate::config::{
    section::{SectionKind, Sections},
    symbol::{SymBss, SymData, SymbolMap},
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
        let data_address = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

        let Some(section) = sections.get_by_contained_address(data_address) else {
            // Not a pointer, or points to a different module
            continue;
        };

        let name = format!("{}{:08x}", name_prefix, data_address);

        match section.kind {
            SectionKind::Code => {}
            SectionKind::Data => symbol_map.add_data(Some(name), data_address, SymData::Any)?,
            SectionKind::Bss => symbol_map.add_bss(Some(name), data_address, SymBss { size: None })?,
        }
    }

    Ok(())
}
