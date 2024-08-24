use anyhow::Result;

use crate::config::{
    module::Module,
    section::{Section, SectionKind, Sections},
    symbol::{SymBss, SymData, SymbolMap},
    xref::{Xref, XrefTo},
};

use super::functions::Function;

pub fn find_local_data_from_pools(
    function: &Function,
    sections: &Sections,
    symbol_map: &mut SymbolMap,
    name_prefix: &str,
) -> Result<()> {
    for pool_constant in function.iter_pool_constants() {
        let pointer = pool_constant.value;
        let Some((_, section)) = sections.get_by_contained_address(pointer) else {
            // Not a pointer, or points to a different module
            continue;
        };
        add_symbol_from_pointer(section, pointer, symbol_map, name_prefix)?;
    }

    Ok(())
}

pub fn find_local_data_from_section(
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
    for word in section.iter_words(code) {
        let pointer = word.value;
        let Some((_, section)) = sections.get_by_contained_address(pointer) else {
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

pub fn analyze_cross_references(modules: &[Module], module_index: usize) -> Result<XrefResult> {
    let result = find_xrefs_in_functions(modules, module_index)?;

    Ok(result)
}

fn find_xrefs_in_functions(modules: &[Module], module_index: usize) -> Result<XrefResult> {
    let mut result = XrefResult::new();
    for section in modules[module_index].sections().iter() {
        for function in section.functions.values() {
            find_external_function_calls(modules, module_index, function, &mut result)?;
            find_external_data_from_pools(modules, module_index, function, &mut result)?;
        }
    }
    Ok(result)
}

fn find_external_function_calls(
    modules: &[Module],
    module_index: usize,
    function: &Function,
    result: &mut XrefResult,
) -> Result<()> {
    for (&address, &called_function) in function.function_calls() {
        if modules[module_index].sections().get_by_contained_address(called_function.address).is_some() {
            // Ignore internal references
            continue;
        }
        let candidates = modules
            .iter()
            .enumerate()
            .filter(|&(index, module)| {
                index != module_index
                    && module
                        .sections()
                        .get_by_contained_address(called_function.address)
                        .and_then(|(_, s)| s.functions.get(&called_function.address))
                        .is_some()
            })
            .map(|(_, module)| module);
        let to = XrefTo::from_modules(candidates)?;
        if to == XrefTo::None {
            eprintln!("No functions from 0x{address:08x} to 0x{:08x}:", called_function.address);
        }

        result.xrefs.push(Xref::new_call(address, to));
    }
    Ok(())
}

fn find_external_data_from_pools<'a: 'b, 'b>(
    modules: &[Module],
    module_index: usize,
    function: &Function,
    result: &mut XrefResult,
) -> Result<()> {
    for pool_constant in function.iter_pool_constants() {
        if modules[module_index].sections().get_by_contained_address(pool_constant.value).is_some() {
            // Ignore internal references
            continue;
        }

        let candidates = modules
            .iter()
            .enumerate()
            .filter_map(|(index, module)| {
                if index == module_index {
                    return None;
                }
                let Some((section_index, section)) = module.sections().get_by_contained_address(pool_constant.value) else {
                    return None;
                };
                if section.kind == SectionKind::Code && section.functions.get(&pool_constant.value).is_none() {
                    return None;
                };
                Some(SymbolCandidate { module_index: index, section_index })
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            // Probably not a pointer
            continue;
        }

        let candidate_modules = candidates.iter().map(|c| &modules[c.module_index]);
        let to = XrefTo::from_modules(candidate_modules)?;

        result.xrefs.push(Xref::new_load(pool_constant.address, to));

        result.external_symbols.push(ExternalSymbol { candidates, address: pool_constant.value });
    }

    Ok(())
}

pub struct XrefResult {
    pub xrefs: Vec<Xref>,
    pub external_symbols: Vec<ExternalSymbol>,
}

impl XrefResult {
    fn new() -> Self {
        Self { xrefs: vec![], external_symbols: vec![] }
    }
}

pub struct ExternalSymbol {
    pub candidates: Vec<SymbolCandidate>,
    pub address: u32,
}

pub struct SymbolCandidate {
    pub module_index: usize,
    pub section_index: usize,
}
