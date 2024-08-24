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
    let mut result = XrefResult::new();
    find_xrefs_in_functions(modules, module_index, &mut result)?;
    find_xrefs_in_sections(modules, module_index, &mut result)?;
    Ok(result)
}

fn find_xrefs_in_sections(modules: &[Module], module_index: usize, result: &mut XrefResult) -> Result<()> {
    for section in modules[module_index].sections().iter() {
        match section.kind {
            SectionKind::Data => {}
            SectionKind::Code | SectionKind::Bss => continue,
        }

        let code = section.code(modules[module_index].code(), modules[module_index].base_address())?.unwrap();
        for word in section.iter_words(code) {
            find_external_data(modules, module_index, word.address, word.value, result)?;
        }
    }
    Ok(())
}

fn find_xrefs_in_functions(modules: &[Module], module_index: usize, result: &mut XrefResult) -> Result<()> {
    for section in modules[module_index].sections().iter() {
        for function in section.functions.values() {
            find_external_function_calls(modules, module_index, function, result)?;
            find_external_data_from_pools(modules, module_index, function, result)?;
        }
    }
    Ok(())
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
        find_external_data(modules, module_index, pool_constant.address, pool_constant.value, result)?;
    }
    Ok(())
}

fn find_external_data(
    modules: &[Module],
    module_index: usize,
    address: u32,
    pointer: u32,
    result: &mut XrefResult,
) -> Result<()> {
    let candidates = find_symbol_candidates(modules, module_index, pointer);
    if candidates.is_empty() {
        // Probably not a pointer
        return Ok(());
    }

    let candidate_modules = candidates.iter().map(|c| &modules[c.module_index]);
    let to = XrefTo::from_modules(candidate_modules)?;

    result.xrefs.push(Xref::new_load(address, to));
    result.external_symbols.push(ExternalSymbol { candidates, address: pointer });
    Ok(())
}

fn find_symbol_candidates(modules: &[Module], module_index: usize, pointer: u32) -> Vec<SymbolCandidate> {
    modules
        .iter()
        .enumerate()
        .filter_map(|(index, module)| {
            if index == module_index {
                return None;
            }
            let Some((section_index, section)) = module.sections().get_by_contained_address(pointer) else {
                return None;
            };
            if section.kind == SectionKind::Code && section.functions.get(&pointer).is_none() {
                return None;
            };
            Some(SymbolCandidate { module_index: index, section_index })
        })
        .collect::<Vec<_>>()
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
