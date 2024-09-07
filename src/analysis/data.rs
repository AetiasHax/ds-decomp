use anyhow::Result;

use crate::config::{
    module::{Module, ModuleKind},
    relocation::{Relocation, RelocationModule, Relocations},
    section::{Section, SectionKind, Sections},
    symbol::{SymBss, SymData, SymbolMap, SymbolMaps},
};

use super::functions::Function;

pub fn find_local_data_from_pools(
    function: &Function,
    sections: &Sections,
    module_kind: ModuleKind,
    symbol_map: &mut SymbolMap,
    relocations: &mut Relocations,
    name_prefix: &str,
) -> Result<()> {
    for pool_constant in function.iter_pool_constants() {
        let pointer = pool_constant.value;
        let Some((_, section)) = sections.get_by_contained_address(pointer) else {
            // Not a pointer, or points to a different module
            continue;
        };
        add_symbol_from_pointer(section, pool_constant.address, pointer, module_kind, symbol_map, relocations, name_prefix)?;
    }

    Ok(())
}

pub fn find_local_data_from_section(
    sections: &Sections,
    section: &Section,
    code: &[u8],
    module_kind: ModuleKind,
    symbol_map: &mut SymbolMap,
    relocations: &mut Relocations,
    name_prefix: &str,
) -> Result<()> {
    find_pointers(sections, section, code, module_kind, symbol_map, relocations, name_prefix)?;
    Ok(())
}

fn find_pointers(
    sections: &Sections,
    section: &Section,
    code: &[u8],
    module_kind: ModuleKind,
    symbol_map: &mut SymbolMap,
    relocations: &mut Relocations,
    name_prefix: &str,
) -> Result<()> {
    for word in section.iter_words(code) {
        let pointer = word.value;
        if sections.get_by_contained_address(pointer).is_none() {
            continue;
        };
        add_symbol_from_pointer(section, word.address, pointer, module_kind, symbol_map, relocations, name_prefix)?;
    }
    Ok(())
}

fn add_symbol_from_pointer(
    section: &Section,
    address: u32,
    pointer: u32,
    module_kind: ModuleKind,
    symbol_map: &mut SymbolMap,
    relocations: &mut Relocations,
    name_prefix: &str,
) -> Result<()> {
    let name = format!("{}{:08x}", name_prefix, pointer);

    match section.kind() {
        SectionKind::Code => {}
        SectionKind::Data => {
            symbol_map.add_data(Some(name), pointer, SymData::Any);
            relocations.add_load(address, pointer, module_kind.into());
        }
        SectionKind::Bss => {
            symbol_map.add_bss(Some(name), pointer, SymBss { size: None });
            relocations.add_load(address, pointer, module_kind.into());
        }
    }

    Ok(())
}

pub fn analyze_external_references(
    modules: &[Module],
    module_index: usize,
    symbol_maps: &mut SymbolMaps,
) -> Result<RelocationResult> {
    let mut result = RelocationResult::new();
    find_relocations_in_functions(modules, module_index, symbol_maps, &mut result)?;
    find_external_references_in_sections(modules, module_index, &mut result)?;
    Ok(result)
}

fn find_external_references_in_sections(modules: &[Module], module_index: usize, result: &mut RelocationResult) -> Result<()> {
    for section in modules[module_index].sections().iter() {
        match section.kind() {
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

fn find_relocations_in_functions(
    modules: &[Module],
    module_index: usize,
    symbol_maps: &mut SymbolMaps,
    result: &mut RelocationResult,
) -> Result<()> {
    for section in modules[module_index].sections().iter() {
        for function in section.functions().values() {
            add_function_calls_as_relocations(modules, module_index, function, symbol_maps, result)?;
            find_external_data_from_pools(modules, module_index, function, result)?;
        }
    }
    Ok(())
}

fn add_function_calls_as_relocations(
    modules: &[Module],
    module_index: usize,
    function: &Function,
    symbol_maps: &mut SymbolMaps,
    result: &mut RelocationResult,
) -> Result<()> {
    for (&address, &called_function) in function.function_calls() {
        let local_module = &modules[module_index];
        let is_local = local_module.sections().get_by_contained_address(called_function.address).is_some();

        let module: RelocationModule = if is_local {
            let module_kind = local_module.kind();
            let symbol_map = symbol_maps.get_mut(module_kind);
            let Some((_, symbol)) = symbol_map.get_function_containing(called_function.address) else {
                panic!(
                    "Function call from 0x{:08x} in {} to 0x{:08x} leads to no function",
                    address, module_kind, called_function.address
                );
            };
            if called_function.address != symbol.addr {
                eprintln!("Function call from 0x{:08x} in {} to 0x{:08x} goes to middle of function '{}' at 0x{:08x}, adding an external label symbol",
                address, module_kind, called_function.address, symbol.name, symbol.addr);
                symbol_map.add_external_label(called_function.address, called_function.thumb);
            }

            module_kind.into()
        } else {
            let candidates = modules.iter().enumerate().map(|(_, module)| module).filter(|&module| {
                module
                    .sections()
                    .get_by_contained_address(called_function.address)
                    .and_then(|(_, s)| s.functions().get(&called_function.address))
                    .is_some()
            });
            RelocationModule::from_modules(candidates)?
        };

        if module == RelocationModule::None {
            eprintln!(
                "No functions from 0x{address:08x} in {} to 0x{:08x}:",
                modules[module_index].kind(),
                called_function.address
            );
        }

        result.relocations.push(Relocation::new_call(
            address,
            called_function.address,
            module,
            function.is_thumb(),
            called_function.thumb,
        ));
    }
    Ok(())
}

fn find_external_data_from_pools(
    modules: &[Module],
    module_index: usize,
    function: &Function,
    result: &mut RelocationResult,
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
    result: &mut RelocationResult,
) -> Result<()> {
    let local_module = &modules[module_index];
    let is_local = local_module.sections().get_by_contained_address(pointer).is_some();
    if is_local {
        return Ok(());
    }

    let candidates = find_symbol_candidates(modules, module_index, pointer);
    if candidates.is_empty() {
        // Probably not a pointer
        return Ok(());
    }

    let candidate_modules = candidates.iter().map(|c| &modules[c.module_index]);
    let module = RelocationModule::from_modules(candidate_modules)?;

    result.relocations.push(Relocation::new_load(address, pointer, module));
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
            if section.kind() == SectionKind::Code && section.functions().get(&pointer).is_none() {
                return None;
            };
            Some(SymbolCandidate { module_index: index, section_index })
        })
        .collect::<Vec<_>>()
}

pub struct RelocationResult {
    pub relocations: Vec<Relocation>,
    pub external_symbols: Vec<ExternalSymbol>,
}

impl RelocationResult {
    fn new() -> Self {
        Self { relocations: vec![], external_symbols: vec![] }
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
