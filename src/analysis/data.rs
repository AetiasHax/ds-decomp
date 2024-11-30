use anyhow::{bail, Result};
use bon::builder;

use crate::config::{
    module::{Module, ModuleKind},
    relocation::{Relocation, RelocationModule, Relocations},
    section::{Section, SectionKind, Sections},
    symbol::{SymBss, SymData, SymbolMap, SymbolMaps},
};

use super::functions::Function;

#[builder]
pub fn find_local_data_from_pools(
    function: &Function,
    sections: &Sections,
    module_kind: ModuleKind,
    symbol_map: &mut SymbolMap,
    relocations: &mut Relocations,
    name_prefix: &str,
    module_code: &[u8],
    base_address: u32,
) -> Result<()> {
    for pool_constant in function.iter_pool_constants(module_code, base_address) {
        let pointer = pool_constant.value;
        let Some((_, section)) = sections.get_by_contained_address(pointer) else {
            // Not a pointer, or points to a different module
            continue;
        };
        if section.kind() == SectionKind::Code && symbol_map.get_function(pointer & !1)?.is_some() {
            // Relocate function pointer
            relocations.add_load(pool_constant.address, pointer, 0, module_kind.try_into()?)?;
        } else {
            add_symbol_from_pointer(
                section,
                pool_constant.address,
                pointer,
                module_kind,
                symbol_map,
                relocations,
                name_prefix,
            )?;
        }
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
        let Some((_, section)) = sections.get_by_contained_address(pointer) else {
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
        SectionKind::Code => {
            if symbol_map.get_function(pointer)?.is_some() {
                relocations.add_load(address, pointer, 0, module_kind.try_into()?)?;
            }
        }
        SectionKind::Data => {
            symbol_map.add_data(Some(name), pointer, SymData::Any)?;
            relocations.add_load(address, pointer, 0, module_kind.try_into()?)?;
        }
        SectionKind::Bss => {
            symbol_map.add_bss(Some(name), pointer, SymBss { size: None })?;
            relocations.add_load(address, pointer, 0, module_kind.try_into()?)?;
        }
    }

    Ok(())
}

#[builder]
pub fn analyze_external_references(
    modules: &[Module<'_>],
    module_index: usize,
    symbol_maps: &mut SymbolMaps,
    allow_unknown_function_calls: bool,
) -> Result<RelocationResult> {
    let mut result = RelocationResult::new();
    find_relocations_in_functions()
        .modules(modules)
        .module_index(module_index)
        .symbol_maps(symbol_maps)
        .result(&mut result)
        .allow_unknown_function_calls(allow_unknown_function_calls)
        .call()?;
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

#[builder]
fn find_relocations_in_functions(
    modules: &[Module<'_>],
    module_index: usize,
    symbol_maps: &mut SymbolMaps,
    result: &mut RelocationResult,
    allow_unknown_function_calls: bool,
) -> Result<()> {
    for section in modules[module_index].sections().iter() {
        for function in section.functions().values() {
            add_function_calls_as_relocations()
                .modules(modules)
                .module_index(module_index)
                .function(function)
                .symbol_maps(symbol_maps)
                .result(result)
                .allow_unknown_function_calls(allow_unknown_function_calls)
                .call()?;
            find_external_data_from_pools(modules, module_index, function, result)?;
        }
    }
    Ok(())
}

#[derive(Debug, Snafu)]
pub enum AddFunctionCallAsRelocationsError {
    #[snafu(display("Local function call from 0x{from:08x} in {module_kind} to 0x{to:08x} leads to no function"))]
    LocalFunctionNotFound { from: u32, to: u32, module_kind: ModuleKind },
}

#[builder]
fn add_function_calls_as_relocations(
    modules: &[Module<'_>],
    module_index: usize,
    function: &Function,
    symbol_maps: &mut SymbolMaps,
    result: &mut RelocationResult,
    allow_unknown_function_calls: bool,
) -> Result<()> {
    for (&address, &called_function) in function.function_calls() {
        if called_function.ins.is_conditional() {
            // Dumb mwld linker bug removes the condition code from relocated call instructions
            continue;
        }

        let local_module = &modules[module_index];
        let is_local = local_module.sections().get_by_contained_address(called_function.address).is_some();

        let module: RelocationModule = if is_local {
            let module_kind = local_module.kind();
            let symbol_map = symbol_maps.get_mut(module_kind);
            let symbol = match symbol_map.get_function_containing(called_function.address) {
                Some((_, symbol)) => symbol,
                None => {
                    if !allow_unknown_function_calls {
                        let error =
                            LocalFunctionNotFoundSnafu { from: address, to: called_function.address, module_kind }.build();
                        log::error!("{error}");
                        return Err(error.into());
                    } else {
                        log::warn!("Local function call from 0x{:08x} in {} to 0x{:08x} leads to no function, inserting an unknown function symbol",
                        address,
                        module_kind,
                        called_function.address);
                        let thumb_bit = if called_function.thumb { 1 } else { 0 };
                        let function_address = called_function.address | thumb_bit;

                        let name = format!("{}{:08x}_unk", local_module.default_func_prefix, function_address);
                        let (_, symbol) = symbol_map.add_unknown_function(name, function_address, called_function.thumb);
                        symbol
                    }
                }
            };
            if called_function.address != symbol.addr {
                log::warn!("Local function call from 0x{:08x} in {} to 0x{:08x} goes to middle of function '{}' at 0x{:08x}, adding an external label symbol",
                address, module_kind, called_function.address, symbol.name, symbol.addr);
                symbol_map.add_external_label(called_function.address, called_function.thumb)?;
            }

            module_kind.try_into()?
        } else {
            let candidates = modules.iter().enumerate().map(|(_, module)| module).filter(|&module| {
                let symbol_map = symbol_maps.get(module.kind()).unwrap();
                let Some((function, _)) = symbol_map.get_function(called_function.address).unwrap() else {
                    return false;
                };
                function.mode.into_thumb() == Some(called_function.thumb)
            });
            RelocationModule::from_modules(candidates)?
        };

        if module == RelocationModule::None {
            log::warn!(
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

fn find_external_data_from_pools<'a>(
    modules: &[Module<'a>],
    module_index: usize,
    function: &Function,
    result: &mut RelocationResult,
) -> Result<()> {
    let module = &modules[module_index];
    for pool_constant in function.iter_pool_constants(module.code(), module.base_address()) {
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

    result.relocations.push(Relocation::new_load(address, pointer, 0, module));
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
            if section.kind() == SectionKind::Code {
                let Some(function) = section.functions().get(&(pointer & !1)) else {
                    return None;
                };
                let thumb = (pointer & 1) != 0;
                if function.is_thumb() != thumb {
                    return None;
                }
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
