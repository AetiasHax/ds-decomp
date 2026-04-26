use ds_decomp::{
    analysis::functions::{CalledFunction, Function},
    config::{
        module::{AnalysisOptions, Module, ModuleKind},
        relocations::{Relocation, RelocationFromModulesError, RelocationModule},
        section::{SectionCodeError, SectionIndex, SectionKind},
        symbol::{SymFunction, SymLabel, SymbolKind, SymbolMapError, SymbolMaps},
    },
};
use snafu::Snafu;

pub struct AnalyzeExternalReferencesOptions<'a> {
    pub modules: &'a [Module],
    pub module_index: usize,
    pub symbol_maps: &'a mut SymbolMaps,
}

#[derive(Debug, Snafu)]
pub enum AnalyzeExternalReferencesError {
    #[snafu(display(
        "Local function call from {from:#010x} in {module_kind} to {to:#010x} leads to no function"
    ))]
    LocalFunctionNotFound { from: u32, to: u32, module_kind: ModuleKind },
    #[snafu(display(
        "Function call from {from:#010x} in {from_module} to {to:#010x} in {to_module} leads to a non-function symbol"
    ))]
    InvalidCallDestinationSymbol {
        from: u32,
        to: u32,
        from_module: ModuleKind,
        to_module: ModuleKind,
    },
    #[snafu(transparent)]
    SymbolMap { source: SymbolMapError },
    #[snafu(transparent)]
    SectionCode { source: SectionCodeError },
    #[snafu(transparent)]
    RelocationFromModules { source: RelocationFromModulesError },
}

pub fn analyze_external_references(
    options: &mut AnalyzeExternalReferencesOptions,
    analysis_options: &AnalysisOptions,
) -> Result<RelocationResult, AnalyzeExternalReferencesError> {
    let mut result = RelocationResult::new();
    find_relocations_in_functions(&mut result, options, analysis_options)?;
    find_external_references_in_sections(options.modules, options.module_index, &mut result)?;
    Ok(result)
}

fn find_external_references_in_sections(
    modules: &[Module],
    module_index: usize,
    result: &mut RelocationResult,
) -> Result<(), AnalyzeExternalReferencesError> {
    for section in modules[module_index].sections().iter() {
        match section.kind() {
            SectionKind::Data | SectionKind::Rodata => {}
            SectionKind::Code | SectionKind::Bss => continue,
        }

        let code = section
            .code(modules[module_index].code(), modules[module_index].base_address())?
            .unwrap();
        for word in section.iter_words(code, None) {
            find_external_data(modules, module_index, word.address, word.value, result)?;
        }
    }
    Ok(())
}

fn find_relocations_in_functions(
    result: &mut RelocationResult,
    options: &mut AnalyzeExternalReferencesOptions,
    analysis_options: &AnalysisOptions,
) -> Result<(), AnalyzeExternalReferencesError> {
    for section in options.modules[options.module_index].sections().iter() {
        for function in section.functions().values() {
            if analysis_options.allow_unknown_function_calls {
                insert_unknown_function_symbols(function, options)?;
            }
            add_external_labels(function, options)?;
            add_function_calls_as_relocations(function, result, options)?;
            find_external_data_from_pools(options.modules, options.module_index, function, result)?;
        }
    }
    Ok(())
}

fn iter_function_calls(function: &Function) -> impl Iterator<Item = (&u32, &CalledFunction)> {
    function
        .function_calls()
        .iter()
        // TODO: Condition code resets to AL for relocated call instructions
        .filter(|(_, called_function)| !called_function.ins.is_conditional())
}

fn insert_unknown_function_symbols(
    function: &Function,
    options: &mut AnalyzeExternalReferencesOptions,
) -> Result<(), AnalyzeExternalReferencesError> {
    let AnalyzeExternalReferencesOptions { modules, module_index, symbol_maps } = options;

    for (&address, &called_function) in iter_function_calls(function) {
        let local_module = &modules[*module_index];
        let is_local =
            local_module.sections().get_by_contained_address(called_function.address).is_some();
        if !is_local {
            continue;
        }

        let module_kind = local_module.kind();
        let symbol_map = symbol_maps.get_mut(module_kind);
        if symbol_map.get_function_containing(called_function.address).is_none() {
            log::warn!(
                "Local function call from {:#010x} in {} to {:#010x} leads to no function, inserting an unknown function symbol",
                address,
                module_kind,
                called_function.address
            );

            let thumb_bit = if called_function.thumb { 1 } else { 0 };
            let function_address = called_function.address | thumb_bit;

            if symbol_map.get_function(function_address)?.is_none() {
                let name =
                    format!("{}{:08x}_unk", local_module.default_func_prefix, function_address);
                symbol_map.add_unknown_function(name, function_address, called_function.thumb);
            }
        }
    }
    Ok(())
}

fn add_external_labels(
    function: &Function,
    options: &mut AnalyzeExternalReferencesOptions,
) -> Result<(), AnalyzeExternalReferencesError> {
    let AnalyzeExternalReferencesOptions { modules, module_index, symbol_maps } = options;

    for (&address, &called_function) in iter_function_calls(function) {
        let local_module = &modules[*module_index];
        let is_local =
            local_module.sections().get_by_contained_address(called_function.address).is_some();
        if !is_local {
            continue;
        }

        let module_kind = local_module.kind();
        let symbol_map = symbol_maps.get_mut(module_kind);
        let symbol = match symbol_map.get_function_containing(called_function.address) {
            Some((_, symbol)) => symbol,
            None => {
                let error = LocalFunctionNotFoundSnafu {
                    from: address,
                    to: called_function.address,
                    module_kind,
                }
                .build();
                log::error!("{error}");
                return Err(error);
            }
        };
        if called_function.address != symbol.addr {
            log::warn!(
                "Local function call from {:#010x} in {} to {:#010x} goes to middle of function '{}' at {:#010x}, adding an external label symbol",
                address,
                module_kind,
                called_function.address,
                symbol.name,
                symbol.addr
            );
            symbol_map.add_external_label(called_function.address, called_function.thumb)?;
        }
    }
    Ok(())
}

fn add_function_calls_as_relocations(
    function: &Function,
    result: &mut RelocationResult,
    options: &mut AnalyzeExternalReferencesOptions,
) -> Result<(), AnalyzeExternalReferencesError> {
    let AnalyzeExternalReferencesOptions { modules, module_index, symbol_maps } = options;

    for (&address, &called_function) in iter_function_calls(function) {
        let local_module = &modules[*module_index];
        let is_local =
            local_module.sections().get_by_contained_address(called_function.address).is_some();

        let module: RelocationModule = if is_local {
            let module_kind = local_module.kind();
            let symbol_map = symbol_maps.get_mut(module_kind);
            let symbol = match symbol_map.by_address(called_function.address)? {
                Some((_, symbol)) => symbol,
                None => {
                    let error = LocalFunctionNotFoundSnafu {
                        from: address,
                        to: called_function.address,
                        module_kind,
                    }
                    .build();
                    log::error!("{error}");
                    return Err(error);
                }
            };
            match &symbol.kind {
                SymbolKind::Function(_) | SymbolKind::Label(SymLabel { external: true, .. }) => {}

                SymbolKind::Label(SymLabel { external: false, .. })
                | SymbolKind::Undefined
                | SymbolKind::PoolConstant
                | SymbolKind::JumpTable(_)
                | SymbolKind::Data(_)
                | SymbolKind::Bss(_) => {
                    return InvalidCallDestinationSymbolSnafu {
                        from: address,
                        to: called_function.address,
                        from_module: module_kind,
                        to_module: module_kind,
                    }
                    .fail();
                }
            }

            module_kind.into()
        } else {
            let candidates = modules.iter().filter(|&module| {
                let symbol_map = symbol_maps.get(module.kind()).unwrap();
                let Some((_, symbol)) = symbol_map.by_address(called_function.address).unwrap()
                else {
                    return false;
                };

                let mode = match &symbol.kind {
                    SymbolKind::Function(SymFunction { mode, .. })
                    | SymbolKind::Label(SymLabel { external: true, mode }) => mode,

                    SymbolKind::Label(SymLabel { external: false, .. })
                    | SymbolKind::Undefined
                    | SymbolKind::PoolConstant
                    | SymbolKind::JumpTable(_)
                    | SymbolKind::Data(_)
                    | SymbolKind::Bss(_) => return false,
                };

                mode.into_thumb() == Some(called_function.thumb)
            });
            RelocationModule::from_modules(candidates)?
        };

        if module == RelocationModule::None {
            log::warn!(
                "No functions from {address:#010x} in {} to {:#010x}:",
                modules[*module_index].kind(),
                called_function.address
            );
        }

        if called_function.ins.mnemonic() == "b" {
            result.relocations.push(Relocation::new_branch(
                address,
                called_function.address,
                module,
            ));
        } else {
            result.relocations.push(Relocation::new_call(
                address,
                called_function.address,
                module,
                function.is_thumb(),
                called_function.thumb,
            ));
        }
    }
    Ok(())
}

fn find_external_data_from_pools(
    modules: &[Module],
    module_index: usize,
    function: &Function,
    result: &mut RelocationResult,
) -> Result<(), AnalyzeExternalReferencesError> {
    let module = &modules[module_index];
    for pool_constant in function.iter_pool_constants(module.code(), module.base_address()) {
        find_external_data(
            modules,
            module_index,
            pool_constant.address,
            pool_constant.value,
            result,
        )?;
    }
    Ok(())
}

fn find_external_data(
    modules: &[Module],
    module_index: usize,
    address: u32,
    pointer: u32,
    result: &mut RelocationResult,
) -> Result<(), AnalyzeExternalReferencesError> {
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

fn find_symbol_candidates(
    modules: &[Module],
    module_index: usize,
    pointer: u32,
) -> Vec<SymbolCandidate> {
    modules
        .iter()
        .enumerate()
        .filter_map(|(index, module)| {
            if index == module_index {
                return None;
            }
            let (section_index, section) = module.sections().get_by_contained_address(pointer)?;
            if section.kind() == SectionKind::Code {
                let function = section.functions().get(&(pointer & !1))?;
                let thumb = (pointer & 1) != 0;
                if function.is_thumb() != thumb {
                    return None;
                }
            }
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
    pub section_index: SectionIndex,
}
