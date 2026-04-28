use ds_decomp::{
    analysis::functions::{CalledFunction, Function},
    config::{
        module::{Module, ModuleKind},
        relocations::{Relocation, RelocationFromModulesError, RelocationModule},
        section::{SectionCodeError, SectionIndex, SectionKind},
        symbol::{InstructionMode, SymFunction, SymLabel, SymbolKind, SymbolMapError, SymbolMaps},
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
        "Failed to add relocation for local function call from {from:#010x} in {module_kind} to {to:#010x} as it leads to no function"
    ))]
    LocalFunctionNotFound { from: u32, to: u32, module_kind: ModuleKind },
    #[snafu(display(
        "Failed to add relocation for function call from {from:#010x} in {from_module} to {to:#010x} in {to_module} as it leads to a non-function symbol"
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
) -> Result<RelocationResult, AnalyzeExternalReferencesError> {
    let mut result = RelocationResult::new();
    find_relocations_in_functions(&mut result, options)?;
    find_external_references_in_sections(options, &mut result)?;
    Ok(result)
}

fn find_external_references_in_sections(
    options: &mut AnalyzeExternalReferencesOptions,
    result: &mut RelocationResult,
) -> Result<(), AnalyzeExternalReferencesError> {
    let o = options;
    for section in o.modules[o.module_index].sections().iter() {
        match section.kind() {
            SectionKind::Data | SectionKind::Rodata => {}
            SectionKind::Code | SectionKind::Bss => continue,
        }

        let code = section
            .code(o.modules[o.module_index].code(), o.modules[o.module_index].base_address())?
            .unwrap();
        for word in section.iter_words(code, None) {
            find_external_data(o, word.address, word.value, result)?;
        }
    }
    Ok(())
}

fn find_relocations_in_functions(
    result: &mut RelocationResult,
    options: &mut AnalyzeExternalReferencesOptions,
) -> Result<(), AnalyzeExternalReferencesError> {
    for section in options.modules[options.module_index].sections().iter() {
        for function in section.functions().values() {
            add_function_calls_as_relocations(function, result, options)?;
            find_external_data_from_pools(options, function, result)?;
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
    options: &mut AnalyzeExternalReferencesOptions,
    function: &Function,
    result: &mut RelocationResult,
) -> Result<(), AnalyzeExternalReferencesError> {
    let module = &options.modules[options.module_index];
    for pool_constant in function.iter_pool_constants(module.code(), module.base_address()) {
        find_external_data(options, pool_constant.address, pool_constant.value, result)?;
    }
    Ok(())
}

fn find_external_data(
    options: &mut AnalyzeExternalReferencesOptions,
    address: u32,
    pointer: u32,
    result: &mut RelocationResult,
) -> Result<(), AnalyzeExternalReferencesError> {
    let o = options;

    let local_module = &o.modules[o.module_index];
    let is_local = local_module.sections().get_by_contained_address(pointer).is_some();
    if is_local {
        return Ok(());
    }

    let candidates = find_symbol_candidates(o, pointer);
    if candidates.is_empty() {
        // Probably not a pointer
        return Ok(());
    }

    let candidate_modules = candidates.iter().map(|c| &o.modules[c.module_index]);
    let module = RelocationModule::from_modules(candidate_modules)?;

    result.relocations.push(Relocation::new_load(address, pointer, 0, module));
    result.external_symbols.push(ExternalSymbol { candidates, address: pointer });
    Ok(())
}

fn find_symbol_candidates(
    options: &mut AnalyzeExternalReferencesOptions,
    pointer: u32,
) -> Vec<SymbolCandidate> {
    options
        .modules
        .iter()
        .enumerate()
        .filter_map(|(index, module)| {
            if index == options.module_index {
                return None;
            }
            let (section_index, section) = module.sections().get_by_contained_address(pointer)?;
            let symbol_map = options.symbol_maps.get(module.kind()).unwrap();
            if section.kind() == SectionKind::Code {
                let (_, symbol) = symbol_map.by_address(pointer & !1).unwrap()?;
                let symbol_is_thumb = match &symbol.kind {
                    SymbolKind::Function(function) => function.mode == InstructionMode::Thumb,
                    SymbolKind::Label(SymLabel { external: true, mode }) => {
                        *mode == InstructionMode::Thumb
                    }
                    SymbolKind::Label(SymLabel { external: false, .. })
                    | SymbolKind::Undefined
                    | SymbolKind::PoolConstant
                    | SymbolKind::JumpTable(_)
                    | SymbolKind::Data(_)
                    | SymbolKind::Bss(_) => return None,
                };

                let thumb = (pointer & 1) != 0;
                if symbol_is_thumb != thumb {
                    return None;
                }
            }
            if let Some((_, symbol)) = symbol_map.by_address(pointer).unwrap()
                && symbol.local
            {
                // Existing symbol is local, so it can't be referred to by a relocation
                None
            } else {
                Some(SymbolCandidate { module_index: index, section_index })
            }
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
