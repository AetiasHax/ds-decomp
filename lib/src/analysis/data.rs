use std::{collections::BTreeMap, ops::Range};

use snafu::Snafu;

use crate::{
    analysis::functions::{CalledFunction, Function},
    config::{
        Comments,
        module::{AnalysisOptions, Module, ModuleKind},
        relocations::{
            Relocation, RelocationKind, RelocationModule, RelocationOptions, Relocations,
            RelocationsError,
        },
        section::{Section, SectionKind, Sections},
        symbol::{SymBss, SymData, SymbolKind, SymbolMap, SymbolMapError},
    },
    function,
};

pub struct FindLocalDataOptions<'a> {
    pub sections: &'a Sections,
    pub module_kind: ModuleKind,
    pub symbol_map: &'a mut SymbolMap,
    pub relocations: &'a mut Relocations,
    pub name_prefix: &'a str,
    pub code: &'a [u8],
    pub base_address: u32,
    pub address_range: Option<Range<u32>>,
    pub relocation_overrides: &'a BTreeMap<u32, RelocationKind>,
}

#[derive(Debug, Snafu)]
pub enum FindLocalDataError {
    #[snafu(display(
        "Local function call from {from:#010x} in {module_kind} to {to:#010x} leads to no function"
    ))]
    LocalFunctionNotFound { from: u32, to: u32, module_kind: ModuleKind },
    #[snafu(transparent)]
    SymbolMap { source: SymbolMapError },
    #[snafu(transparent)]
    Relocations { source: RelocationsError },
}

pub fn find_local_data_from_pools(
    function: &Function,
    options: FindLocalDataOptions,
    analysis_options: &AnalysisOptions,
) -> Result<(), FindLocalDataError> {
    // TODO: Apply address range
    let FindLocalDataOptions {
        sections,
        module_kind,
        symbol_map,
        relocations,
        name_prefix,
        code,
        base_address,
        relocation_overrides,
        ..
    } = options;
    let address_range = None;

    for pool_constant in function.iter_pool_constants(code, base_address) {
        let pointer = pool_constant.value;
        if let Some(reloc_kind) = relocation_overrides.get(&pointer) {
            relocations.add(Relocation::new(RelocationOptions {
                from: pool_constant.address,
                to: pointer,
                addend: 0,
                kind: *reloc_kind,
                module: RelocationModule::from(module_kind),
                comments: Comments::new(),
            }))?;
            continue;
        }
        let Some((_, section)) = sections.get_by_contained_address(pointer) else {
            // Not a pointer, or points to a different module
            continue;
        };
        let symbol = symbol_map.by_address(pointer & !1)?;
        if section.kind() == SectionKind::Code
            && let Some((_, symbol)) = symbol
        {
            let thumb = (pointer & 1) != 0;
            let symbol_thumb = match &symbol.kind {
                SymbolKind::Function(function) => function.mode.into_thumb(),
                SymbolKind::Label(label) => {
                    if label.external {
                        label.mode.into_thumb()
                    } else {
                        None
                    }
                }
                SymbolKind::Undefined
                | SymbolKind::PoolConstant
                | SymbolKind::JumpTable(_)
                | SymbolKind::Data(_)
                | SymbolKind::Bss(_) => None,
            };
            if let Some(symbol_thumb) = symbol_thumb {
                if symbol_thumb != thumb {
                    // Instruction mode must match
                    continue;
                }

                // Relocate function pointer
                let reloc =
                    relocations.add_load(pool_constant.address, pointer, 0, module_kind.into())?;
                if analysis_options.provide_reloc_source {
                    reloc.comments.post_comment = Some(function!().to_string());
                }
            }
        } else {
            add_symbol_from_pointer(
                section,
                pool_constant.address,
                pointer,
                FindLocalDataOptions {
                    sections,
                    module_kind,
                    symbol_map,
                    relocations,
                    name_prefix,
                    code,
                    base_address,
                    address_range: address_range.clone(),
                    relocation_overrides,
                },
                analysis_options,
            )?;
        }
    }

    Ok(())
}

pub fn find_local_data_from_section(
    section: &Section,
    options: FindLocalDataOptions,
    analysis_options: &AnalysisOptions,
) -> Result<(), FindLocalDataError> {
    let FindLocalDataOptions {
        sections,
        module_kind,
        symbol_map,
        relocations,
        name_prefix,
        code,
        base_address,
        relocation_overrides,
        ..
    } = options;

    let address_range = options.address_range.clone().unwrap_or(section.address_range());

    for word in section.iter_words(code, Some(address_range.clone())) {
        let pointer = word.value;
        if let Some(reloc_kind) = relocation_overrides.get(&pointer) {
            relocations.add(Relocation::new(RelocationOptions {
                from: word.address,
                to: pointer,
                addend: 0,
                kind: *reloc_kind,
                module: RelocationModule::from(module_kind),
                comments: Comments::new(),
            }))?;
            continue;
        }
        let Some((_, section)) = options.sections.get_by_contained_address(pointer) else {
            continue;
        };
        add_symbol_from_pointer(
            section,
            word.address,
            pointer,
            FindLocalDataOptions {
                sections,
                module_kind,
                symbol_map,
                relocations,
                name_prefix,
                code,
                base_address,
                address_range: Some(address_range.clone()),
                relocation_overrides,
            },
            analysis_options,
        )?;
    }
    Ok(())
}

fn add_symbol_from_pointer(
    section: &Section,
    address: u32,
    pointer: u32,
    options: FindLocalDataOptions,
    analysis_options: &AnalysisOptions,
) -> Result<(), FindLocalDataError> {
    let FindLocalDataOptions { module_kind, symbol_map, relocations, name_prefix, .. } = options;

    let name = format!("{name_prefix}{pointer:08x}");

    let reloc = match section.kind() {
        SectionKind::Code => {
            let thumb = (pointer & 1) != 0;
            if let Some((function, _)) = symbol_map.get_function(pointer)? {
                // Instruction mode must match
                if function.mode.into_thumb() == Some(thumb) {
                    relocations.add_load(address, pointer, 0, module_kind.into())?
                } else {
                    return Ok(());
                }
            } else {
                return Ok(());
            }
        }
        SectionKind::Data | SectionKind::Rodata => {
            symbol_map.add_data(Some(name), pointer, SymData::Any)?;
            relocations.add_load(address, pointer, 0, module_kind.into())?
        }
        SectionKind::Bss => {
            symbol_map.add_bss(Some(name), pointer, SymBss { size: None })?;
            relocations.add_load(address, pointer, 0, module_kind.into())?
        }
    };
    if analysis_options.provide_reloc_source {
        reloc.comments.post_comment = Some(function!().to_string());
    }

    Ok(())
}

pub fn find_function_labels(
    module: &Module,
    symbol_map: &mut SymbolMap,
    options: &AnalysisOptions,
) -> Result<(), FindLocalDataError> {
    for section in module.sections().iter() {
        for function in section.functions().values() {
            if options.allow_unknown_function_calls {
                insert_unknown_function_symbols(function, module, symbol_map)?;
            }
            add_external_labels(function, module, symbol_map)?;
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
    module: &Module,
    symbol_map: &mut SymbolMap,
) -> Result<(), FindLocalDataError> {
    for (&address, &called_function) in iter_function_calls(function) {
        let local_module = module;
        let is_local =
            local_module.sections().get_by_contained_address(called_function.address).is_some();
        if !is_local {
            continue;
        }

        let module_kind = local_module.kind();
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
    module: &Module,
    symbol_map: &mut SymbolMap,
) -> Result<(), FindLocalDataError> {
    for (&address, &called_function) in iter_function_calls(function) {
        let is_local =
            module.sections().get_by_contained_address(called_function.address).is_some();
        if !is_local {
            continue;
        }

        let module_kind = module.kind();
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
