use std::ops::Range;

use snafu::Snafu;

use crate::{
    analysis::functions::Function,
    config::{
        module::{AnalysisOptions, ModuleKind},
        relocations::{Relocations, RelocationsError},
        section::{Section, SectionKind, Sections},
        symbol::{SymBss, SymData, SymbolMap, SymbolMapError},
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
}

#[derive(Debug, Snafu)]
pub enum FindLocalDataError {
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
    let FindLocalDataOptions { sections, module_kind, symbol_map, relocations, name_prefix, code, base_address, .. } = options;
    let address_range = None;

    for pool_constant in function.iter_pool_constants(code, base_address) {
        let pointer = pool_constant.value;
        let Some((_, section)) = sections.get_by_contained_address(pointer) else {
            // Not a pointer, or points to a different module
            continue;
        };
        let function = symbol_map.get_function(pointer & !1)?;
        if section.kind() == SectionKind::Code
            && let Some((function, _)) = function
        {
            let thumb = (pointer & 1) != 0;
            if function.mode.into_thumb() != Some(thumb) {
                // Instruction mode must match
                continue;
            }

            // Relocate function pointer
            let reloc = relocations.add_load(pool_constant.address, pointer, 0, module_kind.into())?;
            if analysis_options.provide_reloc_source {
                reloc.source = Some(function!().to_string());
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
    let FindLocalDataOptions { sections, module_kind, symbol_map, relocations, name_prefix, code, base_address, .. } = options;

    let address_range = options.address_range.clone().unwrap_or(section.address_range());

    for word in section.iter_words(code, Some(address_range.clone())) {
        let pointer = word.value;
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
        reloc.source = Some(function!().to_string());
    }

    Ok(())
}
