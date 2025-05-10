use std::{
    backtrace::Backtrace,
    collections::{BTreeMap, BTreeSet},
    fmt::Display,
};

use ds_rom::rom::{
    raw::{AutoloadKind, RawBuildInfoError},
    Arm9, Autoload, Overlay,
};
use snafu::Snafu;

use crate::analysis::{
    ctor::{CtorRange, CtorRangeError},
    data::{self, FindLocalDataOptions},
    exception::{ExceptionData, ExceptionDataError},
    functions::{
        FindFunctionsOptions, Function, FunctionAnalysisError, FunctionParseOptions, FunctionSearchOptions,
        ParseFunctionOptions, ParseFunctionResult,
    },
    main::{MainFunction, MainFunctionError},
};

use self::data::FindLocalDataError;

use super::{
    relocations::Relocations,
    section::{Section, SectionCodeError, SectionError, SectionKind, SectionOptions, Sections, SectionsError},
    symbol::{SymData, SymbolKind, SymbolMap, SymbolMapError, SymbolMaps},
};

pub struct Module<'a> {
    name: String,
    kind: ModuleKind,
    relocations: Relocations,
    code: &'a [u8],
    base_address: u32,
    bss_size: u32,
    pub default_func_prefix: String,
    pub default_data_prefix: String,
    sections: Sections,
    signed: bool,
}

#[derive(Debug, Snafu)]
pub enum ModuleError {
    #[snafu(display("no sections provided:\n{backtrace}"))]
    NoSections { backtrace: Backtrace },
    #[snafu(transparent)]
    CtorRange { source: CtorRangeError },
    #[snafu(transparent)]
    MainFunction { source: MainFunctionError },
    #[snafu(transparent)]
    RawBuildInfo { source: RawBuildInfoError },
    #[snafu(transparent)]
    SymbolMap { source: SymbolMapError },
    #[snafu(transparent)]
    FunctionAnalysis { source: FunctionAnalysisError },
    #[snafu(display("function {name} could not be analyzed: {parse_result:x?}:\n{backtrace}"))]
    FunctionAnalysisFailed { name: String, parse_result: ParseFunctionResult, backtrace: Backtrace },
    #[snafu(transparent)]
    Section { source: SectionError },
    #[snafu(transparent)]
    Sections { source: SectionsError },
    #[snafu(display(
        ".init section exists in {module_kind} ({min_address:#x}..{max_address:#x}) but no functions were found:\n{backtrace}"
    ))]
    NoInitFunctions { module_kind: ModuleKind, min_address: u32, max_address: u32, backtrace: Backtrace },
    #[snafu(display("Entry functions not found:\n{backtrace}"))]
    NoEntryFunctions { backtrace: Backtrace },
    #[snafu(display("No functions in ARM9 main module:\n{backtrace}"))]
    NoArm9Functions { backtrace: Backtrace },
    #[snafu(display("No functions in ITCM:\n{backtrace}"))]
    NoItcmFunctions { backtrace: Backtrace },
    #[snafu(transparent)]
    FindLocalData { source: FindLocalDataError },
    #[snafu(transparent)]
    SectionCode { source: SectionCodeError },
    #[snafu(display("The provided autoload is not an unknown autoload:\n{backtrace}"))]
    NotAnUnknownAutoload { backtrace: Backtrace },
    #[snafu(transparent)]
    ExceptionData { source: ExceptionDataError },
}

pub struct OverlayModuleOptions<'a> {
    pub id: u16,
    pub code: &'a [u8],
    pub signed: bool,
}

pub struct ModuleOptions<'a> {
    pub kind: ModuleKind,
    pub name: String,
    pub relocations: Relocations,
    pub sections: Sections,
    pub code: &'a [u8],
    pub signed: bool,
}

impl<'a> Module<'a> {
    pub fn new(symbol_map: &mut SymbolMap, options: ModuleOptions<'a>) -> Result<Module<'a>, ModuleError> {
        let ModuleOptions { kind, name, relocations, mut sections, code, signed } = options;

        let base_address = sections.base_address().ok_or_else(|| NoSectionsSnafu.build())?;
        let end_address = sections.end_address().ok_or_else(|| NoSectionsSnafu.build())?;
        let bss_size = sections.bss_size();
        Self::import_functions(symbol_map, &mut sections, base_address, end_address, code)?;

        let (default_func_prefix, default_data_prefix) = match kind {
            ModuleKind::Overlay(id) => (format!("func_ov{:03}_", id), format!("data_ov{:03}_", id)),
            _ => ("func_".to_string(), "data_".to_string()),
        };

        Ok(Self {
            name,
            kind,
            relocations,
            code,
            base_address,
            bss_size,
            default_func_prefix,
            default_data_prefix,
            sections,
            signed,
        })
    }

    /// Depricated, use [`Self::new`] instead.
    ///
    /// Creates a new ARM9 main module.
    #[deprecated]
    pub fn new_arm9(
        name: String,
        symbol_map: &mut SymbolMap,
        relocations: Relocations,
        mut sections: Sections,
        code: &'a [u8],
    ) -> Result<Module<'a>, ModuleError> {
        let base_address = sections.base_address().ok_or_else(|| NoSectionsSnafu.build())?;
        let end_address = sections.end_address().ok_or_else(|| NoSectionsSnafu.build())?;
        let bss_size = sections.bss_size();
        Self::import_functions(symbol_map, &mut sections, base_address, end_address, code)?;
        Ok(Self {
            name,
            kind: ModuleKind::Arm9,
            relocations,
            code,
            base_address,
            bss_size,
            default_func_prefix: "func_".to_string(),
            default_data_prefix: "data_".to_string(),
            sections,
            signed: false,
        })
    }

    pub fn analyze_arm9(
        arm9: &'a Arm9,
        unknown_autoloads: &[&Autoload],
        symbol_maps: &mut SymbolMaps,
        options: &AnalysisOptions,
    ) -> Result<Self, ModuleError> {
        let ctor_range = CtorRange::find_in_arm9(arm9, unknown_autoloads)?;
        let main_func = MainFunction::find_in_arm9(arm9)?;
        let exception_data = ExceptionData::analyze(arm9, unknown_autoloads)?;

        let mut module = Self {
            name: "main".to_string(),
            kind: ModuleKind::Arm9,
            relocations: Relocations::new(),
            code: arm9.code()?,
            base_address: arm9.base_address(),
            bss_size: arm9.bss()?.len() as u32,
            default_func_prefix: "func_".to_string(),
            default_data_prefix: "data_".to_string(),
            sections: Sections::new(),
            signed: false,
        };
        let symbol_map = symbol_maps.get_mut(module.kind);

        module.find_sections_arm9(symbol_map, ctor_range, exception_data, arm9)?;
        module.find_data_from_pools(symbol_map, options)?;
        module.find_data_from_sections(symbol_map, options)?;

        symbol_map.rename_by_address(arm9.entry_function(), "Entry")?;
        symbol_map.rename_by_address(main_func.address, "main")?;

        Ok(module)
    }

    /// Depricated, use [`Self::new`] instead.
    ///
    /// Creates a new overlay module.
    #[deprecated]
    pub fn new_overlay(
        name: String,
        symbol_map: &mut SymbolMap,
        relocations: Relocations,
        mut sections: Sections,
        options: OverlayModuleOptions<'a>,
    ) -> Result<Self, ModuleError> {
        let OverlayModuleOptions { id, code, signed } = options;

        let base_address = sections.base_address().ok_or_else(|| NoSectionsSnafu.build())?;
        let end_address = sections.end_address().ok_or_else(|| NoSectionsSnafu.build())?;
        let bss_size = sections.bss_size();
        Self::import_functions(symbol_map, &mut sections, base_address, end_address, code)?;
        Ok(Self {
            name,
            kind: ModuleKind::Overlay(id),
            relocations,
            code,
            base_address,
            bss_size,
            default_func_prefix: format!("func_ov{:03}_", id),
            default_data_prefix: format!("data_ov{:03}_", id),
            sections,
            signed,
        })
    }

    pub fn analyze_overlay(
        overlay: &'a Overlay,
        symbol_maps: &mut SymbolMaps,
        options: &AnalysisOptions,
    ) -> Result<Self, ModuleError> {
        let mut module = Self {
            name: format!("ov{:03}", overlay.id()),
            kind: ModuleKind::Overlay(overlay.id()),
            relocations: Relocations::new(),
            code: overlay.code(),
            base_address: overlay.base_address(),
            bss_size: overlay.bss_size(),
            default_func_prefix: format!("func_ov{:03}_", overlay.id()),
            default_data_prefix: format!("data_ov{:03}_", overlay.id()),
            sections: Sections::new(),
            signed: overlay.is_signed(),
        };
        let symbol_map = symbol_maps.get_mut(module.kind);

        log::debug!("Analyzing overlay {}", overlay.id());
        module.find_sections_overlay(symbol_map, CtorRange { start: overlay.ctor_start(), end: overlay.ctor_end() })?;
        module.find_data_from_pools(symbol_map, options)?;
        module.find_data_from_sections(symbol_map, options)?;

        Ok(module)
    }

    /// Depricated, use [`Self::new`] instead.
    ///
    /// Creates a new autoload module.
    #[deprecated]
    pub fn new_autoload(
        name: String,
        symbol_map: &mut SymbolMap,
        relocations: Relocations,
        mut sections: Sections,
        kind: AutoloadKind,
        code: &'a [u8],
    ) -> Result<Self, ModuleError> {
        let base_address = sections.base_address().ok_or_else(|| NoSectionsSnafu.build())?;
        let end_address = sections.end_address().ok_or_else(|| NoSectionsSnafu.build())?;
        let bss_size = sections.bss_size();
        Self::import_functions(symbol_map, &mut sections, base_address, end_address, code)?;
        Ok(Self {
            name,
            kind: ModuleKind::Autoload(kind),
            relocations,
            code,
            base_address,
            bss_size,
            default_func_prefix: "func_".to_string(),
            default_data_prefix: "data_".to_string(),
            sections,
            signed: false,
        })
    }

    pub fn analyze_itcm(
        autoload: &'a Autoload,
        symbol_maps: &mut SymbolMaps,
        options: &AnalysisOptions,
    ) -> Result<Self, ModuleError> {
        let mut module = Self {
            name: "itcm".to_string(),
            kind: ModuleKind::Autoload(AutoloadKind::Itcm),
            relocations: Relocations::new(),
            code: autoload.code(),
            base_address: autoload.base_address(),
            bss_size: autoload.bss_size(),
            default_func_prefix: "func_".to_string(),
            default_data_prefix: "data_".to_string(),
            sections: Sections::new(),
            signed: false,
        };
        let symbol_map = symbol_maps.get_mut(module.kind);

        module.find_sections_itcm(symbol_map)?;
        module.find_data_from_pools(symbol_map, options)?;

        Ok(module)
    }

    pub fn analyze_dtcm(
        autoload: &'a Autoload,
        symbol_maps: &mut SymbolMaps,
        options: &AnalysisOptions,
    ) -> Result<Self, ModuleError> {
        let mut module = Self {
            name: "dtcm".to_string(),
            kind: ModuleKind::Autoload(AutoloadKind::Dtcm),
            relocations: Relocations::new(),
            code: autoload.code(),
            base_address: autoload.base_address(),
            bss_size: autoload.bss_size(),
            default_func_prefix: "func_".to_string(),
            default_data_prefix: "data_".to_string(),
            sections: Sections::new(),
            signed: false,
        };
        let symbol_map = symbol_maps.get_mut(module.kind);

        module.find_sections_dtcm()?;
        module.find_data_from_sections(symbol_map, options)?;

        Ok(module)
    }

    pub fn analyze_unknown_autoload(
        autoload: &'a Autoload,
        symbol_maps: &mut SymbolMaps,
        options: &AnalysisOptions,
    ) -> Result<Self, ModuleError> {
        let AutoloadKind::Unknown(autoload_index) = autoload.kind() else {
            return NotAnUnknownAutoloadSnafu.fail();
        };
        let mut module = Self {
            name: format!("autoload_{}", autoload_index),
            kind: ModuleKind::Autoload(autoload.kind()),
            relocations: Relocations::new(),
            code: autoload.code(),
            base_address: autoload.base_address(),
            bss_size: autoload.bss_size(),
            default_func_prefix: "func_".to_string(),
            default_data_prefix: "data_".to_string(),
            sections: Sections::new(),
            signed: false,
        };
        let symbol_map = symbol_maps.get_mut(module.kind);

        module.find_sections_unknown_autoload(symbol_map, autoload)?;
        module.find_data_from_pools(symbol_maps.get_mut(module.kind), options)?;
        module.find_data_from_sections(symbol_maps.get_mut(module.kind), options)?;

        Ok(module)
    }

    fn import_functions(
        symbol_map: &mut SymbolMap,
        sections: &mut Sections,
        base_address: u32,
        end_address: u32,
        code: &'a [u8],
    ) -> Result<(), ModuleError> {
        for (sym_function, symbol) in symbol_map.clone_functions() {
            if sym_function.unknown {
                continue;
            }
            let offset = symbol.addr - base_address;
            let size = sym_function.size;
            let parse_result = Function::parse_function(FunctionParseOptions {
                name: symbol.name.to_string(),
                start_address: symbol.addr,
                base_address: symbol.addr,
                module_code: &code[offset as usize..],
                known_end_address: Some(symbol.addr + size),
                module_start_address: base_address,
                module_end_address: end_address,
                parse_options: ParseFunctionOptions { thumb: sym_function.mode.into_thumb() },
                ..Default::default()
            })?;
            let function = match parse_result {
                ParseFunctionResult::Found(function) => function,
                _ => return FunctionAnalysisFailedSnafu { name: symbol.name, parse_result }.fail(),
            };
            function.add_local_symbols_to_map(symbol_map)?;
            sections.add_function(function);
        }
        Ok(())
    }

    fn find_functions(
        &mut self,
        symbol_map: &mut SymbolMap,
        search_options: FunctionSearchOptions,
    ) -> Result<Option<FoundFunctions>, ModuleError> {
        let functions = Function::find_functions(FindFunctionsOptions {
            default_name_prefix: &self.default_func_prefix,
            base_address: self.base_address,
            module_code: self.code,
            symbol_map,
            module_start_address: self.base_address,
            module_end_address: self.end_address(),
            search_options,
        })?;

        if functions.is_empty() {
            Ok(None)
        } else {
            let start = functions.first_key_value().unwrap().1.start_address();
            // Align by 4 in case of Thumb function ending on a 2-byte boundary
            let end = functions.last_key_value().unwrap().1.end_address().next_multiple_of(4);
            log::debug!("Found {} functions in {}: {:#x} to {:#x}", functions.len(), self.kind, start, end);
            Ok(Some(FoundFunctions { functions, start, end }))
        }
    }

    /// Adds the .ctor section to this module. Returns the min and max address of .init functions in the .ctor section.
    fn add_ctor_section(&mut self, ctor_range: &CtorRange) -> Result<Option<InitFunctions>, ModuleError> {
        let section = Section::new(SectionOptions {
            name: ".ctor".to_string(),
            kind: SectionKind::Rodata,
            start_address: ctor_range.start,
            end_address: ctor_range.end,
            alignment: 4,
            functions: None,
        })?;
        self.sections.add(section)?;

        let start = (ctor_range.start - self.base_address) as usize;
        let end = (ctor_range.end - self.base_address) as usize;
        let ctor = &self.code[start..end];

        let mut init_functions = InitFunctions(BTreeSet::new());

        let mut prev_address = 0;
        for address in ctor.chunks(4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]])).take_while(|&addr| addr != 0) {
            if address < prev_address {
                // Not in order, abort

                // TODO: Create other sections for initializer functions that are not in order in .ctor. As in, every subrange
                // of functions that are in order gets is own section, so that .ctor can be delinked and linked in a correct
                // order.
                break;
            }
            prev_address = address;
            init_functions.0.insert(address & !1);
        }

        if init_functions.0.is_empty() {
            Ok(None)
        } else {
            Ok(Some(init_functions))
        }
    }

    /// Adds the .init section to this module. Returns the start and end address of the .init section.
    fn add_init_section(
        &mut self,
        symbol_map: &mut SymbolMap,
        ctor: &CtorRange,
        init_functions: InitFunctions,
        continuous: bool,
    ) -> Result<Option<(u32, u32)>, ModuleError> {
        let functions_min = *init_functions.0.first().unwrap();
        let functions_max = *init_functions.0.last().unwrap();
        let FoundFunctions { functions: init_functions, start: init_start, end: init_end } = self
            .find_functions(
                symbol_map,
                FunctionSearchOptions {
                    start_address: Some(functions_min),
                    last_function_address: Some(functions_max),
                    function_addresses: Some(init_functions.0),
                    check_defs_uses: true,
                    ..Default::default()
                },
            )?
            .ok_or_else(|| {
                NoInitFunctionsSnafu { module_kind: self.kind, min_address: functions_min, max_address: functions_max }.build()
            })?;
        // Functions in .ctor can sometimes point to .text instead of .init
        if !continuous || init_end == ctor.start {
            self.sections.add(Section::new(SectionOptions {
                name: ".init".to_string(),
                kind: SectionKind::Code,
                start_address: init_start,
                end_address: init_end,
                alignment: 4,
                functions: Some(init_functions),
            })?)?;
            Ok(Some((init_start, init_end)))
        } else {
            Ok(None)
        }
    }

    /// Adds the .text section to this module.
    fn add_text_section(&mut self, functions_result: FoundFunctions) -> Result<(), ModuleError> {
        let FoundFunctions { functions, start, end } = functions_result;

        if start < end {
            self.sections.add(Section::new(SectionOptions {
                name: ".text".to_string(),
                kind: SectionKind::Code,
                start_address: start,
                end_address: end,
                alignment: 32,
                functions: Some(functions),
            })?)?;
        }
        Ok(())
    }

    fn add_rodata_section(&mut self, start: u32, end: u32) -> Result<(), ModuleError> {
        if start < end {
            self.sections.add(Section::new(SectionOptions {
                name: ".rodata".to_string(),
                kind: SectionKind::Rodata,
                start_address: start,
                end_address: end,
                alignment: 4,
                functions: None,
            })?)?;
        }
        Ok(())
    }

    fn add_data_section(&mut self, start: u32, end: u32) -> Result<(), ModuleError> {
        if start < end {
            self.sections.add(Section::new(SectionOptions {
                name: ".data".to_string(),
                kind: SectionKind::Data,
                start_address: start,
                end_address: end,
                alignment: 32,
                functions: None,
            })?)?;
        }
        Ok(())
    }

    fn add_bss_section(&mut self, start: u32) -> Result<(), ModuleError> {
        self.sections.add(Section::new(SectionOptions {
            name: ".bss".to_string(),
            kind: SectionKind::Bss,
            start_address: start,
            end_address: start + self.bss_size,
            alignment: 32,
            functions: None,
        })?)?;
        Ok(())
    }

    fn find_sections_overlay(&mut self, symbol_map: &mut SymbolMap, ctor: CtorRange) -> Result<(), ModuleError> {
        let rodata_end = if let Some(init_functions) = self.add_ctor_section(&ctor)? {
            if let Some((init_start, _)) = self.add_init_section(symbol_map, &ctor, init_functions, true)? {
                init_start
            } else {
                ctor.start
            }
        } else {
            ctor.start
        };

        let rodata_start = if let Some(functions_result) = self.find_functions(
            symbol_map,
            FunctionSearchOptions {
                end_address: Some(rodata_end),
                use_data_as_upper_bound: true,
                check_defs_uses: true,
                ..Default::default()
            },
        )? {
            let end = functions_result.end;
            self.add_text_section(functions_result)?;
            end
        } else {
            self.base_address
        };

        self.add_rodata_section(rodata_start, rodata_end)?;

        let data_start = ctor.end.next_multiple_of(32);
        let data_end = self.base_address + self.code.len() as u32;
        self.add_data_section(data_start, data_end)?;
        self.add_bss_section(data_end)?;

        Ok(())
    }

    fn find_sections_arm9(
        &mut self,
        symbol_map: &mut SymbolMap,
        ctor: CtorRange,
        exception_data: Option<ExceptionData>,
        arm9: &Arm9,
    ) -> Result<(), ModuleError> {
        // .ctor and .init
        let (read_only_end, rodata_start) = if let Some(init_functions) = self.add_ctor_section(&ctor)? {
            if let Some(init_range) = self.add_init_section(symbol_map, &ctor, init_functions, false)? {
                (init_range.0, Some(init_range.1))
            } else {
                (ctor.start, None)
            }
        } else {
            (ctor.start, None)
        };

        // Secure area functions (software interrupts)
        let secure_area = &self.code[..0x800];
        let mut functions = Function::find_secure_area_functions(secure_area, self.base_address, symbol_map);

        // Build info
        let build_info_offset = arm9.build_info_offset();
        let build_info_address = arm9.base_address() + build_info_offset;
        symbol_map.add_data(Some("BuildInfo".to_string()), build_info_address, SymData::Any)?;

        // Autoload callback
        let autoload_callback_address = arm9.autoload_callback();
        let name = "AutoloadCallback";
        let parse_result = Function::parse_function(FunctionParseOptions {
            name: name.to_string(),
            start_address: autoload_callback_address,
            base_address: self.base_address,
            module_code: self.code,
            known_end_address: None,
            module_start_address: self.base_address,
            module_end_address: self.end_address(),
            parse_options: Default::default(),
            check_defs_uses: true,
            existing_functions: Some(&functions),
        })?;
        let autoload_function = match parse_result {
            ParseFunctionResult::Found(function) => function,
            _ => return FunctionAnalysisFailedSnafu { name, parse_result }.fail(),
        };
        symbol_map.add_function(&autoload_function);
        functions.insert(autoload_function.first_instruction_address(), autoload_function);

        // Entry functions
        let FoundFunctions { functions: entry_functions, .. } = self
            .find_functions(
                symbol_map,
                FunctionSearchOptions {
                    start_address: Some(self.base_address + 0x800),
                    end_address: Some(build_info_address),
                    existing_functions: Some(&functions),
                    check_defs_uses: true,
                    ..Default::default()
                },
            )?
            .ok_or_else(|| NoEntryFunctionsSnafu.build())?;
        functions.extend(entry_functions);

        // All other functions, starting from main
        let exception_start = exception_data.as_ref().and_then(|e| e.exception_start());
        let text_max = exception_start.unwrap_or(read_only_end);
        let main_start = self.find_build_info_end_address(arm9);
        let FoundFunctions { functions: text_functions, end: mut text_end, .. } = self
            .find_functions(
                symbol_map,
                FunctionSearchOptions {
                    start_address: Some(main_start),
                    end_address: Some(text_max),
                    // Skips over segments of strange EOR instructions which are never executed
                    max_function_start_search_distance: u32::MAX,
                    use_data_as_upper_bound: true,
                    // There are some handwritten assembly functions in ARM9 main that don't follow the procedure call standard
                    check_defs_uses: false,
                    ..Default::default()
                },
            )?
            .ok_or_else(|| NoArm9FunctionsSnafu.build())?;
        let text_start = self.base_address;
        functions.extend(text_functions);
        self.add_text_section(FoundFunctions { functions, start: text_start, end: text_end })?;

        // Add .exception and .exceptix sections if they exist
        if let Some(exception_data) = exception_data {
            if let Some(exception_start) = exception_data.exception_start() {
                self.sections.add(Section::new(SectionOptions {
                    name: ".exception".to_string(),
                    kind: SectionKind::Rodata,
                    start_address: exception_start,
                    end_address: exception_data.exceptix_start(),
                    alignment: 1,
                    functions: None,
                })?)?;
            }

            self.sections.add(Section::new(SectionOptions {
                name: ".exceptix".to_string(),
                kind: SectionKind::Rodata,
                start_address: exception_data.exceptix_start(),
                end_address: exception_data.exceptix_end(),
                alignment: 4,
                functions: None,
            })?)?;

            text_end = exception_data.exceptix_end();
        }

        // .rodata
        let rodata_start = rodata_start.unwrap_or(text_end);
        self.add_rodata_section(rodata_start, ctor.start)?;

        // .data and .bss
        let data_start = ctor.end.next_multiple_of(32);
        let data_end = self.base_address + self.code.len() as u32;
        self.add_data_section(data_start, data_end)?;
        let bss_start = data_end.next_multiple_of(32);
        self.add_bss_section(bss_start)?;

        let section_after_text = self.sections.get_section_after(text_end);
        if let Some(section_after_text) = section_after_text {
            if text_end != section_after_text.start_address() {
                log::warn!(
                    "Expected .text to end ({:#010x}) where {} starts ({:#010x})",
                    text_end,
                    section_after_text.name(),
                    section_after_text.start_address()
                );
            }
        }

        Ok(())
    }

    fn find_build_info_end_address(&self, arm9: &Arm9) -> u32 {
        let build_info_offset = arm9.build_info_offset();
        let library_list_start = build_info_offset + 0x24; // 0x24 is the size of the build info struct

        let mut offset = library_list_start as usize;
        loop {
            // Up to 4 bytes of zeros for alignment
            let Some((library_offset, ch)) = self.code[offset..offset + 4].iter().enumerate().find(|(_, &b)| b != b'0') else {
                break;
            };
            if *ch != b'[' {
                // Not a library name
                break;
            }
            offset += library_offset;

            let library_length = self.code[offset..].iter().position(|&b| b == b']').unwrap() + 1;
            offset += library_length + 1; // +1 for the null terminator
        }

        arm9.base_address() + offset.next_multiple_of(4) as u32
    }

    fn find_sections_itcm(&mut self, symbol_map: &mut SymbolMap) -> Result<(), ModuleError> {
        let text_functions = self
            .find_functions(
                symbol_map,
                FunctionSearchOptions {
                    // ITCM only contains code, so there's no risk of running into non-code by skipping illegal instructions
                    max_function_start_search_distance: u32::MAX,
                    // There are some handwritten assembly functions in the ITCM that don't follow the procedure call standard
                    check_defs_uses: false,
                    ..Default::default()
                },
            )?
            .ok_or_else(|| NoItcmFunctionsSnafu.build())?;
        let text_end = text_functions.end;
        self.add_text_section(text_functions)?;

        let bss_start = text_end.next_multiple_of(32);
        self.add_bss_section(bss_start)?;

        Ok(())
    }

    fn find_sections_dtcm(&mut self) -> Result<(), ModuleError> {
        let data_start = self.base_address;
        let data_end = data_start + self.code.len() as u32;
        self.add_data_section(data_start, data_end)?;

        let bss_start = data_end.next_multiple_of(32);
        self.add_bss_section(bss_start)?;

        Ok(())
    }

    fn find_sections_unknown_autoload(&mut self, symbol_map: &mut SymbolMap, autoload: &Autoload) -> Result<(), ModuleError> {
        let base_address = autoload.base_address();
        let AutoloadKind::Unknown(autoload_index) = autoload.kind() else {
            panic!("Not an unknown autoload: {}", autoload.kind());
        };
        let code = autoload.code();

        let text_functions = self.find_functions(
            symbol_map,
            FunctionSearchOptions {
                max_function_start_search_distance: 32,
                use_data_as_upper_bound: true,
                // There are some handwritten assembly functions in unknown autoloads that don't follow the procedure call standard
                check_defs_uses: false,
                ..Default::default()
            },
        )?;

        let text_end = if let Some(text_functions) = text_functions {
            let text_end = text_functions.end;
            self.add_text_section(text_functions)?;
            text_end
        } else {
            self.base_address
        };

        let rodata_start = text_end.next_multiple_of(4);
        let rodata_end = rodata_start.next_multiple_of(32);
        log::warn!(
            "Cannot determine size of .rodata in unknown autoload {}, using {:#010x}..{:#010x}",
            autoload_index,
            rodata_start,
            rodata_end
        );
        self.add_rodata_section(rodata_start, rodata_end)?;

        let data_start = rodata_end;
        let data_end = base_address + code.len() as u32;
        self.add_data_section(data_start, data_end)?;

        let bss_start = data_end.next_multiple_of(32);
        self.add_bss_section(bss_start)?;

        Ok(())
    }

    fn find_data_from_pools(&mut self, symbol_map: &mut SymbolMap, options: &AnalysisOptions) -> Result<(), ModuleError> {
        for function in self.sections.functions() {
            data::find_local_data_from_pools(
                function,
                FindLocalDataOptions {
                    sections: &self.sections,
                    module_kind: self.kind,
                    symbol_map,
                    relocations: &mut self.relocations,
                    name_prefix: &self.default_data_prefix,
                    code: self.code,
                    base_address: self.base_address,
                    address_range: None,
                },
                options,
            )?;
        }
        Ok(())
    }

    fn find_data_from_sections(&mut self, symbol_map: &mut SymbolMap, options: &AnalysisOptions) -> Result<(), ModuleError> {
        for section in self.sections.iter() {
            match section.kind() {
                SectionKind::Data | SectionKind::Rodata => {
                    let code = section.code(self.code, self.base_address)?.unwrap();
                    data::find_local_data_from_section(
                        section,
                        FindLocalDataOptions {
                            sections: &self.sections,
                            module_kind: self.kind,
                            symbol_map,
                            relocations: &mut self.relocations,
                            name_prefix: &self.default_data_prefix,
                            code,
                            base_address: self.base_address,
                            address_range: None,
                        },
                        options,
                    )?;
                }
                SectionKind::Code => {
                    // Look for data in gaps between functions
                    let mut symbols = symbol_map
                        .iter_by_address(section.address_range())
                        .filter(|s| matches!(s.kind, SymbolKind::Function(_)))
                        .peekable();
                    let mut gaps = vec![];
                    while let Some(symbol) = symbols.next() {
                        if symbol.addr >= 0x2000000 && symbol.addr < 0x2000800 {
                            // Secure area gaps are just random bytes
                            continue;
                        }

                        let next_address = symbols.peek().map(|s| s.addr).unwrap_or(section.end_address());
                        let end_address = symbol.addr + symbol.size(next_address);
                        if end_address < next_address {
                            gaps.push(end_address..next_address);
                            log::debug!("Found gap between functions from {end_address:#x} to {next_address:#x}");
                        }
                    }
                    for gap in gaps {
                        if let Some(code) = section.code(self.code, self.base_address)? {
                            data::find_local_data_from_section(
                                section,
                                FindLocalDataOptions {
                                    sections: &self.sections,
                                    module_kind: self.kind,
                                    symbol_map,
                                    relocations: &mut self.relocations,
                                    name_prefix: &self.default_data_prefix,
                                    code,
                                    base_address: self.base_address,
                                    address_range: Some(gap),
                                },
                                options,
                            )?;
                        }
                    }
                }
                SectionKind::Bss => {}
            }
        }
        Ok(())
    }

    pub fn relocations(&self) -> &Relocations {
        &self.relocations
    }

    pub fn relocations_mut(&mut self) -> &mut Relocations {
        &mut self.relocations
    }

    pub fn sections(&self) -> &Sections {
        &self.sections
    }

    pub fn sections_mut(&mut self) -> &mut Sections {
        &mut self.sections
    }

    pub fn code(&self) -> &[u8] {
        self.code
    }

    pub fn base_address(&self) -> u32 {
        self.base_address
    }

    pub fn end_address(&self) -> u32 {
        self.base_address + self.code.len() as u32 + self.bss_size()
    }

    pub fn get_function(&self, addr: u32) -> Option<&Function> {
        self.sections.get_by_contained_address(addr).and_then(|(_, s)| s.functions().get(&addr))
    }

    pub fn bss_size(&self) -> u32 {
        self.bss_size
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kind(&self) -> ModuleKind {
        self.kind
    }

    pub fn signed(&self) -> bool {
        self.signed
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum ModuleKind {
    Arm9,
    Overlay(u16),
    Autoload(AutoloadKind),
}

impl Display for ModuleKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ModuleKind::Arm9 => write!(f, "ARM9 main"),
            ModuleKind::Overlay(index) => write!(f, "overlay {index}"),
            ModuleKind::Autoload(kind) => match kind {
                AutoloadKind::Itcm => write!(f, "ITCM"),
                AutoloadKind::Dtcm => write!(f, "DTCM"),
                AutoloadKind::Unknown(index) => write!(f, "autoload {index}"),
            },
        }
    }
}

struct FoundFunctions {
    functions: BTreeMap<u32, Function>,
    start: u32,
    end: u32,
}

/// Sorted list of .init function addresses
struct InitFunctions(BTreeSet<u32>);

pub struct AnalysisOptions {
    /// Generates function symbols when a local function call doesn't lead to a known function. This can happen if the
    /// destination function is encrypted or otherwise wasn't found during function analysis.
    pub allow_unknown_function_calls: bool,
    /// If true, every relocation in relocs.txt will have a comment explaining where/why it was generated.
    pub provide_reloc_source: bool,
}
