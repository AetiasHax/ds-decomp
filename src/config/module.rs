use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use ds_decomp_config::config::{
    module::ModuleKind,
    relocations::Relocations,
    section::{Section, SectionKind},
    symbol::{SymData, SymbolKind, SymbolMap, SymbolMaps},
};
use ds_rom::rom::{raw::AutoloadKind, Arm9, Autoload, Overlay};

use crate::analysis::{
    ctor::CtorRange,
    data::{self, FindLocalDataOptions},
    functions::{
        FindFunctionsOptions, Function, FunctionParseOptions, FunctionSearchOptions, ParseFunctionOptions, ParseFunctionResult,
    },
    main::MainFunction,
};

use super::{
    section::{DsdSections, SectionExt, SectionFunctions},
    symbol::SymbolMapExt,
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
    sections: DsdSections,
}

impl<'a> Module<'a> {
    pub fn new_arm9(
        name: String,
        symbol_map: &mut SymbolMap,
        relocations: Relocations,
        mut sections: DsdSections,
        code: &'a [u8],
    ) -> Result<Module<'a>> {
        let base_address = sections.base_address().context("no sections provided")?;
        let end_address = sections.end_address().context("no sections provided")?;
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
        })
    }

    pub fn analyze_arm9(arm9: &'a Arm9, symbol_maps: &mut SymbolMaps, options: &AnalysisOptions) -> Result<Self> {
        let ctor_range = CtorRange::find_in_arm9(arm9)?;
        let main_func = MainFunction::find_in_arm9(arm9)?;

        let mut module = Self {
            name: "main".to_string(),
            kind: ModuleKind::Arm9,
            relocations: Relocations::new(),
            code: arm9.code()?,
            base_address: arm9.base_address(),
            bss_size: arm9.bss()?.len() as u32,
            default_func_prefix: "func_".to_string(),
            default_data_prefix: "data_".to_string(),
            sections: DsdSections::new(),
        };
        let symbol_map = symbol_maps.get_mut(module.kind);

        module.find_sections_arm9(symbol_map, ctor_range, main_func, arm9)?;
        module.find_data_from_pools(symbol_map, options)?;
        module.find_data_from_sections(symbol_map, options)?;

        symbol_map.rename_by_address(arm9.entry_function(), "Entry")?;
        symbol_map.rename_by_address(main_func.address, "main")?;

        Ok(module)
    }

    pub fn new_overlay(
        name: String,
        symbol_map: &mut SymbolMap,
        relocations: Relocations,
        mut sections: DsdSections,
        id: u16,
        code: &'a [u8],
    ) -> Result<Self> {
        let base_address = sections.base_address().context("no sections provided")?;
        let end_address = sections.end_address().context("no sections provided")?;
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
        })
    }

    pub fn analyze_overlay(overlay: &'a Overlay, symbol_maps: &mut SymbolMaps, options: &AnalysisOptions) -> Result<Self> {
        let mut module = Self {
            name: format!("ov{:03}", overlay.id()),
            kind: ModuleKind::Overlay(overlay.id()),
            relocations: Relocations::new(),
            code: overlay.code(),
            base_address: overlay.base_address(),
            bss_size: overlay.bss_size(),
            default_func_prefix: format!("func_ov{:03}_", overlay.id()),
            default_data_prefix: format!("data_ov{:03}_", overlay.id()),
            sections: DsdSections::new(),
        };
        let symbol_map = symbol_maps.get_mut(module.kind);

        log::debug!("Analyzing overlay {}", overlay.id());
        module.find_sections_overlay(symbol_map, CtorRange { start: overlay.ctor_start(), end: overlay.ctor_end() })?;
        module.find_data_from_pools(symbol_map, options)?;
        module.find_data_from_sections(symbol_map, options)?;

        Ok(module)
    }

    pub fn new_autoload(
        name: String,
        symbol_map: &mut SymbolMap,
        relocations: Relocations,
        mut sections: DsdSections,
        kind: AutoloadKind,
        code: &'a [u8],
    ) -> Result<Self> {
        let base_address = sections.base_address().context("no sections provided")?;
        let end_address = sections.end_address().context("no sections provided")?;
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
        })
    }

    pub fn analyze_itcm(autoload: &'a Autoload, symbol_maps: &mut SymbolMaps, options: &AnalysisOptions) -> Result<Self> {
        let mut module = Self {
            name: "itcm".to_string(),
            kind: ModuleKind::Autoload(AutoloadKind::Itcm),
            relocations: Relocations::new(),
            code: autoload.code(),
            base_address: autoload.base_address(),
            bss_size: autoload.bss_size(),
            default_func_prefix: "func_".to_string(),
            default_data_prefix: "data_".to_string(),
            sections: DsdSections::new(),
        };
        let symbol_map = symbol_maps.get_mut(module.kind);

        module.find_sections_itcm(symbol_map)?;
        module.find_data_from_pools(symbol_map, options)?;

        Ok(module)
    }

    pub fn analyze_dtcm(autoload: &'a Autoload, symbol_maps: &mut SymbolMaps, options: &AnalysisOptions) -> Result<Self> {
        let mut module = Self {
            name: "dtcm".to_string(),
            kind: ModuleKind::Autoload(AutoloadKind::Dtcm),
            relocations: Relocations::new(),
            code: autoload.code(),
            base_address: autoload.base_address(),
            bss_size: autoload.bss_size(),
            default_func_prefix: "func_".to_string(),
            default_data_prefix: "data_".to_string(),
            sections: DsdSections::new(),
        };
        let symbol_map = symbol_maps.get_mut(module.kind);

        module.find_sections_dtcm()?;
        module.find_data_from_sections(symbol_map, options)?;

        Ok(module)
    }

    fn import_functions(
        symbol_map: &mut SymbolMap,
        sections: &mut DsdSections,
        base_address: u32,
        end_address: u32,
        code: &'a [u8],
    ) -> Result<()> {
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
            })?;
            let function = match parse_result {
                ParseFunctionResult::Found(function) => function,
                _ => bail!("function {} could not be analyzed: {:?}", symbol.name, parse_result),
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
    ) -> Result<Option<FoundFunctions>> {
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
            let end = functions.last_key_value().unwrap().1.end_address();
            Ok(Some(FoundFunctions { functions, start, end }))
        }
    }

    /// Adds the .ctor section to this module. Returns the min and max address of .init functions in the .ctor section.
    fn add_ctor_section(&mut self, ctor_range: &CtorRange) -> Result<Option<InitFunctions>> {
        self.sections.add(
            Section::new(".ctor".to_string(), SectionKind::Data, ctor_range.start, ctor_range.end, 4)?,
            SectionFunctions::new(),
        )?;

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
    ) -> Result<Option<(u32, u32)>> {
        let functions_min = *init_functions.0.first().unwrap();
        let functions_max = *init_functions.0.last().unwrap();
        let FoundFunctions { functions: init_functions, start: init_start, end: init_end } = self
            .find_functions(
                symbol_map,
                FunctionSearchOptions {
                    start_address: Some(functions_min),
                    last_function_address: Some(functions_max),
                    function_addresses: Some(init_functions.0),
                    ..Default::default()
                },
            )?
            .with_context(|| {
                format!(
                    ".init section exists in {} ({:#x}..{:#x}) but no functions were found",
                    self.kind, functions_min, functions_max
                )
            })?;
        // Functions in .ctor can sometimes point to .text instead of .init
        if !continuous || init_end == ctor.start {
            self.sections.add(
                Section::new(".init".to_string(), SectionKind::Code, init_start, init_end, 4)?,
                SectionFunctions(init_functions),
            )?;
            Ok(Some((init_start, init_end)))
        } else {
            Ok(None)
        }
    }

    /// Adds the .text section to this module.
    fn add_text_section(&mut self, functions_result: FoundFunctions) -> Result<()> {
        let FoundFunctions { functions, start, end } = functions_result;

        if start < end {
            self.sections
                .add(Section::new(".text".to_string(), SectionKind::Code, start, end, 32)?, SectionFunctions(functions))?;
        }
        Ok(())
    }

    fn add_rodata_section(&mut self, start: u32, end: u32) -> Result<()> {
        if start < end {
            self.sections
                .add(Section::new(".rodata".to_string(), SectionKind::Data, start, end, 4)?, SectionFunctions::new())?;
        }
        Ok(())
    }

    fn add_data_section(&mut self, start: u32, end: u32) -> Result<()> {
        if start < end {
            self.sections
                .add(Section::new(".data".to_string(), SectionKind::Data, start, end, 32)?, SectionFunctions::new())?;
        }
        Ok(())
    }

    fn add_bss_section(&mut self, start: u32) -> Result<()> {
        self.sections.add(
            Section::new(".bss".to_string(), SectionKind::Bss, start, start + self.bss_size, 32)?,
            SectionFunctions::new(),
        )?;
        Ok(())
    }

    fn find_sections_overlay(&mut self, symbol_map: &mut SymbolMap, ctor: CtorRange) -> Result<()> {
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
            FunctionSearchOptions { end_address: Some(rodata_end), use_data_as_upper_bound: true, ..Default::default() },
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
        main_func: MainFunction,
        arm9: &Arm9,
    ) -> Result<()> {
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
        let has_init_section = read_only_end != ctor.start;

        // Secure area functions (software interrupts)
        let secure_area = &self.code[..0x800];
        let mut functions = Function::find_secure_area_functions(secure_area, self.base_address, symbol_map);

        // Build info
        let build_info_offset = arm9.build_info_offset();
        let build_info_address = arm9.base_address() + build_info_offset;
        symbol_map.add_data(Some("BuildInfo".to_string()), build_info_address, SymData::Any)?;

        // Autoload callback
        let autoload_callback_address = arm9.autoload_callback();
        let autoload_function = match Function::parse_function(FunctionParseOptions {
            name: "AutoloadCallback".to_string(),
            start_address: autoload_callback_address,
            base_address: self.base_address,
            module_code: self.code,
            known_end_address: None,
            module_start_address: self.base_address,
            module_end_address: self.end_address(),
            parse_options: Default::default(),
        })? {
            ParseFunctionResult::Found(function) => function,
            ParseFunctionResult::IllegalIns { .. } => bail!("Illegal instruction in autoload callback"),
            ParseFunctionResult::NoEpilogue => bail!("No epilogue in autoload callback"),
            ParseFunctionResult::InvalidStart { .. } => bail!("Autoload callback has an invalid start instruction"),
        };
        symbol_map.add_function(&autoload_function);

        // Entry functions
        let FoundFunctions { functions: entry_functions, .. } = self
            .find_functions(
                symbol_map,
                FunctionSearchOptions {
                    start_address: Some(self.base_address + 0x800),
                    end_address: Some(build_info_address),
                    ..Default::default()
                },
            )?
            .context("Entry functions not found")?;
        functions.extend(entry_functions);

        // All other functions, starting from main
        let FoundFunctions { functions: text_functions, end: mut text_end, .. } = self
            .find_functions(
                symbol_map,
                FunctionSearchOptions {
                    start_address: Some(main_func.address),
                    end_address: Some(read_only_end),
                    // Skips over segments of strange EOR instructions which are never executed
                    keep_searching_for_valid_function_start: true,
                    use_data_as_upper_bound: true,
                    ..Default::default()
                },
            )?
            .context("No functions in ARM9 main module")?;
        if text_end != read_only_end && has_init_section {
            log::warn!("Expected .text to end ({text_end:#x}) where .init starts ({read_only_end:#x})");
        }
        let text_start = self.base_address;
        if has_init_section {
            text_end = read_only_end;
        }
        functions.extend(text_functions);
        self.add_text_section(FoundFunctions { functions, start: text_start, end: text_end })?;

        // .rodata
        let rodata_start = rodata_start.unwrap_or(text_end);
        self.add_rodata_section(rodata_start, ctor.start)?;

        // .data and .bss
        let data_start = ctor.end.next_multiple_of(32);
        let data_end = self.base_address + self.code.len() as u32;
        self.add_data_section(data_start, data_end)?;
        let bss_start = data_end.next_multiple_of(32);
        self.add_bss_section(bss_start)?;

        Ok(())
    }

    fn find_sections_itcm(&mut self, symbol_map: &mut SymbolMap) -> Result<()> {
        let text_functions = self
            .find_functions(
                symbol_map,
                FunctionSearchOptions {
                    // ITCM only contains code, so there's no risk of running into non-code by skipping illegal instructions
                    keep_searching_for_valid_function_start: true,
                    ..Default::default()
                },
            )?
            .context("No functions in ITCM")?;
        let text_end = text_functions.end;
        self.add_text_section(text_functions)?;

        let bss_start = text_end.next_multiple_of(32);
        self.add_bss_section(bss_start)?;

        Ok(())
    }

    fn find_sections_dtcm(&mut self) -> Result<()> {
        let data_start = self.base_address;
        let data_end = data_start + self.code.len() as u32;
        self.add_data_section(data_start, data_end)?;

        let bss_start = data_end.next_multiple_of(32);
        self.add_bss_section(bss_start)?;

        Ok(())
    }

    fn find_data_from_pools(&mut self, symbol_map: &mut SymbolMap, options: &AnalysisOptions) -> Result<()> {
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

    fn find_data_from_sections(&mut self, symbol_map: &mut SymbolMap, options: &AnalysisOptions) -> Result<()> {
        for entry in self.sections.iter() {
            match entry.section.kind() {
                SectionKind::Data => {
                    let code = entry.section.code(self.code, self.base_address)?.unwrap();
                    data::find_local_data_from_section(
                        entry.section,
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
                        .iter_by_address(entry.section.address_range())
                        .filter(|s| matches!(s.kind, SymbolKind::Function(_)))
                        .peekable();
                    let mut gaps = vec![];
                    while let Some(symbol) = symbols.next() {
                        if symbol.addr >= 0x2000000 && symbol.addr < 0x2000800 {
                            // Secure area gaps are just random bytes
                            continue;
                        }

                        let next_address = symbols.peek().map(|s| s.addr).unwrap_or(entry.section.end_address());
                        let end_address = symbol.addr + symbol.size(next_address);
                        if end_address < next_address {
                            gaps.push(end_address..next_address);
                            log::debug!("Found gap between functions from {end_address:#x} to {next_address:#x}");
                        }
                    }
                    for gap in gaps {
                        if let Some(code) = entry.section.code(self.code, self.base_address)? {
                            data::find_local_data_from_section(
                                entry.section,
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

    pub fn sections(&self) -> &DsdSections {
        &self.sections
    }

    pub fn sections_mut(&mut self) -> &mut DsdSections {
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
        self.sections.get_by_contained_address(addr).and_then(|(_, s)| s.functions.0.get(&addr))
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
