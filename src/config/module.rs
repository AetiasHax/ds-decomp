use std::collections::BTreeMap;

use anyhow::{bail, Context, Result};
use ds_rom::rom::{Arm9, Autoload, Overlay};

use crate::{
    analysis::{
        ctor::CtorRange,
        data,
        functions::{FindFunctionsOptions, Function, ParseFunctionOptions, ParseFunctionResult},
        main::MainFunction,
    },
    config::section::SectionKind,
};

use super::{
    section::{Section, Sections},
    symbol::{Symbol, SymbolMap},
};

pub struct Module<'a> {
    symbol_map: SymbolMap,
    code: &'a [u8],
    base_address: u32,
    bss_size: u32,
    pub default_func_prefix: String,
    pub default_data_prefix: String,
    sections: Sections<'a>,
}

impl<'a> Module<'a> {
    pub fn new_arm9(mut symbol_map: SymbolMap, mut sections: Sections<'a>, code: &'a [u8]) -> Result<Module<'a>> {
        let base_address = sections.base_address().context("no sections provided")?;
        let bss_size = sections.bss_size();
        Self::import_functions(&mut symbol_map, &mut sections, base_address, code)?;
        Ok(Self {
            symbol_map,
            code,
            base_address,
            bss_size,
            default_func_prefix: "func_".to_string(),
            default_data_prefix: "data_".to_string(),
            sections,
        })
    }

    pub fn analyze_arm9(symbol_map: SymbolMap, arm9: &'a Arm9) -> Result<Self> {
        let ctor_range = CtorRange::find_in_arm9(&arm9)?;
        let main_func = MainFunction::find_in_arm9(&arm9)?;

        let mut module = Self {
            symbol_map,
            code: arm9.code()?,
            base_address: arm9.base_address(),
            bss_size: arm9.bss()?.len() as u32,
            default_func_prefix: "func_".to_string(),
            default_data_prefix: "data_".to_string(),
            sections: Sections::new(),
        };
        module.find_sections_arm9(ctor_range, main_func)?;
        for function in module.sections.functions() {
            data::find_data_from_pools(function, &module.sections, &mut module.symbol_map, &module.default_data_prefix)
                .context("in ARM9 main")?;
        }

        Ok(module)
    }

    pub fn new_overlay(mut symbol_map: SymbolMap, mut sections: Sections<'a>, id: u32, code: &'a [u8]) -> Result<Self> {
        let base_address = sections.base_address().context("no sections provided")?;
        let bss_size = sections.bss_size();
        Self::import_functions(&mut symbol_map, &mut sections, base_address, code)?;
        Ok(Self {
            symbol_map,
            code,
            base_address,
            bss_size,
            default_func_prefix: format!("func_ov{:03}_", id),
            default_data_prefix: format!("data_ov{:03}_", id),
            sections,
        })
    }

    pub fn analyze_overlay(symbol_map: SymbolMap, overlay: &'a Overlay) -> Result<Self> {
        let mut module = Self {
            symbol_map,
            code: overlay.code(),
            base_address: overlay.base_address(),
            bss_size: overlay.bss_size(),
            default_func_prefix: format!("func_ov{:03}_", overlay.id()),
            default_data_prefix: format!("data_ov{:03}_", overlay.id()),
            sections: Sections::new(),
        };
        module.find_sections_overlay(CtorRange { start: overlay.ctor_start(), end: overlay.ctor_end() })?;
        for function in module.sections.functions() {
            data::find_data_from_pools(function, &module.sections, &mut module.symbol_map, &module.default_data_prefix)
                .with_context(|| format!("in overlay {}", overlay.id()))?;
        }

        Ok(module)
    }

    pub fn new_autoload(mut symbol_map: SymbolMap, mut sections: Sections<'a>, code: &'a [u8]) -> Result<Self> {
        let base_address = sections.base_address().context("no sections provided")?;
        let bss_size = sections.bss_size();
        Self::import_functions(&mut symbol_map, &mut sections, base_address, code)?;
        Ok(Self {
            symbol_map,
            code,
            base_address,
            bss_size,
            default_func_prefix: "func_".to_string(),
            default_data_prefix: "data_".to_string(),
            sections,
        })
    }

    pub fn analyze_itcm(symbol_map: SymbolMap, autoload: &'a Autoload) -> Result<Self> {
        let mut module = Self {
            symbol_map,
            code: autoload.code(),
            base_address: autoload.base_address(),
            bss_size: autoload.bss_size(),
            default_func_prefix: "func_".to_string(),
            default_data_prefix: "data_".to_string(),
            sections: Sections::new(),
        };
        module.find_sections_itcm()?;
        for function in module.sections.functions() {
            data::find_data_from_pools(function, &module.sections, &mut module.symbol_map, &module.default_data_prefix)
                .context("in ITCM")?;
        }

        Ok(module)
    }

    pub fn analyze_dtcm(symbol_map: SymbolMap, autoload: &'a Autoload) -> Result<Self> {
        let mut module = Self {
            symbol_map,
            code: autoload.code(),
            base_address: autoload.base_address(),
            bss_size: autoload.bss_size(),
            default_func_prefix: "func_".to_string(),
            default_data_prefix: "data_".to_string(),
            sections: Sections::new(),
        };
        module.find_sections_dtcm()?;
        Ok(module)
    }

    fn import_functions(
        symbol_map: &mut SymbolMap,
        sections: &mut Sections<'a>,
        base_address: u32,
        code: &'a [u8],
    ) -> Result<()> {
        for (sym_function, symbol) in symbol_map.clone_functions() {
            let offset = symbol.addr - base_address;
            let parse_result = Function::parse_function(
                symbol.name.to_string(),
                symbol.addr,
                &code[offset as usize..],
                ParseFunctionOptions { thumb: sym_function.mode.into_thumb() },
            );
            let function = match parse_result {
                ParseFunctionResult::Found(function) => function,
                _ => bail!("function {} could not be analyzed: {:?}", symbol.name, parse_result),
            };
            function.add_local_symbols_to_map(symbol_map);
            sections.add_function(function);
        }
        Ok(())
    }

    fn find_functions(&mut self, options: FindFunctionsOptions) -> (BTreeMap<u32, Function<'a>>, u32, u32) {
        let functions =
            Function::find_functions(&self.code, self.base_address, &self.default_func_prefix, &mut self.symbol_map, options);

        let start = functions.first_key_value().unwrap().1.start_address();
        let end = functions.last_key_value().unwrap().1.end_address();
        (functions, start, end)
    }

    /// Adds the .ctor section to this module. Returns the min and max address of .init functions in the .ctor section.
    fn add_ctor_section(&mut self, ctor: &CtorRange) -> Result<(u32, u32)> {
        self.sections.add(Section {
            name: ".ctor".to_string(),
            kind: SectionKind::Data,
            start_address: ctor.start,
            end_address: ctor.end,
            alignment: 4,
            functions: BTreeMap::new(),
        });

        let start = (ctor.start - self.base_address) as usize;
        let end = (ctor.end - self.base_address) as usize;
        let ctor = &self.code[start..end];

        let (min, max) = ctor
            .chunks(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .take_while(|&addr| addr != 0)
            .fold((u32::MAX, u32::MIN), |(start, end), addr| (start.min(addr), end.max(addr)));

        Ok((min, max))
    }

    /// Adds the .init section to this module. Returns the start and end address of the .init section.
    fn add_init_section(&mut self, ctor: &CtorRange, min: u32, max: u32, continuous: bool) -> Option<(u32, u32)> {
        if min != u32::MAX && max != u32::MIN {
            let (init_functions, init_start, init_end) = self.find_functions(FindFunctionsOptions {
                start_address: Some(min),
                last_function_address: Some(max),
                ..Default::default()
            });
            // Functions in .ctor can sometimes point to .text instead of .init
            if !continuous || init_end == ctor.start {
                self.sections.add(Section {
                    name: ".init".to_string(),
                    kind: SectionKind::Code,
                    start_address: init_start,
                    end_address: init_end,
                    alignment: 4,
                    functions: init_functions,
                });
                Some((init_start, init_end))
            } else {
                None
            }
        } else {
            None
        }
    }

    /// Adds the .text section to this module.
    fn add_text_section(&mut self, functions: BTreeMap<u32, Function<'a>>, start: u32, end: u32) {
        if start < end {
            self.sections.add(Section {
                name: ".text".to_string(),
                kind: SectionKind::Code,
                start_address: start,
                end_address: end,
                alignment: 32,
                functions,
            });
        }
    }

    fn add_rodata_section(&mut self, start: u32, end: u32) {
        if start < end {
            self.sections.add(Section {
                name: ".rodata".to_string(),
                kind: SectionKind::Data,
                start_address: start,
                end_address: end,
                alignment: 4,
                functions: BTreeMap::new(),
            });
        }
    }

    fn add_data_section(&mut self, start: u32, end: u32) {
        if start < end {
            self.sections.add(Section {
                name: ".data".to_string(),
                kind: SectionKind::Data,
                start_address: start,
                end_address: end,
                alignment: 32,
                functions: BTreeMap::new(),
            });
        }
    }

    fn add_bss_section(&mut self, start: u32) {
        if self.bss_size > 0 {
            self.sections.add(Section {
                name: ".bss".to_string(),
                kind: SectionKind::Bss,
                start_address: start,
                end_address: start + self.bss_size,
                alignment: 32,
                functions: BTreeMap::new(),
            });
        }
    }

    pub fn find_sections_overlay(&mut self, ctor: CtorRange) -> Result<()> {
        let (init_min, init_max) = self.add_ctor_section(&ctor)?;
        let (init_start, _) = self.add_init_section(&ctor, init_min, init_max, true).unwrap_or((ctor.start, ctor.start));
        let (text_functions, text_start, text_end) =
            self.find_functions(FindFunctionsOptions { end_address: Some(init_start), ..Default::default() });
        self.add_text_section(text_functions, text_start, text_end);
        self.add_rodata_section(text_end, init_start);

        let data_start = ctor.end.next_multiple_of(32);
        let data_end = self.base_address + self.code.len() as u32;
        self.add_data_section(data_start, data_end);
        self.add_bss_section(data_end);

        Ok(())
    }

    fn find_sections_arm9(&mut self, ctor: CtorRange, main_func: MainFunction) -> Result<()> {
        // .ctor and .init
        let (init_min, init_max) = self.add_ctor_section(&ctor)?;
        let init_range = self.add_init_section(&ctor, init_min, init_max, false);
        let init_start = init_range.map(|r| r.0).unwrap_or(ctor.start);

        // Secure area functions (software interrupts)
        let secure_area = &self.code[..0x800];
        let mut functions = Function::find_secure_area_functions(secure_area, self.base_address, &mut self.symbol_map);

        // Entry functions
        let (entry_functions, _, _) = self.find_functions(FindFunctionsOptions {
            start_address: Some(self.base_address + 0x800),
            end_address: Some(init_start),
            ..Default::default()
        });
        functions.extend(entry_functions);

        // All other functions, starting from main
        let (text_functions, _, text_end) = self.find_functions(FindFunctionsOptions {
            start_address: Some(main_func.address),
            end_address: Some(init_start),
            ..Default::default()
        });
        if text_end != init_start {
            eprintln!("Expected .text to end ({text_end:#x}) where .init starts ({init_start:#x})");
        }
        let text_start = self.base_address;
        let text_end = init_start;
        functions.extend(text_functions);
        self.add_text_section(functions, text_start, text_end);

        // .rodata
        let init_end = init_range.map(|r| r.1).unwrap_or(text_end);
        self.add_rodata_section(init_end, ctor.start);

        // .data and .bss
        let data_start = ctor.end.next_multiple_of(32);
        let data_end = self.base_address + self.code.len() as u32;
        self.add_data_section(data_start, data_end);
        self.add_bss_section(data_end);

        Ok(())
    }

    fn find_sections_itcm(&mut self) -> Result<()> {
        let (functions, start, end) = self.find_functions(FindFunctionsOptions {
            // ITCM only contains code, so there's no risk of running into non-code by skipping illegal instructions
            keep_searching_for_valid_function_start: true,
            ..Default::default()
        });
        self.add_text_section(functions, start, end);
        Ok(())
    }

    fn find_sections_dtcm(&mut self) -> Result<()> {
        let data_start = self.base_address;
        let data_end = data_start + self.code.len() as u32;
        self.add_data_section(data_start, data_end);

        let bss_start = data_end;
        self.add_bss_section(bss_start);

        Ok(())
    }

    pub fn add_symbol(&mut self, symbol: Symbol) -> Result<()> {
        self.symbol_map.add(symbol)
    }

    pub fn symbol_map(&self) -> &SymbolMap {
        &self.symbol_map
    }

    pub fn sections(&self) -> &Sections<'a> {
        &self.sections
    }

    pub fn sections_mut(&mut self) -> &mut Sections<'a> {
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
        self.sections.get_by_contained_address(addr).and_then(|s| s.functions.get(&addr))
    }

    pub fn bss_size(&self) -> u32 {
        self.bss_size
    }
}
