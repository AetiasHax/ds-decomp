use anyhow::{bail, Context, Result};
use ds_rom::rom::{Arm9, Overlay};

use crate::{
    analysis::{
        ctor::CtorRange,
        functions::{FindFunctionsOptions, Function},
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
    ctor: CtorRange,
    main_func: Option<MainFunction>,
    default_name_prefix: String,
    sections: Sections<'a>,
}

impl<'a> Module<'a> {
    pub fn new_arm9(symbol_map: SymbolMap, arm9: &'a Arm9) -> Result<Self> {
        let ctor_range = CtorRange::find_in_arm9(&arm9)?;
        let main_func = MainFunction::find_in_arm9(&arm9)?;

        Ok(Self {
            symbol_map,
            code: arm9.code()?,
            base_address: arm9.base_address(),
            bss_size: arm9.bss()?.len() as u32,
            ctor: ctor_range,
            main_func: Some(main_func),
            default_name_prefix: "func_".to_string(),
            sections: Sections::new(),
        })
    }

    pub fn new_overlay(symbol_map: SymbolMap, overlay: &'a Overlay) -> Result<Self> {
        Ok(Self {
            symbol_map,
            code: overlay.code(),
            base_address: overlay.base_address(),
            bss_size: overlay.bss_size(),
            ctor: CtorRange { start: overlay.ctor_start(), end: overlay.ctor_end() },
            main_func: None,
            default_name_prefix: format!("func_ov{:03}_", overlay.id()),
            sections: Sections::new(),
        })
    }

    fn find_functions(&mut self, options: FindFunctionsOptions) -> (Vec<Function<'a>>, u32, u32) {
        let functions =
            Function::find_functions(&self.code, self.base_address, &self.default_name_prefix, &mut self.symbol_map, options);

        let start = functions.first().unwrap().start_address();
        let end = functions.last().unwrap().end_address();
        (functions, start, end)
    }

    /// Adds the .ctor section to this module. Returns the min and max address of .init functions in the .ctor section.
    fn add_ctor_section(&mut self) -> Result<(u32, u32)> {
        if self.ctor.end <= self.ctor.start {
            bail!("missing .ctor range");
        }

        self.sections.add(Section {
            name: ".ctor".to_string(),
            kind: SectionKind::Data,
            start_address: self.ctor.start,
            end_address: self.ctor.end,
            alignment: 4,
            functions: vec![],
        });

        let start = (self.ctor.start - self.base_address) as usize;
        let end = (self.ctor.end - self.base_address) as usize;
        let ctor = &self.code[start..end];

        let (min, max) = ctor
            .chunks(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .take_while(|&addr| addr != 0)
            .fold((u32::MAX, u32::MIN), |(start, end), addr| (start.min(addr), end.max(addr)));

        Ok((min, max))
    }

    /// Adds the .init section to this module. Returns the start and end address of the .init section.
    fn add_init_section(&mut self, min: u32, max: u32, continuous: bool) -> Option<(u32, u32)> {
        if min != u32::MAX && max != u32::MIN {
            let (init_functions, init_start, init_end) = self.find_functions(FindFunctionsOptions {
                start_address: Some(min),
                last_function_address: Some(max),
                ..Default::default()
            });
            // Functions in .ctor can sometimes point to .text instead of .init
            if !continuous || init_end == self.ctor.start {
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
    fn add_text_section(&mut self, functions: Vec<Function<'a>>, start: u32, end: u32) {
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
                functions: vec![],
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
                functions: vec![],
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
                functions: vec![],
            });
        }
    }

    pub fn find_sections_overlay(&mut self) -> Result<()> {
        let (init_min, init_max) = self.add_ctor_section()?;
        let (init_start, _) = self.add_init_section(init_min, init_max, true).unwrap_or((self.ctor.start, self.ctor.start));
        let (text_functions, text_start, text_end) =
            self.find_functions(FindFunctionsOptions { end_address: Some(init_start), ..Default::default() });
        self.add_text_section(text_functions, text_start, text_end);
        self.add_rodata_section(text_end, init_start);

        let data_start = self.ctor.end.next_multiple_of(32);
        let data_end = self.base_address + self.code.len() as u32;
        self.add_data_section(data_start, data_end);
        self.add_bss_section(data_end);

        Ok(())
    }

    pub fn find_sections_arm9(&mut self) -> Result<()> {
        // .ctor and .init
        let (init_min, init_max) = self.add_ctor_section()?;
        let init_range = self.add_init_section(init_min, init_max, false);
        let init_start = init_range.map(|r| r.0).unwrap_or(self.ctor.start);

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
        let main_func = self.main_func.context("ARM9 program must have a main function")?;
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
        self.add_rodata_section(init_end, self.ctor.start);

        // .data and .bss
        let data_start = self.ctor.end.next_multiple_of(32);
        let data_end = self.base_address + self.code.len() as u32;
        self.add_data_section(data_start, data_end);
        self.add_bss_section(data_end);

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
}
