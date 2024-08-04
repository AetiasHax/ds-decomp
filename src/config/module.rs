use anyhow::Result;
use ds_rom::rom::Overlay;

use crate::{analysis::functions::Function, config::section::SectionKind};

use super::{
    section::{Section, Sections},
    symbol::{Symbol, SymbolMap},
};

pub struct Module<'a> {
    symbol_map: SymbolMap,
    code: &'a [u8],
    base_address: u32,
    bss_size: u32,
    default_name_prefix: String,
    sections: Sections<'a>,
}

impl<'a> Module<'a> {
    pub fn new_overlay(symbol_map: SymbolMap, overlay: &'a Overlay) -> Result<Self> {
        let mut sections = Sections::new();
        sections.add(Section {
            name: ".ctor".to_string(),
            kind: SectionKind::Data,
            start_address: overlay.ctor_start(),
            end_address: overlay.ctor_end(),
            alignment: 4,
            functions: vec![],
        });

        Ok(Self {
            symbol_map,
            code: overlay.code(),
            base_address: overlay.base_address(),
            bss_size: overlay.bss_size(),
            default_name_prefix: format!("func_ov{:03}_", overlay.id()),
            sections,
        })
    }

    fn find_functions(
        &mut self,
        start_address: Option<u32>,
        end_address: Option<u32>,
        num_functions: Option<usize>,
    ) -> (Vec<Function<'a>>, u32, u32) {
        let functions = Function::find_functions(
            &self.code,
            self.base_address,
            &self.default_name_prefix,
            &mut self.symbol_map,
            start_address,
            end_address,
            num_functions,
        );

        let start = functions.first().unwrap().start_address();
        let end = functions.last().unwrap().end_address();
        (functions, start, end)
    }

    pub fn find_sections(&mut self) {
        let ctor = self.sections.get(".ctor").expect(".ctor section must be registered");
        let ctor_start = ctor.start_address;
        let ctor_end = ctor.end_address;
        let start = (ctor_start - self.base_address) as usize;
        let end = (ctor_end - self.base_address) as usize;
        let ctor = &self.code[start..end];

        let (min, max) = ctor
            .chunks(4)
            .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
            .take_while(|&addr| addr != 0)
            .fold((u32::MAX, u32::MIN), |(start, end), addr| (start.min(addr), end.max(addr)));

        let init_start = if min != u32::MAX && max != u32::MIN {
            println!("{}: {} {}", self.default_name_prefix, min, max);
            let (init_functions, init_start, init_end) = self.find_functions(Some(min), Some(max), None);
            self.sections.add(Section {
                name: ".init".to_string(),
                kind: SectionKind::Code,
                start_address: init_start,
                end_address: init_end,
                alignment: 4,
                functions: init_functions,
            });
            init_start
        } else {
            ctor_start
        };

        let (text_functions, text_start, text_end) = self.find_functions(None, Some(init_start), None);
        self.sections.add(Section {
            name: ".text".to_string(),
            kind: SectionKind::Code,
            start_address: text_start,
            end_address: text_end,
            alignment: 32,
            functions: text_functions,
        });

        self.sections.add(Section {
            name: ".rodata".to_string(),
            kind: SectionKind::Data,
            start_address: text_end,
            end_address: init_start,
            alignment: 4,
            functions: vec![],
        });

        let data_start = ctor_end.next_multiple_of(32);
        let data_end = self.base_address + self.code.len() as u32;
        self.sections.add(Section {
            name: ".data".to_string(),
            kind: SectionKind::Data,
            start_address: data_start,
            end_address: data_end,
            alignment: 32,
            functions: vec![],
        });

        self.sections.add(Section {
            name: ".bss".to_string(),
            kind: SectionKind::Bss,
            start_address: data_end,
            end_address: data_end + self.bss_size,
            alignment: 32,
            functions: vec![],
        });
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
