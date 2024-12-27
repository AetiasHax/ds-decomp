use std::{collections::BTreeMap, ops::Range};

use anyhow::{bail, Context, Result};
use ds_decomp_config::config::{
    relocations::{Relocation, RelocationKind},
    section::{Section, SectionIndex, SectionKind, Sections, SectionsError},
};
use object::{Object, ObjectSymbol};

use crate::{analysis::functions::Function, util::bytes::FromSlice};

use super::module::Module;

#[derive(Default, Clone)]
pub struct SectionFunctions(pub BTreeMap<u32, Function>);

impl SectionFunctions {
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }
}

pub trait SectionExt {
    fn code_from_module<'a>(&'a self, module: &'a Module) -> Result<Option<&'a [u8]>>;
    fn code<'a>(&'a self, code: &'a [u8], base_address: u32) -> Result<Option<&'a [u8]>>;
    fn relocatable_code(&self, module: &Module) -> Result<Option<Vec<u8>>>;
    fn relocations<'a>(&'a self, module: &'a Module) -> impl Iterator<Item = &'a Relocation>;

    /// Iterates over every 32-bit word in the specified `range`, which defaults to the entire section if it is `None`. Note
    /// that `code` must be the full raw content of this section.
    fn iter_words<'a>(&'a self, code: &'a [u8], range: Option<Range<u32>>) -> impl Iterator<Item = Word> + 'a;

    /// Name of this section for creating section boundary symbols, e.g. ARM9_BSS_START
    fn boundary_name(&self) -> String;
    fn range_from_object(&self, module_name: &str, object: &object::File<'_>) -> Result<Range<u32>>;
}

impl SectionExt for Section {
    fn code_from_module<'a>(&'a self, module: &'a Module) -> Result<Option<&'a [u8]>> {
        self.code(module.code(), module.base_address())
    }

    fn code<'a>(&'a self, code: &'a [u8], base_address: u32) -> Result<Option<&'a [u8]>> {
        if self.kind() == SectionKind::Bss {
            return Ok(None);
        }
        if self.start_address() < base_address {
            bail!("section starts before base address");
        }
        let start = self.start_address() - base_address;
        let end = self.end_address() - base_address;
        if end > code.len() as u32 {
            bail!("section ends after code ends");
        }
        Ok(Some(&code[start as usize..end as usize]))
    }

    fn relocatable_code(&self, module: &Module) -> Result<Option<Vec<u8>>> {
        let Some(code) = self.code_from_module(module)? else { return Ok(None) };
        let mut code = code.to_vec();

        for relocation in self.relocations(module) {
            let from = relocation.from_address();
            let offset = (from - self.start_address()) as usize;

            // Clear bits in `code` to treat them as the implicit addend
            let ins = match relocation.kind() {
                RelocationKind::ArmCall => {
                    // R_ARM_PC24
                    &[0xfe, 0xff, 0xff, 0xeb] // bl #0
                }
                RelocationKind::ArmCallThumb => {
                    // R_ARM_XPC25
                    &[0xfe, 0xff, 0xff, 0xfa] // blx #0
                }
                RelocationKind::ThumbCall => {
                    // R_ARM_THM_PC22
                    &[0xff, 0xf7, 0xfe, 0xff] // bl #0
                }
                RelocationKind::ThumbCallArm => {
                    // R_ARM_THM_XPC22
                    &[0xff, 0xf7, 0xfe, 0xff] // bl #0
                }
                RelocationKind::ArmBranch => {
                    // R_ARM_PC24
                    &[0xfe, 0xff, 0xff, 0xea] // b #0
                }
                RelocationKind::Load => {
                    // R_ARM_ABS32
                    &[0x00, 0x00, 0x00, 0x00]
                }
            };
            code[offset..offset + 4].copy_from_slice(ins);
        }

        Ok(Some(code))
    }

    fn relocations<'a>(&'a self, module: &'a Module) -> impl Iterator<Item = &'a Relocation> {
        module.relocations().iter_range(self.address_range()).map(|(_, r)| r)
    }

    /// Iterates over every 32-bit word in the specified `range`, which defaults to the entire section if it is `None`. Note
    /// that `code` must be the full raw content of this section.
    fn iter_words<'a>(&'a self, code: &'a [u8], range: Option<Range<u32>>) -> impl Iterator<Item = Word> + 'a {
        let range = range.unwrap_or(self.address_range());
        let start = range.start.next_multiple_of(4);
        let end = range.end & !3;

        (start..end).step_by(4).map(move |address| {
            let offset = address - self.start_address();
            let bytes = &code[offset as usize..];
            Word { address, value: u32::from_le_slice(bytes) }
        })
    }

    /// Name of this section for creating section boundary symbols, e.g. ARM9_BSS_START
    fn boundary_name(&self) -> String {
        self.name().strip_prefix('.').unwrap_or(self.name()).to_uppercase()
    }

    fn range_from_object(&self, module_name: &str, object: &object::File<'_>) -> Result<Range<u32>> {
        let boundary_name = self.boundary_name();
        let boundary_start = format!("{module_name}_{boundary_name}_START");
        let boundary_end = format!("{module_name}_{boundary_name}_END");
        let start = object
            .symbol_by_name(&boundary_start)
            .with_context(|| format!("Failed to find symbol {boundary_start}"))?
            .address() as u32;
        let end =
            object.symbol_by_name(&boundary_end).with_context(|| format!("Failed to find symbol {boundary_end}"))?.address()
                as u32;
        Ok(start..end)
    }
}

pub struct DsdSections {
    sections: Sections,
    section_functions: Vec<SectionFunctions>,
}

impl From<Sections> for DsdSections {
    fn from(sections: Sections) -> Self {
        Self { section_functions: vec![Default::default(); sections.len()], sections }
    }
}

pub struct SectionEntry<'a> {
    pub section: &'a Section,
    pub functions: &'a SectionFunctions,
}

pub struct SectionEntryMut<'a> {
    pub section: &'a mut Section,
    pub functions: &'a mut SectionFunctions,
}

impl DsdSections {
    pub fn new() -> Self {
        Self { sections: Sections::new(), section_functions: vec![] }
    }

    pub fn add(&mut self, section: Section, functions: SectionFunctions) -> Result<SectionIndex, SectionsError> {
        let index = self.sections.add(section)?;
        assert!(index.0 == self.section_functions.len());
        self.section_functions.push(functions);
        Ok(index)
    }

    pub fn get(&self, index: usize) -> SectionEntry {
        SectionEntry { section: self.sections.get(index), functions: &self.section_functions[index] }
    }

    pub fn get_mut(&mut self, index: usize) -> SectionEntryMut {
        SectionEntryMut { section: self.sections.get_mut(index), functions: &mut self.section_functions[index] }
    }

    pub fn by_name(&self, name: &str) -> Option<(SectionIndex, SectionEntry)> {
        self.sections
            .by_name(name)
            .map(|(index, section)| (index, SectionEntry { section, functions: &self.section_functions[index.0] }))
    }

    pub fn iter(&self) -> impl Iterator<Item = SectionEntry> {
        self.sections.iter().zip(self.section_functions.iter()).map(|(section, functions)| SectionEntry { section, functions })
    }

    pub fn iter_mut(&mut self) -> impl Iterator<Item = SectionEntryMut> {
        self.sections
            .iter_mut()
            .zip(self.section_functions.iter_mut())
            .map(|(section, functions)| SectionEntryMut { section, functions })
    }

    pub fn len(&self) -> usize {
        self.sections.len()
    }

    pub fn get_by_contained_address(&self, address: u32) -> Option<(SectionIndex, SectionEntry)> {
        let (index, _) = self.sections.get_by_contained_address(address).unzip();
        index.map(|index| (index, self.get(index.0)))
    }

    pub fn get_by_contained_address_mut(&mut self, address: u32) -> Option<(SectionIndex, SectionEntryMut)> {
        let (index, _) = self.sections.get_by_contained_address(address).unzip();
        index.map(|index| (index, self.get_mut(index.0)))
    }

    pub fn sorted_by_address(&self) -> Vec<&Section> {
        self.sections.sorted_by_address()
    }

    pub fn base_address(&self) -> Option<u32> {
        self.sections.base_address()
    }

    pub fn end_address(&self) -> Option<u32> {
        self.sections.end_address()
    }

    pub fn bss_size(&self) -> u32 {
        self.sections.bss_size()
    }

    pub fn bss_range(&self) -> Option<Range<u32>> {
        self.sections.bss_range()
    }

    pub fn add_function(&mut self, function: Function) {
        let address = function.first_instruction_address();
        self.iter_mut()
            .find(|s| address >= s.section.start_address() && address < s.section.end_address())
            .unwrap()
            .functions
            .0
            .insert(address, function);
    }

    pub fn functions(&self) -> impl Iterator<Item = &Function> {
        self.iter().flat_map(|s| s.functions.0.values())
    }

    pub fn functions_mut(&mut self) -> impl Iterator<Item = &mut Function> {
        self.iter_mut().flat_map(|s| s.functions.0.values_mut())
    }

    pub fn sections(&self) -> &Sections {
        &self.sections
    }
}

pub struct Word {
    pub address: u32,
    pub value: u32,
}
