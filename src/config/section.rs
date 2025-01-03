use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
    ops::Range,
};

use anyhow::{bail, Context, Result};
use object::{Object, ObjectSymbol};

use crate::{
    analysis::functions::Function,
    util::{bytes::FromSlice, parse::parse_u32},
};

use super::{
    iter_attributes,
    module::Module,
    relocation::{Relocation, RelocationKind},
    ParseContext,
};

pub struct Section {
    name: String,
    kind: SectionKind,
    start_address: u32,
    end_address: u32,
    alignment: u32,
    functions: BTreeMap<u32, Function>,
}

impl Section {
    pub fn new(name: String, kind: SectionKind, start_address: u32, end_address: u32, alignment: u32) -> Result<Self> {
        Self::with_functions(name, kind, start_address, end_address, alignment, BTreeMap::new())
    }

    pub fn with_functions(
        name: String,
        kind: SectionKind,
        start_address: u32,
        end_address: u32,
        alignment: u32,
        functions: BTreeMap<u32, Function>,
    ) -> Result<Self> {
        if end_address < start_address {
            bail!("Section {name} must not end ({end_address:#010x}) before it starts ({start_address:#010x})");
        }
        if !alignment.is_power_of_two() {
            bail!("Section {name} alignment ({alignment}) must be a power of two");
        }
        let misalign_mask = alignment - 1;
        if (start_address & misalign_mask) != 0 {
            bail!(
                "Section {name} starts at a misaligned address {start_address:#010x}; the provided alignment was {alignment}"
            );
        }

        Ok(Self { name, kind, start_address, end_address, alignment, functions })
    }

    pub fn inherit(other: &Section, start_address: u32, end_address: u32) -> Result<Self> {
        let name = other.name.clone();
        if end_address < start_address {
            bail!("Section {name} must not end ({end_address:#010x}) before it starts ({start_address:#010x})");
        }
        Ok(Self { name, kind: other.kind, start_address, end_address, alignment: other.alignment, functions: BTreeMap::new() })
    }

    pub fn parse(line: &str, context: &ParseContext) -> Result<Option<Self>> {
        let mut words = line.split_whitespace();
        let Some(name) = words.next() else { return Ok(None) };

        let mut kind = None;
        let mut start = None;
        let mut end = None;
        let mut align = None;
        for (key, value) in iter_attributes(words) {
            match key {
                "kind" => kind = Some(SectionKind::parse(value, context)?),
                "start" => {
                    start = Some(
                        parse_u32(value).with_context(|| format!("{}: failed to parse start address '{}'", context, value))?,
                    )
                }
                "end" => {
                    end = Some(
                        parse_u32(value).with_context(|| format!("{}: failed to parse end address '{}'", context, value))?,
                    )
                }
                "align" => {
                    align =
                        Some(parse_u32(value).with_context(|| format!("{}: failed to parse alignment '{}'", context, value))?)
                }
                _ => bail!("{}: expected section attribute 'kind', 'start', 'end' or 'align' but got '{}'", context, key),
            }
        }

        Ok(Some(Section::new(
            name.to_string(),
            kind.with_context(|| format!("{}: missing 'kind' attribute", context))?,
            start.with_context(|| format!("{}: missing 'start' attribute", context))?,
            end.with_context(|| format!("{}: missing 'end' attribute", context))?,
            align.with_context(|| format!("{}: missing 'align' attribute", context))?,
        )?))
    }

    pub fn parse_inherit(line: &str, context: &ParseContext, sections: &Sections) -> Result<Option<Self>> {
        let mut words = line.split_whitespace();
        let Some(name) = words.next() else { return Ok(None) };

        let inherit_section = sections
            .by_name(name)
            .with_context(|| format!("{context}: section {name} does not exist in this file's header"))?;

        let mut start = None;
        let mut end = None;
        for (key, value) in iter_attributes(words) {
            match key {
                "kind" => bail!("{context}: attribute 'kind' should be omitted as it is inherited from this file's header"),
                "start" => {
                    start =
                        Some(parse_u32(value).with_context(|| format!("{context}: failed to parse start address '{value}'"))?)
                }
                "end" => {
                    end = Some(parse_u32(value).with_context(|| format!("{context}: failed to parse end address '{value}'"))?)
                }
                "align" => bail!("{context}: attribute 'align' should be omitted as it is inherited from this file's header"),
                _ => bail!("{context}: expected section attribute 'start' or 'end' but got '{key}'"),
            }
        }

        Ok(Some(Section::inherit(
            inherit_section,
            start.with_context(|| format!("{context}: missing 'start' attribute"))?,
            end.with_context(|| format!("{context}: missing 'end' attribute"))?,
        )?))
    }

    pub fn code_from_module<'a>(&'a self, module: &'a Module) -> Result<Option<&'a [u8]>> {
        self.code(module.code(), module.base_address())
    }

    pub fn code<'a>(&'a self, code: &'a [u8], base_address: u32) -> Result<Option<&'a [u8]>> {
        if self.kind == SectionKind::Bss {
            return Ok(None);
        }
        if self.start_address < base_address {
            bail!("section starts before base address");
        }
        let start = self.start_address - base_address;
        let end = self.end_address - base_address;
        if end > code.len() as u32 {
            bail!("section ends after code ends");
        }
        Ok(Some(&code[start as usize..end as usize]))
    }

    pub fn relocatable_code(&self, module: &Module) -> Result<Option<Vec<u8>>> {
        let Some(code) = self.code_from_module(module)? else { return Ok(None) };
        let mut code = code.to_vec();

        for relocation in self.relocations(module) {
            let from = relocation.from_address();
            let offset = (from - self.start_address) as usize;

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

    pub fn relocations<'a>(&'a self, module: &'a Module) -> impl Iterator<Item = &'a Relocation> {
        module.relocations().iter_range(self.address_range()).map(|(_, r)| r)
    }

    pub fn size(&self) -> u32 {
        self.end_address - self.start_address
    }

    /// Iterates over every 32-bit word in the specified `range`, which defaults to the entire section if it is `None`. Note
    /// that `code` must be the full raw content of this section.
    pub fn iter_words<'a>(&'a self, code: &'a [u8], range: Option<Range<u32>>) -> impl Iterator<Item = Word> + 'a {
        let range = range.unwrap_or(self.address_range());
        let start = range.start.next_multiple_of(4);
        let end = range.end & !3;

        (start..end).step_by(4).map(move |address| {
            let offset = address - self.start_address;
            let bytes = &code[offset as usize..];
            Word { address, value: u32::from_le_slice(bytes) }
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn kind(&self) -> SectionKind {
        self.kind
    }

    pub fn start_address(&self) -> u32 {
        self.start_address
    }

    pub fn end_address(&self) -> u32 {
        self.end_address
    }

    pub fn address_range(&self) -> Range<u32> {
        self.start_address..self.end_address
    }

    pub fn alignment(&self) -> u32 {
        self.alignment
    }

    pub fn functions(&self) -> &BTreeMap<u32, Function> {
        &self.functions
    }

    pub fn overlaps_with(&self, other: &Section) -> bool {
        self.start_address < other.end_address && other.start_address < self.end_address
    }

    /// Name of this section for creating section boundary symbols, e.g. ARM9_BSS_START
    pub fn boundary_name(&self) -> String {
        self.name.strip_prefix('.').unwrap_or(&self.name).to_uppercase()
    }

    pub fn range_from_object(&self, module_name: &str, object: &object::File<'_>) -> Result<Range<u32>> {
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

impl Display for Section {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:11} start:{:#010x} end:{:#010x} kind:{} align:{}",
            self.name, self.start_address, self.end_address, self.kind, self.alignment
        )
    }
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum SectionKind {
    Code,
    Data,
    Bss,
}

impl SectionKind {
    pub fn parse(value: &str, context: &ParseContext) -> Result<Self> {
        match value {
            "code" => Ok(Self::Code),
            "data" => Ok(Self::Data),
            "bss" => Ok(Self::Bss),
            _ => bail!("{}: unknown section kind '{}', must be one of: code, data, bss", context, value),
        }
    }

    pub fn is_initialized(self) -> bool {
        match self {
            SectionKind::Code => true,
            SectionKind::Data => true,
            SectionKind::Bss => false,
        }
    }
}

impl Display for SectionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Code => write!(f, "code"),
            Self::Data => write!(f, "data"),
            Self::Bss => write!(f, "bss"),
        }
    }
}

type SectionIndex = usize;

pub struct Sections {
    sections: Vec<Section>,
    sections_by_name: HashMap<String, SectionIndex>,
}

impl Sections {
    pub fn new() -> Self {
        Self { sections: vec![], sections_by_name: HashMap::new() }
    }

    pub fn add(&mut self, section: Section) -> Result<()> {
        if self.sections_by_name.contains_key(&section.name) {
            bail!("Section '{}' already exists", section.name);
        }
        for other in &self.sections {
            if section.overlaps_with(other) {
                bail!("Section '{}' overlaps with '{}'", section.name, other.name);
            }
        }

        let index = self.sections.len();
        self.sections_by_name.insert(section.name.clone(), index);
        self.sections.push(section);
        Ok(())
    }

    pub fn get(&self, index: usize) -> &Section {
        &self.sections[index]
    }

    pub fn get_mut(&mut self, index: usize) -> &mut Section {
        &mut self.sections[index]
    }

    pub fn by_name(&self, name: &str) -> Option<&Section> {
        let &index = self.sections_by_name.get(name)?;
        Some(&self.sections[index])
    }

    pub fn iter(&self) -> impl Iterator<Item = &Section> {
        self.sections.iter()
    }

    pub fn len(&self) -> usize {
        self.sections.len()
    }

    pub fn get_by_contained_address(&self, address: u32) -> Option<(SectionIndex, &Section)> {
        self.sections.iter().enumerate().find(|(_, s)| address >= s.start_address && address < s.end_address)
    }

    pub fn get_by_contained_address_mut(&mut self, address: u32) -> Option<&mut Section> {
        self.sections.iter_mut().find(|s| address >= s.start_address && address < s.end_address)
    }

    pub fn add_function(&mut self, function: Function) {
        let address = function.first_instruction_address();
        self.sections
            .iter_mut()
            .find(|s| address >= s.start_address && address < s.end_address)
            .unwrap()
            .functions
            .insert(address, function);
    }

    pub fn sorted_by_address(&self) -> Vec<&Section> {
        let mut sections = self.sections.iter().collect::<Vec<_>>();
        sections.sort_unstable_by_key(|s| s.start_address);
        sections
    }

    pub fn functions(&self) -> impl Iterator<Item = &Function> {
        self.sections.iter().flat_map(|s| s.functions.values())
    }

    pub fn functions_mut(&mut self) -> impl Iterator<Item = &mut Function> {
        self.sections.iter_mut().flat_map(|s| s.functions.values_mut())
    }

    pub fn base_address(&self) -> Option<u32> {
        self.sections.iter().map(|s| s.start_address).min()
    }

    pub fn end_address(&self) -> Option<u32> {
        self.sections.iter().map(|s| s.end_address).max()
    }

    pub fn bss_size(&self) -> u32 {
        self.sections.iter().filter(|s| s.kind == SectionKind::Bss).map(|s| s.size()).sum()
    }

    pub fn bss_range(&self) -> Option<Range<u32>> {
        self.sections
            .iter()
            .filter(|s| s.kind == SectionKind::Bss)
            .map(|s| s.address_range())
            .reduce(|a, b| a.start.min(b.start)..a.end.max(b.end))
    }
}

impl IntoIterator for Sections {
    type Item = Section;

    type IntoIter = <Vec<Section> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.sections.into_iter()
    }
}

pub struct Word {
    pub address: u32,
    pub value: u32,
}
