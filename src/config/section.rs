use std::{
    collections::{BTreeMap, HashMap},
    fmt::Display,
};

use anyhow::{bail, Context, Result};

use crate::{analysis::functions::Function, util::parse::parse_u32};

use super::{iter_attributes, module::Module, ParseContext};

pub struct Section<'a> {
    pub name: String,
    pub kind: SectionKind,
    pub start_address: u32,
    pub end_address: u32,
    pub alignment: u32,
    pub functions: BTreeMap<u32, Function<'a>>,
}

impl<'a> Section<'a> {
    pub fn parse(line: &str, context: &ParseContext) -> Result<Option<Self>> {
        let mut words = line.split_whitespace();
        let Some(name) = words.next() else { return Ok(None) };

        let mut kind = None;
        let mut start = None;
        let mut end = None;
        let mut align = None;
        for pair in iter_attributes(words, context) {
            let (key, value) = pair?;
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
                _ => bail!("{}: expected symbol attribute 'start', 'end' or 'align' but got '{}'", context, key),
            }
        }

        Ok(Some(Section {
            name: name.to_string(),
            kind: kind.with_context(|| format!("{}: missing 'kind' attribute", context))?,
            start_address: start.with_context(|| format!("{}: missing 'start' attribute", context))?,
            end_address: end.with_context(|| format!("{}: missing 'end' attribute", context))?,
            alignment: align.with_context(|| format!("{}: missing 'align' attribute", context))?,
            functions: BTreeMap::new(),
        }))
    }

    pub fn code_from_module(&'a self, module: &'a Module) -> Result<Option<&[u8]>> {
        self.code(module.code(), module.base_address())
    }

    pub fn code(&'a self, code: &'a [u8], base_address: u32) -> Result<Option<&[u8]>> {
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

    pub fn size(&self) -> u32 {
        self.end_address - self.start_address
    }
}

impl<'a> Display for Section<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:11} start:0x{:08x} end:0x{:08x} kind:{} align:{}",
            self.name, self.start_address, self.end_address, self.kind, self.alignment
        )
    }
}

#[derive(PartialEq, Eq)]
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

pub struct Sections<'a> {
    pub sections: HashMap<String, Section<'a>>,
}

impl<'a> Sections<'a> {
    pub fn new() -> Self {
        Self { sections: HashMap::new() }
    }

    pub fn add(&mut self, section: Section<'a>) {
        self.sections.insert(section.name.clone(), section);
    }

    pub fn get(&self, name: &str) -> Option<&Section> {
        self.sections.get(name)
    }

    pub fn get_by_contained_address(&'a self, address: u32) -> Option<&'a Section> {
        self.sections.values().find(|s| address >= s.start_address && address < s.end_address)
    }

    pub fn get_by_contained_address_mut(&'a mut self, address: u32) -> Option<&'a mut Section> {
        self.sections.values_mut().find(|s| address >= s.start_address && address < s.end_address)
    }

    pub fn add_function(&mut self, function: Function<'a>) {
        let address = function.start_address();
        self.sections
            .values_mut()
            .find(|s| address >= s.start_address && address < s.end_address)
            .unwrap()
            .functions
            .insert(function.start_address(), function);
    }

    pub fn sorted_by_address(&self) -> Vec<&Section<'a>> {
        let mut sections = self.sections.values().collect::<Vec<_>>();
        sections.sort_unstable_by_key(|s| s.start_address);
        sections
    }

    pub fn functions(&self) -> impl Iterator<Item = &Function> {
        self.sections.values().flat_map(|s| s.functions.values())
    }

    pub fn functions_mut(&mut self) -> impl Iterator<Item = &mut Function<'a>> {
        self.sections.values_mut().flat_map(|s| s.functions.values_mut())
    }

    pub fn base_address(&self) -> Option<u32> {
        self.sections.values().map(|s| s.start_address).min()
    }

    pub fn bss_size(&self) -> u32 {
        self.sections.values().filter(|s| s.kind == SectionKind::Bss).map(|s| s.size()).sum()
    }
}
