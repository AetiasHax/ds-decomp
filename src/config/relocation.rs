use std::{
    collections::BTreeMap,
    fmt::Display,
    io::{BufRead, BufReader, BufWriter, Write},
    iter,
    ops::Range,
    path::Path,
};

use anyhow::{bail, Context, Result};
use ds_rom::rom::raw::AutoloadKind;

use crate::util::{
    io::{create_file, open_file},
    parse::{parse_u16, parse_u32},
};

use super::{
    iter_attributes,
    module::{Module, ModuleKind},
    ParseContext,
};

pub struct Relocations {
    relocations: BTreeMap<u32, Relocation>,
}

impl Relocations {
    pub fn new() -> Self {
        Self { relocations: BTreeMap::new() }
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let mut context = ParseContext { file_path: path.to_str().unwrap().to_string(), row: 0 };

        let file = open_file(path)?;
        let reader = BufReader::new(file);

        let mut relocations = BTreeMap::new();
        for line in reader.lines() {
            context.row += 1;
            let Some(relocation) = Relocation::parse(line?.as_str(), &context)? else {
                continue;
            };
            relocations.insert(relocation.from, relocation);
        }

        Ok(Self { relocations })
    }

    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();

        let file = create_file(path)?;
        let mut writer = BufWriter::new(file);

        for relocation in self.relocations.values() {
            writeln!(writer, "{relocation}")?;
        }
        Ok(())
    }

    pub fn add(&mut self, relocation: Relocation) {
        self.relocations.insert(relocation.from, relocation);
    }

    pub fn add_call(&mut self, from: u32, to: RelocationTo) {
        self.add(Relocation::new_call(from, to));
    }

    pub fn add_load(&mut self, from: u32, to: RelocationTo) {
        self.add(Relocation::new_load(from, to));
    }

    pub fn extend(&mut self, relocations: Vec<Relocation>) {
        for relocation in relocations.into_iter() {
            self.add(relocation);
        }
    }

    pub fn get(&self, from: u32) -> Option<&Relocation> {
        self.relocations.get(&from)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Relocation> {
        self.relocations.values()
    }

    pub fn iter_range(&self, range: Range<u32>) -> impl Iterator<Item = (&u32, &Relocation)> {
        self.relocations.range(range)
    }
}

pub struct Relocation {
    from: u32,
    kind: RelocationKind,
    to: RelocationTo,
}

impl Relocation {
    fn parse(line: &str, context: &ParseContext) -> Result<Option<Self>> {
        let words = line.split_whitespace();

        let mut from = None;
        let mut kind = None;
        let mut to = None;
        for (key, value) in iter_attributes(words) {
            match key {
                "from" => {
                    from = Some(parse_u32(value).with_context(|| format!("{}: failed to parse address '{}'", context, value))?)
                }
                "kind" => kind = Some(RelocationKind::parse(value, context)?),
                "to" => to = Some(RelocationTo::parse(value, context)?),
                _ => bail!("{}: expected relocation attribute 'from', 'kind' or 'to' but got '{}'", context, key),
            }
        }

        let from = from.with_context(|| format!("{}: missing 'from' attribute", context))?;
        let kind = kind.with_context(|| format!("{}: missing 'kind' attribute", context))?;
        let to = to.with_context(|| format!("{}: missing 'to' attribute", context))?;

        Ok(Some(Self { from, kind, to }))
    }

    pub fn new_call(from: u32, to: RelocationTo) -> Self {
        Self { from, kind: RelocationKind::Call, to }
    }

    pub fn new_load(from: u32, to: RelocationTo) -> Self {
        Self { from, kind: RelocationKind::Load, to }
    }

    pub fn from_address(&self) -> u32 {
        self.from
    }

    pub fn kind(&self) -> RelocationKind {
        self.kind
    }

    pub fn to(&self) -> &RelocationTo {
        &self.to
    }
}

impl Display for Relocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "from:0x{:08x} kind:{} to:{}", self.from, self.kind, self.to)
    }
}

#[derive(Clone, Copy)]
pub enum RelocationKind {
    Call,
    Load,
}

impl RelocationKind {
    fn parse(text: &str, context: &ParseContext) -> Result<Self> {
        match text {
            "call" => Ok(Self::Call),
            "load" => Ok(Self::Load),
            _ => bail!("{}: unknown relocation kind '{}', must be one of: call, load", context, text),
        }
    }
}

impl Display for RelocationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Call => write!(f, "call"),
            Self::Load => write!(f, "load"),
        }
    }
}

#[derive(PartialEq, Eq)]
pub enum RelocationTo {
    None,
    Overlay { id: u16 },
    Overlays { ids: Vec<u16> },
    Main,
    Itcm,
    Dtcm,
}

impl RelocationTo {
    pub fn from_modules<'a, I>(mut modules: I) -> Result<Self>
    where
        I: Iterator<Item = &'a Module<'a>>,
    {
        let Some(first) = modules.next() else { return Ok(Self::None) };

        match first.kind() {
            ModuleKind::Arm9 => {
                if modules.next().is_some() {
                    panic!("Relocations to main should be unambiguous");
                }
                Ok(Self::Main)
            }
            ModuleKind::Autoload(AutoloadKind::Itcm) => {
                if modules.next().is_some() {
                    panic!("Relocations to ITCM should be unambiguous");
                }
                Ok(Self::Itcm)
            }
            ModuleKind::Autoload(AutoloadKind::Dtcm) => {
                if modules.next().is_some() {
                    panic!("Relocations to DTCM should be unambiguous");
                }
                Ok(Self::Dtcm)
            }
            ModuleKind::Autoload(kind) => bail!("Unknown autoload kind '{kind}'"),
            ModuleKind::Overlay(id) => {
                let ids = iter::once(first)
                    .chain(modules)
                    .map(|module| {
                        if let ModuleKind::Overlay(id) = module.kind() {
                            id
                        } else {
                            panic!("Relocations to overlays should not go to other kinds of modules");
                        }
                    })
                    .collect::<Vec<_>>();
                if ids.len() > 1 {
                    Ok(Self::Overlays { ids })
                } else {
                    Ok(Self::Overlay { id })
                }
            }
        }
    }

    fn parse(text: &str, context: &ParseContext) -> Result<Self> {
        let (value, options) = text.split_once('(').unwrap_or((text, ""));
        let options = options.strip_suffix(')').unwrap_or(options);

        match value {
            "none" => {
                if options.is_empty() {
                    Ok(Self::None)
                } else {
                    bail!("{}: relocations to 'none' have no options, but got '({})'", context, options);
                }
            }
            "overlay" => Ok(Self::Overlay {
                id: parse_u16(options).with_context(|| format!("{}: failed to parse overlay ID '{}'", context, options))?,
            }),
            "overlays" => {
                let ids = options
                    .split(',')
                    .map(|x| parse_u16(x).with_context(|| format!("{}: failed to parse overlay ID '{}'", context, x)))
                    .collect::<Result<Vec<_>>>()?;
                if ids.len() < 2 {
                    bail!("{}: relocation to 'overlays' must have two or more overlay IDs, but got {:?}", context, ids);
                }
                Ok(Self::Overlays { ids })
            }
            "main" => {
                if options.is_empty() {
                    Ok(Self::Main)
                } else {
                    bail!("{}: relocation to 'main' have no options, but got '({})'", context, options);
                }
            }
            "itcm" => {
                if options.is_empty() {
                    Ok(Self::Itcm)
                } else {
                    bail!("{}: relocations to 'ITCM' have no options, but got '({})'", context, options);
                }
            }
            "dtcm" => {
                if options.is_empty() {
                    Ok(Self::Dtcm)
                } else {
                    bail!("{}: relocations to 'DTCM' have no options, but got '({})'", context, options);
                }
            }
            _ => {
                bail!("{}: unknown relocation to '{}', must be one of: overlays, overlay, main, itcm, dtcm", context, value);
            }
        }
    }

    /// Returns the first (and possibly only) module this relocation is pointing to.
    pub fn first_module(&self) -> Option<ModuleKind> {
        match self {
            RelocationTo::None => None,
            RelocationTo::Overlays { ids } => Some(ModuleKind::Overlay(*ids.first().unwrap())),
            RelocationTo::Overlay { id } => Some(ModuleKind::Overlay(*id)),
            RelocationTo::Main => Some(ModuleKind::Arm9),
            RelocationTo::Itcm => Some(ModuleKind::Autoload(AutoloadKind::Itcm)),
            RelocationTo::Dtcm => Some(ModuleKind::Autoload(AutoloadKind::Dtcm)),
        }
    }

    /// Returns all modules other than the first that this relocation is pointing to.
    pub fn other_modules(&self) -> Option<impl Iterator<Item = ModuleKind> + '_> {
        match self {
            RelocationTo::Overlays { ids } => Some(ids[1..].iter().map(|&id| ModuleKind::Overlay(id))),
            RelocationTo::None => None,
            RelocationTo::Overlay { .. } => None,
            RelocationTo::Main => None,
            RelocationTo::Itcm => None,
            RelocationTo::Dtcm => None,
        }
    }
}

impl From<ModuleKind> for RelocationTo {
    fn from(value: ModuleKind) -> Self {
        match value {
            ModuleKind::Arm9 => Self::Main,
            ModuleKind::Overlay(id) => Self::Overlay { id },
            ModuleKind::Autoload(kind) => match kind {
                AutoloadKind::Itcm => Self::Itcm,
                AutoloadKind::Dtcm => Self::Dtcm,
                AutoloadKind::Unknown => panic!("Unknown autoload kind '{}'", kind),
            },
        }
    }
}

impl Display for RelocationTo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelocationTo::None => write!(f, "none"),
            RelocationTo::Overlay { id } => write!(f, "overlay({id})"),
            RelocationTo::Overlays { ids } => {
                write!(f, "overlays({}", ids[0])?;
                for id in &ids[1..] {
                    write!(f, ",{}", id)?;
                }
                write!(f, ")")?;
                Ok(())
            }
            RelocationTo::Main => write!(f, "main"),
            RelocationTo::Itcm => write!(f, "itcm"),
            RelocationTo::Dtcm => write!(f, "dtcm"),
        }
    }
}
