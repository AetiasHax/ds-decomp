use std::{
    collections::BTreeMap,
    fmt::Display,
    io::{BufRead, BufReader, BufWriter, Write},
    iter,
    path::Path,
};

use anyhow::{bail, Context, Result};
use ds_rom::rom::raw::AutoloadKind;

use crate::util::{
    io::{create_file, open_file},
    parse::parse_u32,
};

use super::{
    iter_attributes,
    module::{Module, ModuleKind},
    ParseContext,
};

pub struct Xrefs {
    xrefs: BTreeMap<u32, Xref>,
}

impl Xrefs {
    pub fn new() -> Self {
        Self { xrefs: BTreeMap::new() }
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let mut context = ParseContext { file_path: path.to_str().unwrap().to_string(), row: 0 };

        let file = open_file(path)?;
        let reader = BufReader::new(file);

        let mut xrefs = BTreeMap::new();
        for line in reader.lines() {
            context.row += 1;
            let Some(xref) = Xref::parse(line?.as_str(), &context)? else {
                continue;
            };
            xrefs.insert(xref.from, xref);
        }

        Ok(Self { xrefs })
    }

    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let path = path.as_ref();

        let file = create_file(path)?;
        let mut writer = BufWriter::new(file);

        for xref in self.xrefs.values() {
            writeln!(writer, "{xref}")?;
        }
        Ok(())
    }

    pub fn add_function(&mut self, from: u32, to: XrefTo) {
        self.xrefs.insert(from, Xref { from, kind: XrefKind::Call, to });
    }

    pub fn add_data(&mut self, from: u32, to: XrefTo) {
        self.xrefs.insert(from, Xref { from, kind: XrefKind::Load, to });
    }
}

pub struct Xref {
    from: u32,
    kind: XrefKind,
    to: XrefTo,
}

impl Xref {
    fn parse(line: &str, context: &ParseContext) -> Result<Option<Self>> {
        let words = line.split_whitespace();

        let mut from = None;
        let mut kind = None;
        let mut to = None;
        for pair in iter_attributes(words, context) {
            let (key, value) = pair?;
            match key {
                "from" => {
                    from = Some(parse_u32(value).with_context(|| format!("{}: failed to parse address '{}'", context, value))?)
                }
                "kind" => kind = Some(XrefKind::parse(value, context)?),
                "to" => to = Some(XrefTo::parse(value, context)?),
                _ => bail!("{}: expected xref attribute 'from', 'kind' or 'to' but got '{}'", context, key),
            }
        }

        let from = from.with_context(|| format!("{}: missing 'from' attribute", context))?;
        let kind = kind.with_context(|| format!("{}: missing 'kind' attribute", context))?;
        let to = to.with_context(|| format!("{}: missing 'to' attribute", context))?;

        Ok(Some(Self { from, kind, to }))
    }
}

impl Display for Xref {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "from:0x{:08x} kind:{} to:{}", self.from, self.kind, self.to)
    }
}

pub enum XrefKind {
    Call,
    Load,
}

impl XrefKind {
    fn parse(text: &str, context: &ParseContext) -> Result<Self> {
        match text {
            "call" => Ok(Self::Call),
            "load" => Ok(Self::Load),
            _ => bail!("{}: unknown xref kind '{}', must be one of: call, load", context, text),
        }
    }
}

impl Display for XrefKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Call => write!(f, "call"),
            Self::Load => write!(f, "load"),
        }
    }
}

pub enum XrefTo {
    None,
    Overlay { id: u32 },
    Overlays { ids: Vec<u32> },
    Main,
    Itcm,
    Dtcm,
}

impl XrefTo {
    pub fn from_modules<'a, M>(mut modules: M) -> Result<Self>
    where
        M: Iterator<Item = &'a Module<'a>>,
    {
        let Some(first) = modules.next() else { return Ok(Self::None) };

        match first.kind() {
            ModuleKind::Arm9 => {
                if modules.next().is_some() {
                    panic!("Xrefs to main should be unambiguous");
                }
                Ok(Self::Main)
            }
            ModuleKind::Autoload(AutoloadKind::Itcm) => {
                if modules.next().is_some() {
                    panic!("Xrefs to ITCM should be unambiguous");
                }
                Ok(Self::Itcm)
            }
            ModuleKind::Autoload(AutoloadKind::Dtcm) => {
                if modules.next().is_some() {
                    panic!("Xrefs to DTCM should be unambiguous");
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
                            panic!("Xrefs to overlays should not go to other kinds of modules");
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
                    bail!("{}: xrefs to 'none' have no options, but got '({})'", context, options);
                }
            }
            "overlay" => Ok(Self::Overlay {
                id: parse_u32(options).with_context(|| format!("{}: failed to parse overlay ID '{}'", context, options))?,
            }),
            "overlays" => {
                let ids = options
                    .split(',')
                    .map(|x| parse_u32(x).with_context(|| format!("{}: failed to parse overlay ID '{}'", context, x)))
                    .collect::<Result<Vec<_>>>()?;
                if ids.len() < 2 {
                    bail!("{}: xref to 'overlays' must have two or more overlay IDs, but got {:?}", context, ids);
                }
                Ok(Self::Overlays { ids })
            }
            "main" => {
                if options.is_empty() {
                    Ok(Self::Main)
                } else {
                    bail!("{}: xrefs to 'main' have no options, but got '({})'", context, options);
                }
            }
            "itcm" => {
                if options.is_empty() {
                    Ok(Self::Main)
                } else {
                    bail!("{}: xrefs to 'ITCM' have no options, but got '({})'", context, options);
                }
            }
            "dtcm" => {
                if options.is_empty() {
                    Ok(Self::Main)
                } else {
                    bail!("{}: xrefs to 'DTCM' have no options, but got '({})'", context, options);
                }
            }
            _ => {
                bail!("{}: unknown xref to '{}', must be one of: overlays, overlay, main, itcm, dtcm", context, value);
            }
        }
    }
}

impl Display for XrefTo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            XrefTo::None => write!(f, "none"),
            XrefTo::Overlay { id } => write!(f, "overlay({id})"),
            XrefTo::Overlays { ids } => {
                write!(f, "overlays({}", ids[0])?;
                for id in &ids[1..] {
                    write!(f, ",{}", id)?;
                }
                write!(f, ")")?;
                Ok(())
            }
            XrefTo::Main => write!(f, "main"),
            XrefTo::Itcm => write!(f, "itcm"),
            XrefTo::Dtcm => write!(f, "dtcm"),
        }
    }
}
