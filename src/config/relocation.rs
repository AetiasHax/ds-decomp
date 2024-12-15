use std::{
    collections::{btree_map, BTreeMap},
    fmt::Display,
    io::{BufRead, BufReader, BufWriter, Write},
    iter,
    ops::Range,
    path::Path,
};

use anyhow::{bail, Context, Result};
use ds_rom::rom::raw::AutoloadKind;
use object::elf::{R_ARM_ABS32, R_ARM_PC24, R_ARM_THM_PC22, R_ARM_XPC25};

use crate::util::{
    io::{create_file, open_file},
    parse::{parse_i32, parse_u16, parse_u32},
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

            let line = line?;
            let comment_start = line.find("//").unwrap_or(line.len());
            let line = &line[..comment_start];

            let Some(relocation) = Relocation::parse(line, &context)? else {
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

    pub fn add(&mut self, relocation: Relocation) -> Result<&mut Relocation> {
        match self.relocations.entry(relocation.from) {
            btree_map::Entry::Vacant(entry) => Ok(entry.insert(relocation)),
            btree_map::Entry::Occupied(entry) => {
                if entry.get() == &relocation {
                    log::warn!(
                        "Relocation from {:#010x} to {:#010x} in {} is identical to existing one",
                        relocation.from,
                        relocation.to,
                        relocation.module
                    );
                    Ok(entry.into_mut())
                } else {
                    log::error!(
                        "Relocation from {:#010x} to {:#010x} in {} collides with existing one to {:#010x} in {}",
                        relocation.from,
                        relocation.to,
                        relocation.module,
                        entry.get().to,
                        entry.get().module
                    );
                    bail!("Relocation collides with existing one")
                }
            }
        }
    }

    pub fn add_call(
        &mut self,
        from: u32,
        to: u32,
        module: RelocationModule,
        from_thumb: bool,
        to_thumb: bool,
    ) -> Result<&mut Relocation> {
        self.add(Relocation::new_call(from, to, module, from_thumb, to_thumb))
    }

    pub fn add_load(&mut self, from: u32, to: u32, addend: i32, module: RelocationModule) -> Result<&mut Relocation> {
        self.add(Relocation::new_load(from, to, addend, module))
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

#[derive(PartialEq, Eq)]
pub struct Relocation {
    from: u32,
    to: u32,
    addend: i32,
    kind: RelocationKind,
    module: RelocationModule,
    pub source: Option<String>,
}

impl Relocation {
    fn parse(line: &str, context: &ParseContext) -> Result<Option<Self>> {
        let words = line.split_whitespace();

        let mut from = None;
        let mut to = None;
        let mut addend = 0;
        let mut kind = None;
        let mut module = None;
        for (key, value) in iter_attributes(words) {
            match key {
                "from" => {
                    from = Some(
                        parse_u32(value).with_context(|| format!("{context}: failed to parse \"from\" address '{value}'"))?,
                    )
                }
                "to" => {
                    to = Some(
                        parse_u32(value).with_context(|| format!("{context}: failed to parse \"to\" address '{value}'"))?,
                    )
                }
                "add" => {
                    addend =
                        parse_i32(value).with_context(|| format!("{context}: failed to parse \"add\" addend '{value}'"))?
                }
                "kind" => kind = Some(RelocationKind::parse(value, context)?),
                "module" => module = Some(RelocationModule::parse(value, context)?),
                _ => bail!("{context}: expected relocation attribute 'from', 'to', 'add', 'kind' or 'module' but got '{key}'"),
            }
        }

        let from = from.with_context(|| format!("{}: missing 'from' attribute", context))?;
        let to = to.with_context(|| format!("{}: missing 'to' attribute", context))?;
        let kind = kind.with_context(|| format!("{}: missing 'kind' attribute", context))?;
        let module = module.with_context(|| format!("{}: missing 'module' attribute", context))?;

        Ok(Some(Self { from, to, addend, kind, module, source: None }))
    }

    pub fn new_call(from: u32, to: u32, module: RelocationModule, from_thumb: bool, to_thumb: bool) -> Self {
        Self {
            from,
            to,
            addend: 0,
            kind: match (from_thumb, to_thumb) {
                (true, true) => RelocationKind::ThumbCall,
                (true, false) => RelocationKind::ThumbCallArm,
                (false, true) => RelocationKind::ArmCallThumb,
                (false, false) => RelocationKind::ArmCall,
            },
            module,
            source: None,
        }
    }

    pub fn new_branch(from: u32, to: u32, module: RelocationModule) -> Self {
        Self { from, to, addend: 0, kind: RelocationKind::ArmBranch, module, source: None }
    }

    pub fn new_load(from: u32, to: u32, addend: i32, module: RelocationModule) -> Self {
        Self { from, to, addend, kind: RelocationKind::Load, module, source: None }
    }

    pub fn from_address(&self) -> u32 {
        self.from
    }

    pub fn to_address(&self) -> u32 {
        self.to
    }

    pub fn kind(&self) -> RelocationKind {
        self.kind
    }

    pub fn module(&self) -> &RelocationModule {
        &self.module
    }

    pub fn addend(&self) -> i64 {
        self.addend as i64 + self.kind.addend()
    }
}

impl Display for Relocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "from:{:#010x} kind:{} to:{:#010x} module:{}", self.from, self.kind, self.to, self.module)?;
        if let Some(source) = &self.source {
            write!(f, " // {source}")?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum RelocationKind {
    ArmCall,
    ThumbCall,
    ArmCallThumb,
    ThumbCallArm,
    ArmBranch,
    Load,
}

impl RelocationKind {
    fn parse(text: &str, context: &ParseContext) -> Result<Self> {
        match text {
            "arm_call" => Ok(Self::ArmCall),
            "thumb_call" => Ok(Self::ThumbCall),
            "arm_call_thumb" => Ok(Self::ArmCallThumb),
            "thumb_call_arm" => Ok(Self::ThumbCallArm),
            "arm_branch" => Ok(Self::ArmBranch),
            "load" => Ok(Self::Load),
            _ => bail!(
                "{}: unknown relocation kind '{}', must be one of: arm_call, thumb_call, arm_call_thumb, thumb_call_arm, arm_branch, load",
                context,
                text
            ),
        }
    }

    pub fn into_obj_symbol_kind(&self) -> object::SymbolKind {
        match self {
            Self::ArmCall => object::SymbolKind::Text,
            Self::ThumbCall => object::SymbolKind::Text,
            Self::ArmCallThumb => object::SymbolKind::Text,
            Self::ThumbCallArm => object::SymbolKind::Text,
            Self::ArmBranch => object::SymbolKind::Text,
            Self::Load => object::SymbolKind::Data,
        }
    }

    pub fn into_elf_relocation_type(&self) -> u32 {
        match self {
            Self::ArmCall => R_ARM_PC24,
            Self::ThumbCall => R_ARM_THM_PC22,
            Self::ArmCallThumb => R_ARM_XPC25,
            // Bug in mwld thinks that the range of XPC22 is only +-2MB, but it should be +-4MB. Fortunately we can use PC22 as
            // it has the correct range, and the linker resolves BL instructions to BLX automatically anyway.
            Self::ThumbCallArm => R_ARM_THM_PC22,
            Self::ArmBranch => R_ARM_PC24,
            Self::Load => R_ARM_ABS32,
        }
    }

    pub fn addend(&self) -> i64 {
        match self {
            Self::ArmCall => -8,
            Self::ThumbCall => -4,
            Self::ArmCallThumb => -8,
            Self::ThumbCallArm => -4,
            Self::ArmBranch => -8,
            Self::Load => 0,
        }
    }
}

impl Display for RelocationKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ArmCall => write!(f, "arm_call"),
            Self::ThumbCall => write!(f, "thumb_call"),
            Self::ArmCallThumb => write!(f, "arm_call_thumb"),
            Self::ThumbCallArm => write!(f, "thumb_call_arm"),
            Self::ArmBranch => write!(f, "arm_branch"),
            Self::Load => write!(f, "load"),
        }
    }
}

#[derive(PartialEq, Eq)]
pub enum RelocationModule {
    None,
    Overlay { id: u16 },
    Overlays { ids: Vec<u16> },
    Main,
    Itcm,
    Dtcm,
}

impl RelocationModule {
    pub fn from_modules<'a, I>(mut modules: I) -> Result<Self>
    where
        I: Iterator<Item = &'a Module<'a>>,
    {
        let Some(first) = modules.next() else { return Ok(Self::None) };

        match first.kind() {
            ModuleKind::Arm9 => {
                if modules.next().is_some() {
                    log::error!("Relocations to main should be unambiguous");
                    bail!("Relocations to main should be unambiguous");
                }
                Ok(Self::Main)
            }
            ModuleKind::Autoload(AutoloadKind::Itcm) => {
                if modules.next().is_some() {
                    log::error!("Relocations to ITCM should be unambiguous");
                    bail!("Relocations to ITCM should be unambiguous");
                }
                Ok(Self::Itcm)
            }
            ModuleKind::Autoload(AutoloadKind::Dtcm) => {
                if modules.next().is_some() {
                    log::error!("Relocations to DTCM should be unambiguous");
                    bail!("Relocations to DTCM should be unambiguous");
                }
                Ok(Self::Dtcm)
            }
            ModuleKind::Autoload(kind) => {
                log::error!("Unknown autoload kind '{kind}'");
                bail!("Unknown autoload kind '{kind}'");
            }
            ModuleKind::Overlay(id) => {
                let ids = iter::once(first)
                    .chain(modules)
                    .map(|module| {
                        if let ModuleKind::Overlay(id) = module.kind() {
                            Ok(id)
                        } else {
                            log::error!("Relocations to overlays should not go to other kinds of modules");
                            bail!("Relocations to overlays should not go to other kinds of modules");
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;
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
            RelocationModule::None => None,
            RelocationModule::Overlays { ids } => Some(ModuleKind::Overlay(*ids.first().unwrap())),
            RelocationModule::Overlay { id } => Some(ModuleKind::Overlay(*id)),
            RelocationModule::Main => Some(ModuleKind::Arm9),
            RelocationModule::Itcm => Some(ModuleKind::Autoload(AutoloadKind::Itcm)),
            RelocationModule::Dtcm => Some(ModuleKind::Autoload(AutoloadKind::Dtcm)),
        }
    }

    /// Returns all modules other than the first that this relocation is pointing to.
    pub fn other_modules(&self) -> Option<impl Iterator<Item = ModuleKind> + '_> {
        match self {
            RelocationModule::Overlays { ids } => Some(ids[1..].iter().map(|&id| ModuleKind::Overlay(id))),
            RelocationModule::None => None,
            RelocationModule::Overlay { .. } => None,
            RelocationModule::Main => None,
            RelocationModule::Itcm => None,
            RelocationModule::Dtcm => None,
        }
    }
}

impl TryFrom<ModuleKind> for RelocationModule {
    type Error = anyhow::Error;

    fn try_from(value: ModuleKind) -> Result<Self> {
        match value {
            ModuleKind::Arm9 => Ok(Self::Main),
            ModuleKind::Overlay(id) => Ok(Self::Overlay { id }),
            ModuleKind::Autoload(kind) => match kind {
                AutoloadKind::Itcm => Ok(Self::Itcm),
                AutoloadKind::Dtcm => Ok(Self::Dtcm),
                AutoloadKind::Unknown(_) => {
                    log::error!("Unknown autoload kind '{}'", kind);
                    bail!("Unknown autoload kind '{}'", kind);
                }
            },
        }
    }
}

impl Display for RelocationModule {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelocationModule::None => write!(f, "none"),
            RelocationModule::Overlay { id } => write!(f, "overlay({id})"),
            RelocationModule::Overlays { ids } => {
                write!(f, "overlays({}", ids[0])?;
                for id in &ids[1..] {
                    write!(f, ",{}", id)?;
                }
                write!(f, ")")?;
                Ok(())
            }
            RelocationModule::Main => write!(f, "main"),
            RelocationModule::Itcm => write!(f, "itcm"),
            RelocationModule::Dtcm => write!(f, "dtcm"),
        }
    }
}
