mod apply;
mod new;

use std::{
    collections::{HashMap, VecDeque},
    io::{BufReader, BufWriter},
    path::{Path, PathBuf},
};

use anyhow::Result;
use apply::*;
use clap::{Args, Subcommand};
use ds_decomp::config::{
    delinks::Categories,
    module::ModuleKind,
    relocations::{RelocationKind, RelocationModule},
    section::SectionKind,
    symbol::SymbolKind,
};
use new::*;
use serde::{Deserialize, Serialize};

use crate::util::{
    io,
    serde_hex::{Hex, IHex},
};

/// Subcommands for creating/applying dsd diffs.
#[derive(Args)]
pub struct DiffArgs {
    #[command(subcommand)]
    command: DiffCommand,
}

impl DiffArgs {
    pub fn run(&self) -> Result<()> {
        match &self.command {
            DiffCommand::New(new) => new.run(),
            DiffCommand::Apply(apply) => apply.run(),
        }
    }

    pub fn configure_logger(&self, builder: &mut env_logger::Builder) -> Result<()> {
        #[allow(clippy::single_match)]
        match &self.command {
            DiffCommand::Apply(apply) => apply.configure_logger(builder)?,
            _ => {}
        };
        Ok(())
    }
}

#[derive(Subcommand)]
enum DiffCommand {
    New(NewDiffCmd),
    Apply(ApplyDiffCmd),
}

#[derive(Serialize, Deserialize)]
pub(crate) struct DsdDiff {
    config_before: PathBuf,
    config_after: PathBuf,
    actions: Vec<ModuleDiffAction>,
}

impl DsdDiff {
    pub(crate) fn to_file(&self, path: &Path) -> Result<()> {
        serde_saphyr::to_io_writer(&mut BufWriter::new(io::create_file(path)?), self)?;
        Ok(())
    }

    pub(crate) fn from_file(path: &Path) -> Result<Self> {
        Ok(serde_saphyr::from_reader(BufReader::new(io::open_file(path)?))?)
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct ModuleDiffAction {
    module: ModuleKind,
    action: DiffAction,
}

#[derive(Serialize, Deserialize)]
pub(crate) enum DiffAction {
    ChangeSections(SectionsDiff),
    AddGlobalCategory(String),
    RemoveGlobalCategory(String),

    AddDelink(NewDelinkFile),
    DeleteDelink(NewDelinkFile),
    ChangeDelinkSections { delink_name: String, sections: SectionsDiff },
    ChangeDelinkComplete { delink_name: String, before: bool, after: bool },
    AddDelinkCategory { delink_name: String, category: String },
    RemoveDelinkCategory { delink_name: String, category: String },

    AddSymbol(NewSymbol),
    DeleteSymbol(NewSymbol),
    ChangeSymbol(SymbolDiff),

    AddRelocation(NewRelocation),
    DeleteRelocation(NewRelocation),
    ChangeRelocation(RelocationDiff),

    Group(VecDeque<ModuleDiffAction>),
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SectionsDiff {
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub(crate) added: Vec<NewSection>,
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub(crate) removed: Vec<NewSection>,
    #[serde(skip_serializing_if = "HashMap::is_empty", default)]
    pub(crate) diffs: HashMap<String, SectionDiff>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct NewSection {
    pub(crate) name: String,
    pub(crate) kind: SectionKind,
    pub(crate) start_address: Hex<u32>,
    pub(crate) end_address: Hex<u32>,
    pub(crate) alignment: u32,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SectionDiff {
    pub(crate) name: Diff<String>,
    pub(crate) kind: Diff<SectionKind>,
    pub(crate) start_address: Diff<Hex<u32>>,
    pub(crate) end_address: Diff<Hex<u32>>,
    pub(crate) alignment: Diff<u32>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct NewDelinkFile {
    pub(crate) name: String,
    pub(crate) sections: Vec<NewSection>,
    #[serde(skip_serializing_if = "is_false", default)]
    pub(crate) complete: bool,
    #[serde(skip_serializing_if = "Categories::is_empty", default)]
    pub(crate) categories: Categories,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct NewSymbol {
    pub(crate) name: String,
    pub(crate) kind: SymbolKind,
    pub(crate) addr: Hex<u32>,
    #[serde(skip_serializing_if = "is_false", default)]
    pub(crate) ambiguous: bool,
    #[serde(skip_serializing_if = "is_false", default)]
    pub(crate) local: bool,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct SymbolDiff {
    pub(crate) name: Diff<String>,
    pub(crate) kind: Diff<SymbolKind>,
    pub(crate) addr: Hex<u32>,
    pub(crate) ambiguous: Diff<bool>,
    pub(crate) local: Diff<bool>,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct NewRelocation {
    pub(crate) from: Hex<u32>,
    pub(crate) to: Hex<u32>,
    #[serde(skip_serializing_if = "IHex::is_zero", default)]
    pub(crate) addend: IHex<i64>,
    pub(crate) kind: RelocationKind,
    pub(crate) module: RelocationModule,
}

#[derive(Serialize, Deserialize)]
pub(crate) struct RelocationDiff {
    pub(crate) from: Hex<u32>,
    pub(crate) to: Diff<Hex<u32>>,
    pub(crate) addend: Diff<IHex<i64>>,
    pub(crate) kind: Diff<RelocationKind>,
    pub(crate) module: Diff<RelocationModule>,
}

#[derive(Serialize, Deserialize)]
pub(crate) enum Diff<T: Eq> {
    Equal(T),
    Diff { before: T, after: T },
}

impl<T: Eq> Diff<T> {
    pub(crate) fn new(before: T, after: T) -> Self {
        if before == after {
            Self::Equal(before)
        } else {
            Self::Diff { before, after }
        }
    }

    pub(crate) fn is_equal(&self) -> bool {
        match self {
            Diff::Equal(_) => true,
            Diff::Diff { .. } => false,
        }
    }

    pub(crate) fn before(&self) -> &T {
        match self {
            Diff::Equal(value) => value,
            Diff::Diff { before, after: _ } => before,
        }
    }

    pub(crate) fn after(&self) -> &T {
        match self {
            Diff::Equal(value) => value,
            Diff::Diff { before: _, after } => after,
        }
    }
}

fn is_false(b: &bool) -> bool {
    !b
}
