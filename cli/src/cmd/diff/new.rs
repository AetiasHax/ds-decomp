use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::Args;
use ds_decomp::config::{
    config::Config,
    delinks::{Categories, DelinkFile, Delinks},
    module::{Module, ModuleKind},
    relocations::{Relocation, Relocations},
    section::{Section, Sections},
    symbol::{Symbol, SymbolKind, SymbolMap},
};
use ds_rom::rom::Rom;
use path_slash::PathBufExt;
use pathdiff::diff_paths;
use serde::Serialize;

use crate::{
    cmd::{
        Diff, DiffAction, DsdDiff, ModuleDiffAction, NewDelinkFile, NewRelocation, NewSection,
        NewSymbol, RelocationDiff, SectionDiff, SymbolDiff, diff::SectionsDiff,
    },
    config::{
        delinks::{DelinksMap, DelinksMapOptions},
        program::Program,
    },
    util::{
        path::PathExt,
        serde_hex::{Hex, IHex},
    },
};

/// Computes a list of diff actions between two dsd projects.
#[derive(Args)]
pub struct NewDiffCmd {
    /// Path to config.yaml for the first project.
    #[arg(long, short = '1')]
    config_before: PathBuf,

    /// Path to config.yaml for the second project.
    #[arg(long, short = '2')]
    config_after: PathBuf,

    /// Path to diff output file, defaults to dsd_diff.yaml
    #[arg(long, short = 'o')]
    output_path: Option<PathBuf>,

    /// Skips diff actions that affect delink files.
    #[arg(long)]
    skip_files: bool,

    /// Skips diff actions that rename symbols to their default names.
    #[arg(long)]
    skip_default_names: bool,

    /// Skips diff actions that add more overlay candidates to ambiguous relocations.
    #[arg(long)]
    skip_broadened_relocs: bool,

    /// Skips diff actions that set a relocation's addend to zero.
    #[arg(long)]
    skip_zeroed_addends: bool,

    /// Skips diff actions that turn a local symbol to global.
    #[arg(long)]
    skip_globalized_symbols: bool,

    /// Skips diff actions that removes the explicit size of BSS/data symbols.
    #[arg(long)]
    skip_sizeless_data: bool,

    /// Skips diff actions that add symbols marked with `ambiguous`.
    #[arg(long)]
    skip_ambiguous_symbols: bool,
}

pub const DEFAULT_OUT_FILE_NAME: &str = "dsd_diff.yaml";

impl NewDiffCmd {
    pub fn run(&self) -> Result<()> {
        let config_before_path = self.config_before.parent().unwrap();
        let config_after_path = self.config_after.parent().unwrap();

        let config_before = Config::from_file(&self.config_before)?;
        let config_after = Config::from_file(&self.config_after)?;

        let rom_before = config_before.load_rom(config_before_path)?;
        let rom_after = config_after.load_rom(config_after_path)?;

        let project_before = ProjectInfo::new(&config_before, config_before_path, &rom_before)?;
        let project_after = ProjectInfo::new(&config_after, config_after_path, &rom_after)?;

        let Some(diff) = ModulesDiff::new(&project_before, &project_after, self)? else {
            return Ok(());
        };
        let actions = diff.diff_actions(self);
        let num_actions: usize = actions.len();
        log::info!("Found {} diff actions", num_actions);

        let output_path = self.output_path.clone().unwrap_or(PathBuf::from(DEFAULT_OUT_FILE_NAME));
        let absolute_output_path = PathExt::absolute(output_path.as_path())?;
        let base_path = absolute_output_path.parent().unwrap();
        let diff = DsdDiff {
            config_before: Self::make_path(&self.config_before, base_path)?,
            config_after: Self::make_path(&self.config_after, base_path)?,
            actions,
        };
        diff.to_file(&output_path)?;

        Ok(())
    }

    fn make_path<P: AsRef<Path>, B: AsRef<Path>>(path: P, base: B) -> Result<PathBuf> {
        let path = PathExt::absolute(path.as_ref())?;
        let base = PathExt::absolute(base.as_ref())?;
        let diff = diff_paths(path, base).unwrap();
        let diff_slash = diff.to_slash_lossy();
        let diff_str: &str = diff_slash.as_ref();
        Ok(PathBuf::from(diff_str))
    }
}

struct ProjectInfo {
    delinks_map: DelinksMap,
    program: Program,
}

impl ProjectInfo {
    fn new(config: &Config, config_path: &Path, rom: &Rom) -> Result<Self> {
        let delinks_map_options = DelinksMapOptions {
            migrate_sections: false,
            generate_gap_files: false,
            module_filter: Vec::new(),
        };
        Ok(ProjectInfo {
            delinks_map: DelinksMap::from_config(config, config_path, delinks_map_options)?,
            program: Program::from_config(config_path, config, rom)?,
        })
    }
}

#[derive(Serialize)]
struct ModulesDiff {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    added: Vec<NewModule>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    removed: Vec<ModuleKind>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    diffs: BTreeMap<ModuleKind, ModuleDiff>,
}

impl ModulesDiff {
    fn new(before: &ProjectInfo, after: &ProjectInfo, cmd: &NewDiffCmd) -> Result<Option<Self>> {
        let mut removed = Vec::new();
        let mut diffs = BTreeMap::new();
        let mut equals = BTreeSet::new();
        for module_before in before.program.modules() {
            let module_kind = module_before.kind();
            let delinks_before = before.delinks_map.get(module_kind).with_context(|| {
                format!("Delinks not found for {} in first project", module_kind)
            })?;
            let symbols_before =
                before.program.symbol_maps().get(module_kind).with_context(|| {
                    format!("Symbol map not found for {} in first project", module_kind)
                })?;

            let Some(module_after) = after.program.by_module_kind(module_kind) else {
                removed.push(module_kind);
                continue;
            };
            let delinks_after = after.delinks_map.get(module_kind).with_context(|| {
                format!("Delinks not found for {} in second project", module_kind)
            })?;
            let symbols_after =
                after.program.symbol_maps().get(module_kind).with_context(|| {
                    format!("Symbol map not found for {} in second project", module_kind)
                })?;

            let Some(diff) = ModuleDiff::new(
                module_before,
                delinks_before,
                symbols_before,
                module_after,
                delinks_after,
                symbols_after,
                cmd,
            ) else {
                equals.insert(module_kind);
                continue;
            };

            diffs.insert(module_kind, diff);
        }

        let mut added = Vec::new();
        for module in after.program.modules() {
            if !equals.contains(&module.kind()) && !diffs.contains_key(&module.kind()) {
                let delinks = after.delinks_map.get(module.kind()).with_context(|| {
                    format!("Delinks not found for {} in second project", module.kind())
                })?;
                let symbols =
                    after.program.symbol_maps().get(module.kind()).with_context(|| {
                        format!("Symbol map not found for {} in second project", module.kind())
                    })?;
                added.push(NewModule::new(module, delinks, symbols));
            }
        }

        if added.is_empty() && removed.is_empty() && diffs.is_empty() {
            Ok(None)
        } else {
            Ok(Some(Self { added, removed, diffs }))
        }
    }

    fn diff_actions(self, cmd: &NewDiffCmd) -> Vec<ModuleDiffAction> {
        let mut actions = self.diffs.into_values().map(ModuleDiff::diff_actions).fold(
            ModuleDiffActions::default(),
            |mut acc, actions| {
                acc.delinks.categories.extend(actions.delinks.categories);
                acc.delinks.files.extend(actions.delinks.files);
                acc.delinks.sections.extend(actions.delinks.sections);
                acc.relocations.extend(actions.relocations);
                acc.symbols.extend(actions.symbols);
                acc
            },
        );

        // Group changes to symbols with relocations that point to them
        let mut symbols_relocs_actions = Vec::new();
        while let Some(symbol_action) = actions.symbols.pop_front() {
            let mut related_actions: VecDeque<ModuleDiffAction> = match &symbol_action.action {
                DiffAction::AddSymbol(new_symbol) => actions
                    .relocations
                    .extract_if(.., |reloc| match &reloc.action {
                        DiffAction::AddRelocation(new_relocation) => {
                            new_relocation.to == new_symbol.addr
                                && new_relocation.module.contains(symbol_action.module)
                        }
                        DiffAction::ChangeRelocation(relocation_diff) => match relocation_diff.to {
                            Diff::Equal(to_after) | Diff::Diff { before: _, after: to_after } => {
                                match &relocation_diff.module {
                                    Diff::Equal(module_after)
                                    | Diff::Diff { before: _, after: module_after } => {
                                        to_after == new_symbol.addr
                                            && module_after.contains(symbol_action.module)
                                    }
                                }
                            }
                        },
                        DiffAction::DeleteRelocation(_) => false,
                        _ => {
                            panic!("Non-relocation action found in actions.relocations")
                        }
                    })
                    .collect(),
                DiffAction::DeleteSymbol(deleted_symbol) => actions
                    .relocations
                    .extract_if(.., |reloc| match &reloc.action {
                        DiffAction::AddRelocation(_) => false,
                        DiffAction::DeleteRelocation(deleted_relocation) => {
                            deleted_relocation.to == deleted_symbol.addr
                        }
                        DiffAction::ChangeRelocation(relocation_diff) => match relocation_diff.to {
                            Diff::Equal(to_before) | Diff::Diff { before: to_before, after: _ } => {
                                match &relocation_diff.module {
                                    Diff::Equal(module_before)
                                    | Diff::Diff { before: module_before, after: _ } => {
                                        to_before == deleted_symbol.addr
                                            && module_before.contains(symbol_action.module)
                                    }
                                }
                            }
                        },
                        _ => {
                            panic!("Non-relocation action found in actions.relocations")
                        }
                    })
                    .collect(),
                DiffAction::ChangeSymbol(_) => VecDeque::new(),
                _ => {
                    panic!("Non-symbol action found in actions.symbols")
                }
            };

            if cmd.skip_zeroed_addends && !related_actions.is_empty() {
                let only_zeroed_addends = related_actions.iter().all(|a| match &a.action {
                    DiffAction::ChangeRelocation(relocation_diff) => match relocation_diff.addend {
                        Diff::Equal(_) => false,
                        Diff::Diff { before: _, after } => after.0 == 0,
                    },
                    _ => false,
                });
                if only_zeroed_addends {
                    continue;
                }
            }

            if related_actions.is_empty() {
                symbols_relocs_actions.push(symbol_action);
            } else {
                let module = symbol_action.module;
                related_actions.push_front(symbol_action);
                symbols_relocs_actions
                    .push(ModuleDiffAction { module, action: DiffAction::Group(related_actions) });
            }
        }

        // Append remaining relocations that were not grouped with a symbol
        symbols_relocs_actions.extend(actions.relocations.into_iter().filter(|reloc_action| {
            match &reloc_action.action {
                DiffAction::AddRelocation(_) => true,
                DiffAction::DeleteRelocation(_) => true,
                DiffAction::ChangeRelocation(relocation_diff) => {
                    if cmd.skip_zeroed_addends
                        && relocation_diff.kind.is_equal()
                        && relocation_diff.module.is_equal()
                        && let Diff::Diff { before: _, after } = relocation_diff.addend
                        && after.0 == 0
                    {
                        false
                    } else {
                        true
                    }
                }
                _ => {
                    panic!("Non-relocation action found in actions.relocations")
                }
            }
        }));

        let mut sorted = Vec::new();

        // Prioritize delinks changes first
        sorted.extend(actions.delinks.sections);
        sorted.extend(actions.delinks.categories);
        sorted.extend(actions.delinks.files);

        // Then symbols and relocations sorted by module kind
        symbols_relocs_actions.sort_by_key(|a| a.module);
        sorted.extend(symbols_relocs_actions);

        sorted
    }
}

#[derive(Serialize)]
struct NewModule {
    name: String,
    kind: ModuleKind,
    #[serde(flatten)]
    delinks: NewDelinks,
    #[serde(flatten)]
    symbols: NewSymbols,
    #[serde(flatten)]
    relocations: NewRelocations,
}

impl NewModule {
    fn new(module: &Module, delinks: &Delinks, symbols: &SymbolMap) -> Self {
        Self {
            name: module.name().to_string(),
            kind: module.kind(),
            delinks: NewDelinks::from(delinks),
            symbols: NewSymbols::from(symbols),
            relocations: NewRelocations::from(module.relocations()),
        }
    }
}

#[derive(Serialize)]
struct ModuleDiff {
    #[serde(skip)]
    module: ModuleKind,
    name: Diff<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delinks: Option<DelinksDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    symbols: Option<SymbolsDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    relocations: Option<RelocationsDiff>,
}

impl ModuleDiff {
    fn new(
        module_before: &Module,
        delinks_before: &Delinks,
        symbols_before: &SymbolMap,
        module_after: &Module,
        delinks_after: &Delinks,
        symbols_after: &SymbolMap,
        cmd: &NewDiffCmd,
    ) -> Option<Self> {
        assert_eq!(module_before.kind(), module_after.kind());

        let name = Diff::new(module_before.name().to_string(), module_after.name().to_string());
        let delinks = DelinksDiff::new(delinks_before, delinks_after, cmd);
        let symbols = SymbolsDiff::new(symbols_before, symbols_after, cmd);
        let relocations =
            RelocationsDiff::new(module_before.relocations(), module_after.relocations(), cmd);

        if name.is_equal() && delinks.is_none() && symbols.is_none() && relocations.is_none() {
            None
        } else {
            Some(Self { module: module_before.kind(), name, delinks, symbols, relocations })
        }
    }

    fn diff_actions(self) -> ModuleDiffActions {
        let module = self.module;
        ModuleDiffActions {
            delinks: self.delinks.map(|d| d.diff_actions(module)).unwrap_or_default(),
            symbols: self
                .symbols
                .into_iter()
                .flat_map(SymbolsDiff::diff_actions)
                .map(|action| ModuleDiffAction { module, action })
                .collect(),
            relocations: self
                .relocations
                .into_iter()
                .flat_map(RelocationsDiff::diff_actions)
                .map(|action| ModuleDiffAction { module, action })
                .collect(),
        }
    }
}

#[derive(Default)]
struct ModuleDiffActions {
    delinks: DelinksDiffActions,
    symbols: VecDeque<ModuleDiffAction>,
    relocations: Vec<ModuleDiffAction>,
}

#[derive(Serialize)]
struct NewRelocations {
    relocations: Vec<NewRelocation>,
}

impl From<&Relocations> for NewRelocations {
    fn from(relocations: &Relocations) -> Self {
        Self { relocations: relocations.iter().map(NewRelocation::from).collect() }
    }
}

#[derive(Serialize)]
struct RelocationsDiff {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    added: Vec<NewRelocation>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    removed: Vec<NewRelocation>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    diffs: BTreeMap<Hex<u32>, RelocationDiff>,
}

impl RelocationsDiff {
    fn new(before: &Relocations, after: &Relocations, cmd: &NewDiffCmd) -> Option<Self> {
        let mut removed = Vec::new();
        let mut diffs = BTreeMap::new();
        let mut equals = BTreeSet::new();
        for reloc_before in before.iter() {
            let from = reloc_before.from_address();
            let Some(reloc_after) = after.get(from) else {
                removed.push(NewRelocation::from(reloc_before));
                continue;
            };

            let Some(diff) = RelocationDiff::new(reloc_before, reloc_after, cmd) else {
                equals.insert(from);
                continue;
            };

            diffs.insert(Hex(from), diff);
        }

        let mut added = Vec::new();
        for reloc in after.iter() {
            let from = reloc.from_address();
            if !equals.contains(&from) && !diffs.contains_key(&Hex(from)) {
                added.push(NewRelocation::from(reloc));
            }
        }

        if added.is_empty() && removed.is_empty() && diffs.is_empty() {
            None
        } else {
            Some(Self { added, removed, diffs })
        }
    }

    fn diff_actions(self) -> impl Iterator<Item = DiffAction> {
        self.added
            .into_iter()
            .map(DiffAction::AddRelocation)
            .chain(self.removed.into_iter().map(DiffAction::DeleteRelocation))
            .chain(self.diffs.into_values().map(DiffAction::ChangeRelocation))
    }
}

impl From<&Relocation> for NewRelocation {
    fn from(relocation: &Relocation) -> Self {
        Self {
            from: Hex(relocation.from_address()),
            to: Hex(relocation.to_address()),
            addend: IHex(relocation.addend_value()),
            kind: relocation.kind(),
            module: relocation.module().clone(),
        }
    }
}

impl RelocationDiff {
    fn new(before: &Relocation, after: &Relocation, cmd: &NewDiffCmd) -> Option<Self> {
        assert_eq!(before.from_address(), after.from_address());

        let to = Diff::new(Hex(before.to_address()), Hex(after.to_address()));
        let addend = Diff::new(IHex(before.addend_value()), IHex(after.addend_value()));
        let kind = Diff::new(before.kind(), after.kind());
        let module = if cmd.skip_broadened_relocs && before.module().is_subset_of(after.module()) {
            Diff::Equal(before.module().clone())
        } else {
            Diff::new(before.module().clone(), after.module().clone())
        };
        if to.is_equal() && addend.is_equal() && kind.is_equal() && module.is_equal() {
            None
        } else {
            Some(Self { from: Hex(before.from_address()), to, addend, kind, module })
        }
    }
}

#[derive(Serialize)]
struct NewSymbols {
    symbols: Vec<NewSymbol>,
}

impl From<&SymbolMap> for NewSymbols {
    fn from(symbols: &SymbolMap) -> Self {
        Self { symbols: symbols.iter().filter_map(NewSymbol::new).collect() }
    }
}

#[derive(Serialize)]
struct SymbolsDiff {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    added: Vec<NewSymbol>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    removed: Vec<NewSymbol>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    diffs: BTreeMap<Hex<u32>, Vec<SymbolDiff>>,
}

impl SymbolsDiff {
    fn new(before: &SymbolMap, after: &SymbolMap, cmd: &NewDiffCmd) -> Option<Self> {
        let mut removed = Vec::new();
        let mut diffs: BTreeMap<Hex<u32>, Vec<SymbolDiff>> = BTreeMap::new();
        let mut equals = BTreeSet::new();
        for symbol_before in before.iter() {
            let Some(mut symbols_after) = after.for_address(symbol_before.addr) else {
                if let Some(deleted_symbol) = NewSymbol::delete(symbol_before, cmd) {
                    removed.push(deleted_symbol);
                }
                continue;
            };
            let symbol_after = match symbols_after.len() {
                0 => None,
                1 => Some(symbols_after.next().unwrap()),
                2.. => symbols_after.find(|(_, s)| s.name == symbol_before.name),
            };
            let Some((_, symbol_after)) = symbol_after else {
                if let Some(deleted_symbol) = NewSymbol::delete(symbol_before, cmd) {
                    removed.push(deleted_symbol);
                }
                continue;
            };

            let Some(diff) = SymbolDiff::new(symbol_before, symbol_after, cmd) else {
                equals.insert(symbol_before.addr);
                continue;
            };

            diffs.entry(Hex(symbol_before.addr)).or_default().push(diff);
        }

        let mut added = Vec::new();
        for symbol in after.iter() {
            if cmd.skip_ambiguous_symbols && symbol.ambiguous {
                continue;
            }

            if !equals.contains(&symbol.addr)
                && !diffs.contains_key(&Hex(symbol.addr))
                && let Some(new_symbol) = NewSymbol::new(symbol)
            {
                added.push(new_symbol);
            }
        }

        if added.is_empty() && removed.is_empty() && diffs.is_empty() {
            None
        } else {
            Some(Self { added, removed, diffs })
        }
    }

    fn diff_actions(self) -> impl Iterator<Item = DiffAction> {
        self.added
            .into_iter()
            .map(DiffAction::AddSymbol)
            .chain(self.removed.into_iter().map(DiffAction::DeleteSymbol))
            .chain(self.diffs.into_values().flatten().map(DiffAction::ChangeSymbol))
    }
}

impl NewSymbol {
    fn new(symbol: &Symbol) -> Option<NewSymbol> {
        if symbol.should_write() {
            Some(NewSymbol {
                name: symbol.name.clone(),
                kind: symbol.kind.clone(),
                addr: Hex(symbol.addr),
                ambiguous: symbol.ambiguous,
                scope: symbol.scope,
            })
        } else {
            None
        }
    }

    fn delete(symbol: &Symbol, cmd: &NewDiffCmd) -> Option<NewSymbol> {
        if cmd.skip_default_names && !has_default_symbol_name(symbol) {
            None
        } else {
            Self::new(symbol)
        }
    }
}

impl SymbolDiff {
    fn new(before: &Symbol, after: &Symbol, cmd: &NewDiffCmd) -> Option<Self> {
        assert_eq!(before.addr, after.addr);

        let name = if cmd.skip_default_names && has_default_symbol_name(after) {
            Diff::Equal(before.name.clone())
        } else {
            Diff::new(before.name.clone(), after.name.clone())
        };

        let skip_kind = match (&before.kind, &after.kind) {
            (SymbolKind::Data(_), SymbolKind::Data(data_after)) => {
                cmd.skip_sizeless_data && data_after.count().is_none()
            }
            (SymbolKind::Bss(_), SymbolKind::Bss(bss_after)) => {
                cmd.skip_sizeless_data && bss_after.size.is_none()
            }
            _ => false,
        };
        let kind = if skip_kind {
            Diff::Equal(before.kind.clone())
        } else {
            Diff::new(before.kind.clone(), after.kind.clone())
        };

        let ambiguous = if cmd.skip_ambiguous_symbols && after.ambiguous {
            Diff::Equal(before.ambiguous)
        } else {
            Diff::new(before.ambiguous, after.ambiguous)
        };
        let scope = if cmd.skip_globalized_symbols && after.scope.is_global() {
            Diff::Equal(before.scope)
        } else {
            Diff::new(before.scope, after.scope)
        };
        if name.is_equal() && kind.is_equal() && ambiguous.is_equal() && scope.is_equal() {
            None
        } else {
            Some(Self { name, kind, addr: Hex(before.addr), ambiguous, scope })
        }
    }
}

fn has_default_symbol_name(symbol: &Symbol) -> bool {
    let name = &symbol.name;
    name.starts_with("func_")
        || name.starts_with("data_")
        || name.starts_with("__sinit_")
        || name.starts_with(".p__sinit_")
}

#[derive(Serialize)]
struct NewDelinks {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    sections: Vec<NewSection>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    categories: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    files: Vec<NewDelinkFile>,
}

impl From<&Delinks> for NewDelinks {
    fn from(delinks: &Delinks) -> Self {
        Self {
            sections: delinks.sections.iter().map(NewSection::from).collect(),
            categories: delinks.global_categories.categories.clone(),
            files: delinks.files.iter().map(NewDelinkFile::from).collect(),
        }
    }
}

#[derive(Serialize)]
struct DelinksDiff {
    #[serde(skip_serializing_if = "Option::is_none")]
    sections: Option<SectionsDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    files: Option<DelinkFilesDiff>,
    #[serde(skip_serializing_if = "Option::is_none")]
    categories: Option<CategoriesDiff>,
}

impl DelinksDiff {
    fn new(before: &Delinks, after: &Delinks, cmd: &NewDiffCmd) -> Option<Self> {
        let sections = SectionsDiff::new(&before.sections, &after.sections);
        let files = if cmd.skip_files {
            None
        } else {
            DelinkFilesDiff::new(&before.files, &after.files)
        };
        let categories = CategoriesDiff::new(&before.global_categories, &after.global_categories);
        if sections.is_none() && files.is_none() && categories.is_none() {
            None
        } else {
            Some(Self { sections, files, categories })
        }
    }

    fn diff_actions(self, module: ModuleKind) -> DelinksDiffActions {
        DelinksDiffActions {
            sections: self
                .sections
                .into_iter()
                .map(DiffAction::ChangeSections)
                .map(|action| ModuleDiffAction { module, action })
                .collect(),
            categories: self
                .categories
                .into_iter()
                .flat_map(CategoriesDiff::module_diff_actions)
                .map(|action| ModuleDiffAction { module, action })
                .collect(),
            files: self
                .files
                .into_iter()
                .flat_map(DelinkFilesDiff::diff_actions)
                .map(|action| ModuleDiffAction { module, action })
                .collect(),
        }
    }
}

#[derive(Default)]
struct DelinksDiffActions {
    sections: Vec<ModuleDiffAction>,
    categories: Vec<ModuleDiffAction>,
    files: Vec<ModuleDiffAction>,
}

#[derive(Serialize)]
struct CategoriesDiff {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    added: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    removed: Vec<String>,
}

impl CategoriesDiff {
    fn new(before: &Categories, after: &Categories) -> Option<Self> {
        let mut added = Vec::new();
        let mut removed = Vec::new();

        for category in &before.categories {
            if !after.categories.contains(category) {
                removed.push(category.clone());
            }
        }
        for category in &after.categories {
            if !before.categories.contains(category) {
                added.push(category.clone());
            }
        }

        if added.is_empty() && removed.is_empty() {
            None
        } else {
            Some(Self { added, removed })
        }
    }

    fn module_diff_actions(self) -> impl Iterator<Item = DiffAction> {
        self.added
            .into_iter()
            .map(DiffAction::AddGlobalCategory)
            .chain(self.removed.into_iter().map(DiffAction::RemoveGlobalCategory))
    }

    fn delink_diff_actions(self, delink_name: String) -> Vec<DiffAction> {
        self.added
            .into_iter()
            .map(|category| DiffAction::AddDelinkCategory {
                delink_name: delink_name.clone(),
                category,
            })
            .chain(self.removed.into_iter().map(|category| DiffAction::RemoveDelinkCategory {
                delink_name: delink_name.clone(),
                category,
            }))
            .collect()
    }
}

#[derive(Serialize)]
struct DelinkFilesDiff {
    #[serde(skip_serializing_if = "Vec::is_empty")]
    added: Vec<NewDelinkFile>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    removed: Vec<NewDelinkFile>,
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    diffs: HashMap<String, DelinkFileDiff>,
}

impl DelinkFilesDiff {
    fn new(before: &[DelinkFile], after: &[DelinkFile]) -> Option<Self> {
        let mut removed = Vec::new();
        let mut diffs = HashMap::new();
        let mut equals = HashSet::new();
        for file_before in before.iter() {
            let Some(file_after) = after.iter().find(|f| f.name == file_before.name) else {
                removed.push(NewDelinkFile::from(file_before));
                continue;
            };
            let Some(diff) = DelinkFileDiff::new(file_before, file_after) else {
                equals.insert(file_before.name.clone());
                continue;
            };

            diffs.insert(file_before.name.clone(), diff);
        }

        let mut added = Vec::new();
        for file in after.iter() {
            let name = file.name.clone();
            if !equals.contains(&name) && !diffs.contains_key(&name) {
                added.push(NewDelinkFile::from(file));
            }
        }

        if added.is_empty() && removed.is_empty() && diffs.is_empty() {
            None
        } else {
            Some(Self { added, removed, diffs })
        }
    }

    fn diff_actions(self) -> impl Iterator<Item = DiffAction> {
        self.added
            .into_iter()
            .map(DiffAction::AddDelink)
            .chain(self.removed.into_iter().map(DiffAction::DeleteDelink))
            .chain(self.diffs.into_values().flat_map(DelinkFileDiff::diff_actions))
    }
}

impl From<&DelinkFile> for NewDelinkFile {
    fn from(file: &DelinkFile) -> Self {
        Self {
            name: file.name.clone(),
            sections: file.sections.iter().map(NewSection::from).collect(),
            complete: file.complete,
            categories: file.categories.clone(),
        }
    }
}

#[derive(Serialize)]
struct DelinkFileDiff {
    #[serde(skip)]
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    sections: Option<SectionsDiff>,
    complete: Diff<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    categories: Option<CategoriesDiff>,
}

impl DelinkFileDiff {
    fn new(before: &DelinkFile, after: &DelinkFile) -> Option<Self> {
        assert_eq!(before.name, after.name);

        let sections = SectionsDiff::new(&before.sections, &after.sections);
        let complete = Diff::new(before.complete, after.complete);
        let categories = CategoriesDiff::new(&before.categories, &after.categories);

        if sections.is_none() && complete.is_equal() && categories.is_none() {
            None
        } else {
            Some(Self { name: before.name.clone(), sections, complete, categories })
        }
    }

    fn diff_actions(self) -> Vec<DiffAction> {
        let mut actions = Vec::new();
        if let Some(sections) = self.sections {
            actions.push(DiffAction::ChangeDelinkSections {
                delink_name: self.name.clone(),
                sections,
            });
        }
        if let Diff::Diff { before, after } = self.complete {
            actions.push(DiffAction::ChangeDelinkComplete {
                delink_name: self.name.clone(),
                before,
                after,
            })
        }
        if let Some(categories) = self.categories {
            actions.extend(categories.delink_diff_actions(self.name.clone()));
        }
        actions
    }
}

impl SectionsDiff {
    fn new(before: &Sections, after: &Sections) -> Option<Self> {
        let mut removed = Vec::new();
        let mut diffs = HashMap::new();
        let mut equals = HashSet::new();
        for section_before in before.iter() {
            let section_name = section_before.name().to_string();
            let Some((_, section_after)) = after.by_name(&section_name) else {
                removed.push(NewSection::from(section_before));
                continue;
            };
            let Some(diff) = SectionDiff::new(section_before, section_after) else {
                equals.insert(section_name);
                continue;
            };

            diffs.insert(section_before.name().to_string(), diff);
        }

        let mut added = Vec::new();
        for section in after.iter() {
            let name = section.name().to_string();
            if !equals.contains(&name) && !diffs.contains_key(&name) {
                added.push(NewSection::from(section));
            }
        }

        if added.is_empty() && removed.is_empty() && diffs.is_empty() {
            None
        } else {
            Some(Self { added, removed, diffs })
        }
    }
}

impl From<&Section> for NewSection {
    fn from(section: &Section) -> Self {
        Self {
            name: section.name().to_string(),
            kind: section.kind(),
            start_address: Hex(section.start_address()),
            end_address: Hex(section.end_address()),
            alignment: section.alignment(),
        }
    }
}

impl SectionDiff {
    fn new(before: &Section, after: &Section) -> Option<Self> {
        let name = Diff::new(before.name().to_string(), after.name().to_string());
        let kind = Diff::new(before.kind(), after.kind());
        let start_address = Diff::new(Hex(before.start_address()), Hex(after.start_address()));
        let end_address = Diff::new(Hex(before.end_address()), Hex(after.end_address()));
        let alignment = Diff::new(before.alignment(), after.alignment());

        if name.is_equal()
            && kind.is_equal()
            && start_address.is_equal()
            && end_address.is_equal()
            && alignment.is_equal()
        {
            None
        } else {
            Some(SectionDiff { name, kind, start_address, end_address, alignment })
        }
    }
}
