use std::{
    fmt::Display,
    io::BufWriter,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use clap::Args;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use ds_decomp::config::{
    config::Config,
    delinks::{DelinkFile, DelinkFileOptions, Delinks},
    module::ModuleKind,
    relocations::{Relocation, RelocationOptions, Relocations},
    section::{Section, SectionOptions, Sections},
    symbol::{Symbol, SymbolId, SymbolMap, SymbolMaps},
};
use ratatui::{
    DefaultTerminal, Frame,
    layout::{Constraint, Layout, Spacing},
    style::{Color, Style, Stylize},
    symbols::merge::MergeStrategy,
    text::{Line, Span, Text},
    widgets::{Block, List, ListState, Paragraph, Wrap},
};
use similar::{ChangeTag, TextDiff};

use crate::{
    cmd::{
        DiffAction, DsdDiff, ModuleDiffAction, NewDelinkFile, NewRelocation, NewSection, NewSymbol,
        RelocationDiff, SectionDiff, SymbolDiff,
    },
    config::{
        delinks::{DelinksMap, DelinksMapOptions},
        relocation::RelocationsMap,
    },
    util::io,
};

/// Opens an interactive TUI for applying or rejecting diff actions.
#[derive(Args)]
pub struct ApplyDiffCmd {
    /// Path to diff file created by `dsd diff new`, defaults to dsd_diff.yaml.
    #[arg(long, short = 'i')]
    input_path: Option<PathBuf>,

    /// Skips the interactive TUI and applies all actions.
    #[arg(long)]
    all: bool,
}

const LOG_FILE_NAME: &str = "dsd_diff.log";

impl ApplyDiffCmd {
    pub fn run(&self) -> Result<()> {
        let input_path = self.get_input_path();
        let input_dir = input_path.parent().unwrap();

        let diff = DsdDiff::from_file(&input_path)?;

        let config_file_path = input_dir.join(&diff.config_before);
        let config_path = config_file_path.parent().unwrap();
        let config = Config::from_file(&config_file_path)?;

        if self.all {
            log::info!("Applying {} diff actions", diff.actions.len());
            apply_actions(diff.actions.iter(), &config, config_path)?;
            return Ok(());
        }

        let mut tui =
            ApplyTui::new(diff, input_path.to_path_buf(), config, config_path.to_path_buf());
        ratatui::run(|terminal| tui.run(terminal))?;

        Ok(())
    }

    pub(crate) fn configure_logger(&self, builder: &mut env_logger::Builder) -> Result<()> {
        if self.all {
            return Ok(());
        }

        // Log to file instead of stderr
        let input_path = self.get_input_path();
        let input_dir = input_path.parent().unwrap();
        let log_file = io::append_file(input_dir.join(LOG_FILE_NAME))?;
        builder.target(env_logger::Target::Pipe(Box::new(BufWriter::new(log_file))));

        // Disable colors
        builder.write_style(env_logger::WriteStyle::Never);

        // More log details
        builder.format_timestamp(Some(env_logger::TimestampPrecision::Micros));
        builder.format_target(true);

        Ok(())
    }

    fn get_input_path(&self) -> PathBuf {
        self.input_path.clone().unwrap_or(PathBuf::from(super::new::DEFAULT_OUT_FILE_NAME))
    }
}

struct ApplyTui {
    diff: DsdDiff,
    diff_path: PathBuf,
    approvals: Vec<ActionApproval>,
    config: Config,
    config_path: PathBuf,
    action_list_state: ListState,
    description_scroll_y: u16,
    exit: bool,
    state: TuiState,
}

#[derive(Default)]
enum TuiState {
    #[default]
    Normal,
    ConfirmQuit {
        confirmed: bool,
    },
    ConfirmApply {
        confirmed: bool,
    },
    Error,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ActionApproval {
    Skip,
    Good,
    Bad,
}

impl ActionApproval {
    fn color(self) -> Color {
        match self {
            ActionApproval::Skip => Color::White,
            ActionApproval::Good => Color::LightGreen,
            ActionApproval::Bad => Color::LightRed,
        }
    }
}

impl ApplyTui {
    fn new(diff: DsdDiff, diff_path: PathBuf, config: Config, config_path: PathBuf) -> Self {
        Self {
            approvals: vec![ActionApproval::Skip; diff.actions.len()],
            diff,
            diff_path,
            config,
            config_path,
            action_list_state: ListState::default(),
            description_scroll_y: 0,
            exit: false,
            state: TuiState::default(),
        }
    }

    fn run(&mut self, terminal: &mut DefaultTerminal) -> std::io::Result<()> {
        self.action_list_state.select_first();
        while !self.exit {
            terminal.draw(|frame| self.draw(frame).unwrap())?;
            self.handle_events()?;
        }
        Ok(())
    }

    fn selected_pos(&self) -> usize {
        self.action_list_state.selected().unwrap_or(0).min(self.diff.actions.len() - 1)
    }

    fn draw(&mut self, frame: &mut Frame) -> Result<()> {
        let area = frame.area();

        let [top, bottom] =
            Layout::vertical([Constraint::Fill(1), Constraint::Length(1)]).areas(area);
        let [left, right] = Layout::horizontal([Constraint::Max(40), Constraint::Fill(1)])
            .spacing(Spacing::Overlap(1))
            .areas(top);

        let action_pos = self.selected_pos();
        let action_list_block = Block::bordered()
            .title(format!("Diff actions ({}/{})", action_pos, self.diff.actions.len()))
            .merge_borders(MergeStrategy::Exact);
        let list = List::new(self.actions().map(|(action, approval)| {
            Line::from(vec![action.action.short_line().fg(approval.color())])
        }))
        .block(action_list_block)
        .highlight_style(Style::new().bg(self.approvals[action_pos].color()));
        frame.render_stateful_widget(list, left, &mut self.action_list_state);

        let selected_action = &self.diff.actions[action_pos];

        let description_block =
            Block::bordered().title("Description").merge_borders(MergeStrategy::Exact);
        let description = Paragraph::new(selected_action.description_text()?)
            .block(description_block)
            .wrap(Wrap { trim: true })
            .scroll((self.description_scroll_y, 0));
        frame.render_widget(description, right);

        let bottom_line = match self.state {
            TuiState::Normal => Line::from(vec![
                " q ".bg(Color::White).bold(),
                " Quit  ".into(),
                " ↓ ".bg(Color::White).bold(),
                " Next  ".into(),
                " ↑ ".bg(Color::White).bold(),
                " Prev  ".into(),
                " 1 ".bg(Color::White).bold(),
                " Good  ".into(),
                " 2 ".bg(Color::White).bold(),
                " Bad  ".into(),
                " 3 ".bg(Color::White).bold(),
                " Skip  ".into(),
                " ↵ ".bg(Color::White).bold(),
                " Apply  ".into(),
                " j ".bg(Color::White).bold(),
                " Scroll down  ".into(),
                " k ".bg(Color::White).bold(),
                " Scroll up  ".into(),
            ]),
            TuiState::ConfirmQuit { confirmed } => Line::from(vec![
                format!(
                    "Are you sure? {} good/bad markings will be lost.  ",
                    self.approvals.iter().filter(|&&a| a != ActionApproval::Skip).count(),
                )
                .into(),
                " y ".bg(if confirmed { Color::LightBlue } else { Color::White }).bold(),
                " Yes  ".fg(if confirmed { Color::LightBlue } else { Color::White }),
                " n ".bg(if !confirmed { Color::LightBlue } else { Color::White }).bold(),
                " No  ".fg(if !confirmed { Color::LightBlue } else { Color::White }),
                " ↵ ".bg(Color::White).bold(),
                if confirmed { " Quit  ".into() } else { " Go back  ".into() },
            ]),
            TuiState::ConfirmApply { confirmed } => Line::from(vec![
                format!(
                    "Are you sure? ({} actions to apply, {} to discard)  ",
                    self.approvals.iter().filter(|&&a| a == ActionApproval::Good).count(),
                    self.approvals.iter().filter(|&&a| a == ActionApproval::Bad).count(),
                )
                .into(),
                " y ".bg(if confirmed { Color::LightBlue } else { Color::White }).bold(),
                " Yes  ".fg(if confirmed { Color::LightBlue } else { Color::White }),
                " n ".bg(if !confirmed { Color::LightBlue } else { Color::White }).bold(),
                " No  ".fg(if !confirmed { Color::LightBlue } else { Color::White }),
                " ↵ ".bg(Color::White).bold(),
                if confirmed { " Apply  ".into() } else { " Go back  ".into() },
            ]),
            TuiState::Error => Line::from(vec![
                format!("Error occurred while applying, see {LOG_FILE_NAME}  ").red(),
                " ↵ ".bg(Color::White).bold(),
                " OK  ".into(),
            ]),
        };
        let bottom_block = Block::new().title(bottom_line);
        frame.render_widget(bottom_block, bottom);

        Ok(())
    }

    fn actions(&self) -> impl Iterator<Item = (&ModuleDiffAction, ActionApproval)> {
        self.diff.actions.iter().zip(self.approvals.iter().copied())
    }

    fn handle_events(&mut self) -> std::io::Result<()> {
        #[allow(clippy::single_match)]
        match event::read()? {
            Event::Key(key_event) => match key_event.kind {
                KeyEventKind::Press => self.handle_key_press(key_event),
                _ => {}
            },
            _ => {}
        };
        Ok(())
    }

    fn handle_key_press(&mut self, key_event: KeyEvent) {
        let ctrl = key_event.modifiers.contains(KeyModifiers::CONTROL);
        let speed = if ctrl { 10 } else { 1 };

        #[allow(clippy::single_match)]
        match &mut self.state {
            TuiState::Normal => match key_event.code {
                KeyCode::Char('q') => {
                    if self.approvals.iter().any(|&a| a != ActionApproval::Skip) {
                        self.state = TuiState::ConfirmQuit { confirmed: false };
                    } else {
                        self.quit();
                    }
                }
                KeyCode::Char('c') if ctrl => {
                    self.quit();
                }
                KeyCode::Down => {
                    self.action_list_state.scroll_down_by(speed);
                    self.description_scroll_y = 0;
                }
                KeyCode::Up => {
                    self.action_list_state.scroll_up_by(speed);
                    self.description_scroll_y = 0;
                }
                KeyCode::Home => {
                    self.action_list_state.select_first();
                    self.description_scroll_y = 0;
                }
                KeyCode::End => {
                    self.action_list_state.select_last();
                    self.description_scroll_y = 0;
                }
                KeyCode::Char('j') => {
                    self.description_scroll_y = self.description_scroll_y.saturating_add(1)
                }
                KeyCode::Char('k') => {
                    self.description_scroll_y = self.description_scroll_y.saturating_sub(1)
                }
                KeyCode::Char('1') => {
                    let pos = self.selected_pos();
                    self.approvals[pos] = ActionApproval::Good;
                }
                KeyCode::Char('2') => {
                    let pos = self.selected_pos();
                    self.approvals[pos] = ActionApproval::Bad;
                }
                KeyCode::Char('3') => {
                    let pos = self.selected_pos();
                    self.approvals[pos] = ActionApproval::Skip;
                }
                KeyCode::Enter if self.approvals.iter().any(|&a| a != ActionApproval::Skip) => {
                    self.state = TuiState::ConfirmApply { confirmed: false };
                }
                _ => {}
            },
            TuiState::ConfirmQuit { confirmed } => match key_event.code {
                KeyCode::Char('y') | KeyCode::Left => *confirmed = true,
                KeyCode::Char('n') | KeyCode::Right => *confirmed = false,
                KeyCode::Enter => {
                    if *confirmed {
                        self.quit();
                    } else {
                        self.state = TuiState::Normal;
                    }
                }
                _ => {}
            },
            TuiState::ConfirmApply { confirmed } => match key_event.code {
                KeyCode::Char('y') | KeyCode::Left => *confirmed = true,
                KeyCode::Char('n') | KeyCode::Right => *confirmed = false,
                KeyCode::Enter => {
                    if *confirmed {
                        let actions_to_apply = self
                            .diff
                            .actions
                            .iter()
                            .enumerate()
                            .filter(|(i, _)| self.approvals[*i] == ActionApproval::Good)
                            .map(|(_, a)| a);
                        match apply_actions(actions_to_apply, &self.config, &self.config_path) {
                            Ok(()) => {
                                // Remove actions from diff and save
                                for i in (0..self.diff.actions.len()).rev() {
                                    if self.approvals[i] != ActionApproval::Skip {
                                        self.approvals.remove(i);
                                        self.diff.actions.remove(i);
                                    }
                                }
                                if let Err(e) = self.diff.to_file(&self.diff_path) {
                                    log::error!("{e}");
                                    self.state = TuiState::Error;
                                }

                                self.action_list_state.select_first();
                                if self.diff.actions.is_empty() {
                                    self.quit();
                                } else {
                                    self.state = TuiState::Normal;
                                }
                            }
                            Err(e) => {
                                log::error!("{e}");
                                self.state = TuiState::Error;
                            }
                        }
                    } else {
                        self.state = TuiState::Normal;
                    }
                }
                _ => {}
            },
            TuiState::Error => match key_event.code {
                KeyCode::Enter => {
                    self.state = TuiState::Normal;
                }
                _ => {}
            },
        }
    }

    fn quit(&mut self) {
        self.exit = true;
    }
}

fn apply_actions<'a>(
    actions: impl Iterator<Item = &'a ModuleDiffAction>,
    config: &Config,
    config_path: &Path,
) -> Result<()> {
    let mut delinks_map = DelinksMap::from_config(config, config_path, DelinksMapOptions {
        migrate_sections: false,
        generate_gap_files: false,
    })?;
    let mut symbol_maps = SymbolMaps::from_config(config_path, config)?;
    let mut relocations_map = RelocationsMap::from_config(config, config_path)?;

    fn get_delinks(delinks_map: &mut DelinksMap, module: ModuleKind) -> Result<&mut Delinks> {
        delinks_map.get_mut(module).with_context(|| format!("Failed to get delinks for {}", module))
    }

    fn get_symbol_id(
        symbol_map: &mut SymbolMap,
        name: &str,
        addr: u32,
        module: ModuleKind,
    ) -> Result<SymbolId> {
        Ok(symbol_map
                .for_name(name).with_context(|| {
                    format!("Could not find symbol '{}' in {}", name, module)
                })?
                .find(|(_, s)| s.name == name)
                .with_context(|| format!(
                    "Could not delete symbol '{}' in {} because it is on the wrong address, expected {:#010x}",
                    name, module, addr
                ))?.0)
    }

    fn get_relocations(
        relocations_map: &mut RelocationsMap,
        module: ModuleKind,
    ) -> Result<&mut Relocations> {
        relocations_map
            .get_mut(module)
            .with_context(|| format!("Failed to get relocations for {}", module))
    }

    fn apply_action(
        action: &ModuleDiffAction,
        delinks_map: &mut DelinksMap,
        symbol_maps: &mut SymbolMaps,
        relocations_map: &mut RelocationsMap,
    ) -> Result<()> {
        let module = action.module;

        match &action.action {
            DiffAction::ChangeSections(sections) => {
                let delinks = get_delinks(delinks_map, module)?;
                for section in &sections.removed {
                    delinks.sections.remove(&section.name).with_context(|| {
                        format!(
                            "Could not remove section {} in {} because the section does not exist",
                            section.name, module
                        )
                    })?;
                    log::info!("Removed section {} from {}", section.name, module);
                }
                for section in sections.diffs.values() {
                    delinks.sections.remove(section.name.before()).with_context(|| {
                        format!(
                            "Could not change section {} in {} because the section does not exist",
                            section.name.before(),
                            module
                        )
                    })?;
                    delinks.sections.add(section.as_section_after()?)?;
                    log::info!("Changed section {} in {}", section.name.after(), module);
                }
                for section in &sections.added {
                    delinks.sections.add(section.as_section()?)?;
                    log::info!("Added section {} to {}", section.name, module);
                }
            }
            DiffAction::AddGlobalCategory(category) => {
                let delinks = get_delinks(delinks_map, module)?;
                delinks.global_categories.add(category.clone());
                log::info!("Added progress category {} to {}", category, module);
            }
            DiffAction::RemoveGlobalCategory(category) => {
                let delinks = get_delinks(delinks_map, module)?;
                delinks.global_categories.remove(category);
                log::info!("Removed progress category {} from {}", category, module);
            }
            DiffAction::AddDelink(delink_file) => {
                let delinks = get_delinks(delinks_map, module)?;
                delinks.files.push(delink_file.as_delink_file()?);
                log::info!("Added delink file '{}' to {}", delink_file.name, module);
            }
            DiffAction::DeleteDelink(delink_file) => {
                let delinks = get_delinks(delinks_map, module)?;
                let pos = delinks.files.iter().position(|d| d.name == delink_file.name)
                .with_context(|| format!("Failed to delete delink file '{}' in {} because it was not found in delinks.txt", delink_file.name, module))?;
                delinks.files.remove(pos);
                log::info!("Removed delink file '{}' from {}", delink_file.name, module);
            }
            DiffAction::ChangeDelinkSections { delink_name, sections } => {
                let delinks = get_delinks(delinks_map, module)?;
                let delink =
                    delinks.files.iter_mut().find(|d| d.name == *delink_name).with_context(
                        || format!("Failed to get delink file '{}' in {}", delink_name, module),
                    )?;
                for section in &sections.removed {
                    delink.sections.remove(&section.name).with_context(|| format!(
                        "Could not remove section {} in delink '{}' from {} because the section does not exist",
                        section.name, delink_name, module
                    ))?;
                }
                for section in sections.diffs.values() {
                    delink.sections.remove(section.name.before()).with_context(|| format!(
                        "Could not change section {} in delink '{}' from {} because the section does not exist",
                        section.name.before(), delink_name, module
                    ))?;
                    delink.sections.add(section.as_section_after()?)?;
                    log::info!(
                        "Changed section {} in delink file '{}' in {}",
                        section.name.after(),
                        delink_name,
                        module
                    );
                }
                for section in &sections.added {
                    delink.sections.add(section.as_section()?)?;
                    log::info!(
                        "Added section {} to delink file '{}' in {}",
                        section.name,
                        delink_name,
                        module
                    );
                }
            }
            DiffAction::ChangeDelinkComplete { delink_name, before: _, after } => {
                let delinks = get_delinks(delinks_map, module)?;
                let delink =
                    delinks.files.iter_mut().find(|d| d.name == *delink_name).with_context(
                        || format!("Failed to get delink file '{}' in {}", delink_name, module),
                    )?;
                delink.complete = *after;
                log::info!(
                    "Marked delink file '{}' in {} as {}",
                    delink_name,
                    module,
                    if *after { "complete" } else { "incomplete" }
                );
            }
            DiffAction::AddDelinkCategory { delink_name, category } => {
                let delinks = get_delinks(delinks_map, module)?;
                let delink =
                    delinks.files.iter_mut().find(|d| d.name == *delink_name).with_context(
                        || format!("Failed to get delink file '{}' in {}", delink_name, module),
                    )?;
                delink.categories.add(category.clone());
                log::info!(
                    "Added progress category {} to delink file '{}' in {}",
                    category,
                    delink_name,
                    module
                );
            }
            DiffAction::RemoveDelinkCategory { delink_name, category } => {
                let delinks = get_delinks(delinks_map, module)?;
                let delink =
                    delinks.files.iter_mut().find(|d| d.name == *delink_name).with_context(
                        || format!("Failed to get delink file '{}' in {}", delink_name, module),
                    )?;
                delink.categories.remove(category);
                log::info!(
                    "Removed progress category {} from delink file '{}' in {}",
                    category,
                    delink_name,
                    module
                );
            }
            DiffAction::AddSymbol(symbol) => {
                let symbol_map = symbol_maps.get_mut(module);
                symbol_map.add(symbol.as_symbol());
                log::info!("Added symbol {} at {:#010x} to {}", symbol.name, symbol.addr.0, module);
            }
            DiffAction::DeleteSymbol(symbol) => {
                let symbol_map = symbol_maps.get_mut(module);
                let id = get_symbol_id(symbol_map, &symbol.name, symbol.addr.0, module)?;
                symbol_map.remove(id).with_context(|| {
                    format!("Failed to delete symbol '{}' in {}", symbol.name, module)
                })?;
                log::info!(
                    "Removed symbol {} at {:#010x} from {}",
                    symbol.name,
                    symbol.addr.0,
                    module
                );
            }
            DiffAction::ChangeSymbol(symbol) => {
                let symbol_map = symbol_maps.get_mut(module);
                let id = get_symbol_id(symbol_map, symbol.name.before(), symbol.addr.0, module)?;
                symbol_map.remove(id).with_context(|| {
                    format!("Failed to change symbol '{}' in {}", symbol.name.before(), module)
                })?;
                symbol_map.add(symbol.as_symbol_after());
                log::info!(
                    "Changed symbol {} at {:#010x} in {}",
                    symbol.name.after(),
                    symbol.addr.0,
                    module
                );
            }
            DiffAction::AddRelocation(relocation) => {
                let relocations = get_relocations(relocations_map, module)?;
                relocations.add(relocation.as_relocation())?;
                log::info!(
                    "Added relocation from {:#010x} to {:#010x}{} in {}",
                    relocation.from.0,
                    relocation.to.0,
                    addend_to_string(relocation.addend.0),
                    module
                );
            }
            DiffAction::DeleteRelocation(relocation) => {
                let relocations = get_relocations(relocations_map, module)?;
                relocations.remove(relocation.from.0).with_context(|| {
                    format!(
                        "Failed to delete relocation from {:#010x} in {}",
                        relocation.from.0, module
                    )
                })?;
                log::info!(
                    "Removed relocation from {:#010x} to {:#010x}{} in {}",
                    relocation.from.0,
                    relocation.to.0,
                    addend_to_string(relocation.addend.0),
                    module
                );
            }
            DiffAction::ChangeRelocation(relocation) => {
                let relocations = get_relocations(relocations_map, module)?;
                relocations.remove(relocation.from.0).with_context(|| {
                    format!(
                        "Failed to change relocation from {:#010x} in {}",
                        relocation.from.0, module
                    )
                })?;
                relocations.add(relocation.as_relocation_after())?;
                log::info!(
                    "Changed relocation from {:#010x} to {:#010x}{} in {}",
                    relocation.from.0,
                    relocation.to.after().0,
                    addend_to_string(relocation.addend.after().0),
                    module
                );
            }
            DiffAction::Group(actions) => {
                log::info!("Applying {} related actions...", actions.len());
                for action in actions {
                    apply_action(action, delinks_map, symbol_maps, relocations_map)?;
                }
            }
        };
        Ok(())
    }

    for action in actions {
        apply_action(action, &mut delinks_map, &mut symbol_maps, &mut relocations_map)?;
    }

    delinks_map.to_files(config, config_path)?;
    symbol_maps.to_files(config, config_path)?;
    relocations_map.to_files(config, config_path)?;

    Ok(())
}

impl ModuleDiffAction {
    fn description_text(&self) -> Result<Text<'_>> {
        Ok(Text::from(self.action.description_lines(self.module)?))
    }
}

impl DiffAction {
    fn short_line(&self) -> String {
        match self {
            DiffAction::ChangeSections(sections) => {
                let num_changes =
                    sections.added.len() + sections.removed.len() + sections.diffs.len();
                format!("CHANGE {} SECTIONS", num_changes)
            }
            DiffAction::AddGlobalCategory(category) => format!("ADD CATEGORY {}", category),
            DiffAction::RemoveGlobalCategory(category) => format!("REMOVE CATEGORY {}", category),

            DiffAction::AddDelink(delink_file) => {
                format!("ADD DELINK {}", delink_file.name)
            }
            DiffAction::DeleteDelink(delink_file) => format!("DELETE DELINK {}", delink_file.name),
            DiffAction::ChangeDelinkSections { delink_name, sections } => {
                let num_changes =
                    sections.added.len() + sections.removed.len() + sections.diffs.len();
                format!("CHANGE {} SECTIONS in {}", num_changes, delink_name)
            }
            DiffAction::ChangeDelinkComplete { delink_name, before: _, after } => {
                format!("{} {}", if *after { "COMPLETE" } else { "UNCOMPLETE" }, delink_name)
            }
            DiffAction::AddDelinkCategory { delink_name: _, category } => {
                format!("ADD DELINK CATEGORY {}", category)
            }
            DiffAction::RemoveDelinkCategory { delink_name: _, category } => {
                format!("REMOVE DELINK CATEGORY {}", category)
            }

            DiffAction::AddSymbol(new_symbol) => format!("ADD {}", new_symbol.name),
            DiffAction::DeleteSymbol(deleted_symbol) => format!("DELETE {}", deleted_symbol.name),
            DiffAction::ChangeSymbol(symbol_diff) => {
                format!("CHANGE {}", symbol_diff.name.before())
            }

            DiffAction::AddRelocation(new_relocation) => {
                format!("ADD RELOC {:#010x}", new_relocation.from.0)
            }
            DiffAction::DeleteRelocation(deleted_relocation) => {
                format!("DELETE RELOC {:#010x}", deleted_relocation.from.0)
            }
            DiffAction::ChangeRelocation(relocation_diff) => {
                format!("CHANGE RELOC {:#010x}", relocation_diff.from.0)
            }

            DiffAction::Group(module_diff_actions) => {
                let first = &module_diff_actions[0];
                format!("{} (+{})", first.action.short_line(), module_diff_actions.len() - 1)
            }
        }
    }

    fn description_lines(&self, module: ModuleKind) -> Result<Vec<Line<'_>>> {
        let lines = match self {
            DiffAction::ChangeSections(sections) => {
                let mut lines = vec![format!("In {module}, update sections:").into()];
                if !sections.removed.is_empty() {
                    lines.push("".into());
                    lines.push(format!("Remove {} sections:", sections.removed.len()).into());
                    for section in &sections.removed {
                        lines.push(diff_line_remove(section.as_section()?));
                    }
                }
                if !sections.diffs.is_empty() {
                    lines.push("".into());
                    lines.push(format!("Change {} sections:", sections.diffs.len()).into());
                    let diff_lines = sections
                        .diffs
                        .values()
                        .map(|s| {
                            Ok(diff_line_compare(s.as_section_before()?, s.as_section_after()?))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    lines.extend(diff_lines.iter().map(|[before, _]| before.clone()));
                    lines.extend(diff_lines.iter().map(|[_, after]| after.clone()));
                }
                if !sections.added.is_empty() {
                    lines.push("".into());
                    lines.push(format!("Add {} sections:", sections.added.len()).into());
                    for section in &sections.added {
                        lines.push(diff_line_add(section.as_section()?));
                    }
                }
                lines
            }
            DiffAction::AddGlobalCategory(category) => {
                vec![format!("In {module}, add a progress category: {}", category).into()]
            }
            DiffAction::RemoveGlobalCategory(category) => {
                vec![format!("In {module}, remove a progress category: {}", category).into()]
            }

            DiffAction::AddDelink(delink_file) => vec![
                format!("In {module}, add a delink file called {}", delink_file.name).into(),
                diff_line_add(delink_file.as_delink_file()?),
            ],
            DiffAction::DeleteDelink(delink_file) => vec![
                format!("In {module}, remove the delink file {}", delink_file.name).into(),
                diff_line_remove(delink_file.as_delink_file()?),
            ],
            DiffAction::ChangeDelinkSections { delink_name, sections } => {
                let mut lines = vec![
                    format!("In {module}, update sections in delink file {delink_name}:").into(),
                ];
                if !sections.removed.is_empty() {
                    lines.push("".into());
                    lines.push(format!("Remove {} sections:", sections.removed.len()).into());
                    for section in &sections.removed {
                        lines.push(diff_line_remove(section.as_section()?.display_inherited()));
                    }
                }
                if !sections.diffs.is_empty() {
                    lines.push("".into());
                    lines.push(format!("Change {} sections:", sections.diffs.len()).into());
                    let diff_lines = sections
                        .diffs
                        .values()
                        .map(|s| {
                            Ok(diff_line_compare(
                                s.as_section_before()?.display_inherited(),
                                s.as_section_after()?.display_inherited(),
                            ))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    lines.extend(diff_lines.iter().map(|[before, _]| before.clone()));
                    lines.extend(diff_lines.iter().map(|[_, after]| after.clone()));
                }
                if !sections.added.is_empty() {
                    lines.push("".into());
                    lines.push(format!("Add {} sections:", sections.added.len()).into());
                    for section in &sections.added {
                        lines.push(diff_line_add(section.as_section()?.display_inherited()));
                    }
                }
                lines
            }
            DiffAction::ChangeDelinkComplete { delink_name, before: _, after } => vec![
                format!(
                    "In {module}, mark the delink file {} as {}",
                    delink_name,
                    if *after { "complete" } else { "incomplete" }
                )
                .into(),
            ],
            DiffAction::AddDelinkCategory { delink_name, category } => {
                vec![
                    format!(
                        "In {module}, add the progress category '{}' to delink file {}",
                        category, delink_name
                    )
                    .into(),
                ]
            }
            DiffAction::RemoveDelinkCategory { delink_name, category } => vec![
                format!(
                    "In {module}, remove the progress category '{}' from delink file {}",
                    category, delink_name
                )
                .into(),
            ],

            DiffAction::AddSymbol(symbol) => vec![
                format!(
                    "In {module}, add a symbol called {} at {:#010x}",
                    symbol.name, symbol.addr.0
                )
                .into(),
                diff_line_add(symbol.as_symbol()),
            ],
            DiffAction::DeleteSymbol(symbol) => vec![
                format!(
                    "In {module}, delete the symbol {} at {:#010x}",
                    symbol.name, symbol.addr.0
                )
                .into(),
                diff_line_remove(symbol.as_symbol()),
            ],
            DiffAction::ChangeSymbol(symbol) => {
                let [before, after] =
                    diff_line_compare(symbol.as_symbol_before(), symbol.as_symbol_after());
                vec![
                    format!(
                        "In {module}, change the symbol {} at {:#010x}",
                        symbol.name.before(),
                        symbol.addr.0
                    )
                    .into(),
                    before,
                    after,
                ]
            }

            DiffAction::AddRelocation(relocation) => vec![
                format!(
                    "In {module}, add a relocation from {:#010x} to {:#010x}{}",
                    relocation.from.0,
                    relocation.to.0,
                    addend_to_string(relocation.addend.0),
                )
                .into(),
                diff_line_add(relocation.as_relocation()),
            ],
            DiffAction::DeleteRelocation(relocation) => vec![
                format!(
                    "In {module}, delete the relocation from {:#010x} to {:#010x}{}",
                    relocation.from.0,
                    relocation.to.0,
                    addend_to_string(relocation.addend.0),
                )
                .into(),
                diff_line_remove(relocation.as_relocation()),
            ],
            DiffAction::ChangeRelocation(relocation) => {
                let [before, after] = diff_line_compare(
                    relocation.as_relocation_before(),
                    relocation.as_relocation_after(),
                );
                vec![
                    format!(
                        "In {module}, change the relocation from {:#010x} to {:#010x}{}",
                        relocation.from.0,
                        relocation.to.before().0,
                        addend_to_string(relocation.addend.before().0),
                    )
                    .into(),
                    before,
                    after,
                ]
            }

            DiffAction::Group(actions) => {
                let mut lines = vec![
                    format!("Performs {} related actions together:", actions.len()).into(),
                    "".into(),
                ];
                for action in actions.iter() {
                    lines.extend(action.action.description_lines(action.module)?);
                    lines.push("".into());
                }
                lines
            }
        };

        Ok(lines)
    }
}

fn addend_to_string(addend: i64) -> String {
    match addend {
        0 => String::new(),
        ..0 => format!(" - {:#x}", -addend),
        1.. => format!(" + {:#x}", addend),
    }
}

const EQUAL_REMOVE_FG: Color = Color::Rgb(0xf1, 0x4d, 0x4d);
const DIFF_REMOVE_FG: Color = Color::Rgb(0xff, 0x96, 0x95);
const DIFF_REMOVE_BG: Color = Color::Rgb(0x77, 0x00, 0x0b);

const EQUAL_ADD_FG: Color = Color::Rgb(0x28, 0xd0, 0x8a);
const DIFF_ADD_FG: Color = Color::Rgb(0xbc, 0xf4, 0xdd);
const DIFF_ADD_BG: Color = Color::Rgb(0x00, 0x78, 0x41);

fn diff_line_remove<'a, T: Display>(value: T) -> Line<'a> {
    format!("- {}", value).fg(EQUAL_REMOVE_FG).into()
}

fn diff_line_add<'a, T: Display>(value: T) -> Line<'a> {
    format!("+ {}", value).fg(EQUAL_ADD_FG).into()
}

fn diff_line_compare<'a, T: Display>(before: T, after: T) -> [Line<'a>; 2] {
    let text_before = format!("{before}");
    let text_after = format!("{after}");
    let diff = TextDiff::from_chars(text_before, text_after);

    let mut remove_spans = vec!["- ".fg(EQUAL_REMOVE_FG)];
    remove_spans.extend(diff.iter_all_changes().filter_map(|change| {
        let text = Span::from(change.value().to_string());
        match change.tag() {
            ChangeTag::Equal => Some(text.fg(EQUAL_REMOVE_FG)),
            ChangeTag::Delete => Some(text.fg(DIFF_REMOVE_FG).bg(DIFF_REMOVE_BG)),
            ChangeTag::Insert => None,
        }
    }));
    let remove_line = Line::from(remove_spans);

    let mut add_spans = vec!["+ ".fg(EQUAL_ADD_FG)];
    add_spans.extend(diff.iter_all_changes().filter_map(|change| {
        let text = Span::from(change.value().to_string()).fg(Color::LightGreen);
        match change.tag() {
            ChangeTag::Equal => Some(text.fg(EQUAL_ADD_FG)),
            ChangeTag::Delete => None,
            ChangeTag::Insert => Some(text.fg(DIFF_ADD_FG).bg(DIFF_ADD_BG)),
        }
    }));
    let add_line = Line::from(add_spans);

    [remove_line, add_line]
}

impl NewSection {
    fn as_section(&self) -> Result<Section> {
        Ok(Section::new(SectionOptions {
            name: self.name.clone(),
            kind: self.kind,
            start_address: self.start_address.0,
            end_address: self.end_address.0,
            alignment: self.alignment,
            functions: None,
            comments: Default::default(),
        })?)
    }
}

impl SectionDiff {
    fn as_section_before(&self) -> Result<Section> {
        Ok(Section::new(SectionOptions {
            name: self.name.before().clone(),
            kind: *self.kind.before(),
            start_address: self.start_address.before().0,
            end_address: self.end_address.before().0,
            alignment: *self.alignment.before(),
            functions: None,
            comments: Default::default(),
        })?)
    }

    fn as_section_after(&self) -> Result<Section> {
        Ok(Section::new(SectionOptions {
            name: self.name.after().clone(),
            kind: *self.kind.after(),
            start_address: self.start_address.after().0,
            end_address: self.end_address.after().0,
            alignment: *self.alignment.after(),
            functions: None,
            comments: Default::default(),
        })?)
    }
}

impl NewDelinkFile {
    fn as_delink_file(&self) -> Result<DelinkFile> {
        Ok(DelinkFile::new(DelinkFileOptions {
            name: self.name.clone(),
            sections: Sections::from_sections(
                self.sections.iter().map(NewSection::as_section).collect::<Result<_>>()?,
            )?,
            complete: self.complete,
            categories: self.categories.clone(),
            gap: false,
            migrated: false,
            comments: Default::default(),
        }))
    }
}

impl NewSymbol {
    fn as_symbol(&self) -> Symbol {
        Symbol {
            name: self.name.clone(),
            kind: self.kind.clone(),
            addr: self.addr.0,
            ambiguous: self.ambiguous,
            scope: self.scope,
            skip: false,
            comments: Default::default(),
        }
    }
}

impl SymbolDiff {
    fn as_symbol_before(&self) -> Symbol {
        Symbol {
            name: self.name.before().clone(),
            kind: self.kind.before().clone(),
            addr: self.addr.0,
            ambiguous: *self.ambiguous.before(),
            scope: *self.scope.before(),
            skip: false,
            comments: Default::default(),
        }
    }

    fn as_symbol_after(&self) -> Symbol {
        Symbol {
            name: self.name.after().clone(),
            kind: self.kind.after().clone(),
            addr: self.addr.0,
            ambiguous: *self.ambiguous.after(),
            scope: *self.scope.after(),
            skip: false,
            comments: Default::default(),
        }
    }
}

impl NewRelocation {
    fn as_relocation(&self) -> Relocation {
        Relocation::new(RelocationOptions {
            from: self.from.0,
            to: self.to.0,
            addend: self.addend.0,
            kind: self.kind,
            module: self.module.clone(),
            comments: Default::default(),
        })
    }
}

impl RelocationDiff {
    fn as_relocation_before(&self) -> Relocation {
        Relocation::new(RelocationOptions {
            from: self.from.0,
            to: self.to.before().0,
            addend: self.addend.before().0,
            kind: *self.kind.before(),
            module: self.module.before().clone(),
            comments: Default::default(),
        })
    }

    fn as_relocation_after(&self) -> Relocation {
        Relocation::new(RelocationOptions {
            from: self.from.0,
            to: self.to.after().0,
            addend: self.addend.after().0,
            kind: *self.kind.after(),
            module: self.module.after().clone(),
            comments: Default::default(),
        })
    }
}
