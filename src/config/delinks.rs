use std::{
    cmp::Ordering,
    collections::HashMap,
    fmt::Display,
    fs::File,
    io::{BufRead, BufReader, BufWriter, Lines, Write},
    path::Path,
};

use anyhow::{bail, Context, Result};
use ds_rom::rom::raw::AutoloadKind;
use petgraph::{graph::NodeIndex, Graph};

use crate::util::io::{create_file, open_file};

use super::{
    module::ModuleKind,
    section::{Section, Sections},
    ParseContext,
};

pub struct Delinks<'a> {
    pub sections: Sections<'a>,
    pub files: Vec<DelinkFile<'a>>,
    module_kind: ModuleKind,
}

pub struct DelinkFile<'a> {
    pub name: String,
    pub sections: Sections<'a>,
    gap: bool,
}

impl<'a> Delinks<'a> {
    pub fn from_file<P: AsRef<Path>>(path: P, module_kind: ModuleKind) -> Result<Self> {
        let path = path.as_ref();
        let mut context = ParseContext { file_path: path.to_str().unwrap().to_string(), row: 0 };

        let file = open_file(path)?;
        let reader = BufReader::new(file);

        let mut sections = Sections::new();
        let mut files = vec![];

        let mut lines = reader.lines();
        while let Some(line) = lines.next() {
            context.row += 1;
            let line = line?;
            if Self::try_parse_delink_file(&line, &mut lines, &mut context, &mut files, &sections)? {
                break;
            }
            let Some(section) = Section::parse(&line, &context)? else {
                continue;
            };
            sections.add(section)?;
        }

        while let Some(line) = lines.next() {
            context.row += 1;
            let line = line?;
            Self::try_parse_delink_file(&line, &mut lines, &mut context, &mut files, &sections)?;
        }

        let mut delinks = Delinks { sections, files, module_kind };
        delinks.generate_gap_files()?;
        Ok(delinks)
    }

    fn try_parse_delink_file(
        line: &str,
        lines: &mut Lines<BufReader<File>>,
        context: &mut ParseContext,
        files: &mut Vec<DelinkFile<'_>>,
        sections: &Sections,
    ) -> Result<bool> {
        if line.chars().next().map_or(false, |c| !c.is_whitespace()) {
            let delink_file = DelinkFile::parse(&line, lines, context, sections)?;
            files.push(delink_file);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn to_file<P: AsRef<Path>>(path: P, sections: &Sections) -> Result<()> {
        let path = path.as_ref();

        let file = create_file(path)?;
        let mut writer = BufWriter::new(file);

        write!(writer, "{}", DisplayDelinks { sections, files: &[] })?;

        // TODO: Export delink files here? This function was made for generating a config, and delink files are not generated currently.

        Ok(())
    }

    pub fn display(&self) -> DisplayDelinks {
        DisplayDelinks { sections: &self.sections, files: &self.files }
    }

    fn generate_gap_files(&mut self) -> Result<()> {
        self.sort_files()?;
        self.validate_files()?;

        // Find gaps in each section
        let mut prev_section_ends =
            self.sections.iter().map(|s| (s.name().to_string(), s.start_address())).collect::<HashMap<_, _>>();
        let mut gap_files = vec![];
        for file in &self.files {
            for section in self.sections.iter() {
                let Some(file_section) = file.sections.by_name(section.name()) else { continue };
                let prev_section_end = prev_section_ends.get_mut(section.name()).unwrap();
                if *prev_section_end < file_section.start_address() {
                    let mut gap = DelinkFile::new_gap(self.module_kind, gap_files.len())?;
                    gap.sections.add(Section::inherit(section, *prev_section_end, file_section.start_address())?)?;
                    gap_files.push(gap);
                }
                *prev_section_end = file_section.end_address();
            }
        }

        // Add gaps after last file
        for section in self.sections.iter() {
            let prev_section_end = *prev_section_ends.get(section.name()).unwrap();
            if prev_section_end < section.end_address() {
                let mut gap = DelinkFile::new_gap(self.module_kind, gap_files.len())?;
                gap.sections.add(Section::inherit(section, prev_section_end, section.end_address())?)?;
                gap_files.push(gap);
            }
        }

        // Sort gap files into files list
        self.files.extend(gap_files.into_iter());
        self.sort_files()?;

        // Combine adjacent gap files
        for i in (1..self.files.len()).rev() {
            let j = i - 1;
            if self.files[i].gap && self.files[j].gap {
                let file = self.files.remove(i);
                for section in file.sections.into_iter() {
                    self.files[j]
                        .sections
                        .add(section)
                        .with_context(|| format!("when combining gaps {} and {}", file.name, self.files[j].name))?;
                }
            }
        }

        Ok(())
    }

    fn sort_files(&mut self) -> Result<()> {
        let mut graph = Graph::<(), ()>::new();

        for _ in 0..self.files.len() {
            graph.add_node(());
        }

        for i in 0..self.files.len() {
            let i_node = NodeIndex::new(i);
            for j in i + 1..self.files.len() {
                let j_node = NodeIndex::new(j);
                match self.compare_files(&self.files[i], &self.files[j]) {
                    Ordering::Less => {
                        graph.add_edge(i_node, j_node, ());
                    }
                    Ordering::Equal => {}
                    Ordering::Greater => {
                        graph.add_edge(j_node, i_node, ());
                    }
                }
            }
        }

        let mut nodes = match petgraph::algo::toposort(&graph, None) {
            Ok(nodes) => nodes,
            Err(_) => bail!("Cycle detected when sorting delink files"),
        };

        // Sort by node indices
        for i in 0..self.files.len() {
            if nodes[i].index() != i {
                let mut current = i;
                loop {
                    let target = nodes[current].index();
                    nodes[current] = NodeIndex::new(current);
                    if nodes[target] == NodeIndex::new(target) {
                        break;
                    }
                    self.files.swap(current, target);
                    current = target;
                }
            }
        }

        Ok(())
    }

    fn compare_files(&self, a: &DelinkFile, b: &DelinkFile) -> Ordering {
        for section in self.sections.iter() {
            let Some(a_section) = a.sections.by_name(section.name()) else {
                continue;
            };
            let Some(b_section) = b.sections.by_name(section.name()) else {
                continue;
            };
            let ordering = a_section.start_address().cmp(&b_section.start_address());
            if ordering.is_ne() {
                return ordering;
            }
        }
        Ordering::Equal
    }

    /// Checks that adjacent files do not overlap and that their sections are in ascending order. Assumes that the files list
    /// is already sorted using [`Self::sort_files`].
    fn validate_files(&self) -> Result<()> {
        for section in self.sections.iter() {
            let mut prev_name = "";
            let mut prev_start = section.start_address();
            let mut prev_end = section.start_address();
            for file in &self.files {
                let Some(file_section) = file.sections.by_name(section.name()) else {
                    continue;
                };
                if file_section.start_address() < prev_end {
                    if file_section.end_address() > prev_start {
                        bail!(
                            "{} in file '{}' ({:#x}..{:#x}) overlaps with previous file '{}' ({:#x}..{:#x})",
                            file_section.name(),
                            file.name,
                            file_section.start_address(),
                            file_section.end_address(),
                            prev_name,
                            prev_start,
                            prev_end
                        );
                    } else {
                        bail!("File '{}' has mixed section order with previous file, see {}", file.name, file_section.name());
                    }
                }
                prev_name = &file.name;
                prev_start = file_section.start_address();
                prev_end = file_section.end_address();
            }
        }

        Ok(())
    }
}

pub struct DisplayDelinks<'a> {
    sections: &'a Sections<'a>,
    files: &'a [DelinkFile<'a>],
}

impl<'a> Display for DisplayDelinks<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for section in self.sections.sorted_by_address() {
            writeln!(f, "    {section}")?;
        }
        writeln!(f)?;
        for file in self.files {
            writeln!(f, "{file}")?;
        }
        Ok(())
    }
}

impl<'a> DelinkFile<'a> {
    pub fn new(name: String, sections: Sections<'a>) -> Self {
        Self { name, sections, gap: false }
    }

    fn new_gap(module_kind: ModuleKind, id: usize) -> Result<Self> {
        let name = match module_kind {
            ModuleKind::Arm9 => format!("main_{id}"),
            ModuleKind::Overlay(overlay_id) => format!("ov{overlay_id:03}_{id}"),
            ModuleKind::Autoload(kind) => match kind {
                AutoloadKind::Itcm => format!("itcm_{id}"),
                AutoloadKind::Dtcm => format!("dtcm_{id}"),
                AutoloadKind::Unknown => {
                    log::error!("Unknown autoload kind");
                    bail!("Unknown autoload kind");
                }
            },
        };

        Ok(Self { name, sections: Sections::new(), gap: true })
    }

    pub fn parse(
        first_line: &str,
        lines: &mut Lines<BufReader<File>>,
        context: &mut ParseContext,
        inherit_sections: &Sections,
    ) -> Result<Self> {
        let name = first_line
            .trim()
            .strip_suffix(':')
            .with_context(|| format!("{}: expected file path to end with ':'", context))?
            .to_string();

        let mut sections = Sections::new();
        while let Some(line) = lines.next() {
            context.row += 1;
            let line = line?;
            let line = line.trim();
            if line.is_empty() {
                break;
            }
            let section = Section::parse_inherit(&line, &context, inherit_sections)?.unwrap();
            sections.add(section)?;
        }

        Ok(DelinkFile { name, sections, gap: false })
    }

    pub fn split_file_ext(&self) -> (&str, &str) {
        self.name.rsplit_once('.').unwrap_or((&self.name, ""))
    }
}

impl<'a> Display for DelinkFile<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}:", self.name)?;
        for section in self.sections.sorted_by_address() {
            writeln!(f, "    {section}")?;
        }
        Ok(())
    }
}
