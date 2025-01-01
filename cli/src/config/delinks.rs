use std::{cmp::Ordering, collections::HashMap, path::Path};

use anyhow::{bail, Context, Result};
use ds_decomp::config::{
    delinks::{DelinkFile, Delinks},
    module::ModuleKind,
    section::{Section, Sections},
};
use ds_rom::rom::raw::AutoloadKind;
use petgraph::{graph::NodeIndex, Graph};

pub trait DelinksExt
where
    Self: Sized,
{
    fn from_file_and_generate_gaps<P: AsRef<Path>>(path: P, module_kind: ModuleKind) -> Result<Self>;
}
trait DelinksPrivExt {
    fn generate_gap_files(&mut self) -> Result<()>;
    fn sort_files(&mut self) -> Result<()>;
    fn compare_files(&self, a: &DelinkFile, b: &DelinkFile) -> Ordering;
    fn validate_files(&self) -> Result<()>;
}

impl DelinksExt for Delinks {
    fn from_file_and_generate_gaps<P: AsRef<Path>>(path: P, module_kind: ModuleKind) -> Result<Self> {
        let mut delinks = Delinks::from_file(path, module_kind)?;
        delinks.generate_gap_files()?;
        Ok(delinks)
    }
}
impl DelinksPrivExt for Delinks {
    fn generate_gap_files(&mut self) -> Result<()> {
        self.sort_files()?;
        self.validate_files()?;

        // Find gaps in each section
        let mut prev_section_ends =
            self.sections.iter().map(|s| (s.name().to_string(), s.start_address())).collect::<HashMap<_, _>>();
        let mut gap_files = vec![];
        for file in &self.files {
            for section in self.sections.iter() {
                let Some((_, file_section)) = file.sections.by_name(section.name()) else { continue };
                let prev_section_end = prev_section_ends.get_mut(section.name()).unwrap();
                if *prev_section_end < file_section.start_address() {
                    let mut gap = DelinkFile::new_gap(self.module_kind(), gap_files.len())?;
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
                let mut gap = DelinkFile::new_gap(self.module_kind(), gap_files.len())?;
                gap.sections.add(Section::inherit(section, prev_section_end, section.end_address())?)?;
                gap_files.push(gap);
            }
        }

        // Sort gap files into files list
        self.files.extend(gap_files);
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
            let Some((_, a_section)) = a.sections.by_name(section.name()) else {
                continue;
            };
            let Some((_, b_section)) = b.sections.by_name(section.name()) else {
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
                let Some((_, file_section)) = file.sections.by_name(section.name()) else {
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

trait DelinkFileExt
where
    Self: Sized,
{
    fn new_gap(module_kind: ModuleKind, id: usize) -> Result<Self>;
}

impl DelinkFileExt for DelinkFile {
    fn new_gap(module_kind: ModuleKind, id: usize) -> Result<Self> {
        let name = match module_kind {
            ModuleKind::Arm9 => format!("main_{id}"),
            ModuleKind::Overlay(overlay_id) => format!("ov{overlay_id:03}_{id}"),
            ModuleKind::Autoload(kind) => match kind {
                AutoloadKind::Itcm => format!("itcm_{id}"),
                AutoloadKind::Dtcm => format!("dtcm_{id}"),
                AutoloadKind::Unknown(_) => {
                    log::error!("Unknown autoload kind");
                    bail!("Unknown autoload kind");
                }
            },
        };

        Ok(Self { name, sections: Sections::new(), complete: false, gap: true })
    }
}
