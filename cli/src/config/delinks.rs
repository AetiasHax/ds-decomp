use std::{
    cmp::Ordering,
    collections::{BTreeMap, HashMap},
    path::Path,
};

use anyhow::{Context, Result, bail};
use ds_decomp::config::{
    Comments,
    config::Config,
    delinks::{Categories, DelinkFile, DelinkFileOptions, Delinks},
    module::ModuleKind,
    section::{MigrateSection, Section, SectionInheritOptions, Sections},
};
use ds_rom::rom::raw::AutoloadKind;
use petgraph::{Graph, graph::NodeIndex};

pub trait DelinksExt
where
    Self: Sized,
{
    fn remove_section(&mut self, section_name: &str);
    fn sort_files(&mut self) -> Result<()>;
    fn generate_gap_files(&mut self) -> Result<()>;
}
trait DelinksPrivExt {
    fn compare_files(&self, a: &DelinkFile, b: &DelinkFile) -> Ordering;
    fn validate_files(&self) -> Result<()>;
    fn extract_section(&self, section: &Section) -> Result<Vec<DelinkFile>>;
}

impl DelinksExt for Delinks {
    fn remove_section(&mut self, section_name: &str) {
        for file in &mut self.files {
            file.sections.remove(section_name);
        }
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
                    gap.sections.add(Section::inherit(section, SectionInheritOptions {
                        start_address: *prev_section_end,
                        end_address: file_section.start_address(),
                        comments: Comments::new(),
                    })?)?;
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
                gap.sections.add(Section::inherit(section, SectionInheritOptions {
                    start_address: prev_section_end,
                    end_address: section.end_address(),
                    comments: Comments::new(),
                })?)?;
                gap_files.push(gap);
            }
        }

        // Sort gap files into files list
        self.files.extend(gap_files);
        self.sort_files()?;

        // Combine adjacent gap files
        for i in (1..self.files.len()).rev() {
            let j = i - 1;
            if self.files[i].gap() && self.files[j].gap() {
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
}

impl DelinksPrivExt for Delinks {
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

                if file_section.start_address() >= section.end_address()
                    || file_section.end_address() < section.start_address()
                {
                    bail!(
                        "{} in file '{}' ({:#x}..{:#x}) is out of bounds ({:#x}..{:#x})",
                        file_section.name(),
                        file.name,
                        file_section.start_address(),
                        file_section.end_address(),
                        section.start_address(),
                        section.end_address(),
                    );
                }

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
                        bail!(
                            "{} in file '{}' has mixed section order with previous file '{}'",
                            file_section.name(),
                            file.name,
                            prev_name
                        );
                    }
                }
                prev_name = &file.name;
                prev_start = file_section.start_address();
                prev_end = file_section.end_address();
            }
        }

        Ok(())
    }

    fn extract_section(&self, section: &Section) -> Result<Vec<DelinkFile>> {
        self.files
            .iter()
            .filter_map(|delink_file| {
                if let Some((_, migrated_section)) = delink_file.sections.by_name(section.name()) {
                    Some((delink_file, migrated_section))
                } else {
                    None
                }
            })
            .map(|(delink_file, migrated_section)| {
                Ok(DelinkFile::new(DelinkFileOptions {
                    name: delink_file.name.clone(),
                    sections: Sections::from_sections(vec![Section::inherit(section, SectionInheritOptions {
                        start_address: migrated_section.start_address(),
                        end_address: migrated_section.end_address(),
                        comments: Comments::new(),
                    })?])?,
                    complete: delink_file.complete,
                    categories: delink_file.categories.clone(),
                    gap: false,
                    comments: Comments::new(),
                }))
            })
            .collect()
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
            ModuleKind::Arm9 => format!("_dsd_gap$main_{id}"),
            ModuleKind::Overlay(overlay_id) => format!("_dsd_gap$ov{overlay_id:03}_{id}"),
            ModuleKind::Autoload(kind) => match kind {
                AutoloadKind::Itcm => format!("_dsd_gap$itcm_{id}"),
                AutoloadKind::Dtcm => format!("_dsd_gap$dtcm_{id}"),
                AutoloadKind::Unknown(index) => format!("_dsd_gap$autoload_{index}_{id}"),
            },
        };

        Ok(Self::new(DelinkFileOptions {
            name,
            sections: Sections::new(),
            complete: false,
            categories: Categories::new(),
            gap: true,
            comments: Comments::new(),
        }))
    }
}

pub struct DelinksMap {
    map: BTreeMap<ModuleKind, Delinks>,
}

impl DelinksMap {
    pub fn from_config(config: &Config, path: impl AsRef<Path>) -> Result<DelinksMap> {
        let path = path.as_ref();
        let map = config
            .iter_modules()
            .map(|(kind, config)| {
                let delinks = Delinks::from_file(path.join(&config.delinks), kind)?;
                Ok((kind, delinks))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let mut map = DelinksMap { map };

        map.migrate_sections()?;
        for delinks in map.map.values_mut() {
            delinks.generate_gap_files()?;
        }
        Ok(map)
    }

    fn migrate_sections(&mut self) -> Result<()> {
        let modules = self.map.keys().copied().collect::<Vec<_>>();

        for target_module in modules.iter() {
            let migrate_section = MigrateSection::from(target_module);
            let Some(section_name) = migrate_section.name() else { continue };

            let section = {
                let target = self.map.get(target_module).context("Failed to find target module of section migration")?;
                let Some((_, section)) = target.sections.by_name(section_name) else {
                    continue;
                };
                section.clone()
            };

            for source_module in modules.iter() {
                let source = self.map.get_mut(source_module).unwrap();
                let files = source.extract_section(&section)?;
                source.remove_section(section_name);

                let target = self.map.get_mut(target_module).unwrap();
                target.files.extend(files.into_iter());
            }
        }

        Ok(())
    }

    pub fn get(&self, kind: ModuleKind) -> Option<&Delinks> {
        self.map.get(&kind)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Delinks> {
        self.map.values()
    }

    pub fn delink_files(&self) -> impl Iterator<Item = &DelinkFile> {
        self.iter().flat_map(|delinks| delinks.files.iter())
    }
}
