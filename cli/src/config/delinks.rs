use std::{cmp::Ordering, collections::HashMap, path::Path};

use anyhow::{Context, Result, bail};
use ds_decomp::config::{
    config::{Config, ConfigModule},
    delinks::{Categories, DelinkFile, Delinks},
    module::ModuleKind,
    section::{DTCM_SECTION, Section, Sections},
};
use ds_rom::rom::raw::AutoloadKind;
use petgraph::{Graph, graph::NodeIndex};

pub trait DelinksExt
where
    Self: Sized,
{
    fn from_file_and_generate_gaps<P: AsRef<Path>>(path: P, module_kind: ModuleKind) -> Result<Self>;
    fn without_dtcm_sections(self) -> Self;
    fn new_dtcm<P: AsRef<Path>>(config_path: P, config: &Config, dtcm_config: &ConfigModule) -> Result<Self>;
}
trait DelinksPrivExt {
    fn generate_gap_files(&mut self) -> Result<()>;
    fn sort_files(&mut self) -> Result<()>;
    fn compare_files(&self, a: &DelinkFile, b: &DelinkFile) -> Ordering;
    fn validate_files(&self) -> Result<()>;
    fn append_dtcm_sections<P: AsRef<Path>>(
        &mut self,
        config_path: P,
        module_config: &ConfigModule,
        module_kind: ModuleKind,
    ) -> Result<()>;
}

impl DelinksExt for Delinks {
    fn from_file_and_generate_gaps<P: AsRef<Path>>(path: P, module_kind: ModuleKind) -> Result<Self> {
        let mut delinks = Delinks::from_file(path, module_kind)?;
        delinks.generate_gap_files()?;
        Ok(delinks)
    }

    fn without_dtcm_sections(mut self) -> Self {
        for file in &mut self.files {
            file.sections.remove(DTCM_SECTION);
        }
        self
    }

    fn new_dtcm<P: AsRef<Path>>(config_path: P, config: &Config, dtcm_config: &ConfigModule) -> Result<Self> {
        let config_path = config_path.as_ref();
        let mut delinks =
            Delinks::from_file(config_path.join(&dtcm_config.delinks), ModuleKind::Autoload(AutoloadKind::Dtcm))?;
        delinks.append_dtcm_sections(config_path, &config.main_module, ModuleKind::Arm9)?;
        for autoload in &config.autoloads {
            if autoload.kind != AutoloadKind::Dtcm {
                delinks.append_dtcm_sections(config_path, &autoload.module, ModuleKind::Autoload(autoload.kind))?;
            }
        }
        for overlay in &config.overlays {
            delinks.append_dtcm_sections(config_path, &overlay.module, ModuleKind::Overlay(overlay.id))?;
        }
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

    fn append_dtcm_sections<P: AsRef<Path>>(
        &mut self,
        config_path: P,
        module_config: &ConfigModule,
        module_kind: ModuleKind,
    ) -> Result<()> {
        let Some((_, bss_section)) = self.sections.by_name(DTCM_SECTION) else {
            return Ok(());
        };

        let config_path = config_path.as_ref();
        let delinks_path = config_path.join(&module_config.delinks);
        let delinks = Delinks::from_file(delinks_path, module_kind)?;

        for delink_file in delinks.files.into_iter() {
            let Some((_, dtcm_section)) = delink_file.sections.by_name(DTCM_SECTION) else {
                continue;
            };
            self.files.push(DelinkFile {
                name: delink_file.name,
                sections: Sections::from_sections(vec![Section::inherit(
                    bss_section,
                    dtcm_section.start_address(),
                    dtcm_section.end_address(),
                )?])?,
                complete: delink_file.complete,
                categories: delink_file.categories.clone(),
                gap: false,
            });
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
                AutoloadKind::Unknown(index) => format!("autoload_{index}_{id}"),
            },
        };

        Ok(Self { name, sections: Sections::new(), complete: false, categories: Categories::new(), gap: true })
    }
}
