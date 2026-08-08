use std::{
    collections::{BTreeMap, HashMap},
    ops::Range,
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

use crate::util::toposort::toposort;

pub trait DelinksExt
where
    Self: Sized,
{
    fn sort_files(&mut self) -> Result<()>;
    fn generate_gap_files(&mut self) -> Result<()>;
}
trait DelinksPrivExt {
    fn validate_files(&self) -> Result<()>;
    fn migrate_section(
        &mut self,
        section: &Section,
        migration: MigrateSection,
    ) -> Result<Vec<DelinkFile>>;
}

impl DelinksExt for Delinks {
    fn sort_files(&mut self) -> Result<()> {
        // Make lists of delink indices for each section, sorted by start address for that section
        let mut files_sorted_by_section: BTreeMap<&str, Vec<usize>> = BTreeMap::new();
        for (i, file) in self.files.iter().enumerate() {
            for section in file.sections.iter() {
                files_sorted_by_section.entry(section.name()).or_default().push(i);
            }
        }
        for (section_name, files) in files_sorted_by_section.iter_mut() {
            files.sort_unstable_by_key(|&i| {
                self.files[i].sections.by_name(section_name).unwrap().1.start_address()
            });
        }

        // Create edges in link order graph between adjacent delinks
        let mut graph = vec![Vec::new(); self.files.len()];
        for files in files_sorted_by_section.values() {
            for pair in files.windows(2) {
                graph[pair[0]].push(pair[1]);
            }
        }

        // Compute link order
        match toposort(&graph) {
            Ok(sorted) => {
                // Sort delinks by their position in the link order
                let mut sorted_files = vec![DelinkFile::default(); sorted.len()];
                for (pos, index) in sorted.into_iter().enumerate() {
                    sorted_files[pos] = std::mem::take(&mut self.files[index]);
                }
                self.files = sorted_files;

                Ok(())
            }
            Err(cycle) => {
                // Print link order cycle
                let first = cycle[0];
                let cycle = cycle.into_iter().map(|i| &self.files[i].name).fold(
                    String::new(),
                    |mut acc, name| {
                        acc.push_str(name);
                        acc.push_str(" -> ");
                        acc
                    },
                );
                bail!(
                    "Link order cycle detected while sorting delink files: {}{}",
                    cycle,
                    self.files[first].name
                )
            }
        }
    }

    fn generate_gap_files(&mut self) -> Result<()> {
        self.sort_files()?;
        self.validate_files()?;

        // Find gaps in each section
        let mut prev_section_ends = self
            .sections
            .iter()
            .map(|s| (s.name().to_string(), s.start_address()))
            .collect::<HashMap<_, _>>();
        let mut gap_files = vec![];
        for file in &self.files {
            for section in self.sections.iter() {
                let Some((_, file_section)) = file.sections.by_name(section.name()) else {
                    continue;
                };
                let prev_section_end = prev_section_ends.get_mut(section.name()).unwrap();
                if *prev_section_end < file_section.start_address() {
                    let mut gap = DelinkFile::new_gap(self.module_kind(), gap_files.len())?;
                    gap.sections.add(Section::inherit(section, SectionInheritOptions {
                        start_address: *prev_section_end,
                        end_address: file_section.start_address(),
                        comments: Comments::new(),
                        migration: None,
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
                    migration: None,
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
                for section in file.sections {
                    self.files[j].sections.add(section).with_context(|| {
                        format!("when combining gaps {} and {}", file.name, self.files[j].name)
                    })?;
                }
            }
        }

        Ok(())
    }
}

impl DelinksPrivExt for Delinks {
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

    fn migrate_section(
        &mut self,
        section: &Section,
        migration: MigrateSection,
    ) -> Result<Vec<DelinkFile>> {
        fn migrate_delink_file(
            section: &Section,
            migration: MigrateSection,
            address_range: Range<u32>,
            delink_file: &mut DelinkFile,
        ) -> Result<DelinkFile> {
            let new_section = Section::inherit(section, SectionInheritOptions {
                start_address: address_range.start,
                end_address: address_range.end,
                comments: Comments::new(),
                migration: Some(migration),
            })?;
            let new_sections = Sections::from_sections(vec![new_section])?;
            let new_file = DelinkFile::new(DelinkFileOptions {
                name: delink_file.name.clone(),
                sections: new_sections,
                complete: delink_file.complete,
                categories: delink_file.categories.clone(),
                gap: false,
                migrated: true,
                comments: Comments::new(),
            });
            delink_file.migrate_section_by_name(migration.source_name().as_ref())?;
            Ok(new_file)
        }

        self.files
            .iter_mut()
            .filter_map(|delink_file| {
                let (_, migrated_section) =
                    delink_file.sections.by_name(migration.source_name().as_ref())?;
                Some(migrate_delink_file(
                    section,
                    migration,
                    migrated_section.address_range(),
                    delink_file,
                ))
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

const GAP_FILE_PREFIX: &str = "_dsd_gap@";

impl DelinkFileExt for DelinkFile {
    fn new_gap(module_kind: ModuleKind, id: usize) -> Result<Self> {
        let name = match module_kind {
            ModuleKind::Arm9 => format!("{GAP_FILE_PREFIX}main_{id}"),
            ModuleKind::Overlay(overlay_id) => format!("{GAP_FILE_PREFIX}ov{overlay_id:03}_{id}"),
            ModuleKind::Autoload(kind) => match kind {
                AutoloadKind::Itcm => format!("{GAP_FILE_PREFIX}itcm_{id}"),
                AutoloadKind::Dtcm => format!("{GAP_FILE_PREFIX}dtcm_{id}"),
                AutoloadKind::Unknown(index) => format!("{GAP_FILE_PREFIX}autoload_{index}_{id}"),
            },
        };

        Ok(Self::new(DelinkFileOptions {
            name,
            sections: Sections::new(),
            complete: false,
            categories: Categories::new(),
            gap: true,
            migrated: false,
            comments: Comments::new(),
        }))
    }
}

pub struct DelinksMap {
    map: BTreeMap<ModuleKind, Delinks>,
}

pub struct DelinksMapOptions {
    pub migrate_sections: bool,
    pub generate_gap_files: bool,
    /// If non-empty, only load these modules. Note that autoload modules will always be loaded so
    /// that sections like .dtcm and .itcm may be migrated.
    pub module_filter: Vec<ModuleKind>,
}

impl DelinksMap {
    pub fn from_config(
        config: &Config,
        path: impl AsRef<Path>,
        options: DelinksMapOptions,
    ) -> Result<DelinksMap> {
        let path = path.as_ref();
        let map = config
            .iter_modules()
            .filter(|(kind, _)| {
                options.module_filter.is_empty()
                    || matches!(kind, ModuleKind::Autoload(_))
                    || options.module_filter.contains(kind)
            })
            .map(|(kind, config)| {
                let delinks = Delinks::from_file(path.join(&config.delinks), kind)?;
                Ok((kind, delinks))
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        let mut map = DelinksMap { map };

        if options.migrate_sections {
            map.migrate_sections()?;
        }
        if options.generate_gap_files {
            for delinks in map.map.values_mut() {
                delinks.generate_gap_files()?;
            }
        }
        Ok(map)
    }

    fn migrate_sections(&mut self) -> Result<()> {
        let modules = self.map.keys().copied().collect::<Vec<_>>();

        for target_module in &modules {
            for migrate_section in MigrateSection::sections_to_migrate(*target_module) {
                let source_name = migrate_section.source_name();
                let target_name = migrate_section.target_name();

                let has_migration = modules.iter().any(|source_module| {
                    let source = self.map.get_mut(source_module).unwrap();
                    source.files.iter().any(|file| file.sections.by_name(&source_name).is_some())
                });
                if !has_migration {
                    continue;
                }

                let section = {
                    let target = self
                        .map
                        .get(target_module)
                        .context("Failed to find target module of section migration")?;
                    let Some((_, section)) = target.sections.by_name(target_name) else {
                        bail!(
                            "Failed to find target section {target_name} for migration to module {target_module}"
                        );
                    };
                    section.clone()
                };

                for source_module in &modules {
                    let source = self.map.get_mut(source_module).unwrap();
                    let files = source.migrate_section(&section, migrate_section)?;

                    let target = self.map.get_mut(target_module).unwrap();
                    target.files.extend(files);
                }
            }
        }

        Ok(())
    }

    pub fn to_files(&self, config: &Config, config_path: impl AsRef<Path>) -> Result<()> {
        let config_path = config_path.as_ref();
        for (kind, module) in config.iter_modules() {
            let delinks = self.get(kind).unwrap();
            delinks.to_file(config_path.join(&module.delinks))?;
        }
        Ok(())
    }

    pub fn get(&self, kind: ModuleKind) -> Option<&Delinks> {
        self.map.get(&kind)
    }

    pub fn get_mut(&mut self, kind: ModuleKind) -> Option<&mut Delinks> {
        self.map.get_mut(&kind)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Delinks> {
        self.map.values()
    }

    pub fn delink_files(&self) -> impl Iterator<Item = &DelinkFile> {
        self.iter().flat_map(|delinks| delinks.files.iter())
    }
}
