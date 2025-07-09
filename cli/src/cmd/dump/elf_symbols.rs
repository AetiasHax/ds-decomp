use std::{collections::BTreeMap, path::PathBuf};

use clap::Args;
use object::{Object, ObjectSection, ObjectSymbol};

use crate::util::io::read_file;

/// Dumps symbols from an ELF file.
#[derive(Args, Clone)]
pub struct DumpElfSymbols {
    /// Path to the ELF file to dump symbols from.
    #[arg(long, short = 'e')]
    elf_path: PathBuf,
}

impl DumpElfSymbols {
    pub fn run(&self) -> anyhow::Result<()> {
        let elf_file = read_file(&self.elf_path)?;
        let object = object::File::parse(&*elf_file)?;

        let sections = object.sections().map(|section| (section.index().0, section)).collect::<BTreeMap<_, _>>();

        let mut symbols = object.symbols().collect::<Vec<_>>();
        symbols.sort_unstable_by_key(|s| s.address());
        symbols.sort_by_key(|s| s.section_index().map_or(-1, |i| i.0 as isize));

        for symbol in symbols {
            let name = symbol.name()?;
            match name {
                "$d" | "$a" | "$t" => {
                    continue;
                }
                _ => {}
            }
            if name.starts_with(".L") && symbol.is_local() {
                continue;
            }

            let address = symbol.address();
            let size = symbol.size();
            let kind = symbol.kind();
            let section = if let Some(section_index) = symbol.section_index() {
                if let Some(section) = sections.get(&section_index.0) {
                    section.name()?
                } else {
                    "<not found>"
                }
            } else {
                "<none>"
            };

            let local = if symbol.is_local() { "local" } else { "global" };
            let section_index = symbol.section_index().map_or(-1, |i| i.0 as isize);

            println!("{section}({section_index}) {address:#010x} {size:#x} {local} {name} {kind:?}");
        }

        Ok(())
    }
}
