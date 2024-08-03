use std::{
    collections::HashMap,
    fs::File,
    io::{BufRead, BufReader, Lines},
    path::Path,
};

use anyhow::{Context, Result};

use super::{section::Section, ParseContext};

pub type Sections = HashMap<String, Section>;

pub struct Splits {
    sections: Sections,
    files: Vec<SplitFile>,
}

pub struct SplitFile {
    name: String,
    sections: Sections,
}

impl Splits {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let mut context = ParseContext { file_path: path.to_str().unwrap().to_string(), row: 0 };

        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut sections = Sections::new();
        let mut files = vec![];

        let mut lines = reader.lines();
        while let Some(line) = lines.next() {
            context.row += 1;
            let line = line?;
            if line.chars().next().map_or(false, |c| !c.is_whitespace()) {
                let split_file = SplitFile::parse(&line, &mut lines, &mut context)?;
                files.push(split_file);
                break;
            }
            let Some(section) = Section::parse(&line, &context)? else {
                continue;
            };
            sections.insert(section.name.clone(), section);
        }

        while let Some(line) = lines.next() {
            context.row += 1;
            let line = line?;
            if line.chars().next().map_or(false, |c| !c.is_whitespace()) {
                let split_file = SplitFile::parse(&line, &mut lines, &mut context)?;
                files.push(split_file);
            }
        }

        Ok(Splits { sections, files })
    }
}

impl SplitFile {
    pub fn parse(first_line: &str, lines: &mut Lines<BufReader<File>>, context: &mut ParseContext) -> Result<Self> {
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
            let section = Section::parse(&line, &context)?.unwrap();
            sections.insert(section.name.clone(), section);
        }

        Ok(SplitFile { name, sections })
    }
}
