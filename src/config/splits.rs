use std::{
    fs::File,
    io::{BufRead, BufReader, BufWriter, Lines},
    path::Path,
};

use anyhow::{Context, Result};

use crate::util::io::{create_file, open_file};

use super::{
    section::{Section, Sections},
    ParseContext,
};

pub struct Splits<'a> {
    pub sections: Sections<'a>,
    pub files: Vec<SplitFile<'a>>,
}

pub struct SplitFile<'a> {
    pub name: String,
    pub sections: Sections<'a>,
}

impl<'a> Splits<'a> {
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
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
            if line.chars().next().map_or(false, |c| !c.is_whitespace()) {
                let split_file = SplitFile::parse(&line, &mut lines, &mut context)?;
                files.push(split_file);
                break;
            }
            let Some(section) = Section::parse(&line, &context)? else {
                continue;
            };
            sections.add(section);
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

    pub fn to_file<P: AsRef<Path>>(path: P, sections: &Sections) -> Result<()> {
        let path = path.as_ref();

        let file = create_file(path)?;
        let mut writer = BufWriter::new(file);

        let sections = sections.sorted_by_address();
        for section in sections {
            section.write(&mut writer)?;
        }

        // TODO: Export split files here? This function was made for generating a config, and split files are not generated currently.

        Ok(())
    }
}

impl<'a> SplitFile<'a> {
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
            sections.add(section);
        }

        Ok(SplitFile { name, sections })
    }
}
