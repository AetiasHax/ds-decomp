use std::{
    backtrace::Backtrace,
    fmt::Display,
    fs::File,
    io::{self, BufRead, BufReader, BufWriter, Lines, Write},
    path::Path,
};

use snafu::Snafu;

use crate::util::io::{FileError, create_file, open_file};

use super::{
    ParseContext,
    module::ModuleKind,
    section::{Section, SectionInheritParseError, SectionParseError, Sections, SectionsError},
};

pub struct Delinks {
    pub sections: Sections,
    pub files: Vec<DelinkFile>,
    module_kind: ModuleKind,
}

#[derive(Debug, Snafu)]
pub enum DelinksParseError {
    #[snafu(transparent)]
    File { source: FileError },
    #[snafu(transparent)]
    Io { source: io::Error },
    #[snafu(transparent)]
    SectionParse { source: SectionParseError },
    #[snafu(display("{context}: {error}"))]
    Sections { context: ParseContext, error: Box<SectionsError> },
    #[snafu(transparent)]
    DelinkFileParse { source: DelinkFileParseError },
}

#[derive(Debug, Snafu)]
pub enum DelinksWriteError {
    #[snafu(transparent)]
    File { source: FileError },
    #[snafu(transparent)]
    Io { source: io::Error },
}

impl Delinks {
    pub fn new(sections: Sections, files: Vec<DelinkFile>, module_kind: ModuleKind) -> Self {
        Self { sections, files, module_kind }
    }

    pub fn from_file<P: AsRef<Path>>(path: P, module_kind: ModuleKind) -> Result<Self, DelinksParseError> {
        let path = path.as_ref();
        let mut context = ParseContext { file_path: path.to_str().unwrap().to_string(), row: 0 };

        let file = open_file(path)?;
        let reader = BufReader::new(file);

        let mut sections: Sections = Sections::new();
        let mut files = vec![];

        let mut lines = reader.lines();
        while let Some(line) = lines.next() {
            context.row += 1;

            let line = line?;
            let comment_start = line.find("//").unwrap_or(line.len());
            let line = &line[..comment_start];

            if Self::try_parse_delink_file(line, &mut lines, &mut context, &mut files, &sections)? {
                break;
            }
            let Some(section) = Section::parse(line, &context)? else {
                continue;
            };
            sections.add(section).map_err(|error| SectionsSnafu { context: context.clone(), error }.build())?;
        }

        while let Some(line) = lines.next() {
            context.row += 1;

            let line = line?;
            let comment_start = line.find("//").unwrap_or(line.len());
            let line = &line[..comment_start];

            Self::try_parse_delink_file(line, &mut lines, &mut context, &mut files, &sections)?;
        }

        Ok(Self { sections, files, module_kind })
    }

    fn try_parse_delink_file(
        line: &str,
        lines: &mut Lines<BufReader<File>>,
        context: &mut ParseContext,
        files: &mut Vec<DelinkFile>,
        sections: &Sections,
    ) -> Result<bool, DelinkFileParseError> {
        if line.chars().next().is_some_and(|c| !c.is_whitespace()) {
            let delink_file = DelinkFile::parse(line, lines, context, sections)?;
            files.push(delink_file);
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn to_file<P: AsRef<Path>>(path: P, sections: &Sections) -> Result<(), DelinksWriteError> {
        let path = path.as_ref();

        let file = create_file(path)?;
        let mut writer = BufWriter::new(file);

        write!(writer, "{}", DisplayDelinks { sections, files: &[] })?;

        Ok(())
    }

    pub fn display(&self) -> DisplayDelinks<'_> {
        DisplayDelinks { sections: &self.sections, files: &self.files }
    }

    pub fn module_kind(&self) -> ModuleKind {
        self.module_kind
    }
}
pub struct DisplayDelinks<'a> {
    sections: &'a Sections,
    files: &'a [DelinkFile],
}

impl Display for DisplayDelinks<'_> {
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

pub struct DelinkFile {
    pub name: String,
    pub sections: Sections,
    pub complete: bool,
    pub gap: bool,
}

#[derive(Debug, Snafu)]
pub enum DelinkFileParseError {
    #[snafu(display("{context}: expected file path to end with ':':\n{backtrace}"))]
    MissingColon { context: ParseContext, backtrace: Backtrace },
    #[snafu(transparent)]
    Io { source: io::Error },
    #[snafu(transparent)]
    SectionInheritParse { source: SectionInheritParseError },
    #[snafu(transparent)]
    Sections { source: SectionsError },
}

impl DelinkFile {
    pub fn new(name: String, sections: Sections, complete: bool) -> Self {
        Self { name, sections, complete, gap: false }
    }

    pub fn parse(
        first_line: &str,
        lines: &mut Lines<BufReader<File>>,
        context: &mut ParseContext,
        inherit_sections: &Sections,
    ) -> Result<Self, DelinkFileParseError> {
        let name = first_line
            .trim()
            .strip_suffix(':')
            .ok_or_else(|| MissingColonSnafu { context: context.clone() }.build())?
            .to_string();

        let mut complete = false;
        let mut sections = Sections::new();
        for line in lines.by_ref() {
            context.row += 1;
            let line = line?;
            let line = line.trim();
            if line.is_empty() {
                break;
            }
            if line == "complete" {
                complete = true;
                continue;
            }
            let section = Section::parse_inherit(line, context, inherit_sections)?.unwrap();
            sections.add(section)?;
        }

        Ok(DelinkFile { name, sections, complete, gap: false })
    }

    pub fn split_file_ext(&self) -> (&str, &str) {
        self.name.rsplit_once('.').unwrap_or((&self.name, ""))
    }

    pub fn gap(&self) -> bool {
        self.gap
    }
}

impl Display for DelinkFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{}:", self.name)?;
        for section in self.sections.sorted_by_address() {
            writeln!(f, "    {section}")?;
        }
        Ok(())
    }
}
