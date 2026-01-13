use std::{
    backtrace::Backtrace,
    fmt::Display,
    io::{self, BufWriter, Write},
    iter::Peekable,
    path::Path,
};

use snafu::Snafu;

use super::{
    ParseContext,
    module::ModuleKind,
    section::{Section, SectionInheritParseError, SectionParseError, Sections, SectionsError},
};
use crate::{
    config::{CommentedLine, CommentedLineIterator, Comments},
    util::io::{FileError, create_file},
};

pub struct Delinks {
    pub sections: Sections,
    pub global_categories: Categories,
    module_kind: ModuleKind,
    pub files: Vec<DelinkFile>,
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
        Self { sections, global_categories: Categories::new(), files, module_kind }
    }

    pub fn from_file<P: AsRef<Path>>(path: P, module_kind: ModuleKind) -> Result<Self, DelinksParseError> {
        let path = path.as_ref();

        let mut context = ParseContext { file_path: path.to_str().unwrap().to_string(), row: 0 };
        let mut lines = CommentedLine::read(path)?.peekable();

        let mut sections: Sections = Sections::new();
        let mut files = vec![];
        let mut global_categories = Categories::new();

        while let Some(line) = lines.next() {
            let line = line?;
            context.row = line.row;
            if line.text.trim().is_empty() {
                continue;
            } else if let Some(delink_file) = Self::try_parse_delink_file(&line, &mut lines, &mut context, &sections)? {
                files.push(delink_file);
                break;
            } else if let Some(new_categories) = Categories::try_parse(&line) {
                global_categories.extend(new_categories);
            } else {
                let section = Section::parse(&line, &context)?;
                sections.add(section).map_err(|error| SectionsSnafu { context: context.clone(), error }.build())?;
            }
        }

        while let Some(line) = lines.next() {
            let line = line?;
            context.row = line.row;

            if line.text.trim().is_empty() {
                continue;
            } else if let Some(delink_file) = Self::try_parse_delink_file(&line, &mut lines, &mut context, &sections)? {
                files.push(delink_file);
            }
        }

        Ok(Self { sections, global_categories, files, module_kind })
    }

    fn try_parse_delink_file(
        line: &CommentedLine,
        lines: &mut Peekable<CommentedLineIterator>,
        context: &mut ParseContext,
        sections: &Sections,
    ) -> Result<Option<DelinkFile>, DelinkFileParseError> {
        if line.text.chars().next().is_some_and(|c| !c.is_whitespace()) {
            let delink_file = DelinkFile::parse(line, lines, context, sections)?;
            Ok(Some(delink_file))
        } else {
            Ok(None)
        }
    }

    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), DelinksWriteError> {
        let path = path.as_ref();

        let file = create_file(path)?;
        let mut writer = BufWriter::new(file);
        write!(writer, "{}", self)?;

        Ok(())
    }

    pub fn module_kind(&self) -> ModuleKind {
        self.module_kind
    }
}

impl Display for Delinks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if !self.global_categories.categories.is_empty() {
            writeln!(f, "{}", self.global_categories)?;
        }
        for section in self.sections.sorted_by_address() {
            writeln!(f, "{section}")?;
        }
        for file in &self.files {
            writeln!(f)?;
            write!(f, "{file}")?;
        }
        Ok(())
    }
}

pub struct DelinkFile {
    pub name: String,
    pub sections: Sections,
    pub complete: bool,
    pub categories: Categories,
    gap: bool,
    pub comments: Comments,
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

pub struct DelinkFileOptions {
    pub name: String,
    pub sections: Sections,
    pub complete: bool,
    pub categories: Categories,
    pub gap: bool,
    pub comments: Comments,
}

impl DelinkFile {
    pub fn new(options: DelinkFileOptions) -> Self {
        let DelinkFileOptions { name, sections, complete, categories, gap, mut comments } = options;
        comments.remove_leading_blank_lines();
        Self { name, sections, complete, categories, gap, comments }
    }

    pub fn parse(
        first_line: &CommentedLine,
        lines: &mut Peekable<CommentedLineIterator>,
        context: &mut ParseContext,
        inherit_sections: &Sections,
    ) -> Result<Self, DelinkFileParseError> {
        let name = first_line
            .text
            .trim()
            .strip_suffix(':')
            .ok_or_else(|| MissingColonSnafu { context: context.clone() }.build())?
            .to_string();

        let mut complete = false;
        let mut sections = Sections::new();
        let mut categories = Categories::new();

        loop {
            if let Some(Ok(next)) = lines.peek()
                && next.text.chars().next().is_some_and(|c| !c.is_whitespace())
            {
                break;
            }

            let Some(line) = lines.next() else {
                break;
            };
            let line = line?;
            context.row = line.row;
            let text = line.text.trim();
            if text.is_empty() {
                break;
            } else if text == "complete" {
                complete = true;
            } else if let Some(new_categories) = Categories::try_parse(&line) {
                categories.extend(new_categories);
            } else {
                let section = Section::parse_inherit(&line, context, inherit_sections)?;
                sections.add(section)?;
            }
        }

        Ok(DelinkFile::new(DelinkFileOptions {
            name,
            sections,
            complete,
            categories,
            gap: false,
            comments: first_line.comments.clone(),
        }))
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
        self.comments.write_pre_comments(f)?;
        write!(f, "{}:", self.name)?;
        self.comments.write_post_comment(f)?;
        writeln!(f)?;

        if !self.categories.categories.is_empty() {
            writeln!(f, "{}", self.categories)?;
        }
        if self.complete {
            writeln!(f, "    complete")?;
        }
        for section in self.sections.sorted_by_address() {
            section.write_inherit(f)?;
            writeln!(f)?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Categories {
    pub categories: Vec<String>,
    comments: Comments,
}

impl Categories {
    pub fn new() -> Self {
        Self { categories: Vec::new(), comments: Comments::new() }
    }

    pub fn try_parse(line: &CommentedLine) -> Option<Self> {
        let list = line.text.trim().strip_prefix("categories:")?;
        let categories = list.trim().split(',').map(|category| category.trim().to_string()).collect();
        Some(Self { categories, comments: line.comments.clone() })
    }

    pub fn extend(&mut self, other: Categories) {
        self.categories.extend(other.categories);
        self.categories.sort_unstable();
        self.categories.dedup();
    }
}

impl Default for Categories {
    fn default() -> Self {
        Self::new()
    }
}

impl Display for Categories {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.comments.write_pre_comments(f)?;
        let mut iter = self.categories.iter();
        if let Some(category) = iter.next() {
            write!(f, "    categories: {category}")?;
        }
        for category in iter {
            write!(f, ", {category}")?;
        }
        self.comments.write_post_comment(f)?;
        Ok(())
    }
}
