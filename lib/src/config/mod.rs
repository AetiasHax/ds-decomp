use std::{
    fmt::Display,
    fs::File,
    io::{BufRead as _, BufReader, Lines},
    path::Path,
    str::SplitWhitespace,
};

use crate::util::io::{FileError, open_file};

pub mod config;
pub mod delinks;
pub mod module;
pub mod relocations;
pub mod section;
pub mod symbol;

#[derive(Debug, Clone)]
pub struct ParseContext {
    pub file_path: String,
    pub row: usize,
}

impl Display for ParseContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.file_path, self.row)
    }
}

// Shorthand for snafu errors
impl From<&ParseContext> for ParseContext {
    fn from(val: &ParseContext) -> Self {
        val.clone()
    }
}
impl From<&mut ParseContext> for ParseContext {
    fn from(val: &mut ParseContext) -> Self {
        val.clone()
    }
}

pub(crate) fn iter_attributes(words: SplitWhitespace<'_>) -> ParseAttributesIterator<'_> {
    ParseAttributesIterator { words }
}

pub(crate) struct ParseAttributesIterator<'a> {
    words: SplitWhitespace<'a>,
}

impl<'a> Iterator for ParseAttributesIterator<'a> {
    type Item = (&'a str, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        let word = self.words.next()?;
        Some(word.split_once(':').unwrap_or((word, "")))
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct Comments {
    /// Lines of comments or blank lines that precede the main text line.
    pub pre_lines: Vec<String>,
    /// Comment at the end of the main text line.
    pub post_comment: Option<String>,
}

impl Comments {
    pub fn new() -> Self {
        Self { pre_lines: Vec::new(), post_comment: None }
    }

    pub fn display_pre_comments(&self) -> DisplayPreComments<'_> {
        DisplayPreComments { comments: self }
    }

    pub fn display_post_comment(&self) -> DisplayPostComment<'_> {
        DisplayPostComment { comments: self }
    }

    pub fn remove_leading_blank_lines(&mut self) {
        let non_blank_index = self.pre_lines.iter().position(|line| !line.trim().is_empty()).unwrap_or(self.pre_lines.len());
        self.pre_lines.drain(0..non_blank_index);
    }
}

pub struct DisplayPreComments<'a> {
    comments: &'a Comments,
}

impl Display for DisplayPreComments<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for pre_line in &self.comments.pre_lines {
            writeln!(f, "{pre_line}")?;
        }
        Ok(())
    }
}

pub struct DisplayPostComment<'a> {
    comments: &'a Comments,
}

impl Display for DisplayPostComment<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(post_comment) = &self.comments.post_comment {
            write!(f, " {post_comment}")?;
        }
        Ok(())
    }
}

pub struct CommentedLine {
    /// The main text without comments.
    pub text: String,
    pub row: usize,
    pub comments: Comments,
}

impl CommentedLine {
    pub fn read<P>(path: P) -> Result<CommentedLineIterator, FileError>
    where
        P: AsRef<Path>,
    {
        let path = path.as_ref();
        let file = open_file(path)?;
        let reader = BufReader::new(file);
        let lines = reader.lines();
        Ok(CommentedLineIterator { lines, row: 0 })
    }
}

pub struct CommentedLineIterator {
    lines: Lines<BufReader<File>>,
    row: usize,
}

impl Iterator for CommentedLineIterator {
    type Item = Result<CommentedLine, std::io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        let mut pre_lines = Vec::new();
        for line in self.lines.by_ref() {
            self.row += 1;
            let line = match line {
                Ok(line) => line,
                Err(e) => return Some(Err(e)),
            };
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with("//") {
                pre_lines.push(line);
                continue;
            }
            let (text, post_comment) = if let Some(comment_index) = line.find("//") {
                let (text, post_comment) = line.split_at(comment_index);
                (text, Some(post_comment.trim().to_string()))
            } else {
                (line.as_str(), None)
            };
            let text = text.to_string();
            return Some(Ok(CommentedLine { text, row: self.row, comments: Comments { pre_lines, post_comment } }));
        }
        None
    }
}
