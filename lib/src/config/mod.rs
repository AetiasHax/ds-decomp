use std::{fmt::Display, str::SplitWhitespace};

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
