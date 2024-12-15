use std::{fmt::Display, str::SplitWhitespace};

pub mod config;
pub mod delinks;
pub mod module;
pub mod program;
pub mod relocation;
pub mod section;
pub mod symbol;

pub struct ParseContext {
    file_path: String,
    row: usize,
}

impl Display for ParseContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.file_path, self.row)
    }
}

pub fn iter_attributes(words: SplitWhitespace<'_>) -> ParseAttributesIterator<'_> {
    ParseAttributesIterator { words }
}

pub struct ParseAttributesIterator<'a> {
    words: SplitWhitespace<'a>,
}

impl<'a> Iterator for ParseAttributesIterator<'a> {
    type Item = (&'a str, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        let word = self.words.next()?;
        Some(word.split_once(':').unwrap_or((word, "")))
    }
}
