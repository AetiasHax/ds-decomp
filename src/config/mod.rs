use std::{fmt::Display, str::SplitWhitespace};

use anyhow::{Context, Result};

pub mod config;
pub mod delinks;
pub mod module;
pub mod program;
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

pub fn iter_attributes<'a>(words: SplitWhitespace<'a>, context: &'a ParseContext) -> ParseAttributesIterator<'a> {
    ParseAttributesIterator { context, words }
}

pub struct ParseAttributesIterator<'a> {
    context: &'a ParseContext,
    words: SplitWhitespace<'a>,
}

impl<'a> Iterator for ParseAttributesIterator<'a> {
    type Item = Result<(&'a str, &'a str)>;

    fn next(&mut self) -> Option<Self::Item> {
        let Some(word) = self.words.next() else { return None };
        Some(word.split_once(':').with_context(|| {
            format!("{}:{}: expected 'key:value' but got '{}'", self.context.file_path, self.context.row, word)
        }))
    }
}
