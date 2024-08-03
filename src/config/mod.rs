use std::{fmt::Display, str::SplitWhitespace};

use anyhow::{Context, Result};

pub mod config;
pub mod module;
pub mod section;
pub mod splits;
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

pub fn parse_attributes<'a>(line: &'a str, context: &'a ParseContext) -> Result<Option<ParseAttributesIterator<'a>>> {
    let mut words = line.split_whitespace();
    let Some(name) = words.next() else { return Ok(None) };
    Ok(Some(ParseAttributesIterator { name, context, words }))
}

pub struct ParseAttributesIterator<'a> {
    pub name: &'a str,
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
