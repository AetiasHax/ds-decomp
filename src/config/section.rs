use anyhow::{bail, Context, Result};

use crate::util::parse::parse_u32;

use super::{parse_attributes, ParseContext};

pub struct Section {
    pub name: String,
    pub start_address: u32,
    pub end_address: u32,
    pub alignment: u32,
}

impl Section {
    pub fn parse(line: &str, context: &ParseContext) -> Result<Option<Self>> {
        let Some(attributes) = parse_attributes(line, context)? else {
            return Ok(None);
        };
        let name = attributes.name.to_string();

        let mut start = None;
        let mut end = None;
        let mut align = None;
        for pair in attributes {
            let (key, value) = pair?;
            match key {
                "start" => {
                    start = Some(
                        parse_u32(value).with_context(|| format!("{}: failed to parse start address '{}'", context, value))?,
                    )
                }
                "end" => {
                    end = Some(
                        parse_u32(value).with_context(|| format!("{}: failed to parse end address '{}'", context, value))?,
                    )
                }
                "align" => {
                    align =
                        Some(parse_u32(value).with_context(|| format!("{}: failed to parse alignment '{}'", context, value))?)
                }
                _ => bail!("{}: expected symbol attribute 'start', 'end' or 'align' but got '{}'", context, key),
            }
        }

        Ok(Some(Section {
            name,
            start_address: start.with_context(|| format!("{}: missing 'start' attribute", context))?,
            end_address: end.with_context(|| format!("{}: missing 'end' attribute", context))?,
            alignment: align.with_context(|| format!("{}: missing 'align' attribute", context))?,
        }))
    }
}
