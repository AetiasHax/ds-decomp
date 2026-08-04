use std::collections::HashMap;

use object::{Object as _, ObjectSection as _, ObjectSymbol as _};

pub struct ObjectCache<'data, 'file> {
    pub symbols_by_name: HashMap<String, object::Symbol<'data, 'file>>,
    pub sections_by_name: HashMap<String, object::Section<'data, 'file>>,
    pub entry: u32,
}

impl<'data, 'file> ObjectCache<'data, 'file> {
    pub fn new(object: &'data object::File<'data>) -> Self {
        let symbols_by_name = object
            .symbols()
            .filter_map(|symbol| symbol.name().ok().map(|name| (name.to_string(), symbol)))
            .collect::<HashMap<_, _>>();
        let sections_by_name = object
            .sections()
            .filter_map(|section| section.name().ok().map(|name| (name.to_string(), section)))
            .collect::<HashMap<_, _>>();
        let entry = object.entry() as u32;
        Self { symbols_by_name, sections_by_name, entry }
    }
}
