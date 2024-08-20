use std::ops::Range;

use anyhow::Result;

use super::{module::Module, section::Section};

pub struct Program<'a> {
    modules: Vec<Module<'a>>,
    // Indices in modules vec above
    main: usize,
    overlays: Range<usize>,
    autoloads: Range<usize>,
}

impl<'a> Program<'a> {
    pub fn new(main: Module<'a>, overlays: Vec<Module<'a>>, autoloads: Vec<Module<'a>>) -> Self {
        let mut modules = vec![main];
        let main = 0;

        modules.extend(overlays);
        let overlays = (main + 1)..modules.len();

        modules.extend(autoloads);
        let autoloads = overlays.end..modules.len();

        Self { modules, main, overlays, autoloads }
    }

    pub fn analyze_cross_references(&mut self) -> Result<()> {
        for module_index in 0..self.modules.len() {
            // Borrow module separately from the rest
            let (before, after) = self.modules.split_at_mut(module_index);
            let (module, after) = after.split_first_mut().unwrap();

            let external = ExternalModules { before, after };

            module.analyze_cross_refences(&external)?;
        }
        Ok(())
    }

    pub fn main(&self) -> &Module {
        &self.modules[self.main]
    }

    pub fn overlays(&self) -> &[Module] {
        &self.modules[self.overlays.clone()]
    }

    pub fn autoloads(&self) -> &[Module] {
        &self.modules[self.autoloads.clone()]
    }
}

pub struct ExternalModules<'a> {
    before: &'a [Module<'a>],
    after: &'a [Module<'a>],
}

impl<'a> ExternalModules<'a> {
    fn _sections_containing(modules: &'a [Module], address: u32) -> impl Iterator<Item = (&'a Module<'a>, &'a Section<'a>)> {
        modules.iter().filter_map(move |module| {
            if let Some(section) = module.sections().get_by_contained_address(address) {
                Some((module, section))
            } else {
                None
            }
        })
    }

    pub fn sections_containing(&self, address: u32) -> impl Iterator<Item = (&'a Module<'a>, &'a Section<'a>)> {
        Self::_sections_containing(self.before, address).chain(Self::_sections_containing(self.after, address))
    }
}
