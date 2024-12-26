use std::ops::Range;

use anyhow::{bail, Result};

use crate::{
    analysis::data::{self, AnalyzeExternalReferencesOptions, RelocationResult, SymbolCandidate},
    function,
};

use super::{
    module::{AnalysisOptions, Module},
    section::SectionKind,
    symbol::{SymBss, SymData, SymbolMaps},
};

pub struct Program<'a> {
    modules: Vec<Module<'a>>,
    symbol_maps: SymbolMaps,
    // Indices in modules vec above
    main: usize,
    overlays: Range<usize>,
    autoloads: Range<usize>,
}

impl<'a> Program<'a> {
    pub fn new(main: Module<'a>, overlays: Vec<Module<'a>>, autoloads: Vec<Module<'a>>, symbol_maps: SymbolMaps) -> Self {
        let mut modules = vec![main];
        let main = 0;

        modules.extend(overlays);
        let overlays = (main + 1)..modules.len();

        modules.extend(autoloads);
        let autoloads = overlays.end..modules.len();

        Self { modules, symbol_maps, main, overlays, autoloads }
    }

    pub fn analyze_cross_references(&mut self, options: &AnalysisOptions) -> Result<()> {
        for module_index in 0..self.modules.len() {
            let RelocationResult { relocations, external_symbols } = data::analyze_external_references(
                AnalyzeExternalReferencesOptions { modules: &self.modules, module_index, symbol_maps: &mut self.symbol_maps },
                options,
            )?;

            let module_relocations = self.modules[module_index].relocations_mut();
            for reloc in relocations {
                let reloc = module_relocations.add(reloc)?;
                if options.provide_reloc_source {
                    reloc.source = Some(function!().to_string());
                }
            }

            for symbol in external_symbols {
                match symbol.candidates.len() {
                    0 => {
                        log::error!("There should be at least one symbol candidate");
                        bail!("There should be at least one symbol candidate");
                    }
                    1 => {
                        let SymbolCandidate { module_index, section_index } = symbol.candidates[0];
                        let section_kind = self.modules[module_index].sections().get(section_index).kind();
                        let name = format!("{}{:08x}", self.modules[module_index].default_data_prefix, symbol.address);
                        let symbol_map = self.symbol_maps.get_mut(self.modules[module_index].kind());
                        match section_kind {
                            SectionKind::Code => {} // Function symbol, already verified to exist
                            SectionKind::Data => {
                                symbol_map.add_data(Some(name), symbol.address, SymData::Any)?;
                            }
                            SectionKind::Bss => {
                                symbol_map.add_bss(Some(name), symbol.address, SymBss { size: None })?;
                            }
                        }
                    }
                    _ => {
                        for SymbolCandidate { module_index, section_index } in symbol.candidates {
                            let section_kind = self.modules[module_index].sections().get(section_index).kind();
                            let name = format!("{}{:08x}", self.modules[module_index].default_data_prefix, symbol.address);
                            let symbol_map = self.symbol_maps.get_mut(self.modules[module_index].kind());
                            match section_kind {
                                SectionKind::Code => {} // Function symbol, already verified to exist
                                SectionKind::Data => {
                                    symbol_map.add_ambiguous_data(Some(name), symbol.address, SymData::Any)?;
                                }
                                SectionKind::Bss => {
                                    symbol_map.add_ambiguous_bss(Some(name), symbol.address, SymBss { size: None })?;
                                }
                            }
                        }
                    }
                }
            }
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

    pub fn module(&self, index: usize) -> &Module {
        &self.modules[index]
    }

    pub fn module_mut(&'a mut self, index: usize) -> &'a mut Module<'a> {
        &mut self.modules[index]
    }

    pub fn num_modules(&self) -> usize {
        self.modules.len()
    }

    pub fn symbol_maps(&self) -> &SymbolMaps {
        &self.symbol_maps
    }
}
