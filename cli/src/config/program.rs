use std::{ops::Range, path::Path};

use anyhow::{Result, bail};
use ds_decomp::config::{
    config::Config,
    module::{AnalysisOptions, Module, ModuleKind},
    section::SectionKind,
    symbol::{SymBss, SymData, SymbolMaps},
};

use crate::{
    analysis::data::{self, AnalyzeExternalReferencesOptions, RelocationResult, SymbolCandidate},
    function,
};

pub struct Program {
    modules: Vec<Module>,
    symbol_maps: SymbolMaps,
    // Indices in modules vec above
    main: usize,
    overlays: Range<usize>,
    autoloads: Range<usize>,
}

impl Program {
    pub fn new(main: Module, overlays: Vec<Module>, autoloads: Vec<Module>, symbol_maps: SymbolMaps) -> Self {
        let mut modules = vec![main];
        let main = 0;

        modules.extend(overlays);
        let overlays = (main + 1)..modules.len();

        modules.extend(autoloads);
        let autoloads = overlays.end..modules.len();

        Self { modules, symbol_maps, main, overlays, autoloads }
    }

    pub fn from_config<P: AsRef<Path>>(config_path: P, config: &Config) -> Result<Self> {
        let config_path = config_path.as_ref();

        let mut symbol_maps = SymbolMaps::from_config(config_path, config)?;

        let main = config.load_module(config_path, &mut symbol_maps, ModuleKind::Arm9)?;
        let overlays = config
            .overlays
            .iter()
            .map(|overlay| Ok(config.load_module(config_path, &mut symbol_maps, ModuleKind::Overlay(overlay.id))?))
            .collect::<Result<Vec<_>>>()?;
        let autoloads = config
            .autoloads
            .iter()
            .map(|autoload| Ok(config.load_module(config_path, &mut symbol_maps, ModuleKind::Autoload(autoload.kind))?))
            .collect::<Result<Vec<_>>>()?;

        Ok(Self::new(main, overlays, autoloads, symbol_maps))
    }

    pub fn analyze_cross_references(&mut self, options: &AnalysisOptions) -> Result<()> {
        for module_index in 0..self.modules.len() {
            let RelocationResult { relocations, external_symbols } = data::analyze_external_references(
                AnalyzeExternalReferencesOptions {
                    modules: &self.modules,
                    module_index,
                    symbol_maps: &mut self.symbol_maps,
                },
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
                            SectionKind::Data | SectionKind::Rodata => {
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
                                SectionKind::Data | SectionKind::Rodata => {
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

    pub fn by_module_kind(&self, module_kind: ModuleKind) -> Option<&Module> {
        self.modules.iter().find(|m| m.kind() == module_kind)
    }

    pub fn by_module_kind_mut(&mut self, module_kind: ModuleKind) -> Option<&mut Module> {
        self.modules.iter_mut().find(|m| m.kind() == module_kind)
    }

    pub fn module(&self, index: usize) -> &Module {
        &self.modules[index]
    }

    pub fn module_mut(&mut self, index: usize) -> &mut Module {
        &mut self.modules[index]
    }

    pub fn modules(&self) -> &[Module] {
        &self.modules
    }

    pub fn modules_mut(&mut self) -> &mut [Module] {
        &mut self.modules
    }

    pub fn num_modules(&self) -> usize {
        self.modules.len()
    }

    pub fn symbol_maps(&self) -> &SymbolMaps {
        &self.symbol_maps
    }

    pub fn symbol_maps_mut(&mut self) -> &mut SymbolMaps {
        &mut self.symbol_maps
    }

    /// Writes the symbols.txt and relocs.txt files for each module in the program.
    pub fn write_to_files<P: AsRef<Path>>(&self, config_path: P, config: &Config) -> Result<()> {
        let config_path = config_path.as_ref();

        self.symbol_maps.to_files(config, config_path)?;
        for module in &self.modules {
            let module_config = config.get_module_config_by_kind(module.kind()).unwrap();
            module.relocations().to_file(config_path.join(&module_config.relocations))?;
        }

        Ok(())
    }
}
