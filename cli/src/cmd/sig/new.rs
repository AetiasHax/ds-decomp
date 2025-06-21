use std::path::PathBuf;

use anyhow::{anyhow, Result};
use clap::Args;
use ds_decomp::config::{
    config::Config,
    module::ModuleKind,
    symbol::{Symbol, SymbolKind, SymbolMaps},
};

use crate::analysis::signature::Signatures;

#[derive(Args)]
pub struct NewSignature {
    /// Path to config.yaml
    #[arg(long, short = 'c')]
    config_path: PathBuf,

    /// Function name to create the signature for.
    #[arg(long, short = 'f')]
    function: String,

    /// Which function to use, if there are multiple.
    #[arg(long, short = 'n')]
    index: Option<usize>,
}

impl NewSignature {
    pub fn run(&self) -> Result<()> {
        let config_path = self.config_path.parent().unwrap();
        let config = Config::from_file(&self.config_path)?;

        let mut symbol_maps = SymbolMaps::from_config(config_path, &config)?;
        let function_results = self.find_function(&symbol_maps)?;

        if function_results.is_empty() {
            log::error!("No function found with name '{}'", self.function);
            return Ok(());
        }
        if function_results.len() > 1 && self.index.is_none() {
            log::error!("Multiple functions found with name '{}':", self.function);
            for (index, result) in function_results.iter().enumerate() {
                log::error!("  {}: in {} at address {:#010x}", index, result.module_kind, result.symbol.addr);
            }
            log::error!("Please specify an index with --index to choose one of them.");
            return Ok(());
        }
        let function_result = if let Some(index) = self.index {
            function_results.get(index).ok_or_else(|| anyhow!("Index {} is out of bounds for the found functions", index))?
        } else {
            &function_results[0]
        };

        let &FunctionFindResult { ref symbol, module_kind } = function_result;

        let module = config.load_module(config_path, &mut symbol_maps, module_kind)?;
        let function = module.get_function(symbol.addr).ok_or_else(|| {
            anyhow!("Function '{}' at address {:#010x} not found in {}", symbol.name, symbol.addr, module_kind)
        })?;
        let signature = Signatures::from_function(function, &module, &symbol_maps)?;

        let signature_yaml = serde_yml::to_string(&signature)?;
        print!("{signature_yaml}");

        Ok(())
    }

    fn find_function(&self, symbol_maps: &SymbolMaps) -> Result<Vec<FunctionFindResult>> {
        let results = symbol_maps
            .iter()
            .flat_map(|(module_kind, map)| {
                map.iter().filter_map(move |symbol| {
                    let SymbolKind::Function(_) = &symbol.kind else {
                        return None;
                    };
                    (symbol.name == self.function).then_some(FunctionFindResult { symbol: symbol.clone(), module_kind })
                })
            })
            .collect::<Vec<_>>();
        Ok(results)
    }
}

struct FunctionFindResult {
    symbol: Symbol,
    module_kind: ModuleKind,
}
