use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use ds_decomp::{
    self,
    analysis::functions::{Function, FunctionParseOptions, ParseFunctionOptions},
};
use object::{LittleEndian, Object, ObjectSection, ObjectSymbol};

use crate::{analysis::signature::Signatures, util::io};

#[derive(Args)]
pub struct NewElfSignature {
    /// ELF to extract function from
    #[arg(long, short = 'e')]
    elf_path: PathBuf,

    /// Function name to create the signature for.
    #[arg(long, short = 'f')]
    function: String,
}

impl NewElfSignature {
    pub fn run(&self) -> Result<()> {
        let object_bytes = io::read_file(&self.elf_path)?;
        let object = object::read::elf::ElfFile32::<LittleEndian>::parse(object_bytes.as_slice())?;
        let function_symbol = object
            .symbol_by_name(&self.function)
            .with_context(|| format!("Symbol '{}' not found", self.function))?;
        let function_section_index = function_symbol.section_index().unwrap();
        let function_section = object.section_by_index(function_section_index).unwrap();
        let section_data = function_section.uncompressed_data()?;
        let start = function_symbol.address() as usize;
        let end = (function_symbol.address() + function_symbol.size()) as usize;
        let function_code = &section_data[start..end];

        let function = Function::parse_function(FunctionParseOptions {
            name: self.function.clone(),
            start_address: start as u32,
            base_address: start as u32,
            module_code: function_code,
            known_end_address: Some(end as u32),
            module_start_address: start as u32,
            module_end_address: end as u32,
            existing_functions: None,
            check_defs_uses: false,
            parse_options: ParseFunctionOptions { thumb: None },
        })?;
        println!("{function:#x?}");

        // TODO: Rename function
        let signature = Signatures::from_function2(&function, function_code, |address| todo!())?;

        let signature_yaml = serde_saphyr::to_string(&signature)?;
        print!("{signature_yaml}");

        Ok(())
    }
}
