use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use ds_decomp::{
    analysis::functions::{Function, FunctionParseOptions, ParseFunctionOptions},
    config::{config::Config, module::ModuleKind, symbol::SymbolMaps},
};
use object::{Object, ObjectSection, ObjectSymbol};

use crate::{
    analysis::functions::FunctionExt,
    config::{
        module::ModuleKindExt,
        symbol::{SymbolLookup, SymbolMapsExt},
    },
    util::io::read_file,
};

/// Dumps info about a function from the linked ELF file.
#[derive(Args, Clone)]
pub struct DumpElfFunction {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    config_path: PathBuf,

    // Name of the ELF file, defaults to arm9.o.
    #[arg(long, short = 'e', default_value = "arm9.o")]
    elf_name: String,

    /// Name of the function.
    #[arg(long, short = 'n')]
    name: String,
}

impl DumpElfFunction {
    pub fn run(&self) -> anyhow::Result<()> {
        let config = Config::from_file(&self.config_path)?;
        let config_path = self.config_path.parent().unwrap();

        let elf_data = self.read_elf(&config, config_path)?;
        let object = self.parse_elf(&elf_data)?;

        let symbol = self.find_symbol(&object)?;
        self.print_symbol(&symbol);

        let section = self.get_section_for_symbol(&object, &symbol)?;
        let section_name = self.get_section_name(&section)?;
        self.print_section(section_name);

        let module_kind = self.infer_module_kind(section_name)?;
        self.print_module(module_kind);

        for section in object.sections() {
            for (src_addr, relocation) in section.relocations() {
                let object::RelocationTarget::Symbol(symbol_index) = relocation.target() else {
                    continue;
                };
                if symbol_index != symbol.index() {
                    continue;
                }
                let section_name = self.get_section_name(&section)?;
                let module_kind = self.infer_module_kind(section_name)?;
                println!("  Relocation from: {:#010x} in {}", src_addr, module_kind);
            }
        }

        let data = self.read_data(&config, module_kind)?;
        self.print_data(&symbol, &section, &data);
        self.print_disassembly(&object, &symbol, &section, module_kind, &data)?;

        Ok(())
    }

    fn read_elf(&self, config: &Config, config_path: &Path) -> Result<Vec<u8>, anyhow::Error> {
        let build_path = config_path.join(&config.build_path);
        let elf_path = build_path.join(&self.elf_name);
        Ok(read_file(&elf_path)?)
    }

    fn parse_elf<'a>(&self, data: &'a [u8]) -> Result<object::File<'a>, anyhow::Error> {
        Ok(object::File::parse(data)?)
    }

    fn find_symbol<'a>(&self, object: &'a object::File<'_>) -> Result<object::Symbol<'a, '_>> {
        object.symbol_by_name(&self.name).context("No function with that name was found")
    }

    fn print_symbol(&self, symbol: &object::Symbol<'_, '_>) {
        println!("{}:", self.name);
        println!("  Address: {:#010x}", symbol.address());
        println!("  Size: {:#x}", symbol.size());
    }

    fn get_section_for_symbol<'a>(
        &self,
        object: &'a object::File<'_>,
        symbol: &object::Symbol<'_, '_>,
    ) -> Result<object::Section<'a, '_>> {
        let section_index = symbol.section_index().context("Function symbol has no section")?;
        object.section_by_index(section_index).context("Function's section not found")
    }

    fn get_section_name<'a>(&self, section: &'a object::Section<'_, '_>) -> Result<&'a str> {
        section.name().context("Failed to get section name")
    }

    fn print_section(&self, section_name: &str) {
        println!("  Section: {}", section_name);
    }

    fn infer_module_kind(&self, section_name: &str) -> Result<ModuleKind> {
        ModuleKind::from_linked_section_name(section_name)
            .context("Failed to get module kind")?
            .context("Section name does not match any known module")
    }

    fn print_module(&self, module_kind: ModuleKind) {
        println!("  Module: {}", module_kind);
    }

    fn read_data(&self, config: &Config, module_kind: ModuleKind) -> Result<Vec<u8>> {
        let config_path = self.config_path.parent().unwrap();
        let config_module = config
            .get_module_config_by_kind(module_kind)
            .with_context(|| format!("{} not found in config.yaml", module_kind))?;
        let bin_file_path = config_path.join(&config_module.object);
        read_file(&bin_file_path).with_context(|| {
            format!("Failed to read section data from {}", bin_file_path.display())
        })
    }

    fn print_data(
        &self,
        symbol: &object::Symbol<'_, '_>,
        section: &object::Section<'_, '_>,
        data: &[u8],
    ) {
        println!("  Data:");
        let start = (symbol.address() + 1).next_multiple_of(16) - 16;
        let end = (symbol.address() + symbol.size()).next_multiple_of(16);
        for row_address in (start..end).step_by(16) {
            print!("    {:08x} ", row_address);
            for i in 0..16 {
                let address = row_address + i;
                if (symbol.address()..symbol.address() + symbol.size()).contains(&address) {
                    print!(" {:02x}", data[(address - section.address()) as usize]);
                } else {
                    print!(" ..");
                }
            }
            println!();
        }
    }

    fn print_disassembly(
        &self,
        object: &object::File<'_>,
        symbol: &object::Symbol<'_, '_>,
        section: &object::Section<'_, '_>,
        module_kind: ModuleKind,
        data: &[u8],
    ) -> Result<(), anyhow::Error> {
        let function = Function::parse_function(FunctionParseOptions {
            name: self.name.clone(),
            start_address: symbol.address() as u32,
            base_address: section.address() as u32,
            module_code: data,
            known_end_address: None,
            module_start_address: section.address() as u32,
            module_end_address: section.address() as u32 + data.len() as u32,
            existing_functions: None,
            dsprot_encrypted_ranges: &[],
            check_defs_uses: false,
            parse_options: ParseFunctionOptions { thumb: None },
        })
        .context("Failed to parse function")?;

        let symbol_maps =
            SymbolMaps::from_object(object).context("Failed to construct symbol maps from ELF")?;
        let symbol_map = symbol_maps.get(module_kind).unwrap();
        let symbol_lookup =
            SymbolLookup { module_kind, symbol_map, symbol_maps: &symbol_maps, relocations: None };

        println!("Disassembly:");
        function.write_assembly(
            &mut std::io::stdout().lock(),
            &symbol_lookup,
            data,
            section.address() as u32,
            true,
        )?;
        Ok(())
    }
}
