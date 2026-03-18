use std::{collections::BTreeMap, path::PathBuf};

use anyhow::{Context, Result, bail};
use clap::Args;
use ds_decomp::{
    self,
    analysis::functions::{Function, FunctionParseOptions, ParseFunctionOptions},
    config::relocations::RelocationKind,
};
use object::{
    LittleEndian, Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationTarget,
};
use unarm::arm;

use crate::{
    analysis::signature::{SignatureRelocationInfo, Signatures},
    config::relocation::RelocationKindExt,
    util::io,
};

#[derive(Args)]
pub struct NewElfSignature {
    /// ELF to extract function from
    #[arg(long, short = 'i')]
    input: PathBuf,

    /// Function name to create the signature for.
    #[arg(long, short = 'f')]
    function: String,
}

impl NewElfSignature {
    pub fn run(&self) -> Result<()> {
        let object_bytes = io::read_file(&self.input)?;
        let object = object::read::elf::ElfFile32::<LittleEndian>::parse(object_bytes.as_slice())?;
        let function_symbol = object
            .symbol_by_name(&self.function)
            .with_context(|| format!("Symbol '{}' not found", self.function))?;
        let function_section_index = function_symbol.section_index().unwrap();
        let function_section = object.section_by_index(function_section_index).unwrap();
        let section_data = function_section.uncompressed_data()?;
        let start_address = function_symbol.address() as u32;
        let end_address = (function_symbol.address() + function_symbol.size()) as u32;
        let function_code = &section_data[start_address as usize..end_address as usize];

        let function = Function::parse_function(FunctionParseOptions {
            name: self.function.clone(),
            start_address: start_address as u32,
            base_address: start_address as u32,
            module_code: function_code,
            known_end_address: Some(end_address as u32),
            module_start_address: start_address as u32,
            module_end_address: end_address as u32,
            existing_functions: None,
            check_defs_uses: false,
            parse_options: ParseFunctionOptions { thumb: None },
        })?;

        let relocations = function_section
            .relocations()
            .map(|(offset, reloc)| (offset as u32, reloc))
            .filter(|(offset, _)| *offset >= start_address && *offset < end_address)
            .collect::<BTreeMap<_, _>>();

        let signature = Signatures::from_function_raw(&function, function_code, |address, ins| {
            let Some(relocation) = relocations.get(&address) else {
                if ins.is_some() {
                    bail!("Relocation not found for instruction");
                } else {
                    // It's just data, could be a large constant or a link-time constant
                    return Ok(None);
                }
            };
            let target_symbol = match relocation.target() {
                RelocationTarget::Symbol(symbol_index) => {
                    object.symbol_by_index(symbol_index).unwrap()
                }
                target => bail!("Invalid relocation target {target:?}"),
            };
            let name = target_symbol.name().unwrap().to_string();
            let kind = match relocation.flags() {
                RelocationFlags::Elf { r_type } => {
                    // FIXME: mwcc-generated ELFs do not seem to set bit zero to 1 for Thumb
                    // functions, so this ends up being `false` all the time.
                    let dest_thumb = (target_symbol.address() & 1) != 0;
                    // `ins` may be `None` if the relocation is R_ARM_ABS32
                    // `is_branch` only applies to ARM tail calls as there are no recorded instances
                    // of Thumb branches used for tail calls
                    let is_branch = match ins {
                        Some(unarm::Ins::Arm(ins)) => ins.op == arm::Opcode::B,
                        _ => false,
                    };
                    RelocationKind::from_elf_relocation_type(r_type, dest_thumb, is_branch).unwrap()
                }
                flags => bail!("Invalid relocation flags {flags:?}"),
            };
            let addend = match kind {
                RelocationKind::ArmCall | RelocationKind::ArmCallThumb => {
                    relocation.addend() as i32 + 8
                }
                RelocationKind::ThumbCall | RelocationKind::ThumbCallArm => {
                    relocation.addend() as i32 + 4
                }
                RelocationKind::ArmBranch => relocation.addend() as i32,
                RelocationKind::Load
                | RelocationKind::OverlayId
                | RelocationKind::LinkTimeConst(_) => relocation.addend() as i32,
            };
            Ok(Some(SignatureRelocationInfo { name, kind, addend }))
        })?;

        let signature_yaml = serde_saphyr::to_string(&signature)?;
        print!("{signature_yaml}");

        Ok(())
    }
}
