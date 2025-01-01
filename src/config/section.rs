use std::ops::Range;

use anyhow::{Context, Result};
use ds_decomp_config::config::{
    module::Module,
    relocations::{Relocation, RelocationKind},
    section::Section,
};
use object::{Object, ObjectSymbol};

pub trait SectionExt {
    fn relocatable_code(&self, module: &Module) -> Result<Option<Vec<u8>>>;
    fn relocations<'a>(&'a self, module: &'a Module) -> impl Iterator<Item = &'a Relocation>;

    /// Name of this section for creating section boundary symbols, e.g. ARM9_BSS_START
    fn boundary_name(&self) -> String;
    fn range_from_object(&self, module_name: &str, object: &object::File<'_>) -> Result<Range<u32>>;
}

impl SectionExt for Section {
    fn relocatable_code(&self, module: &Module) -> Result<Option<Vec<u8>>> {
        let Some(code) = self.code_from_module(module)? else { return Ok(None) };
        let mut code = code.to_vec();

        for relocation in self.relocations(module) {
            let from = relocation.from_address();
            let offset = (from - self.start_address()) as usize;

            // Clear bits in `code` to treat them as the implicit addend
            let ins = match relocation.kind() {
                RelocationKind::ArmCall => {
                    // R_ARM_PC24
                    &[0xfe, 0xff, 0xff, 0xeb] // bl #0
                }
                RelocationKind::ArmCallThumb => {
                    // R_ARM_XPC25
                    &[0xfe, 0xff, 0xff, 0xfa] // blx #0
                }
                RelocationKind::ThumbCall => {
                    // R_ARM_THM_PC22
                    &[0xff, 0xf7, 0xfe, 0xff] // bl #0
                }
                RelocationKind::ThumbCallArm => {
                    // R_ARM_THM_XPC22
                    &[0xff, 0xf7, 0xfe, 0xff] // bl #0
                }
                RelocationKind::ArmBranch => {
                    // R_ARM_PC24
                    &[0xfe, 0xff, 0xff, 0xea] // b #0
                }
                RelocationKind::Load => {
                    // R_ARM_ABS32
                    &[0x00, 0x00, 0x00, 0x00]
                }
            };
            code[offset..offset + 4].copy_from_slice(ins);
        }

        Ok(Some(code))
    }

    fn relocations<'a>(&'a self, module: &'a Module) -> impl Iterator<Item = &'a Relocation> {
        module.relocations().iter_range(self.address_range()).map(|(_, r)| r)
    }

    /// Name of this section for creating section boundary symbols, e.g. ARM9_BSS_START
    fn boundary_name(&self) -> String {
        self.name().strip_prefix('.').unwrap_or(self.name()).to_uppercase()
    }

    fn range_from_object(&self, module_name: &str, object: &object::File<'_>) -> Result<Range<u32>> {
        let boundary_name = self.boundary_name();
        let boundary_start = format!("{module_name}_{boundary_name}_START");
        let boundary_end = format!("{module_name}_{boundary_name}_END");
        let start = object
            .symbol_by_name(&boundary_start)
            .with_context(|| format!("Failed to find symbol {boundary_start}"))?
            .address() as u32;
        let end =
            object.symbol_by_name(&boundary_end).with_context(|| format!("Failed to find symbol {boundary_end}"))?.address()
                as u32;
        Ok(start..end)
    }
}
