use crate::util::bytes::FromSlice;
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use ds_decomp::{
    analysis::code::blocks::{self, BlockAnalyzer},
    config::{module::ModuleKind, symbol::InstructionMode},
};
use ds_rom::rom::{Arm9, Rom, RomLoadOptions};

#[derive(Args)]
pub struct Init2 {
    /// Path to config file in the extract directory.
    #[arg(long, short = 'r')]
    pub rom_config: PathBuf,
    // /// Output path.
    // #[arg(long, short = 'o')]
    // pub output_path: PathBuf,
}

impl Init2 {
    pub fn run(&self) -> Result<()> {
        let mut block_analyzer = BlockAnalyzer::new();

        let rom = Rom::load(
            &self.rom_config,
            RomLoadOptions {
                key: None,
                compress: false,
                encrypt: false,
                load_files: false,
                load_header: true,
                load_banner: false,
            },
        )?;

        let arm9 = rom.arm9();
        block_analyzer.add_module(blocks::ModuleOptions {
            base_address: arm9.base_address(),
            end_address: arm9.base_address() + arm9.full_data().len() as u32,
            kind: ModuleKind::Arm9,
            code: arm9.full_data().to_vec(),
            data_regions: vec![
                (arm9.base_address(), (arm9.base_address() + 0x800)),
                (arm9.base_address() + arm9.build_info_offset(), (Self::find_build_info_end_address(arm9))),
            ],
        });
        for autoload in arm9.autoloads()? {
            block_analyzer.add_module(blocks::ModuleOptions {
                base_address: autoload.base_address(),
                end_address: autoload.base_address() + autoload.full_data().len() as u32,
                kind: ModuleKind::Autoload(autoload.kind()),
                code: autoload.full_data().to_vec(),
                data_regions: vec![],
            });
        }
        for overlay in rom.arm9_overlays() {
            let end_address = overlay.base_address() + overlay.full_data().len() as u32;
            block_analyzer.add_module(blocks::ModuleOptions {
                base_address: overlay.base_address(),
                end_address,
                kind: ModuleKind::Overlay(overlay.id()),
                code: overlay.full_data().to_vec(),
                data_regions: vec![(overlay.ctor_start(), end_address)],
            });

            let data = overlay.full_data();
            let base = overlay.base_address();
            let ctor_data = &data[(overlay.ctor_start() - base) as usize..(overlay.ctor_end() - base) as usize];
            for chunk in ctor_data.chunks(4) {
                let address = u32::from_le_slice(chunk);
                if address == 0 {
                    continue;
                }
                let mode = if address & 1 != 0 {
                    InstructionMode::Thumb
                } else {
                    InstructionMode::Arm
                };
                block_analyzer.add_function_location(address, ModuleKind::Overlay(overlay.id()), mode);
            }
        }

        block_analyzer.add_function_location(arm9.entry_function(), ModuleKind::Arm9, InstructionMode::Arm);
        block_analyzer.add_function_location(arm9.autoload_callback(), ModuleKind::Arm9, InstructionMode::Arm);

        let _ = block_analyzer.analyze();

        for function in block_analyzer.functions().iter() {
            println!("{function:#x?}");
        }

        Ok(())
    }

    fn find_build_info_end_address(arm9: &Arm9) -> u32 {
        let code = arm9.full_data();

        let build_info_offset = arm9.build_info_offset();
        let library_list_start = build_info_offset + 0x24; // 0x24 is the size of the build info struct

        let mut offset = library_list_start as usize;
        loop {
            // Up to 4 bytes of zeros for alignment
            let Some((library_offset, ch)) = code[offset..offset + 4].iter().enumerate().find(|&(_, &b)| b != b'\0') else {
                break;
            };
            if *ch != b'[' {
                // Not a library name
                break;
            }
            offset += library_offset;

            let library_length = code[offset..].iter().position(|&b| b == b']').unwrap() + 1;
            offset += library_length + 1; // +1 for the null terminator
        }

        arm9.base_address() + offset.next_multiple_of(4) as u32
    }
}
