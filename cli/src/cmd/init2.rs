use crate::util::bytes::FromSlice;
use std::path::PathBuf;

use anyhow::Result;
use clap::Args;
use ds_decomp::{
    analysis::{
        code::{
            blocks::{self, BlockAnalyzer},
            functions::FunctionKind,
        },
        secure_area::{SecureAreaFunction, SecureAreaState},
    },
    config::{module::ModuleKind, symbol::InstructionMode},
};
use ds_rom::rom::{Arm9, Rom, RomLoadOptions};
use unarm::{ArmVersion, ParseFlags, thumb};

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
        let arm9_end_address = arm9.base_address() + arm9.full_data().len() as u32;
        let build_info_end_address = Self::find_build_info_end_address(arm9);
        block_analyzer.add_module(blocks::ModuleOptions {
            base_address: arm9.base_address(),
            end_address: arm9_end_address,
            kind: ModuleKind::Arm9,
            code: arm9.full_data().to_vec(),
            data_regions: vec![
                (arm9.base_address(), (arm9.base_address() + 0x800)),
                (arm9.base_address() + arm9.build_info_offset(), build_info_end_address),
            ],
            data_required_range: build_info_end_address..arm9_end_address,
        });

        block_analyzer.add_function_location(
            arm9.entry_function(),
            ModuleKind::Arm9,
            InstructionMode::Arm,
            FunctionKind::Default,
        );
        block_analyzer.add_function_location(
            arm9.autoload_callback(),
            ModuleKind::Arm9,
            InstructionMode::Arm,
            FunctionKind::Default,
        );

        let secure_area_functions = Self::find_secure_area_functions(arm9.full_data(), arm9.base_address());
        for function in secure_area_functions {
            block_analyzer.add_function_location(
                function.start(),
                ModuleKind::Arm9,
                InstructionMode::Thumb,
                FunctionKind::SecureArea(function),
            );
        }

        for autoload in arm9.autoloads()? {
            block_analyzer.add_module(blocks::ModuleOptions {
                base_address: autoload.base_address(),
                end_address: autoload.base_address() + autoload.full_data().len() as u32,
                kind: ModuleKind::Autoload(autoload.kind()),
                code: autoload.full_data().to_vec(),
                data_regions: vec![],
                data_required_range: 0..u32::MAX,
            });
        }
        for overlay in rom.arm9_overlays() {
            let data = overlay.full_data();
            let base = overlay.base_address();
            let ctor_data = &data[(overlay.ctor_start() - base) as usize..(overlay.ctor_end() - base) as usize];
            let init_functions = ctor_data.chunks(4).map(u32::from_le_slice).filter(|&addr| addr != 0).collect::<Vec<_>>();

            let first_init_function = init_functions.iter().min().copied();

            let end_address = overlay.base_address() + overlay.full_data().len() as u32;
            block_analyzer.add_module(blocks::ModuleOptions {
                base_address: overlay.base_address(),
                end_address,
                kind: ModuleKind::Overlay(overlay.id()),
                code: overlay.full_data().to_vec(),
                data_regions: vec![(overlay.ctor_start(), end_address)],
                data_required_range: 0..first_init_function.unwrap_or(u32::MAX),
            });

            for address in init_functions {
                let mode = if address & 1 != 0 {
                    InstructionMode::Thumb
                } else {
                    InstructionMode::Arm
                };
                block_analyzer.add_function_location(address, ModuleKind::Overlay(overlay.id()), mode, FunctionKind::Default);
            }
        }

        let _ = block_analyzer.analyze();

        for function in block_analyzer.functions().iter() {
            println!("{}", function.display(block_analyzer.block_map(), 0));
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

    fn find_secure_area_functions(module_code: &[u8], base_addr: u32) -> Vec<SecureAreaFunction> {
        let parse_flags = ParseFlags { ual: true, version: ArmVersion::V5Te };

        let mut functions = Vec::new();

        let mut address = base_addr;
        let mut state = SecureAreaState::default();
        for ins_code in module_code.chunks_exact(2) {
            let ins_code = u16::from_le_slice(ins_code);
            let ins = thumb::Ins::new(ins_code as u32, &parse_flags);
            let parsed_ins = ins.parse(&parse_flags);

            state = state.handle(address, &parsed_ins);
            if let Some(function) = state.get_function() {
                functions.push(function);
            }

            address += 2;
        }

        functions
    }
}
