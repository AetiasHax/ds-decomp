use std::io;

use anyhow::{bail, Result};
use ds_decomp_config::analysis::functions::Function;
use unarm::{ArmVersion, DisplayOptions, Endian, ParseFlags, ParseMode, Parser, RegNames};

use crate::config::symbol::{SymDataExt, SymbolLookup};

pub trait FunctionExt {
    fn write_assembly<W: io::Write>(
        &self,
        w: &mut W,
        symbols: &SymbolLookup,
        module_code: &[u8],
        base_address: u32,
        ual: bool,
    ) -> Result<()>;
}

impl FunctionExt for Function {
    fn write_assembly<W: io::Write>(
        &self,
        w: &mut W,
        symbols: &SymbolLookup,
        module_code: &[u8],
        base_address: u32,
        ual: bool,
    ) -> Result<()> {
        let mode = if self.is_thumb() { ParseMode::Thumb } else { ParseMode::Arm };
        let mut parser = Parser::new(
            mode,
            self.start_address(),
            Endian::Little,
            ParseFlags { ual, version: ArmVersion::V5Te },
            self.code(module_code, base_address),
        );

        if self.start_address() < self.first_instruction_address() {
            parser.mode = ParseMode::Data;
        }

        let mut jump_table = None;

        while let Some((address, ins, parsed_ins)) = parser.next() {
            if address == self.first_instruction_address() {
                // declare self
                writeln!(w, "    .global {}", self.name())?;
                if self.is_thumb() {
                    writeln!(w, "    thumb_func_start {}", self.name())?;
                } else {
                    writeln!(w, "    arm_func_start {}", self.name())?;
                }
                writeln!(w, "{}: ; {:#010x}", self.name(), self.first_instruction_address())?;
            }

            let ins_size = parser.mode.instruction_size(0) as u32;

            // write label
            if let Some(label) = symbols.symbol_map.get_label(address)? {
                writeln!(w, "{}:", label.name)?;
            }
            if let Some((table, sym)) = symbols.symbol_map.get_jump_table(address)? {
                jump_table = Some((table, sym));
                writeln!(w, "{}: ; jump table", sym.name)?;
            }

            // write data
            if let Some((data, sym)) = symbols.symbol_map.get_data(address)? {
                let Some(size) = data.size() else {
                    log::error!("Inline tables must have a known size");
                    bail!("Inline tables must have a known size");
                };
                parser.seek_forward(address + size);

                writeln!(w, "{}: ; inline table", sym.name)?;

                let start = (sym.addr - base_address) as usize;
                let end = start + size as usize;
                let bytes = &module_code[start..end];
                data.write_assembly(w, sym, bytes, symbols)?;
                continue;
            }

            // possibly terminate jump table
            if jump_table.map_or(false, |(table, sym)| address >= sym.addr + table.size) {
                jump_table = None;
            }

            // write instruction
            match jump_table {
                Some((table, sym)) if !table.code => {
                    let (directive, value) =
                        if self.is_thumb() { (".short", ins.code() as i16 as i32) } else { (".word", ins.code() as i32) };
                    let label_address = (sym.addr as i32 + value + 2) as u32;
                    let Some(label) = symbols.symbol_map.get_label(label_address)? else {
                        log::error!("Expected label for jump table destination {:#010x}", label_address);
                        bail!("Expected label for jump table destination {:#010x}", label_address);
                    };
                    write!(w, "    {directive} {} - {} - 2", label.name, sym.name)?;
                }
                _ => {
                    if parser.mode != ParseMode::Data {
                        write!(w, "    ")?;
                    }
                    let pc_load_offset = if self.is_thumb() { 4 } else { 8 };
                    write!(
                        w,
                        "{}",
                        parsed_ins.display_with_symbols(
                            DisplayOptions { reg_names: RegNames { ip: true, ..Default::default() } },
                            unarm::Symbols { lookup: symbols, program_counter: address, pc_load_offset }
                        )
                    )?;
                    if let Some(reference) = parsed_ins.pc_relative_reference(address, pc_load_offset) {
                        symbols.write_ambiguous_symbols_comment(w, address, reference)?;
                    }
                }
            }

            // write jump table case
            if let Some((_table, sym)) = jump_table {
                let case = (address - sym.addr) / ins_size;
                writeln!(w, " ; case {case}")?;
            } else {
                writeln!(w)?;
            }

            // write pool constants
            let next_address = address + ins_size;
            for i in 0.. {
                let pool_address = next_address + i * 4;
                if self.pool_constants().contains(&pool_address) {
                    let start = pool_address - base_address;
                    let bytes = &module_code[start as usize..];
                    let const_value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

                    let Some(pool_symbol) = symbols.symbol_map.get_pool_constant(pool_address)? else {
                        log::error!("Pool constant at {:#010x} in function {} has no symbol", pool_address, self.name());
                        bail!("Pool constant at {:#010x} in function {} has no symbol", pool_address, self.name());
                    };
                    write!(w, "{}: ", pool_symbol.name)?;

                    if !symbols.write_symbol(w, pool_address, const_value, &mut false, "")? {
                        writeln!(w, ".word {const_value:#x}")?;
                    }
                } else {
                    if pool_address > parser.address {
                        parser.seek_forward(pool_address);
                    }
                    if pool_address == self.first_instruction_address() {
                        // No more pre-code pool constants, start disassembling
                        parser.mode = mode;
                    }
                    break;
                }
            }
        }

        if self.is_thumb() {
            writeln!(w, "    thumb_func_end {}", self.name())?;
        } else {
            writeln!(w, "    arm_func_end {}", self.name())?;
        }

        writeln!(w)?;

        Ok(())
    }
}
