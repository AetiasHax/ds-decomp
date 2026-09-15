use std::{fmt::Write as _, io};

use anyhow::{Result, bail};
use ds_decomp::{
    analysis::{
        functions::{Function, UNARM_OPTIONS, instruction_size},
        jump_table::{JumpTableKind, ThumbJumpTableJump, ThumbJumpTableKind},
    },
    config::symbol::SymJumpTable,
};
use unarm::{
    AddrLdrStr, AddrMiscLoad, BlxTarget, BranchTarget, FormatIns, FormatValue, Ins, LdrStrOffset,
    MiscLoadOffset, ParseEndian, ParseMode, Parser, Reg,
};

use crate::{
    config::symbol::{SymDataExt, SymbolLookup},
    util::bytes::FromSlice as _,
};

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
        let unarm_options = unarm::Options { ual, ..UNARM_OPTIONS };
        let mut parser = Parser::new(
            self.code(module_code, base_address),
            mode,
            ParseEndian::Little,
            unarm_options.clone(),
        );
        parser.set_pc(self.start_address());

        if self.start_address() < self.first_instruction_address() {
            parser.set_mode(ParseMode::Data);
        }

        let mut jump_table = None;

        let mut address;
        let mut next_address = parser.pc();
        while let Some(ins) = parser.next() {
            address = next_address;
            next_address = parser.pc();

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

            let ins_size = instruction_size(parser.mode());

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
                parser.goto(address + size);

                writeln!(w, "{}: ; inline table", sym.name)?;

                let start = (sym.addr - base_address) as usize;
                let end = start + size as usize;
                let bytes = &module_code[start..end];
                data.write_assembly(w, sym, bytes, symbols)?;
                continue;
            }

            // possibly terminate jump table
            if jump_table.is_some_and(|(table, sym)| address >= sym.addr + table.size) {
                jump_table = None;
            }

            // write instruction
            match jump_table {
                Some((SymJumpTable { kind: JumpTableKind::Thumb { kind, jump }, .. }, sym)) => {
                    let ins_code =
                        u16::from_le_slice(&module_code[(address - base_address) as usize..]);
                    match kind {
                        ThumbJumpTableKind::Halfword => {
                            let value = i32::from(ins_code as i16);
                            write_numerical_jump_table_entry(
                                w, symbols, sym, value, ".short", address, jump,
                            )?;
                        }
                        ThumbJumpTableKind::Byte => {
                            let code = ins_code as i16;
                            let [first_value, second_value] = code.to_le_bytes();
                            let first_value = first_value as i8 as i32;
                            let second_value = second_value as i8 as i32;
                            write_numerical_jump_table_entry(
                                w,
                                symbols,
                                sym,
                                first_value,
                                ".byte",
                                address,
                                jump,
                            )?;
                            write_jump_table_case(w, jump_table, 1, address)?;
                            write_numerical_jump_table_entry(
                                w,
                                symbols,
                                sym,
                                second_value,
                                ".byte",
                                address + 1,
                                jump,
                            )?;
                            write_jump_table_case(w, jump_table, 1, address + 1)?;
                        }
                    }
                }
                _ => {
                    if parser.mode() != ParseMode::Data {
                        write!(w, "    ")?;
                    }
                    let pc_load_offset = if self.is_thumb() { 4 } else { 8 };
                    let mut formatter = InsFormatter {
                        options: &unarm_options,
                        address,
                        pc: address + pc_load_offset,
                        lookup: symbols,
                        w,
                    };
                    formatter.write_ins(&ins)?;
                    if let Some(reference) = pc_relative_reference(&ins, address, pc_load_offset) {
                        symbols.write_ambiguous_symbols_comment(w, address, reference)?;
                    }
                    write_jump_table_case(w, jump_table, ins_size, address)?;
                }
            }

            // write pool constants
            let next_address = address + ins_size;
            for i in 0.. {
                let pool_address = next_address + i * 4;
                if self.pool_constants().contains_key(&pool_address) {
                    let start = pool_address - base_address;
                    let bytes = &module_code[start as usize..];
                    let const_value = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

                    let Some(pool_symbol) = symbols.symbol_map.get_pool_constant(pool_address)?
                    else {
                        log::error!(
                            "Pool constant at {:#010x} in function {} has no symbol",
                            pool_address,
                            self.name()
                        );
                        bail!(
                            "Pool constant at {:#010x} in function {} has no symbol",
                            pool_address,
                            self.name()
                        );
                    };
                    write!(w, "{}: ", pool_symbol.name)?;

                    if !symbols.write_symbol(w, pool_address, const_value, &mut false, "")? {
                        writeln!(w, ".word {const_value:#x}")?;
                    }
                } else {
                    if pool_address > next_address {
                        assert!(
                            pool_address <= self.end_address(),
                            "Failed to seek unarm parser to pool constant at {:#010x} for function at {:#010x}..{:#010x}",
                            pool_address,
                            self.start_address(),
                            self.end_address()
                        );
                        parser.goto(pool_address);
                    }
                    if pool_address == self.first_instruction_address() {
                        // No more pre-code pool constants, start disassembling
                        parser.set_mode(mode);
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

fn write_jump_table_case<W: io::Write>(
    w: &mut W,
    jump_table: Option<(SymJumpTable, &ds_decomp::config::symbol::Symbol)>,
    ins_size: u32,
    address: u32,
) -> std::result::Result<(), io::Error> {
    if let Some((_table, sym)) = jump_table {
        let case = (address - sym.addr) / ins_size;
        writeln!(w, " ; case {case}")
    } else {
        writeln!(w)
    }
}

fn write_numerical_jump_table_entry<W: io::Write>(
    w: &mut W,
    symbols: &SymbolLookup<'_>,
    sym: &ds_decomp::config::symbol::Symbol,
    value: i32,
    directive: &str,
    address: u32,
    jump: ThumbJumpTableJump,
) -> Result<(), anyhow::Error> {
    let pc_offset = match jump {
        ThumbJumpTableJump::AddPc => 2,
        ThumbJumpTableJump::Bx => 0,
    };
    let label_address = (sym.addr.cast_signed() + value + pc_offset).cast_unsigned() & !1;
    let Some(label) = symbols.symbol_map.get_label(label_address)? else {
        log::error!(
            "Expected label for jump table destination from {address:#010x} to {label_address:#010x}"
        );
        bail!(
            "Expected label for jump table destination from {address:#010x} to {label_address:#010x}"
        );
    };
    writeln!(w, "    {} {} - {} {}", directive, label.name, sym.name, match jump {
        ThumbJumpTableJump::AddPc => "- 2",
        ThumbJumpTableJump::Bx => "+ 1",
    },)?;
    Ok(())
}

struct InsFormatter<'a, W: std::io::Write> {
    options: &'a unarm::Options,
    address: u32,
    pc: u32,
    lookup: &'a SymbolLookup<'a>,
    w: &'a mut W,
}

impl<W: std::io::Write> std::fmt::Write for InsFormatter<'_, W> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.w.write_all(s.as_bytes()).map_err(|_| std::fmt::Error)
    }
}

impl<W: std::io::Write> FormatIns for InsFormatter<'_, W> {
    fn options(&self) -> &unarm::Options {
        self.options
    }

    fn write_branch_target(&mut self, branch_target: BranchTarget) -> core::fmt::Result {
        if let Some(symbol) = self.lookup.lookup_symbol_name(self.address, branch_target.addr) {
            self.write_str(symbol)
        } else {
            branch_target.write(self)
        }
    }

    fn write_addr_ldr_str(&mut self, addr_ldr_str: AddrLdrStr) -> core::fmt::Result {
        match addr_ldr_str {
            // [pc, #imm]
            AddrLdrStr::Pre {
                rn: Reg::Pc,
                offset: LdrStrOffset::Imm(offset),
                writeback: false,
            } if let Some(symbol) = self
                .lookup
                .lookup_symbol_name(self.address, (self.pc as i32 + offset) as u32 & !3) =>
            {
                self.write_str(symbol)
            }
            _ => addr_ldr_str.write(self),
        }
    }
}

fn pc_relative_reference(ins: &Ins, address: u32, pc_load_offset: u32) -> Option<u32> {
    match ins {
        // b/bl/blx <label>
        Ins::B { cond: _, target } | Ins::Bl { cond: _, target } => Some(target.addr),
        Ins::Blx { cond: _, target: BlxTarget::Direct(target) } => Some(target.addr),

        // ldr/str *, [pc, #imm]
        Ins::Ldr { cond, rd, addr }
        | Ins::Ldrb { cond, rd, addr }
        | Ins::Str { cond, rd, addr }
        | Ins::Strb { cond, rd, addr }
            if let AddrLdrStr::Pre {
                rn: Reg::Pc,
                offset: LdrStrOffset::Imm(offset),
                writeback: _,
            } = addr =>
        {
            Some(address.wrapping_add(*offset as u32) + pc_load_offset)
        }
        Ins::Ldrd { cond, rd, rd2: _, addr }
        | Ins::Ldrh { cond, rd, addr }
        | Ins::Ldrsb { cond, rd, addr }
        | Ins::Ldrsh { cond, rd, addr }
        | Ins::Strd { cond, rd, rd2: _, addr }
        | Ins::Strh { cond, rd, addr }
            if let AddrMiscLoad::Pre {
                rn: Reg::Pc,
                offset: MiscLoadOffset::Imm(offset),
                writeback: _,
            } = addr =>
        {
            Some(address.wrapping_add(*offset as u32) + pc_load_offset)
        }
        _ => None,
    }
}
