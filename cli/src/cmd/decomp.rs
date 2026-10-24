use std::{
    borrow::Cow,
    collections::BTreeSet,
    fmt::{Display, Write},
    path::PathBuf,
};

use clap::Args;
use ds_decomp::{
    analysis::{
        functions::{Function, UNARM_OPTIONS},
        jump_table::{JumpTable, JumpTableKind, ThumbJumpTableJump, ThumbJumpTableKind},
    },
    config::{config::Config, module::Module, symbol::SymbolMapError},
};
use snafu::Snafu;
use unarm::{
    AddrLdrStr, AddrLdrStrPost, AddrMiscLoad, BlxTarget, BranchTarget, Cond, FormatValue, Ins,
    LdmStmMode, LdrStrOffset, MiscLoadOffset, Op2, Op2Imm, Op2Shift, ParseMode, Parser, Reg,
    ShiftImm, ShiftOp, ShiftReg, parse_arm,
};

use crate::{config::program::Program, util::bytes::FromSlice};

/// Hilariously bad decompiler. Seriously do not use this.
#[derive(Args)]
pub struct Decomp {
    /// Path to config.yaml.
    #[arg(long, short = 'c')]
    config_path: PathBuf,

    /// Which function to decompile, if there are multiple.
    #[arg(long, short = 'i')]
    index: Option<usize>,

    /// Name of the function to decompile.
    name: String,
}

#[derive(Debug, Snafu)]
enum DecompError {
    #[snafu(transparent)]
    Fmt {
        source: std::fmt::Error,
    },
    #[snafu(transparent)]
    SymbolMap {
        source: SymbolMapError,
    },
    NotSupported {
        message: Cow<'static, str>,
    },
}

impl Decomp {
    pub fn run(&self) -> anyhow::Result<()> {
        let config = Config::from_file(&self.config_path)?;
        let config_path = self.config_path.parent().unwrap();
        let rom = config.load_rom(config_path)?;
        let program = Program::from_config(config_path, &config, &rom)?;

        let mut symbols = Vec::new();
        for module in program.modules() {
            for function in module.sections().functions() {
                if function.name() == self.name {
                    symbols.push((module, function));
                }
            }
        }

        let (module, function) = match (symbols.first(), symbols.len()) {
            (None, _) => {
                log::error!("Symbol not found");
                return Ok(());
            }
            (Some(found), 1) => found,
            (Some(_), _) => {
                log::error!("Multiple functions found with name '{}':", self.name);
                for (index, (module, function)) in symbols.iter().enumerate() {
                    log::error!(
                        "  {}: in {} at address {:#010x}",
                        index,
                        module.kind(),
                        function.start_address()
                    );
                }
                log::error!("Please specify an index with --index to choose one of them.");
                return Ok(());
            }
        };

        let parser = function.parser(module.code(), module.base_address());

        let mut decompiler = Decompiler::new(&program, module, function);
        decompiler.decompile(parser)?;
        print!("{}", decompiler.code()?);

        Ok(())
    }
}

struct Decompiler<'a> {
    storages: BTreeSet<Storage>,
    lines: Vec<Line>,
    program: &'a Program,
    module: &'a Module,
    function: &'a Function,
}

impl<'a> Decompiler<'a> {
    fn new(program: &'a Program, module: &'a Module, function: &'a Function) -> Self {
        Self { storages: BTreeSet::new(), lines: Vec::new(), program, module, function }
    }

    fn decompile(&mut self, mut parser: Parser) -> Result<(), DecompError> {
        let pc_offset = match parser.mode() {
            ParseMode::Arm => 8,
            ParseMode::Thumb => 4,
            ParseMode::Data => 0,
        };

        loop {
            let address = parser.pc();
            if address >= self.function.last_instruction_address() {
                break;
            }
            let Some(ins) = parser.next() else {
                break;
            };

            if self.function.pool_constants().get(&address).is_some() {
                continue;
            }

            let mut code_str = String::new();
            let code = &mut code_str;

            if let Some(jump_table) = self.function.jump_tables().get(&address) {
                self.decompile_jump_table(code, jump_table, address)?;
                self.lines.push(Line { ins, address, code: code_str });
                parser.goto(address + jump_table.size);
                continue;
            }

            match self.decompile_cond(code, ins.cond()) {
                Ok(()) => {}
                Err(DecompError::NotSupported { message }) => {
                    self.asm(code, &ins)?;
                    write!(code, "{message}")?;
                }
                Err(e) => return Err(e),
            }
            match ins {
                Ins::Adc { s: _, thumb: _, cond: _, rd: _, rn: _, op2: _ } => {
                    self.asm(code, &ins)?;
                }
                Ins::Add {
                    s: _,
                    thumb: _,
                    cond: _,
                    rd: Reg::Sp,
                    rn: Reg::Sp,
                    op2: Op2::Imm(_),
                } => {
                    continue;
                }
                Ins::Add {
                    s: _,
                    thumb: _,
                    cond: _,
                    rd,
                    rn: Reg::Sp,
                    op2: Op2::Imm(Op2Imm { imm: offset, rotate_imm: _ }),
                } => {
                    let dest = self.reg_storage(rd);
                    let stack = self.stack_storage(offset);
                    write!(code, "{dest} = (u32) &{stack};")?;
                }
                Ins::Add { s, thumb: _, cond: _, rd, rn, op2 } => {
                    self.decompile_data_processing(code, "+", s, rd, rn, op2)?;
                }
                Ins::And { s, thumb: _, cond: _, rd, rn, op2 } => {
                    self.decompile_data_processing(code, "&", s, rd, rn, op2)?;
                }
                Ins::Asr { s, thumb: _, cond: _, rd, rn, op2 } => {
                    self.decompile_shift(code, ShiftOp::Asr, s, rd, rn, op2)?;
                }
                Ins::B { cond: _, target } => {
                    write!(code, "goto ")?;
                    self.label(code, target.addr)?;
                    write!(code, ";")?;
                }
                Ins::Bic { s, thumb: _, cond: _, rd, rn, op2 } => {
                    self.decompile_data_processing(code, "& ~", s, rd, rn, op2)?;
                }
                Ins::Bkpt { imm: _ } => {
                    self.asm(code, &ins)?;
                }
                Ins::Bl { cond: _, target } => {
                    self.decompile_direct_call(code, address, target)?;
                }
                Ins::Blx { cond: _, target } => match target {
                    BlxTarget::Direct(target) => {
                        self.decompile_direct_call(code, address, target)?
                    }
                    BlxTarget::Indirect(reg) => {
                        let dest = self.reg_storage(reg);
                        write!(code, "{dest}();")?;
                    }
                },
                Ins::Bx { cond: _, rm: Reg::Lr } => {
                    if let Some(ret) = self.storages.get(&Storage::Var(VarStorage::Reg(Reg::R0))) {
                        write!(code, "return {ret};")?
                    } else {
                        write!(code, "return;")?
                    }
                }
                Ins::Bx { cond: _, rm: _ } => self.asm(code, &ins)?,
                Ins::Cdp { cond: _, coproc: _, opc1: _, crd: _, crn: _, crm: _, opc2: _ } => {
                    self.asm(code, &ins)?
                }
                Ins::Cdp2 { coproc: _, opc1: _, crd: _, crn: _, crm: _, opc2: _ } => {
                    self.asm(code, &ins)?
                }
                Ins::Clz { cond: _, rd: _, rm: _ } => self.asm(code, &ins)?,
                Ins::Cmn { cond: _, rn: _, op2: _ } => self.asm(code, &ins)?,
                Ins::Cmp { cond: _, rn, op2 } => {
                    let lhs = self.storage(Storage::Var(VarStorage::CmpLhs));
                    let rn = self.reg_storage(rn);
                    let rhs = self.storage(Storage::Var(VarStorage::CmpRhs));
                    write!(code, "{lhs} = {rn}; {rhs} = ")?;
                    self.decompile_op2(code, op2)?;
                    write!(code, ";")?;
                }
                Ins::Csdb { cond: _ } => self.asm(code, &ins)?,
                Ins::Eor { s, thumb: _, cond: _, rd, rn, op2 } => {
                    self.decompile_data_processing(code, "^", s, rd, rn, op2)?;
                }
                Ins::Ldc { l: _, cond: _, coproc: _, crd: _, dest: _ } => self.asm(code, &ins)?,
                Ins::Ldc2 { l: _, coproc: _, crd: _, dest: _ } => self.asm(code, &ins)?,
                Ins::Ldm { mode, cond: _, rn, writeback, regs, user_mode: _ } => {
                    let rn = self.reg_storage(rn);
                    for (i, reg) in regs.iter().enumerate() {
                        let dest = self.reg_storage(reg);
                        let offset = match mode {
                            LdmStmMode::Da => i as i32 * -4,
                            LdmStmMode::Ia => i as i32 * 4,
                            LdmStmMode::Db => (i as i32 + 1) * -4,
                            LdmStmMode::Ib => (i as i32 + 1) * 4,
                        };
                        writeln!(code, "{dest} = *(u32 *) ({rn} + {offset:#x});")?;
                    }
                    if writeback {
                        let offset = match mode {
                            LdmStmMode::Da | LdmStmMode::Db => regs.len() as i32 * -4,
                            LdmStmMode::Ia | LdmStmMode::Ib => regs.len() as i32 * 4,
                        };
                        write!(code, "{rn} = {rn} + {offset:#};")?;
                    }
                }
                Ins::Ldr {
                    cond: _,
                    rd,
                    addr:
                        AddrLdrStr::Pre {
                            rn: Reg::Pc,
                            offset: LdrStrOffset::Imm(offset),
                            writeback: false,
                        },
                } if let Some(pool_constant) = self
                    .function
                    .pool_constants()
                    .get(&((address as i32 + offset + pc_offset) as u32 & !3)) =>
                {
                    let dest = self.reg_storage(rd);
                    if let Some(relocation) = self
                        .module
                        .relocations()
                        .get((address as i32 + offset + pc_offset) as u32 & !3)
                        && let Some(module_kind) = relocation.module().first()
                        && let Some(target_symbols) = self.program.symbol_maps().get(module_kind)
                        && let Some((_, target_symbol)) =
                            target_symbols.by_address(relocation.to_address())?
                    {
                        write!(code, "{dest} = {}", target_symbol.name)?;
                        let addend = relocation.addend_value();
                        if addend > 0 {
                            write!(code, " + {:#x}", addend)?;
                        } else {
                            write!(code, " - {:#x}", -addend)?;
                        }
                        write!(code, ";")?;
                    } else {
                        write!(code, "{dest} = {:#x};", pool_constant.value)?;
                    }
                }
                Ins::Ldr { cond: _, rd, addr } => {
                    self.decompile_load(code, "*(u32 *)", rd, addr)?;
                }
                Ins::Ldrb { cond: _, rd, addr } => {
                    self.decompile_load(code, "*(u8 *)", rd, addr)?;
                }
                Ins::Ldrbt { cond: _, rd: _, addr: _ } => self.asm(code, &ins)?,
                Ins::Ldrd { cond: _, rd: _, rd2: _, addr: _ } => self.asm(code, &ins)?,
                Ins::Ldrh { cond: _, rd, addr } => {
                    self.decompile_misc_load(code, "*(u16 *)", rd, addr)?;
                }
                Ins::Ldrsb { cond: _, rd, addr } => {
                    self.decompile_misc_load(code, "(s32) *(s8*)", rd, addr)?;
                }
                Ins::Ldrsh { cond: _, rd, addr } => {
                    self.decompile_misc_load(code, "(s32) *(s16*)", rd, addr)?;
                }
                Ins::Ldrt { cond: _, rd: _, addr: _ } => self.asm(code, &ins)?,
                Ins::Lsl { s, thumb: _, cond: _, rd, rn, op2 } => {
                    self.decompile_shift(code, ShiftOp::Lsl, s, rd, rn, op2)?;
                }
                Ins::Lsr { s, thumb: _, cond: _, rd, rn, op2 } => {
                    self.decompile_shift(code, ShiftOp::Lsr, s, rd, rn, op2)?;
                }
                Ins::Mcr { cond: _, coproc: _, opc1: _, rd: _, crn: _, crm: _, opc2: _ } => {
                    self.asm(code, &ins)?
                }
                Ins::Mcr2 { coproc: _, opc1: _, rd: _, crn: _, crm: _, opc2: _ } => {
                    self.asm(code, &ins)?
                }
                Ins::Mcrr { cond: _, coproc: _, opc: _, rd: _, rd2: _, crm: _ } => {
                    self.asm(code, &ins)?
                }
                Ins::Mla { s: _, cond: _, rd, rn, rm, ra } => {
                    let rd = self.reg_storage(rd);
                    let rn = self.reg_storage(rn);
                    let rm = self.reg_storage(rm);
                    let ra = self.reg_storage(ra);
                    write!(code, "{rd} = {rn} * {rm} + {ra};")?;
                }
                Ins::Mov { s: _, thumb: _, cond: _, rd, op2 } => {
                    let dest = self.reg_storage(rd);
                    write!(code, "{dest} = ")?;
                    self.decompile_op2(code, op2)?;
                    write!(code, ";")?;
                }
                Ins::Mrc { cond: _, coproc: _, opc1: _, rd: _, crn: _, crm: _, opc2: _ } => {
                    self.asm(code, &ins)?
                }
                Ins::Mrc2 { coproc: _, opc1: _, rd: _, crn: _, crm: _, opc2: _ } => {
                    self.asm(code, &ins)?
                }
                Ins::Mrrc { cond: _, coproc: _, opc: _, rd: _, rd2: _, crm: _ } => {
                    self.asm(code, &ins)?
                }
                Ins::Mrs { cond: _, rd: _, status_reg: _ } => self.asm(code, &ins)?,
                Ins::Msr { cond: _, status_fields: _, op2: _ } => self.asm(code, &ins)?,
                Ins::Mul { s: _, thumb: _, cond: _, rd, rn, rm } => {
                    let dest = self.reg_storage(rd);
                    let lhs = self.reg_storage(rn);
                    let rhs = self.reg_storage(rm);
                    write!(code, "{dest} = {lhs} * {rhs};")?;
                }
                Ins::Mvn { s: _, thumb: _, cond: _, rd, op2 } => {
                    let dest = self.reg_storage(rd);
                    write!(code, "{dest} = ~")?;
                    self.decompile_op2(code, op2)?;
                    write!(code, ";")?;
                }
                Ins::Neg { rd, rm } => {
                    let rd = self.reg_storage(rd);
                    let rm = self.reg_storage(rm);
                    write!(code, "{rd} = -{rm};")?;
                }
                Ins::Orr { s, thumb: _, cond: _, rd, rn, op2 } => {
                    self.decompile_data_processing(code, "|", s, rd, rn, op2)?;
                }
                Ins::Pld { addr: _ } => self.asm(code, &ins)?,
                Ins::Pop { cond: _, regs: _ } => {
                    if let Some(ret) = self.storages.get(&Storage::Var(VarStorage::Reg(Reg::R0))) {
                        write!(code, "return {ret};")?
                    } else {
                        write!(code, "return;")?
                    }
                }
                Ins::Push { cond: _, regs: _ } => continue,
                Ins::Qadd { cond: _, rd: _, rm: _, rn: _ } => self.asm(code, &ins)?,
                Ins::Qdadd { cond: _, rd: _, rm: _, rn: _ } => self.asm(code, &ins)?,
                Ins::Qdsub { cond: _, rd: _, rm: _, rn: _ } => self.asm(code, &ins)?,
                Ins::Qsub { cond: _, rd: _, rm: _, rn: _ } => self.asm(code, &ins)?,
                Ins::Ror { s: _, thumb: _, cond: _, rd: _, rn: _, op2: _ } => {
                    self.asm(code, &ins)?
                }
                Ins::Rrx { s: _, cond: _, rd: _, rm: _ } => self.asm(code, &ins)?,
                Ins::Rsb { s: _, cond: _, rd, rn, op2 } => {
                    let dest = self.reg_storage(rd);
                    let rhs = self.reg_storage(rn);
                    write!(code, "{dest} = ")?;
                    self.decompile_op2(code, op2)?;
                    write!(code, " - {rhs};")?;
                }
                Ins::Rsc { s: _, cond: _, rd: _, rn: _, op2: _ } => self.asm(code, &ins)?,
                Ins::Sbc { s: _, thumb: _, cond: _, rd: _, rn: _, op2: _ } => {
                    self.asm(code, &ins)?;
                }
                Ins::Smla { cond: _, rd: _, rn: _, rn_side: _, rm: _, rm_side: _, ra: _ } => {
                    self.asm(code, &ins)?
                }
                Ins::Smlal { s: _, cond: _, rd_lo: _, rd_hi: _, rn: _, rm: _ } => {
                    self.asm(code, &ins)?
                }
                Ins::SmlalHalf {
                    cond: _,
                    rd_lo: _,
                    rd_hi: _,
                    rn: _,
                    rn_side: _,
                    rm: _,
                    rm_side: _,
                } => self.asm(code, &ins)?,
                Ins::Smlaw { cond: _, rd: _, rn: _, rm: _, rm_side: _, ra: _ } => {
                    self.asm(code, &ins)?
                }
                Ins::Smul { cond: _, rd: _, rn: _, rn_side: _, rm: _, rm_side: _ } => {
                    self.asm(code, &ins)?
                }
                Ins::Smull { s: _, cond: _, rd_lo: _, rd_hi: _, rn: _, rm: _ } => {
                    self.asm(code, &ins)?
                }
                Ins::Smulw { cond: _, rd: _, rn: _, rm: _, rm_side: _ } => self.asm(code, &ins)?,
                Ins::Stc { l: _, cond: _, coproc: _, crd: _, dest: _ } => self.asm(code, &ins)?,
                Ins::Stc2 { l: _, coproc: _, crd: _, dest: _ } => self.asm(code, &ins)?,
                Ins::Stm { mode, cond: _, rn, writeback, regs, user_mode: _ } => {
                    let rn = self.reg_storage(rn);
                    for (i, reg) in regs.iter().enumerate() {
                        let src = self.reg_storage(reg);
                        let offset = match mode {
                            LdmStmMode::Da => i as i32 * -4,
                            LdmStmMode::Ia => i as i32 * 4,
                            LdmStmMode::Db => (i as i32 + 1) * -4,
                            LdmStmMode::Ib => (i as i32 + 1) * 4,
                        };
                        writeln!(code, "*(u32 *) ({rn} + {offset:#x}) = {src};")?;
                    }
                    if writeback {
                        let offset = match mode {
                            LdmStmMode::Da | LdmStmMode::Db => regs.len() as i32 * -4,
                            LdmStmMode::Ia | LdmStmMode::Ib => regs.len() as i32 * 4,
                        };
                        write!(code, "{rn} = {rn} + {offset:#};")?;
                    }
                }
                Ins::Str { cond: _, rd, addr } => {
                    self.decompile_store(code, "u32", rd, addr)?;
                }
                Ins::Strb { cond: _, rd, addr } => {
                    self.decompile_store(code, "u8", rd, addr)?;
                }
                Ins::Strbt { cond: _, rd: _, addr: _ } => self.asm(code, &ins)?,
                Ins::Strd { cond: _, rd: _, rd2: _, addr: _ } => self.asm(code, &ins)?,
                Ins::Strh { cond: _, rd, addr } => {
                    self.decompile_misc_store(code, "u16", rd, addr)?;
                }
                Ins::Strt { cond: _, rd: _, addr: _ } => self.asm(code, &ins)?,
                Ins::Sub {
                    s: _,
                    thumb: _,
                    cond: _,
                    rd: Reg::Sp,
                    rn: Reg::Sp,
                    op2: Op2::Imm(_),
                } => {
                    continue;
                }
                Ins::Sub { s, thumb: _, cond: _, rd, rn, op2 } => {
                    self.decompile_data_processing(code, "-", s, rd, rn, op2)?;
                }
                Ins::Svc { cond: _, imm: _ } => self.asm(code, &ins)?,
                Ins::Swp { cond: _, rd: _, rd2: _, rn: _ } => self.asm(code, &ins)?,
                Ins::Swpb { cond: _, rd: _, rd2: _, rn: _ } => self.asm(code, &ins)?,
                Ins::Teq { cond: _, rn: _, op2: _ } => self.asm(code, &ins)?,
                Ins::Tst { cond: _, rn, op2 } => {
                    let lhs = self.storage(Storage::Var(VarStorage::CmpLhs));
                    let rn = self.reg_storage(rn);
                    let rhs = self.storage(Storage::Var(VarStorage::CmpRhs));
                    write!(code, "{lhs} = {rn} & ")?;
                    self.decompile_op2(code, op2)?;
                    write!(code, "; {rhs} = 0x0;")?;
                }
                Ins::Udf { imm: _ } => self.asm(code, &ins)?,
                Ins::Umlal { s: _, cond: _, rd_lo: _, rd_hi: _, rn: _, rm: _ } => {
                    self.asm(code, &ins)?
                }
                Ins::Umull { s: _, cond: _, rd_lo: _, rd_hi: _, rn: _, rm: _ } => {
                    self.asm(code, &ins)?
                }
                Ins::Word(_) => self.asm(code, &ins)?,
                Ins::HalfWord(_) => self.asm(code, &ins)?,
                Ins::Byte(_) => self.asm(code, &ins)?,
                Ins::Illegal => {
                    write!(code, "// illegal instruction! ")?;
                }
            }
            self.decompile_cond_end(code, ins.cond())?;

            self.lines.push(Line { ins, address, code: code_str });
        }
        Ok(())
    }

    fn decompile_jump_table(
        &mut self,
        code: &mut String,
        jump_table: &JumpTable,
        address: u32,
    ) -> Result<(), DecompError> {
        let step = match jump_table.kind {
            JumpTableKind::Arm => 4,
            JumpTableKind::Thumb { kind: ThumbJumpTableKind::Halfword, .. } => 2,
            JumpTableKind::Thumb { kind: ThumbJumpTableKind::Byte, .. } => 1,
        };
        writeln!(code, "switch (unk) {{")?;
        for (case, case_address) in
            (jump_table.address..jump_table.address + jump_table.size).step_by(step).enumerate()
        {
            let offset = (case_address - self.module.base_address()) as usize;
            let ins = match step {
                4 => u32::from_le_slice(&self.module.code()[offset..]),
                2 => u16::from_le_slice(&self.module.code()[offset..]) as u32,
                1 => self.module.code()[offset] as u32,
                _ => unreachable!(),
            };

            let dest = match jump_table.kind {
                JumpTableKind::Arm => {
                    let Ins::B { cond: _, target } = parse_arm(ins, address, &UNARM_OPTIONS) else {
                        panic!();
                    };
                    target.addr
                }
                JumpTableKind::Thumb { jump, .. } => {
                    let pc_offset = match jump {
                        ThumbJumpTableJump::AddPc => 2,
                        ThumbJumpTableJump::Bx => 0,
                    };
                    (address + ins + pc_offset) & !1
                }
            };

            write!(code, "        case {case}: goto ")?;
            self.label(code, dest)?;
            writeln!(code, ";")?;
        }
        writeln!(code, "    }}")?;
        Ok(())
    }

    fn decompile_misc_load(
        &mut self,
        code: &mut String,
        cast: &str,
        rd: Reg,
        addr: AddrMiscLoad,
    ) -> Result<(), DecompError> {
        let dest = self.reg_storage(rd);
        write!(code, "{dest} = {cast}(")?;
        self.decompile_addr_misc_load(code, addr)?;
        write!(code, ");")?;
        Ok(())
    }

    fn decompile_load(
        &mut self,
        code: &mut String,
        cast: &str,
        rd: Reg,
        addr: AddrLdrStr,
    ) -> Result<(), DecompError> {
        let dest = self.reg_storage(rd);
        write!(code, "{dest} = {cast} (")?;
        self.decompile_addr_ldr_str(code, addr)?;
        write!(code, ");")?;
        Ok(())
    }

    fn decompile_misc_store(
        &mut self,
        code: &mut String,
        ty: &str,
        rd: Reg,
        addr: AddrMiscLoad,
    ) -> Result<(), DecompError> {
        let dest = self.reg_storage(rd);
        write!(code, "*({ty}*) (")?;
        self.decompile_addr_misc_load(code, addr)?;
        write!(code, ") = {dest};")?;
        Ok(())
    }

    fn decompile_store(
        &mut self,
        code: &mut String,
        ty: &str,
        rd: Reg,
        addr: AddrLdrStr,
    ) -> Result<(), DecompError> {
        let dest = self.reg_storage(rd);
        write!(code, "*({ty}*) (")?;
        self.decompile_addr_ldr_str(code, addr)?;
        write!(code, ") = {dest};")?;
        Ok(())
    }

    fn asm(&self, code: &mut String, ins: &Ins) -> Result<(), DecompError> {
        write!(code, "asm(\"{}\");", ins.display(&unarm::Options { ual: false, ..UNARM_OPTIONS }))?;
        Ok(())
    }

    fn decompile_direct_call(
        &mut self,
        code: &mut String,
        address: u32,
        target: BranchTarget,
    ) -> Result<(), DecompError> {
        let ret = self.reg_storage(Reg::R0);
        write!(code, "{ret} = ")?;
        if let Some(reloc) = self.module.relocations().get(address)
            && let Some(module_kind) = reloc.module().first()
            && let Some(target_symbols) = self.program.symbol_maps().get(module_kind)
            && let Some(target_function) = target_symbols.get_function(target.addr)?
        {
            write!(code, "{}();", target_function.1.name)?;
        } else {
            write!(code, "({:#010x})();", target.addr)?;
        }
        Ok(())
    }

    fn decompile_cond(&mut self, code: &mut String, cond: Cond) -> Result<(), DecompError> {
        if cond != Cond::Al {
            let lhs = self.storage(Storage::Var(VarStorage::CmpLhs));
            let rhs = self.storage(Storage::Var(VarStorage::CmpRhs));
            let op = self.cond_op(cond)?;
            write!(code, "if ({lhs} {op} {rhs}) {{ ")?;
        }
        Ok(())
    }

    fn decompile_cond_end(&mut self, code: &mut String, cond: Cond) -> Result<(), DecompError> {
        if cond != Cond::Al {
            write!(code, " }}")?;
        }
        Ok(())
    }

    fn cond_op(&self, cond: Cond) -> Result<&str, DecompError> {
        match cond {
            Cond::Eq => Ok("=="),
            Cond::Ne => Ok("!="),
            Cond::Hs => Ok(">="),
            Cond::Lo => Ok("<"),
            Cond::Mi => NotSupportedSnafu { message: "Condition code 'mi' not supported" }.fail(),
            Cond::Pl => NotSupportedSnafu { message: "Condition code 'pl' not supported" }.fail(),
            Cond::Vs => NotSupportedSnafu { message: "Condition code 'vs' not supported" }.fail(),
            Cond::Vc => NotSupportedSnafu { message: "Condition code 'vc' not supported" }.fail(),
            Cond::Hi => Ok(">"),
            Cond::Ls => Ok("<="),
            Cond::Ge => Ok(">="),
            Cond::Lt => Ok("<"),
            Cond::Gt => Ok(">"),
            Cond::Le => Ok("<="),
            Cond::Al => NotSupportedSnafu { message: "Unexpected condition code 'al'" }.fail(),
        }
    }

    fn decompile_addr_ldr_str(
        &mut self,
        code: &mut String,
        addr: AddrLdrStr,
    ) -> Result<(), DecompError> {
        match addr {
            AddrLdrStr::Pre {
                rn: Reg::Sp,
                offset: LdrStrOffset::Imm(offset),
                writeback: false,
            } => {
                let stack = self.stack_storage(offset as u32);
                write!(code, "&{stack}")?;
            }
            AddrLdrStr::Pre { rn, offset, writeback } => {
                let base = self.reg_storage(rn);
                write!(code, "{base}")?;
                let eq = if writeback { "=" } else { "" };
                match offset {
                    LdrStrOffset::Imm(imm) => {
                        if imm > 0 {
                            write!(code, " +{eq} {:#x}", imm)?;
                        } else if imm < 0 {
                            write!(code, " -{eq} {:#x}", -imm)?;
                        }
                    }
                    LdrStrOffset::Reg { subtract, rm, shift_op, imm } => {
                        let offset = self.reg_storage(rm);
                        let cast = asr_cast(shift_op);
                        if subtract {
                            write!(code, " -{eq} ({cast}{offset}")?;
                        } else {
                            write!(code, " +{eq} ({cast}{offset}")?;
                        }
                        let shift_op_str = self.shift_op(shift_op)?;
                        write!(code, " {shift_op_str} {imm})")?;
                    }
                }
            }
            AddrLdrStr::Post(AddrLdrStrPost { rn, offset }) => {
                let base = self.reg_storage(rn);
                let temp = self.storage(Storage::Var(VarStorage::Temp));
                write!(code, "({temp} = {base}, {base}")?;
                match offset {
                    LdrStrOffset::Imm(imm) => {
                        if imm > 0 {
                            write!(code, " += {:#x}", imm)?;
                        } else if imm < 0 {
                            write!(code, " -= {:#x}", -imm)?;
                        }
                    }
                    LdrStrOffset::Reg { subtract, rm, shift_op, imm } => {
                        let offset = self.reg_storage(rm);
                        let cast = asr_cast(shift_op);
                        if subtract {
                            write!(code, " -= ({cast}{offset}")?;
                        } else {
                            write!(code, " += ({cast}{offset}")?;
                        }
                        let shift_op_str = self.shift_op(shift_op)?;
                        write!(code, " {shift_op_str} {imm})")?;
                    }
                }
                write!(code, ", {temp})")?;
            }
        }
        Ok(())
    }

    fn decompile_addr_misc_load(
        &mut self,
        code: &mut String,
        addr: AddrMiscLoad,
    ) -> Result<(), DecompError> {
        match addr {
            AddrMiscLoad::Pre { rn, offset, writeback } => {
                let base = self.reg_storage(rn);
                write!(code, "{base} ")?;
                let eq = if writeback { "=" } else { "" };
                match offset {
                    MiscLoadOffset::Imm(imm) => {
                        if imm > 0 {
                            write!(code, "+{eq} {:#x}", imm)?;
                        } else if imm < 0 {
                            write!(code, "-{eq} {:#x}", -imm)?;
                        }
                    }
                    MiscLoadOffset::Reg { subtract, rm } => {
                        let offset = self.reg_storage(rm);
                        if subtract {
                            write!(code, "-{eq} {offset}")?;
                        } else {
                            write!(code, "+{eq} {offset}")?;
                        }
                    }
                }
            }
            AddrMiscLoad::Post { rn, offset } => {
                let base = self.reg_storage(rn);
                let temp = self.storage(Storage::Var(VarStorage::Temp));
                write!(code, "({temp} = {base}, {base}")?;
                match offset {
                    MiscLoadOffset::Imm(imm) => {
                        if imm > 0 {
                            write!(code, " += {:#x}", imm)?;
                        } else if imm < 0 {
                            write!(code, " -= {:#x}", -imm)?;
                        }
                    }
                    MiscLoadOffset::Reg { subtract, rm } => {
                        let offset = self.reg_storage(rm);
                        if subtract {
                            write!(code, " -= {offset}")?;
                        } else {
                            write!(code, " += {offset}")?;
                        }
                    }
                }
                write!(code, ", {temp})")?;
            }
        }
        Ok(())
    }

    fn decompile_data_processing(
        &mut self,
        code: &mut String,
        op: &str,
        _s: bool,
        rd: Reg,
        rn: Reg,
        op2: Op2,
    ) -> Result<(), DecompError> {
        let dest = self.reg_storage(rd);
        let lhs = self.reg_storage(rn);
        write!(code, "{dest} = {lhs} {op} ")?;
        self.decompile_op2(code, op2)?;
        write!(code, ";")?;
        Ok(())
    }

    fn decompile_op2(&mut self, code: &mut String, op2: Op2) -> Result<(), DecompError> {
        match op2 {
            Op2::Imm(Op2Imm { imm, rotate_imm: _ }) => {
                write!(code, "{imm:#x}")?;
            }
            Op2::ShiftReg(ShiftReg { rm, shift_op, rs }) => {
                let lhs = self.reg_storage(rm);
                let rhs = self.reg_storage(rs);
                let cast = asr_cast(shift_op);
                write!(code, "({cast}{lhs} {} {rhs})", self.shift_op(shift_op)?)?;
            }
            Op2::ShiftImm(ShiftImm { rm, shift_op, imm }) => {
                let lhs = self.reg_storage(rm);
                write!(code, "({lhs} {} {imm:#x})", self.shift_op(shift_op)?)?;
            }
        }
        Ok(())
    }

    fn shift_op(&self, op: ShiftOp) -> Result<&str, DecompError> {
        match op {
            ShiftOp::Lsl => Ok("<<"),
            ShiftOp::Lsr | ShiftOp::Asr => Ok(">>"),
            ShiftOp::Ror => NotSupportedSnafu { message: "Shift op 'ror' not supported" }.fail(),
        }
    }

    fn decompile_shift(
        &mut self,
        code: &mut String,
        shift_op: ShiftOp,
        _s: bool,
        rd: Reg,
        rn: Reg,
        op2: Op2Shift,
    ) -> Result<(), DecompError> {
        let dest = self.reg_storage(rd);
        let lhs = self.reg_storage(rn);
        let op = self.shift_op(shift_op)?;
        let cast = asr_cast(shift_op);
        write!(code, "{dest} = {cast}{lhs} {op} ")?;
        self.decompile_op2_shift(code, op2)?;
        write!(code, ";")?;
        Ok(())
    }

    fn decompile_op2_shift(&mut self, code: &mut String, op2: Op2Shift) -> Result<(), DecompError> {
        match op2 {
            Op2Shift::Imm(imm) => write!(code, "{imm:#x}")?,
            Op2Shift::Reg(reg) => {
                let reg = self.reg_storage(reg);
                write!(code, "{reg}")?;
            }
        }
        Ok(())
    }

    fn reg_storage(&mut self, reg: Reg) -> Storage {
        self.storage(Storage::Var(VarStorage::Reg(reg)))
    }

    fn stack_storage(&mut self, offset: u32) -> Storage {
        self.storage(Storage::Var(VarStorage::Stack(offset)))
    }

    fn storage(&mut self, storage: Storage) -> Storage {
        self.storages.insert(storage.clone());
        storage
    }

    fn code(&self) -> Result<String, DecompError> {
        let mut code_str = String::new();
        let code = &mut code_str;
        writeln!(code, "void {}(void) {{", self.function.name())?;
        writeln!(
            code,
            "    // Function decompiled by `dsd decomp`. It sucks. Please do not commit this without substantial cleanup."
        )?;
        for storage in &self.storages {
            write!(code, "    ")?;
            match storage {
                Storage::Var(var_storage) => writeln!(code, "u32 {var_storage};")?,
            }
        }
        writeln!(code)?;
        for line in &self.lines {
            if self.function.labels().contains(&line.address) {
                self.label(code, line.address)?;
                writeln!(code, ":")?;
            }
            writeln!(code, "    {} // {}", line.code, line.ins.display(&UNARM_OPTIONS))?;
        }
        writeln!(code, "}}")?;
        Ok(code_str)
    }

    fn label(&self, code: &mut String, address: u32) -> Result<(), DecompError> {
        write!(code, "_{address:08x}")?;
        Ok(())
    }
}

fn asr_cast(shift_op: ShiftOp) -> &'static str {
    if shift_op == ShiftOp::Asr { "(s32) " } else { "" }
}

struct Line {
    ins: Ins,
    address: u32,
    code: String,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
enum Storage {
    Var(VarStorage),
}

impl Display for Storage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Storage::Var(var_storage) => var_storage.fmt(f),
        }
    }
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone)]
enum VarStorage {
    Reg(Reg),
    CmpLhs,
    CmpRhs,
    Stack(u32),
    Temp,
}

impl Display for VarStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VarStorage::Reg(reg) => reg.display(&UNARM_OPTIONS).fmt(f),
            VarStorage::CmpLhs => write!(f, "lhs"),
            VarStorage::CmpRhs => write!(f, "rhs"),
            VarStorage::Stack(offset) => write!(f, "sp{offset:x}"),
            VarStorage::Temp => write!(f, "temp"),
        }
    }
}
