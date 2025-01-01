use unarm::{
    args::{Argument, OffsetReg, Reg, Register},
    arm, thumb, Ins, ParsedIns,
};

pub fn is_valid_function_start_arm(_address: u32, ins: arm::Ins, parsed_ins: &ParsedIns) -> bool {
    if ins.op == arm::Opcode::Illegal || parsed_ins.is_illegal() {
        return false;
    } else if ins.has_cond() && ins.modifier_cond() != arm::Cond::Al {
        return false;
    }
    let args = &parsed_ins.args;
    match (parsed_ins.mnemonic, args[0], args[1], args[2], args[3]) {
        (
            "eor",
            Argument::Reg(Reg { reg: dest, .. }),
            Argument::Reg(Reg { reg: src_a, .. }),
            Argument::Reg(Reg { reg: src_b, .. }),
            Argument::None,
        ) if dest == src_a || dest == src_b || src_a == src_b => {
            // Weird EOR instruction
            false
        }
        _ => true,
    }
}

pub fn is_valid_function_start_thumb(_address: u32, ins: thumb::Ins, parsed_ins: &ParsedIns) -> bool {
    if matches!(ins.op, thumb::Opcode::Illegal | thumb::Opcode::Bl | thumb::Opcode::BlH) || parsed_ins.is_illegal() {
        return false;
    }

    let args = &parsed_ins.args;

    if ins.is_data_operation() {
        if let Argument::Reg(Reg { reg, .. }) = args[1] {
            // Data operand must be an argument register, SP or PC
            if !matches!(reg, Register::R0 | Register::R1 | Register::R2 | Register::R3 | Register::Sp | Register::Pc) {
                return false;
            }
        }
    }

    match (parsed_ins.mnemonic, args[0], args[1], args[2], args[3]) {
        ("mov", Argument::Reg(Reg { reg: dst, .. }), Argument::Reg(Reg { reg: src, .. }), Argument::None, Argument::None)
        | ("movs", Argument::Reg(Reg { reg: dst, .. }), Argument::Reg(Reg { reg: src, .. }), Argument::None, Argument::None)
            if src == dst =>
        {
            // Useless mov
            false
        }
        (
            "lsl",
            Argument::Reg(Reg { reg: dst, .. }),
            Argument::Reg(Reg { reg: src, .. }),
            Argument::UImm(0),
            Argument::None,
        )
        | (
            "lsls",
            Argument::Reg(Reg { reg: dst, .. }),
            Argument::Reg(Reg { reg: src, .. }),
            Argument::UImm(0),
            Argument::None,
        ) if src == dst => {
            // Useless data op
            false
        }
        ("lsl", Argument::Reg(Reg { .. }), Argument::Reg(Reg { .. }), Argument::UImm(shift), Argument::None)
        | ("lsls", Argument::Reg(Reg { .. }), Argument::Reg(Reg { .. }), Argument::UImm(shift), Argument::None)
        | ("lsr", Argument::Reg(Reg { .. }), Argument::Reg(Reg { .. }), Argument::UImm(shift), Argument::None)
        | ("lsrs", Argument::Reg(Reg { .. }), Argument::Reg(Reg { .. }), Argument::UImm(shift), Argument::None)
            if (shift % 4) == 0 && shift != 16 && shift != 24 =>
        {
            // Table of bytes with values 0-7 got interpreted as Thumb code
            // Shift by 16 or 24 is allowed since they may be used for integer type casts
            false
        }
        ("ldr", Argument::Reg(_), Argument::Reg(Reg { deref: true, reg, .. }), _, _)
        | ("ldrh", Argument::Reg(_), Argument::Reg(Reg { deref: true, reg, .. }), _, _)
        | ("ldrb", Argument::Reg(_), Argument::Reg(Reg { deref: true, reg, .. }), _, _)
        | ("ldrsh", Argument::Reg(_), Argument::Reg(Reg { deref: true, reg, .. }), _, _)
        | ("ldrsb", Argument::Reg(_), Argument::Reg(Reg { deref: true, reg, .. }), _, _)
        | ("str", Argument::Reg(_), Argument::Reg(Reg { deref: true, reg, .. }), _, _)
        | ("strb", Argument::Reg(_), Argument::Reg(Reg { deref: true, reg, .. }), _, _)
        | ("strh", Argument::Reg(_), Argument::Reg(Reg { deref: true, reg, .. }), _, _)
            if !matches!(reg, Register::R0 | Register::R1 | Register::R2 | Register::R3 | Register::Sp | Register::Pc) =>
        {
            // Load/store base must be an argument register, SP or PC
            false
        }
        ("strh", Argument::Reg(Reg { reg, .. }), Argument::Reg(Reg { deref: true, reg: base, .. }), _, _)
        | ("strb", Argument::Reg(Reg { reg, .. }), Argument::Reg(Reg { deref: true, reg: base, .. }), _, _)
            if base == reg =>
        {
            // Weird self reference:
            // *ptr = (u16) ptr;
            // *ptr = (u8) ptr;
            false
        }
        ("ldr", Argument::Reg(_), Argument::Reg(Reg { deref: true, .. }), Argument::OffsetReg(OffsetReg { reg, .. }), _)
        | ("ldrh", Argument::Reg(_), Argument::Reg(Reg { deref: true, .. }), Argument::OffsetReg(OffsetReg { reg, .. }), _)
        | ("ldrb", Argument::Reg(_), Argument::Reg(Reg { deref: true, .. }), Argument::OffsetReg(OffsetReg { reg, .. }), _)
        | ("ldrsh", Argument::Reg(_), Argument::Reg(Reg { deref: true, .. }), Argument::OffsetReg(OffsetReg { reg, .. }), _)
        | ("ldrsb", Argument::Reg(_), Argument::Reg(Reg { deref: true, .. }), Argument::OffsetReg(OffsetReg { reg, .. }), _)
            if !matches!(reg, Register::R0 | Register::R1 | Register::R2 | Register::R3) =>
        {
            // Offset register must be an argument register
            false
        }
        _ => true,
    }
}

pub fn is_valid_function_start(address: u32, ins: Ins, parsed_ins: &ParsedIns) -> bool {
    match ins {
        Ins::Arm(ins) => is_valid_function_start_arm(address, ins, parsed_ins),
        Ins::Thumb(ins) => is_valid_function_start_thumb(address, ins, parsed_ins),
        Ins::Data => false,
    }
}
