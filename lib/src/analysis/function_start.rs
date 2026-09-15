use unarm::{Ins, LdrStrOffset, Op2, Op2Shift, Reg, ShiftImm};

pub fn is_valid_function_start_arm(ins: &Ins) -> bool {
    match ins {
        Ins::Illegal => false,
        Ins::Eor { rd, rn, op2: Op2::ShiftImm(ShiftImm { rm, .. }), .. }
            if rd == rn || rd == rm || rn == rm =>
        {
            // Weird EOR instruction
            false
        }
        _ => true,
    }
}

pub fn is_valid_function_start_thumb(ins: &Ins) -> bool {
    if ins.is_data_operation()
        && let Some(rn) = ins.rn()
        && !matches!(rn, Reg::R0 | Reg::R1 | Reg::R2 | Reg::R3 | Reg::Sp | Reg::Pc)
    {
        // Data operand must be an argument register, SP or PC
        return false;
    }

    match ins {
        Ins::Illegal => false,
        Ins::Mov { rd, op2: Op2::ShiftImm(ShiftImm { rm, .. }), .. } if rd == rm => {
            // Useless mov
            false
        }
        Ins::Lsl { rd, rn, op2: Op2Shift::Imm(0), .. } if rd == rn => {
            // Useless data op
            false
        }
        Ins::Lsr { op2: Op2Shift::Imm(shift), .. }
            if (shift % 4) == 0 && *shift != 16 && *shift != 24 =>
        {
            // Table of bytes with values 0-7 got interpreted as Thumb code
            // Shift by 16 or 24 is allowed since they may be used for integer type casts
            false
        }
        Ins::Ldr { addr, .. }
        | Ins::Ldrb { addr, .. }
        | Ins::Str { addr, .. }
        | Ins::Strb { addr, .. }
            if !matches!(addr.rn(), Reg::R0 | Reg::R1 | Reg::R2 | Reg::R3 | Reg::Sp | Reg::Pc) =>
        {
            // Load/store base must be an argument register, SP or PC
            false
        }
        Ins::Ldrh { addr, .. }
        | Ins::Ldrsh { addr, .. }
        | Ins::Ldrsb { addr, .. }
        | Ins::Strh { addr, .. }
            if !matches!(addr.rn(), Reg::R0 | Reg::R1 | Reg::R2 | Reg::R3 | Reg::Sp | Reg::Pc) =>
        {
            // Load/store base must be an argument register, SP or PC
            false
        }
        Ins::Strh { rd, addr, .. } if *rd == addr.rn() => {
            // Weird self reference:
            // *ptr = (u16) ptr;
            false
        }
        Ins::Strb { rd, addr, .. } if *rd == addr.rn() => {
            // Weird self reference:
            // *ptr = (u8) ptr;
            false
        }
        Ins::Ldr { addr, .. } | Ins::Ldrb { addr, .. }
            if let LdrStrOffset::Reg { rm, .. } = addr.offset()
                && !matches!(rm, Reg::R0 | Reg::R1 | Reg::R2 | Reg::R3) =>
        {
            // Offset register must be an argument register
            false
        }
        _ => true,
    }
}

pub fn is_valid_function_start(ins: &Ins, thumb: bool) -> bool {
    if ins.is_conditional() {
        return false;
    }
    if thumb {
        is_valid_function_start_thumb(ins)
    } else {
        is_valid_function_start_arm(ins)
    }
}
