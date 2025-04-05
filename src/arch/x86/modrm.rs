use crate::{
    arch::x86::{X86_REG_BP, X86_REG_BX, X86_REG_DI, X86_REG_SI},
    cursor::CursorImmExtParams,
    ImmExtKind, PisEndianness,
};

use super::{
    ctx::Ctx,
    lift::{apply_rex_bit_to_reg_encoding, Modrm},
    PisOp, PisSize, Result,
};

/// a modrm memory operand, for example `[rsp + 4]`.
pub struct MemOp {
    /// an operand which represents the address of the memory operand.
    ///
    /// for complex memory operands, this is usually a tmp operand which together with the emitted calculation contains the address.
    pub addr: PisOp,
}

/// the rm operand of a modrm byte.
pub enum ModrmRmOp {
    /// the rm operand is a a memory operand.
    Mem(MemOp),

    /// the rm operand is a register operand.
    Reg(PisOp),
}

fn decode_rm_memory_16(ctx: &mut Ctx, operand_size: PisSize, modrm: Modrm) -> Result<MemOp> {
    let mod_val = modrm.mod_val().get();
    let rm = modrm.rm().get();

    if mod_val == 0b00 && rm == 0b110 {
        // special case for 16 bit displacement only
        let addr = ctx.args.code.next_imm(PisSize::B2, PisEndianness::Little)?;
        return Ok(MemOp {
            addr: PisOp::constant(addr, ctx.addr_size),
        });
    }

    // handle base regs
    let base_regs = match rm {
        0b000 => ctx.op_add(X86_REG_BX, X86_REG_SI)?,
        0b001 => ctx.op_add(X86_REG_BX, X86_REG_DI)?,
        0b010 => ctx.op_add(X86_REG_BP, X86_REG_SI)?,
        0b011 => ctx.op_add(X86_REG_BP, X86_REG_DI)?,
        0b100 => X86_REG_SI,
        0b101 => X86_REG_DI,
        0b110 => X86_REG_BP,
        0b111 => X86_REG_BX,
        // rm is only 3 bits
        _ => unreachable!(),
    };

    // now handle displacement
    let maybe_disp = match mod_val {
        0b00 => {
            // no displacement
            None
        }
        0b01 => {
            // 8 bit displacement, sign extended to 16-bits
            let disp = ctx.args.code.next_imm_ext_op(&CursorImmExtParams {
                encoded_size: PisSize::B1,
                extended_size: PisSize::B2,
                ext_kind: ImmExtKind::Sign,
                endianness: PisEndianness::Little,
            })?;
            Some(disp)
        }
        0b10 => {
            // 16 bit displacement
            let disp = ctx
                .args
                .code
                .next_imm_op(PisSize::B2, PisEndianness::Little)?;
            Some(disp)
        }
        0b11 => {
            // unreachable. this is the case for the modrm values that are registers and not memory operands, and it handled
            // elsewhere.
            unreachable!()
        }
        // mod is only 2 bits
        _ => {
            unreachable!()
        }
    };

    // calculate the final address by adding the optional displacement to the base regs
    let mut final_addr = base_regs;
    if let Some(disp) = maybe_disp {
        ctx.op_add_assign(&mut final_addr, disp);
    }

    Ok(MemOp { addr: final_addr })
}

fn decode_rm_memory(ctx: &mut Ctx, operand_size: PisSize, modrm: Modrm) -> Result<MemOp> {
    match ctx.addr_size {
        PisSize::B2 => decode_rm_memory_16(ctx, operand_size, modrm),
        _ => todo!(),
    }
}

pub fn modrm_decode_rm_operand(ctx: &mut Ctx, operand_size: PisSize) -> Result<ModrmRmOp> {
    let modrm = ctx.modrm()?;
    if modrm.mod_val().get() == 0b11 {
        // in this case, the rm operand is a register and not a memory operand
        let encoded_reg = apply_rex_bit_to_reg_encoding(modrm.rm().get(), ctx.prefixes.has_rex_b());
        let reg = ctx.decode_reg(encoded_reg, operand_size);
        Ok(ModrmRmOp::Reg(reg))
    } else {
        Ok(ModrmRmOp::Mem(decode_rm_memory(ctx, operand_size, modrm)?))
    }
}
