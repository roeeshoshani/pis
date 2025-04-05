use std::cmp::min;

use bitpiece::BitPiece;

use crate::{
    arch::x86::{X86_REG_BP, X86_REG_BX, X86_REG_DI, X86_REG_RIP, X86_REG_SI},
    cursor::CursorImmExtParams,
    ImmExtKind, PisEndianness,
};

use super::{
    ctx::Ctx,
    lift::{apply_rex_bit_to_reg_encoding, Modrm, Sib},
    PisOp, PisSize, Result,
};

/// represents the address of a memory operand.
///
/// this is just a thin wrapper to make the code more readable.
struct MemOpAddr(PisOp);

/// a modrm memory operand, for example `[rsp + 4]`.
pub struct MemOp {
    /// an operand which represents the address of the memory operand.
    ///
    /// for complex memory operands, this is usually a tmp operand which together with the emitted calculation contains the address.
    pub addr: PisOp,

    /// the size of the memory access for this memory operand.
    pub size: PisSize,
}

/// the rm operand of a modrm byte.
pub enum ModrmRmOp {
    /// the rm operand is a a memory operand.
    Mem(MemOp),

    /// the rm operand is a register operand.
    Reg(PisOp),
}

/// decode modrm displacement.
fn decode_disp(ctx: &mut Ctx) -> Result<Option<PisOp>> {
    match ctx.modrm()?.mod_val().get() {
        0b00 => {
            // no displacement
            Ok(None)
        }
        0b01 => {
            // 8 bit displacement, sign extended to address size
            let disp = ctx.args.code.next_imm_ext_op(&CursorImmExtParams {
                encoded_size: PisSize::B1,
                extended_size: ctx.addr_size,
                ext_kind: ImmExtKind::Sign,
                endianness: PisEndianness::Little,
            })?;
            Ok(Some(disp))
        }
        0b10 => {
            // displacement with varying size, depending on address size
            //
            // the encoded size of the displacement is equal to the address size, but has a maximum length of 32 bits.
            let encoded_size = min(ctx.addr_size, PisSize::B4);

            let disp = ctx.args.code.next_imm_ext_op(&CursorImmExtParams {
                encoded_size,
                extended_size: ctx.addr_size,
                ext_kind: ImmExtKind::Sign,
                endianness: PisEndianness::Little,
            })?;

            Ok(Some(disp))
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
    }
}

fn decode_and_apply_disp(ctx: &mut Ctx, base_regs: PisOp) -> Result<PisOp> {
    let maybe_disp = decode_disp(ctx)?;
    ctx.op_add_opt(base_regs, maybe_disp)
}

fn decode_sib(ctx: &mut Ctx, modrm: Modrm) -> Result<PisOp> {
    let sib = Sib::from_bits(ctx.args.code.next_byte()?);

    let base = sib.base().get();
    let index = sib.index().get();
    let scale = sib.scale().get();
    let mod_val = modrm.mod_val().get();

    // handle the sib base
    let base_op = if base == 0b101 && mod_val == 0b00 {
        // in this case, the base is a 32-bit displacement instead of a register
        ctx.args.code.next_imm_ext_op(&CursorImmExtParams {
            encoded_size: PisSize::B4,
            extended_size: ctx.addr_size,
            ext_kind: ImmExtKind::Zero,
            endianness: PisEndianness::Little,
        })?
    } else {
        // normal case, the base is a register
        ctx.decode_reg(
            apply_rex_bit_to_reg_encoding(base, ctx.prefixes.has_rex_b()),
            ctx.addr_size,
        )
    };

    // handle the scaled index
    let maybe_scaled_index = if index == 0b100 {
        // no index
        None
    } else {
        let index_reg = ctx.decode_reg(index, ctx.addr_size);

        // SAFETY: the scale is 2 bits so this will never overflow
        let mul_factor = 1u64 << scale;
        let mul_factor_op = PisOp::constant(mul_factor, ctx.addr_size);

        Some(ctx.op_mul_unsigned(index_reg, mul_factor_op)?)
    };

    ctx.op_add_opt(base_op, maybe_scaled_index)
}

fn decode_rm_memory_64(ctx: &mut Ctx, modrm: Modrm) -> Result<MemOpAddr> {
    let mod_val = modrm.mod_val().get();
    let rm = modrm.rm().get();

    if mod_val == 0b00 && rm == 0b101 {
        // special case for rip relative with 32 bit displacement
        let disp = ctx.args.code.next_imm_ext_op(&CursorImmExtParams {
            encoded_size: PisSize::B4,
            extended_size: PisSize::B8,
            ext_kind: ImmExtKind::Sign,
            endianness: PisEndianness::Little,
        })?;
        // we want to use the value of RIP here, but we have no way of calculating it at this point.
        // to calculate RIP, we need to know the full length of the instruction, but at this point, we are only decoding the modrm
        // byte, which may be followed by some additional bytes representing for example an immediate operand, but we don't know it
        // at this point.
        // so, we use the RIP register, which will later be resolved by the lifter to the actual address after we determine the full
        // length of the instruction.
        return Ok(MemOpAddr(ctx.op_add(X86_REG_RIP, disp)?));
    }

    // handle base regs
    let base_regs = if rm == 0b100 {
        decode_sib(ctx, modrm)?
    } else {
        ctx.decode_reg(
            apply_rex_bit_to_reg_encoding(rm, ctx.prefixes.has_rex_b()),
            PisSize::B8,
        )
    };

    // apply the disaplacement
    let addr = decode_and_apply_disp(ctx, base_regs)?;

    Ok(MemOpAddr(addr))
}

fn decode_rm_memory_32(ctx: &mut Ctx, modrm: Modrm) -> Result<MemOpAddr> {
    let mod_val = modrm.mod_val().get();
    let rm = modrm.rm().get();

    if mod_val == 0b00 && rm == 0b110 {
        // special case for 32 bit displacement only
        let addr = ctx.args.code.next_imm(PisSize::B4, PisEndianness::Little)?;
        return Ok(MemOpAddr(PisOp::constant(addr, ctx.addr_size)));
    }

    // handle base regs
    let base_regs = if rm == 0b100 {
        decode_sib(ctx, modrm)?
    } else {
        ctx.decode_reg(rm, PisSize::B4)
    };

    // apply the disaplacement
    let addr = decode_and_apply_disp(ctx, base_regs)?;

    Ok(MemOpAddr(addr))
}

fn decode_rm_memory_16(ctx: &mut Ctx, modrm: Modrm) -> Result<MemOpAddr> {
    let mod_val = modrm.mod_val().get();
    let rm = modrm.rm().get();

    if mod_val == 0b00 && rm == 0b110 {
        // special case for 16 bit displacement only
        let addr = ctx.args.code.next_imm(PisSize::B2, PisEndianness::Little)?;
        return Ok(MemOpAddr(PisOp::constant(addr, ctx.addr_size)));
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

    // apply the disaplacement
    let addr = decode_and_apply_disp(ctx, base_regs)?;

    Ok(MemOpAddr(addr))
}

fn decode_rm_memory(ctx: &mut Ctx, modrm: Modrm) -> Result<MemOpAddr> {
    match ctx.addr_size {
        PisSize::B2 => decode_rm_memory_16(ctx, modrm),
        PisSize::B4 => decode_rm_memory_32(ctx, modrm),
        PisSize::B8 => decode_rm_memory_64(ctx, modrm),
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
        let addr = decode_rm_memory(ctx, modrm)?;
        Ok(ModrmRmOp::Mem(MemOp {
            addr: addr.0,
            size: operand_size,
        }))
    }
}
