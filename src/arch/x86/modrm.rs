use super::lift::apply_rex_bit_to_reg_encoding;
use super::Result;
use super::{ctx::Ctx, lift::Modrm, PisOp, PisSize};

/// the rm operand of a modrm byte.
pub enum ModrmRmOperand {
    /// the rm operand is a a memory operand.
    Mem {
        /// an operand which represents the address of this memory operand.
        addr: PisOp,
    },

    /// the rm operand is a register operand.
    Reg(PisOp),
}

fn decode_rm_memory_16(
    ctx: &mut Ctx,
    operand_size: PisSize,
    modrm: Modrm,
) -> Result<ModrmRmOperand> {
    let mod_val = modrm.mod_val().get();
    if mod_val == 0b00 && mod_val == 0b110 {
        // 16 bit displacement only
        ctx.args.code.next_imm_ext(Curs)
    }
}

fn decode_rm_memory(ctx: &mut Ctx, operand_size: PisSize, modrm: Modrm) -> Result<ModrmRmOperand> {
    match ctx.addr_size {
        PisSize::B2 => decode_rm_memory_16(ctx),
    }
}

pub fn modrm_decode_rm_operand(ctx: &mut Ctx, operand_size: PisSize) -> Result<ModrmRmOperand> {
    let modrm = ctx.modrm()?;
    if modrm.mod_val().get() == 0b11 {
        // in this case, the rm operand is a register and not a memory operand
        let encoded_reg = apply_rex_bit_to_reg_encoding(modrm.rm().get(), ctx.prefixes.has_rex_b());
        let reg = ctx.decode_reg(encoded_reg, operand_size);
        Ok(ModrmRmOperand::Reg(reg))
    } else {
        decode_rm_memory(ctx, operand_size)
    }
}
