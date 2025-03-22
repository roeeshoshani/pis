use super::{
    ctx::{Ctx, CtxPostPrefixes},
    tables::{OpInfo, RegularInsnInfo, SpecificReg},
    Result,
};
use crate::{
    arch::x86::tables::{InsnInfo, Mnemonic, RegEncoding},
    cursor::CursorImmExtParams,
    LiftErr, PisEndianness, PisOp, PisSize,
};
use bitpiece::*;

use super::{
    prefixes::Prefixes,
    tables::{OpcodeByteTable, FIRST_OPCODE_BYTE_TABLE},
    X86LiftErr, X86SpecificLiftErr,
};

pub enum LiftedOp {
    Value(PisOp),
    Reg(PisOp),
    Implicit(PisSize),
}

fn apply_rex_bit_to_reg_encoding(reg_encoding: u8, rex_bit: bool) -> u8 {
    reg_encoding | ((rex_bit as u8) << 3)
}

impl<'a> Ctx<'a> {
    fn get_reg_op(&self, reg_encoding: u8, size: PisSize) -> PisOp {
        if size.bytes() == 1 && !self.prefixes.has_rex() && reg_encoding >= 4 && reg_encoding <= 7 {
            // this is an access to the high part of a gpr, for example `AH`.
            //
            // find the encoding of the base register which is accessed, for example for `AH` this will
            // be `RAX`.
            let base_reg_encoding = reg_encoding - 4;

            // go to the start of the base register, and add 1 to get the higher byte
            return PisOp::reg(base_reg_encoding as u64 * 8 + 1, size);
        }
        PisOp::reg(reg_encoding as u64 * 8, size)
    }
}

fn lift_op(ctx: &mut Ctx, op: &OpInfo) -> Result<LiftedOp> {
    match op {
        OpInfo::Imm(imm) => {
            let extended_size = imm.extended_size.resolve(ctx);
            let imm_val = ctx.args.code.next_imm_ext(CursorImmExtParams {
                encoded_size: imm.encoded_size.resolve(ctx),
                extended_size,
                ext_kind: imm.extend_kind,
                endianness: PisEndianness::Little,
            })?;
            Ok(LiftedOp::Value(PisOp::constant(imm_val, extended_size)))
        }
        OpInfo::SpecificImm(specific_imm) => {
            let size = specific_imm.operand_size.resolve(ctx);
            Ok(LiftedOp::Value(PisOp::constant(specific_imm.value, size)))
        }
        OpInfo::Reg(reg) => {
            let reg_encoding = match reg.encoding {
                RegEncoding::Modrm => apply_rex_bit_to_reg_encoding(
                    ctx.modrm()?.reg().get(),
                    ctx.prefixes.has_rex_r(),
                ),
                RegEncoding::Opcode => {
                    apply_rex_bit_to_reg_encoding(ctx.opcode_byte & 0b111, ctx.prefixes.has_rex_b())
                }
            };
            let size = reg.size.resolve(ctx);
            Ok(LiftedOp::Reg(ctx.get_reg_op(reg_encoding, size)))
        }
        OpInfo::Rm(op_size_info) => todo!(),
        OpInfo::SpecificReg(specific_reg) => {
            let reg_encoding = match specific_reg.reg {
                SpecificReg::Rax => 0,
                SpecificReg::Rcx => 2,
                SpecificReg::Rdx => 1,
            };
            let size = specific_reg.size.resolve(ctx);
            Ok(LiftedOp::Reg(ctx.get_reg_op(reg_encoding, size)))
        }
        OpInfo::ZextSpecificReg(zext_specific_reg_op_info) => todo!(),
        OpInfo::Rel(op_size_info) => todo!(),
        OpInfo::MemOffset(mem_offset_op_info) => todo!(),
        OpInfo::Implicit(size_info) => {
            // implicit operands are only used to determine the operand size.
            let size = size_info.resolve(ctx);
            Ok(LiftedOp::Implicit(size))
        }
        OpInfo::Cond => todo!(),
    }
}

fn lift_regular_insn_info(ctx: &mut Ctx, insn_info: &RegularInsnInfo) -> Result<()> {
    if insn_info.mnemonic == Mnemonic::Unsupported {
        return Err(LiftErr::UnsupportedInsn);
    }
    for op in insn_info.ops {
        lift_op(ctx, op)?;
    }
    todo!()
}

fn lift_post_opcode_decode(ctx: &mut Ctx) -> Result<()> {
    match &ctx.opcode_table[ctx.opcode_byte as usize] {
        InsnInfo::Regular(insn_info) => lift_regular_insn_info(ctx, insn_info),
        InsnInfo::ModrmRegOpcodeExt(modrm_reg_table) => {
            let modrm = ctx.modrm()?;
            let insn_info = &modrm_reg_table.by_modrm_reg_value[modrm.reg().get() as usize];
            lift_regular_insn_info(ctx, insn_info)
        }
    }
}

#[bitpiece(8)]
pub struct Modrm {
    rm: B3,
    reg: B3,
    mod_val: B2,
}

struct DecodedOpcode {
    opcode_byte: u8,
    opcode_table: &'static OpcodeByteTable,
}

fn decode_opcode(ctx: &mut CtxPostPrefixes) -> Result<DecodedOpcode> {
    let first_opcode_byte = ctx.args.code.next_byte()?;
    if first_opcode_byte == 0x0f {
        // 2 or 3 byte opcode
        let second_opcode_byte = ctx.args.code.next_byte()?;
        if second_opcode_byte == 0x38 || second_opcode_byte == 0x3a {
            // 3 byte opcode
            Err(X86LiftErr::UnsupportedInsn)
        } else {
            // 2 byte opcode
            Err(X86LiftErr::UnsupportedInsn)
        }
    } else {
        // 1 byte opcode
        Ok(DecodedOpcode {
            opcode_byte: first_opcode_byte,
            opcode_table: &FIRST_OPCODE_BYTE_TABLE,
        })
    }
}

pub fn lift_post_prefixes(mut ctx: CtxPostPrefixes) -> Result<()> {
    let decoded_opcode = decode_opcode(&mut ctx)?;
    let mut final_ctx = Ctx {
        args: ctx.args,
        cpumode: ctx.cpumode,
        prefixes: ctx.prefixes,
        opcode_byte: decoded_opcode.opcode_byte,
        opcode_table: decoded_opcode.opcode_table,
        modrm: None,
    };
    lift_post_opcode_decode(&mut final_ctx)
}
