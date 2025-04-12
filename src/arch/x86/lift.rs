use super::{
    ctx::{Ctx, CtxPostPrefixes},
    modrm::{modrm_decode_rm_operand, ModrmRmOp},
    prefixes::LegacyPrefix,
    tables::{OpInfo, RegularInsnInfo, SpecificReg},
    tmp_op_allocator::TmpOpAllocator,
    LiftRes, Result, X86Cpumode, X86_INSN_MAX_OPS, X86_REG_FLAGS_CF, X86_REG_FLAGS_OF,
    X86_REG_FLAGS_PF, X86_REG_FLAGS_SF, X86_REG_FLAGS_ZF, X86_REG_RAX, X86_REG_RDX, X86_REG_RIP,
    X86_REG_RSP,
};
use crate::{
    arch::x86::tables::{InsnInfo, Mnemonic, RegEncoding},
    cursor::CursorImmExtParams,
    pis_insn,
    utils::array_vec,
    LiftErr, MachineInsnLen, PisEmitter, PisEndian, PisInsn, PisOp, PisOpcode, PisSize,
    X86_REG_FLAGS_DF, X86_REG_FLAGS_IF, X86_REG_RDI, X86_REG_RSI,
};
use arrayvec::ArrayVec;
use bitpiece::*;

use super::{
    prefixes::Prefixes,
    tables::{OpcodeByteTable, FIRST_OPCODE_BYTE_TABLE},
    X86LiftErr, X86SpecificLiftErr,
};

/// a memory operand, for example `[rsp + 4]`.
pub struct MemOp {
    /// an operand which represents the address of the memory operand.
    ///
    /// for complex memory operands, this is usually a tmp operand which together with the emitted calculation contains the address.
    pub addr: PisOp,

    /// the size of the memory access for this memory operand.
    pub size: PisSize,
}
impl MemOp {
    pub fn read(&self, ctx: &mut Ctx) -> Result<PisOp> {
        let tmp = ctx.emitter.tmp_op_allocator.alloc(self.size)?;
        ctx.emit(pis_insn!(Load! tmp, self.addr));
        Ok(tmp)
    }
}

pub enum LiftedOp {
    Value(PisOp),
    Reg(PisOp),
    Mem(MemOp),
    Implicit(PisSize),
}
impl LiftedOp {
    pub fn read(&self, ctx: &mut Ctx) -> Result<PisOp> {
        match self {
            LiftedOp::Value(value) => Ok(*value),
            LiftedOp::Reg(reg) => Ok(*reg),
            LiftedOp::Mem(mem_op) => mem_op.read(ctx),
            LiftedOp::Implicit(pis_size) => unreachable!(),
        }
    }
    pub fn write(&self, value: PisOp, ctx: &mut Ctx) {
        match self {
            LiftedOp::Value(value) => unreachable!(),
            LiftedOp::Reg(reg) => {
                assert_eq!(value.size, reg.size);
                ctx.emit(pis_insn!(Move! *reg, value));
            }
            LiftedOp::Mem(mem_op) => {
                assert_eq!(value.size, mem_op.size);
                ctx.emit(pis_insn!(Store! mem_op.addr, value));
            }
            LiftedOp::Implicit(pis_size) => unreachable!(),
        }
    }
    pub fn size(&self) -> PisSize {
        match self {
            LiftedOp::Value(value) => value.size,
            LiftedOp::Reg(reg) => reg.size,
            LiftedOp::Mem(mem_op) => mem_op.size,
            LiftedOp::Implicit(size) => *size,
        }
    }
}

pub fn apply_rex_bit_to_reg_encoding(reg_encoding: u8, rex_bit: bool) -> u8 {
    reg_encoding | ((rex_bit as u8) << 3)
}

impl<'a> Ctx<'a> {
    pub fn decode_reg(&self, reg_encoding: u8, size: PisSize) -> PisOp {
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

/// calculates the mask that needs to be applied to the ip value after updating it due to a relative branch.
fn calc_near_branch_ip_mask(ctx: &Ctx) -> u64 {
    match ctx.cpumode {
        X86Cpumode::B32 => {
            // in 32-bit mode the mask depends on the presence of the operand size override prefix.
            if ctx
                .prefixes
                .has_legacy_prefix(LegacyPrefix::OperandSizeOverride)
            {
                // with operand size override, the ip is masked to 16 bits
                u16::MAX as u64
            } else {
                // without operand size override, the ip is masked to 32 bits
                u32::MAX as u64
            }
        }
        X86Cpumode::B64 => {
            // in 64-bit mode, the ip value is always limited to 64-bits, regardless of prefixes
            return u64::MAX;
        }
    }
}

#[bitpiece(4)]
#[derive(Debug, Clone, Copy)]
struct Cond {
    is_negative: bool,
    kind: CondKind,
}

#[bitpiece(3)]
#[derive(Debug, Clone, Copy)]
enum CondKind {
    Overflow,
    Below,
    Equals,
    BelowEqual,
    Sign,
    Parity,
    Lower,
    LowerEqual,
}
impl CondKind {
    fn lift(&self, ctx: &mut Ctx) -> Result<PisOp> {
        match self {
            CondKind::Overflow => Ok(X86_REG_FLAGS_OF),
            CondKind::Below => Ok(X86_REG_FLAGS_CF),
            CondKind::Equals => Ok(X86_REG_FLAGS_ZF),
            CondKind::BelowEqual => {
                Ok(ctx
                    .emitter
                    .op_binop(PisOpcode::Or, X86_REG_FLAGS_ZF, X86_REG_FLAGS_CF)?)
            }
            CondKind::Sign => Ok(X86_REG_FLAGS_SF),
            CondKind::Parity => Ok(X86_REG_FLAGS_PF),
            CondKind::Lower => {
                Ok(ctx
                    .emitter
                    .op_binop(PisOpcode::Xor, X86_REG_FLAGS_SF, X86_REG_FLAGS_OF)?)
            }
            CondKind::LowerEqual => {
                let lower =
                    ctx.emitter
                        .op_binop(PisOpcode::Xor, X86_REG_FLAGS_SF, X86_REG_FLAGS_OF)?;
                Ok(ctx
                    .emitter
                    .op_binop(PisOpcode::Or, lower, X86_REG_FLAGS_ZF)?)
            }
        }
    }
}

fn lift_op(ctx: &mut Ctx, op: &OpInfo) -> Result<LiftedOp> {
    match op {
        OpInfo::Imm(imm) => {
            // an immediate encoded in the instruction
            let extended_size = imm.extended_size.resolve(ctx);
            let imm = ctx.args.code.next_imm_ext_op(&CursorImmExtParams {
                encoded_size: imm.encoded_size.resolve(ctx),
                extended_size,
                ext_kind: imm.extend_kind,
                endian: PisEndian::Little,
            })?;
            Ok(LiftedOp::Value(imm))
        }
        OpInfo::SpecificImm(specific_imm) => {
            // an immediate operand with a specific opcode-hardcoded value
            let size = specific_imm.operand_size.resolve(ctx);
            Ok(LiftedOp::Value(PisOp::constant(specific_imm.value, size)))
        }
        OpInfo::Reg(reg) => {
            // a register operand
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
            Ok(LiftedOp::Reg(ctx.decode_reg(reg_encoding, size)))
        }
        OpInfo::Rm(size_info) => {
            // a modrm rm operand
            let size = size_info.resolve(ctx);
            let rm_operand = modrm_decode_rm_operand(ctx, size)?;
            match rm_operand {
                ModrmRmOp::Mem(mem_op) => Ok(LiftedOp::Mem(mem_op)),
                ModrmRmOp::Reg(reg) => Ok(LiftedOp::Reg(reg)),
            }
        }
        OpInfo::SpecificReg(info) => {
            // a specific register
            let size = info.size.resolve(ctx);

            let reg_encoding = info.reg.reg_encoding();
            let reg = ctx.decode_reg(reg_encoding, size);

            Ok(LiftedOp::Reg(reg))
        }
        OpInfo::ZextSpecificReg(info) => {
            // a specific register, zero extended to a certain value.
            let size = info.size.resolve(ctx);
            let extended_size = info.extended_size.resolve(ctx);

            let reg_encoding = info.reg.reg_encoding();
            let reg = ctx.decode_reg(reg_encoding, size);

            let extended_reg = ctx.emitter.op_zext(reg, extended_size)?;

            Ok(LiftedOp::Value(extended_reg))
        }
        OpInfo::Rel(size_info) => {
            // a relative operand. used for near branches.
            let size = size_info.resolve(ctx);
            let rel_offset = ctx.args.code.next_imm_ext_op(&CursorImmExtParams {
                encoded_size: size,
                extended_size: ctx.addr_size,
                ext_kind: crate::ImmExtKind::Sign,
                endian: PisEndian::Little,
            })?;
            let mask = calc_near_branch_ip_mask(ctx);
            let mask_op = PisOp::constant(mask, PisSize::B8);
            Ok(LiftedOp::Value(ctx.emitter.op_binop(
                PisOpcode::And,
                X86_REG_RIP,
                mask_op,
            )?))
        }
        OpInfo::MemOffset(info) => {
            // abs memory addr encoded as immediate
            let addr = ctx
                .args
                .code
                .next_imm_op(ctx.addr_size, PisEndian::Little)?;
            let size = info.mem_operand_size.resolve(ctx);
            Ok(LiftedOp::Mem(MemOp { addr, size }))
        }
        OpInfo::Implicit(size_info) => {
            // implicit operands are only used to determine the operand size.
            let size = size_info.resolve(ctx);
            Ok(LiftedOp::Implicit(size))
        }
        OpInfo::Cond => {
            let cond = Cond::from_bits(ctx.opcode_byte & 0b1111);
            let mut result = cond.kind().lift(ctx)?;
            if cond.is_negative() {
                result = ctx.emitter.op_unop(PisOpcode::CondNeg, result)?;
            }
            Ok(LiftedOp::Value(result))
        }
    }
}

fn binop_update_flag<F>(
    ctx: &mut Ctx,
    lhs: PisOp,
    rhs: PisOp,
    flag_reg: PisOp,
    calc: F,
) -> Result<()>
where
    F: FnOnce(&mut Ctx, PisOp, PisOp) -> Result<PisOp>,
{
    let value = calc(ctx, lhs, rhs)?;
    ctx.emitter.op_move(flag_reg, value);
    Ok(())
}

fn binop_update_c_f<F>(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp, calc: F) -> Result<()>
where
    F: FnOnce(&mut Ctx, PisOp, PisOp) -> Result<PisOp>,
{
    binop_update_flag(ctx, lhs, rhs, X86_REG_FLAGS_CF, calc)
}

fn binop_update_o_f<F>(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp, calc: F) -> Result<()>
where
    F: FnOnce(&mut Ctx, PisOp, PisOp) -> Result<PisOp>,
{
    binop_update_flag(ctx, lhs, rhs, X86_REG_FLAGS_OF, calc)
}

/// calculates the parity flag value of the given calculation result.
fn calc_pf(ctx: &mut Ctx, calc_res: PisOp) -> Result<PisOp> {
    let low_byte = ctx.emitter.op_trunc(calc_res, PisSize::B1)?;
    Ok(ctx.emitter.op_unop(PisOpcode::Parity, low_byte)?)
}

/// calculates the zero flag value of the given calculation result.
fn calc_zf(ctx: &mut Ctx, calc_res: PisOp) -> Result<PisOp> {
    Ok(ctx.emitter.op_binop(
        PisOpcode::Equals,
        calc_res,
        PisOp::constant(0, calc_res.size),
    )?)
}

/// calculates the most significant bit of the given value.
/// the output is a 1 byte conditional expression which indicates whether the sign bit of the given
/// value is enabled.
fn calc_msb(ctx: &mut Ctx, value: PisOp) -> Result<PisOp> {
    // shift it right such that the msb becomes the lsb
    let shift_amount = value.size.bits() - 1;
    let shift_amount_op = PisOp::constant(shift_amount as u64, value.size);
    let shifted = ctx
        .emitter
        .op_binop(PisOpcode::ShiftRightUnsigned, value, shift_amount_op)?;

    // truncate it to 1 byte
    Ok(ctx.emitter.op_trunc(shifted, PisSize::B1)?)
}

/// calculates the sign flag value of the given calculation result.
fn calc_sf(ctx: &mut Ctx, calc_res: PisOp) -> Result<PisOp> {
    calc_msb(ctx, calc_res)
}

/// updates the parity, zero and sign flags according to the given calculation result.
fn update_parity_zero_sign_flags(ctx: &mut Ctx, calc_res: PisOp) -> Result<()> {
    let pf = calc_pf(ctx, calc_res)?;
    ctx.emitter.op_move(X86_REG_FLAGS_PF, pf);

    let zf = calc_zf(ctx, calc_res)?;
    ctx.emitter.op_move(X86_REG_FLAGS_ZF, zf);

    let sf = calc_sf(ctx, calc_res)?;
    ctx.emitter.op_move(X86_REG_FLAGS_SF, sf);

    Ok(())
}

/// calculates the value of the carry flag according to a addition operation `a + b`.
fn calc_c_f_add(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    Ok(ctx.emitter.op_binop(PisOpcode::UnsignedCarry, lhs, rhs)?)
}

/// updates the value of the overflow flag according to a addition operation `a + b`.
fn calc_o_f_add(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    Ok(ctx.emitter.op_binop(PisOpcode::SignedCarry, lhs, rhs)?)
}

fn update_c_f_add(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<()> {
    binop_update_c_f(ctx, lhs, rhs, calc_c_f_add)
}
fn update_o_f_add(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<()> {
    binop_update_o_f(ctx, lhs, rhs, calc_o_f_add)
}

/// the mnemonic calculation of the ADD mnemonic.
fn mnm_calc_add(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    let res = ctx.emitter.op_binop(PisOpcode::Add, lhs, rhs)?;

    update_c_f_add(ctx, lhs, rhs)?;
    update_o_f_add(ctx, lhs, rhs)?;
    update_parity_zero_sign_flags(ctx, res)?;

    Ok(res)
}

/// calculates the value of the carry flag according to a subtraction operation `a - b`.
fn calc_c_f_sub(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    Ok(ctx
        .emitter
        .op_binop(PisOpcode::LessThanUnsigned, lhs, rhs)?)
}

/// calculates the value of the overflow flag for a subtraction operation `a - b`.
fn calc_o_f_sub(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    // calculate the sign bit of the subtraction result
    let sub_res = ctx.emitter.op_binop(PisOpcode::Sub, lhs, rhs)?;
    let sub_res_msb = calc_msb(ctx, sub_res)?;

    // check if lhs < rhs
    let lhs_less_than_rhs = ctx.emitter.op_binop(PisOpcode::LessThanSigned, lhs, rhs)?;

    // the overflow can be calculated by xoring the less than condition with the sign bit.
    //
    // this is because, if the less than condition is 1, it means that `a < b`, in which case we
    // expect the result to be negative, and if it is not then it is an overflow. so, if less than
    // is 1 and sign is 0, it is an overflow.
    //
    // additionally, if the less than condition is 0, it means that `a >= b`, in which case we
    // expect the result to be positive, and if it is not then it is an overflow. so, if less than
    // is 0 and sign is 1, it is an overflow.
    //
    // both of those cases can be detected by just xoring these values together.
    Ok(ctx
        .emitter
        .op_binop(PisOpcode::Xor, sub_res_msb, lhs_less_than_rhs)?)
}

fn update_c_f_sub(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<()> {
    binop_update_c_f(ctx, lhs, rhs, calc_c_f_sub)
}
fn update_o_f_sub(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<()> {
    binop_update_o_f(ctx, lhs, rhs, calc_o_f_sub)
}

/// the mnemonic calculation of the SUB mnemonic.
fn mnm_calc_sub(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    let res = ctx.emitter.op_binop(PisOpcode::Sub, lhs, rhs)?;

    update_c_f_sub(ctx, lhs, rhs)?;
    update_o_f_sub(ctx, lhs, rhs)?;
    update_parity_zero_sign_flags(ctx, res)?;

    Ok(res)
}

/// the mnemonic calculation of the DEC mnemonic.
fn mnm_calc_dec(ctx: &mut Ctx, value: PisOp) -> Result<PisOp> {
    let one = PisOp::constant(1, value.size);

    let res = ctx.emitter.op_binop(PisOpcode::Sub, value, one)?;

    // NOTE: the carry flag is not updated when using DEC
    update_o_f_sub(ctx, value, one)?;
    update_parity_zero_sign_flags(ctx, res)?;

    Ok(res)
}

/// the mnemonic calculation of the INC mnemonic.
fn mnm_calc_inc(ctx: &mut Ctx, value: PisOp) -> Result<PisOp> {
    let one = PisOp::constant(1, value.size);

    let res = ctx.emitter.op_binop(PisOpcode::Add, value, one)?;

    // NOTE: the carry flag is not updated when using INC
    update_o_f_add(ctx, value, one);
    update_parity_zero_sign_flags(ctx, res)?;

    Ok(res)
}

/// the mnemonic calculation of the NOT mnemonic.
fn mnm_calc_not(ctx: &mut Ctx, value: PisOp) -> Result<PisOp> {
    Ok(ctx.emitter.op_unop(PisOpcode::Not, value)?)
}

/// the mnemonic calculation of the NEG mnemonic.
fn mnm_calc_neg(ctx: &mut Ctx, value: PisOp) -> Result<PisOp> {
    Ok(ctx.emitter.op_unop(PisOpcode::Neg, value)?)
}

/// set the carry flag and overflow flag to zero.
fn zero_c_f_and_o_f(ctx: &mut Ctx) {
    ctx.emitter.op_move_zero(X86_REG_FLAGS_CF);
    ctx.emitter.op_move_zero(X86_REG_FLAGS_OF);
}

/// the mnemonic calculation of the OR mnemonic.
fn mnm_calc_or(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    let res = ctx.emitter.op_binop(PisOpcode::Or, lhs, rhs)?;

    zero_c_f_and_o_f(ctx);
    update_parity_zero_sign_flags(ctx, res)?;

    Ok(res)
}

/// the mnemonic calculation of the XOR mnemonic.
fn mnm_calc_xor(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    let res = ctx.emitter.op_binop(PisOpcode::Xor, lhs, rhs)?;

    zero_c_f_and_o_f(ctx);
    update_parity_zero_sign_flags(ctx, res)?;

    Ok(res)
}

/// the mnemonic calculation of the AND mnemonic.
fn mnm_calc_and(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    let res = ctx.emitter.op_binop(PisOpcode::And, lhs, rhs)?;

    zero_c_f_and_o_f(ctx);
    update_parity_zero_sign_flags(ctx, res)?;

    Ok(res)
}

/// lift a binary operator mnemonic
fn lift_binop<F>(ctx: &mut Ctx, ops: &[LiftedOp], calc: F, store_result: bool) -> Result<()>
where
    F: FnOnce(&mut Ctx, PisOp, PisOp) -> Result<PisOp>,
{
    assert_eq!(ops.len(), 2);
    assert_eq!(ops[0].size(), ops[1].size());

    let lhs = ops[0].read(ctx)?;
    let rhs = ops[1].read(ctx)?;

    let res = calc(ctx, lhs, rhs)?;

    if store_result {
        ops[0].write(res, ctx);
    }

    Ok(())
}

/// lift a unary operator mnemonic
fn lift_unop<F>(ctx: &mut Ctx, ops: &[LiftedOp], calc: F) -> Result<()>
where
    F: FnOnce(&mut Ctx, PisOp) -> Result<PisOp>,
{
    assert_eq!(ops.len(), 1);

    let value = ops[0].read(ctx)?;

    let result = calc(ctx, value)?;

    ops[0].write(result, ctx);

    Ok(())
}

fn lift_mov(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 2);
    assert_eq!(ops[0].size(), ops[1].size());

    let value = ops[1].read(ctx)?;
    ops[0].write(value, ctx);

    Ok(())
}

fn lift_lea(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 2);

    let LiftedOp::Mem(mem_op) = &ops[1] else {
        panic!("lea instruction with a non-memory src operand");
    };

    assert_eq!(ops[0].size(), mem_op.addr.size);

    ops[0].write(mem_op.addr, ctx);

    Ok(())
}

/// information about a mnemonic which implements a binary operator with carry.
struct BinopWithCarryMnmInfo<C, O>
where
    C: Fn(&mut Ctx, PisOp, PisOp) -> Result<PisOp>,
    O: Fn(&mut Ctx, PisOp, PisOp) -> Result<PisOp>,
{
    /// the main opcode of the binary operator.
    /// for example, for an "add with carry" operation, this will be the add opcode.
    opcode: PisOpcode,

    /// a function for calculation the carry flag of applying the binary opcode on the given 2 operands.
    calc_c_f: C,

    /// a function for calculation the overflow flag of applying the binary opcode on the given 2 operands.
    calc_o_f: O,
}

/// a generic implementation of a mnemonic calculation of a binary operator which also uses the carry flag. can be used to
/// implement mnemonics like `ADC` and `SBB`.
fn mnm_calc_binop_with_carry<C, O>(
    ctx: &mut Ctx,
    lhs: PisOp,
    rhs: PisOp,
    info: BinopWithCarryMnmInfo<C, O>,
) -> Result<PisOp>
where
    C: Fn(&mut Ctx, PisOp, PisOp) -> Result<PisOp>,
    O: Fn(&mut Ctx, PisOp, PisOp) -> Result<PisOp>,
{
    let size = lhs.size;
    let orig_c_f = ctx.emitter.op_zext(X86_REG_FLAGS_CF, size)?;

    // the result before applying the carry
    let res_before_carry = ctx.emitter.op_binop(info.opcode, lhs, rhs)?;

    // the final result after applying the carry
    let res_after_carry = ctx
        .emitter
        .op_binop(info.opcode, res_before_carry, orig_c_f)?;

    // carry flag
    let c_f_before_carry = (info.calc_c_f)(ctx, lhs, rhs)?;
    let c_f_after_carry = (info.calc_c_f)(ctx, res_before_carry, orig_c_f)?;
    let final_c_f = ctx
        .emitter
        .op_binop(PisOpcode::Or, c_f_before_carry, c_f_after_carry)?;
    ctx.emitter.op_move(X86_REG_FLAGS_CF, final_c_f);

    // overflow flag
    let o_f_before_carry = (info.calc_o_f)(ctx, lhs, rhs)?;
    let o_f_after_carry = (info.calc_o_f)(ctx, res_before_carry, orig_c_f)?;
    let final_o_f = ctx
        .emitter
        .op_binop(PisOpcode::Or, o_f_before_carry, o_f_after_carry)?;
    ctx.emitter.op_move(X86_REG_FLAGS_OF, final_o_f);

    Ok(res_after_carry)
}

/// the mnemonic calculation of the ADC mnemonic.
fn mnm_calc_adc(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    mnm_calc_binop_with_carry(
        ctx,
        lhs,
        rhs,
        BinopWithCarryMnmInfo {
            opcode: PisOpcode::Add,
            calc_c_f: calc_c_f_add,
            calc_o_f: calc_o_f_add,
        },
    )
}

/// the mnemonic calculation of the SBB mnemonic.
fn mnm_calc_sbb(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    mnm_calc_binop_with_carry(
        ctx,
        lhs,
        rhs,
        BinopWithCarryMnmInfo {
            opcode: PisOpcode::Sub,
            calc_c_f: calc_c_f_sub,
            calc_o_f: calc_o_f_sub,
        },
    )
}

fn push(ctx: &mut Ctx, value: PisOp) -> Result<()> {
    // copy the pushed operand before subtracting sp. this makes sure that instructions like `push rsp` behave properly,
    // by pushing the original value, before the subtraction.
    let value_copy = ctx.emitter.copy_value(value)?;

    let sp = ctx.sp();

    let sub_sp_amount = value.size.bytes();
    let sub_sp_amount_op = PisOp::constant(sub_sp_amount as u64, sp.size);

    ctx.emitter.emit(pis_insn!(Sub! sp, sp, sub_sp_amount_op));
    ctx.emitter.emit(pis_insn!(Store! sp, value_copy));

    Ok(())
}

fn pop(ctx: &mut Ctx, size: PisSize) -> Result<PisOp> {
    let sp = ctx.sp();

    let tmp = ctx.emitter.tmp_op_allocator.alloc(size)?;

    let add_sp_amount = size.bytes();
    let add_sp_amount_op = PisOp::constant(add_sp_amount as u64, sp.size);

    ctx.emitter.emit(pis_insn!(Load! tmp, sp));
    ctx.emitter.emit(pis_insn!(Add! sp, sp, add_sp_amount_op));

    Ok(tmp)
}

fn lift_push(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 1);

    let value = ops[0].read(ctx)?;
    push(ctx, value)?;

    Ok(())
}

fn lift_pop(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 1);

    let value = pop(ctx, ops[0].size())?;
    ops[0].write(value, ctx);

    Ok(())
}

/// calculates the least significant bit of the given value.
/// the output is a 1 byte conditional expression which indicates whether the lsb is enabled.
fn calc_lsb(ctx: &mut Ctx, value: PisOp) -> Result<PisOp> {
    let one = PisOp::constant(1, value.size);
    let masked = ctx.emitter.op_binop(PisOpcode::And, value, one)?;
    Ok(ctx.emitter.op_trunc(masked, PisSize::B1)?)
}

/// masks the `count` operand of a shift operation.
fn mask_shift_count(ctx: &mut Ctx, count: PisOp, operand_size: PisSize) -> Result<PisOp> {
    let count_mask = if operand_size == PisSize::B8 {
        0b111111
    } else {
        0b11111
    };
    let count_mask_op = PisOp::constant(count_mask, operand_size);
    Ok(ctx.emitter.op_binop(PisOpcode::And, count, count_mask_op)?)
}

/// generates a ternary expression. result = (cond ? then_val : else_val)
fn ternary(ctx: &mut Ctx, cond: PisOp, then_val: PisOp, else_val: PisOp) -> Result<PisOp> {
    assert_eq!(cond.size, PisSize::B1);
    assert_eq!(then_val.size, else_val.size);

    let operand_size = then_val.size;

    // zero extend the condition
    let cond_zero_extended = ctx.emitter.op_zext(cond, operand_size)?;

    // arithmetically negate the condition to convert it to a bit mask.
    // if cond is 1, negating it produces all 1s mask. If 0, it produces all 0s mask.
    let cond_mask = ctx.emitter.op_unop(PisOpcode::Neg, cond_zero_extended)?;

    // calculate the negative condition mask
    let not_cond_mask = ctx.emitter.op_unop(PisOpcode::Not, cond_mask)?;

    let true_case = ctx.emitter.op_binop(PisOpcode::And, cond_mask, then_val)?;
    let false_case = ctx
        .emitter
        .op_binop(PisOpcode::And, not_cond_mask, else_val)?;

    Ok(ctx.emitter.op_binop(PisOpcode::Or, true_case, false_case)?)
}

/// updates the parity, zero, and sign flags for a shift operation result.
fn update_shift_parity_zero_sign_flags(
    ctx: &mut Ctx,
    count: PisOp,
    shift_result: PisOp,
) -> Result<()> {
    assert_eq!(count.size, shift_result.size);
    let operand_size = shift_result.size;

    // only modify the flags if the count is non-zero
    let is_count_0 =
        ctx.emitter
            .op_binop(PisOpcode::Equals, count, PisOp::constant(0, operand_size))?;

    let new_pf = calc_pf(ctx, shift_result)?;
    let final_pf = ternary(ctx, is_count_0, X86_REG_FLAGS_PF, new_pf)?;
    ctx.emitter.op_move(X86_REG_FLAGS_PF, final_pf);

    let new_zf = calc_zf(ctx, shift_result)?;
    let final_zf = ternary(ctx, is_count_0, X86_REG_FLAGS_ZF, new_zf)?;
    ctx.emitter.op_move(X86_REG_FLAGS_ZF, final_zf);

    let new_sf = calc_sf(ctx, shift_result)?;
    let final_sf = ternary(ctx, is_count_0, X86_REG_FLAGS_SF, new_sf)?;
    ctx.emitter.op_move(X86_REG_FLAGS_SF, final_sf);

    Ok(())
}

/// calculates the carry flag for a `SHL` operation.
fn calc_c_f_shl(ctx: &mut Ctx, to_shift: PisOp, count: PisOp) -> Result<PisOp> {
    let operand_size = to_shift.size;
    let size_bits_op = PisOp::constant(operand_size.bits() as u64, operand_size);

    // shift right by (size - count) to get the last shifted out bit
    let right_shift_count = ctx.emitter.op_binop(PisOpcode::Sub, size_bits_op, count)?;
    let right_shifted =
        ctx.emitter
            .op_binop(PisOpcode::ShiftRightUnsigned, to_shift, right_shift_count)?;
    let last_extracted_bit = ctx.emitter.op_trunc(right_shifted, PisSize::B1)?;

    // only update CF if count != 0
    let is_count_0 =
        ctx.emitter
            .op_binop(PisOpcode::Equals, count, PisOp::constant(0, operand_size))?;
    ternary(ctx, is_count_0, X86_REG_FLAGS_CF, last_extracted_bit)
}

/// calculates the overflow flag for a `SHL` operation (must be called after CF is calculated).
fn calc_o_f_shl(
    ctx: &mut Ctx,
    to_shift: PisOp,
    count: PisOp,
    shift_result: PisOp,
) -> Result<PisOp> {
    let operand_size = to_shift.size;

    // OF = MSB(result) ^ CF
    let msb = calc_msb(ctx, shift_result)?;
    let new_of = ctx
        .emitter
        .op_binop(PisOpcode::Xor, msb, X86_REG_FLAGS_CF)?;

    // only update OF if count == 1
    let is_count_1 =
        ctx.emitter
            .op_binop(PisOpcode::Equals, count, PisOp::constant(1, operand_size))?;
    ternary(ctx, is_count_1, new_of, X86_REG_FLAGS_OF)
}

/// mnemonic calculation for SHL.
fn mnm_calc_shl(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    let operand_size = lhs.size;
    let count = mask_shift_count(ctx, rhs, operand_size)?;

    // carry Flag
    let cf_val = calc_c_f_shl(ctx, lhs, count)?;
    ctx.emitter.op_move(X86_REG_FLAGS_CF, cf_val);

    // perform the shift
    let res = ctx.emitter.op_binop(PisOpcode::ShiftLeft, lhs, count)?;

    // overflow Flag
    let of_val = calc_o_f_shl(ctx, lhs, count, res)?;
    ctx.emitter.op_move(X86_REG_FLAGS_OF, of_val);

    // parity, Zero, Sign Flags
    update_shift_parity_zero_sign_flags(ctx, count, res)?;

    Ok(res)
}

/// calculates the carry flag for `SHR` or `SAR`.
fn calc_c_f_shr(ctx: &mut Ctx, to_shift: PisOp, count: PisOp) -> Result<PisOp> {
    let operand_size = to_shift.size;

    // shift right by (count - 1) and get the LSB
    let one = PisOp::constant(1, operand_size);
    let count_minus_1 = ctx.emitter.op_binop(PisOpcode::Sub, count, one)?;
    let shifted = ctx
        .emitter
        .op_binop(PisOpcode::ShiftRightUnsigned, to_shift, count_minus_1)?;
    let last_extracted_bit = calc_lsb(ctx, shifted)?;

    // only update CF if count != 0
    let is_count_0 =
        ctx.emitter
            .op_binop(PisOpcode::Equals, count, PisOp::constant(0, operand_size))?;
    ternary(ctx, is_count_0, X86_REG_FLAGS_CF, last_extracted_bit)
}

/// calculates the overflow flag for `SHR`.
fn calc_o_f_shr(ctx: &mut Ctx, to_shift: PisOp, count: PisOp) -> Result<PisOp> {
    let operand_size = to_shift.size;

    // OF = MSB(original)
    let new_of = calc_msb(ctx, to_shift)?;

    // only update OF if count == 1
    let is_count_1 =
        ctx.emitter
            .op_binop(PisOpcode::Equals, count, PisOp::constant(1, operand_size))?;
    ternary(ctx, is_count_1, new_of, X86_REG_FLAGS_OF)
}

/// mnemonic calculation for SHR.
fn mnm_calc_shr(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    let operand_size = lhs.size;
    let count = mask_shift_count(ctx, rhs, operand_size)?;

    // carry Flag
    let cf_val = calc_c_f_shr(ctx, lhs, count)?;
    ctx.emitter.op_move(X86_REG_FLAGS_CF, cf_val);

    // overflow Flag
    let of_val = calc_o_f_shr(ctx, lhs, count)?;
    ctx.emitter.op_move(X86_REG_FLAGS_OF, of_val);

    // perform the shift
    let res = ctx
        .emitter
        .op_binop(PisOpcode::ShiftRightUnsigned, lhs, count)?;

    // parity, Zero, Sign Flags
    update_shift_parity_zero_sign_flags(ctx, count, res)?;

    Ok(res)
}

/// calculates the overflow flag for `SAR`.
fn calc_o_f_sar(ctx: &mut Ctx, count: PisOp, operand_size: PisSize) -> Result<PisOp> {
    // OF = 0
    let new_of = PisOp::constant(0, PisSize::B1);

    // only update OF if count == 1
    let is_count_1 =
        ctx.emitter
            .op_binop(PisOpcode::Equals, count, PisOp::constant(1, operand_size))?;
    ternary(ctx, is_count_1, new_of, X86_REG_FLAGS_OF)
}

/// mnemonic calculation for SAR.
fn mnm_calc_sar(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    let operand_size = lhs.size;
    let count = mask_shift_count(ctx, rhs, operand_size)?;

    // carry Flag (same as SHR)
    let cf_val = calc_c_f_shr(ctx, lhs, count)?;
    ctx.emitter.op_move(X86_REG_FLAGS_CF, cf_val);

    // overflow Flag
    let of_val = calc_o_f_sar(ctx, count, operand_size)?;
    ctx.emitter.op_move(X86_REG_FLAGS_OF, of_val);

    // perform the shift
    let res = ctx
        .emitter
        .op_binop(PisOpcode::ShiftRightSigned, lhs, count)?; // assuming ShiftRightSigned exists

    // parity, Zero, Sign Flags
    update_shift_parity_zero_sign_flags(ctx, count, res)?;

    Ok(res)
}

/// mnemonic calculation for ROL.
fn mnm_calc_rol(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    let operand_size = lhs.size;
    let count = mask_shift_count(ctx, rhs, operand_size)?;

    // perform the rotation (left shift + right shift + or)
    let left_shifted = ctx.emitter.op_binop(PisOpcode::ShiftLeft, lhs, count)?;

    let size_bits_op = PisOp::constant(operand_size.bits() as u64, operand_size);
    let right_shift_count = ctx.emitter.op_binop(PisOpcode::Sub, size_bits_op, count)?;
    let right_shifted =
        ctx.emitter
            .op_binop(PisOpcode::ShiftRightUnsigned, lhs, right_shift_count)?;

    let res = ctx
        .emitter
        .op_binop(PisOpcode::Or, left_shifted, right_shifted)?;

    // carry Flag = LSB of result
    let cf_val = calc_lsb(ctx, res)?;
    ctx.emitter.op_move(X86_REG_FLAGS_CF, cf_val);

    // overflow Flag (same as SHL)
    let of_val = calc_o_f_shl(ctx, lhs, count, res)?;
    ctx.emitter.op_move(X86_REG_FLAGS_OF, of_val);

    // ROL doesn't update PZS flags based on the result like shifts
    // we only update CF and OF based on the specific ROL logic.

    Ok(res)
}

/// mnemonic calculation for ROR.
fn mnm_calc_ror(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    let operand_size = lhs.size;
    let count = mask_shift_count(ctx, rhs, operand_size)?;

    // perform the rotation (right shift + left shift + or)
    let right_shifted = ctx
        .emitter
        .op_binop(PisOpcode::ShiftRightUnsigned, lhs, count)?;

    let size_bits_op = PisOp::constant(operand_size.bits() as u64, operand_size);
    let left_shift_count = ctx.emitter.op_binop(PisOpcode::Sub, size_bits_op, count)?;
    let left_shifted = ctx
        .emitter
        .op_binop(PisOpcode::ShiftLeft, lhs, left_shift_count)?; // assuming ShiftLeft exists

    let res = ctx
        .emitter
        .op_binop(PisOpcode::Or, right_shifted, left_shifted)?;

    // carry Flag = MSB of result
    let cf_val = calc_msb(ctx, res)?;
    ctx.emitter.op_move(X86_REG_FLAGS_CF, cf_val);

    // overflow Flag = MSB(result) ^ MSB-1(result)
    let msb_minus_1_shift = PisOp::constant(1, operand_size);
    let msb_minus_1_val =
        ctx.emitter
            .op_binop(PisOpcode::ShiftRightUnsigned, res, msb_minus_1_shift)?;
    let msb_minus_1 = calc_msb(ctx, msb_minus_1_val)?;
    let new_of = ctx.emitter.op_binop(PisOpcode::Xor, cf_val, msb_minus_1)?;

    // only update OF if count == 1
    let is_count_1 =
        ctx.emitter
            .op_binop(PisOpcode::Equals, count, PisOp::constant(1, operand_size))?;
    let final_of = ternary(ctx, is_count_1, new_of, X86_REG_FLAGS_OF)?;
    ctx.emitter.op_move(X86_REG_FLAGS_OF, final_of);

    // ROR doesn't update PZS flags based on the result like shifts

    Ok(res)
}

/// mnemonic calculation for RCL.
fn mnm_calc_rcl(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    let operand_size = lhs.size;
    // mask count modulo (operand_bits + 1)
    let count_mask_val = operand_size.bits() as u64;
    let count_mask_op = PisOp::constant(count_mask_val, operand_size);
    let count = ctx.emitter.op_binop(PisOpcode::And, rhs, count_mask_op)?;

    // simulate rotation through carry
    // this is complex to emulate directly with basic PIS ops.
    // A loop or more specialized PIS ops would be needed for an accurate RCL.
    // placeholder: treat as ROL for now, flags will be incorrect.
    let res = mnm_calc_rol(ctx, lhs, rhs)?;

    // TODO: Implement proper RCL logic including flags.
    // CF = bit shifted out from MSB
    // OF = MSB(result) ^ CF (only if masked count == 1)

    Ok(res)
}

/// mnemonic calculation for RCR.
fn mnm_calc_rcr(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    let operand_size = lhs.size;
    // mask count modulo (operand_bits + 1)
    let count_mask_val = operand_size.bits() as u64;
    let count_mask_op = PisOp::constant(count_mask_val, operand_size);
    let count = ctx.emitter.op_binop(PisOpcode::And, rhs, count_mask_op)?;

    // simulate rotation through carry
    // this is complex to emulate directly with basic PIS ops.
    // placeholder: treat as ROR for now, flags will be incorrect.
    let res = mnm_calc_ror(ctx, lhs, rhs)?;

    // TODO: Implement proper RCR logic including flags.
    // CF = bit shifted out from LSB
    // OF = MSB(original) ^ MSB(result) (only if masked count == 1)

    Ok(res)
}

/// performs a multiplication operation that operates on the `ax` operand and stores its
/// result in the `ax` and `dx` operands.
fn do_mul_ax(ctx: &mut Ctx, factor: PisOp) -> Result<()> {
    let operand_size = factor.size;
    let ax = ctx.decode_reg(SpecificReg::Rax.reg_encoding(), operand_size);
    let dx = ctx.decode_reg(SpecificReg::Rdx.reg_encoding(), operand_size);

    let result_high: PisOp;
    let result_low: PisOp;

    if operand_size == PisSize::B8 {
        // use a special PIS opcode for 128-bit result if available, otherwise emulate
        // assuming PIS_OPCODE_UNSIGNED_MUL_16 exists:
        // PIS_EMIT(&ctx->args->result, PIS_INSN4(PIS_OPCODE_UNSIGNED_MUL_16, result_high_tmp, result_low_tmp, ax, factor));
        // for now, let's assume we only get the low 64 bits correctly with standard MUL
        result_low = ctx.emitter.op_binop(PisOpcode::MulUnsigned, ax, factor)?;
        result_high = PisOp::constant(0, operand_size);
        // TODO: Implement 64x64->128 multiplication if needed, or add PIS_OPCODE_UNSIGNED_MUL_16
    } else {
        let double_operand_size = match operand_size {
            PisSize::B1 => PisSize::B2,
            PisSize::B2 => PisSize::B4,
            PisSize::B4 => PisSize::B8,
            _ => unreachable!(),
        };

        let factor_zext = ctx.emitter.op_zext(factor, double_operand_size)?;
        let ax_zext = ctx.emitter.op_zext(ax, double_operand_size)?;

        let mul_result = ctx
            .emitter
            .op_binop(PisOpcode::MulUnsigned, ax_zext, factor_zext)?;

        // extract low part
        result_low = ctx.emitter.op_trunc(mul_result, operand_size)?;

        // extract high part
        let shift_amount = PisOp::constant(operand_size.bits() as u64, double_operand_size);
        let shifted_result =
            ctx.emitter
                .op_binop(PisOpcode::ShiftRightUnsigned, mul_result, shift_amount)?;
        result_high = ctx.emitter.op_trunc(shifted_result, operand_size)?;
    }

    // store results
    ctx.emitter.op_move(ax, result_low);
    ctx.emitter.op_move(dx, result_high);

    // calculate Carry and Overflow flags
    let is_high_zero = ctx.emitter.op_binop(
        PisOpcode::Equals,
        result_high,
        PisOp::constant(0, operand_size),
    )?;
    let not_high_zero = ctx.emitter.op_unop(PisOpcode::CondNeg, is_high_zero)?;

    ctx.emitter.op_move(X86_REG_FLAGS_CF, not_high_zero);
    ctx.emitter.op_move(X86_REG_FLAGS_OF, not_high_zero);

    Ok(())
}

/// mnemonic calculation for MUL.
fn lift_mul(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 1);
    let value = ops[0].read(ctx)?;
    do_mul_ax(ctx, value)
}

/// mnemonic calculation for IMUL variants.
fn lift_imul(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    match ops.len() {
        1 => {
            // IMUL r/m (AX = AL * r/m8, DX:AX = AX * r/m16, RDX:RAX = RAX * r/m32/64)
            let factor = ops[0].read(ctx)?;
            let operand_size = factor.size;
            let ax = ctx.decode_reg(SpecificReg::Rax.reg_encoding(), operand_size);
            let dx = ctx.decode_reg(SpecificReg::Rdx.reg_encoding(), operand_size);

            // perform signed multiplication - requires PIS support or emulation
            // placeholder: Use unsigned mul and assume PIS handles signs or specific opcodes exist
            let result_low = ctx.emitter.op_binop(PisOpcode::MulSigned, ax, factor)?;
            let result_high = PisOp::constant(0, operand_size);

            // TODO: Implement signed multiplication with correct high part calculation (e.g., using PIS_OPCODE_SIGNED_MUL_16)
            // TODO: Calculate CF/OF based on whether high part matches sign extension of low part

            ctx.emitter.op_move(ax, result_low);
            ctx.emitter.op_move(dx, result_high);
            // TODO: Update CF/OF correctly for IMUL r/m

            Ok(())
        }
        2 => {
            // IMUL r, r/m
            let lhs = ops[0].read(ctx)?;
            let rhs = ops[1].read(ctx)?;
            let operand_size = lhs.size;

            // perform signed multiplication
            let res = ctx.emitter.op_binop(PisOpcode::MulSigned, lhs, rhs)?;

            // TODO: Calculate CF/OF based on whether the result fits in the destination size without overflow
            // this requires checking if `res` sign-extended from operand_size to 2*operand_size equals `res` zero-extended.
            // or use a dedicated PIS opcode like SIGNED_MUL_OVERFLOW.
            let cf_of_val = ctx
                .emitter
                .op_binop(PisOpcode::MulOverflowSigned, lhs, rhs)?;
            ctx.emitter.op_move(X86_REG_FLAGS_CF, cf_of_val);
            ctx.emitter.op_move(X86_REG_FLAGS_OF, cf_of_val);

            // write result
            ops[0].write(res, ctx);

            // PZS flags are undefined for IMUL r, r/m

            Ok(())
        }
        3 => {
            // IMUL r, r/m, imm
            let _dst = &ops[0];
            let lhs = ops[1].read(ctx)?;
            let rhs = ops[2].read(ctx)?;
            let operand_size = lhs.size;

            // perform signed multiplication
            let res = ctx.emitter.op_binop(PisOpcode::MulSigned, lhs, rhs)?;

            // TODO: Calculate CF/OF (same logic as IMUL r, r/m)
            let cf_of_val = ctx
                .emitter
                .op_binop(PisOpcode::MulOverflowSigned, lhs, rhs)?; // assuming SignedMulOverflow exists
            ctx.emitter.op_move(X86_REG_FLAGS_CF, cf_of_val);
            ctx.emitter.op_move(X86_REG_FLAGS_OF, cf_of_val);

            // write result
            ops[0].write(res, ctx);
            // PZS flags are undefined for IMUL r, r/m, imm

            Ok(())
        }
        _ => unreachable!("Invalid number of operands for IMUL"),
    }
}

/// performs division (DIV or IDIV).
fn do_div_ax_dx(ctx: &mut Ctx, divisor: PisOp, is_signed: bool) -> Result<()> {
    let operand_size = divisor.size;
    let ax = ctx.decode_reg(SpecificReg::Rax.reg_encoding(), operand_size);
    let dx = ctx.decode_reg(SpecificReg::Rdx.reg_encoding(), operand_size);

    if operand_size == PisSize::B8 {
        let div_op = if is_signed {
            PisOpcode::Div16Signed
        } else {
            PisOpcode::Div16Unsigned
        };
        let quotient = ctx.emitter.tmp_op_allocator.alloc(PisSize::B8)?;
        ctx.emitter.emit(PisInsn {
            opcode: div_op,
            operands: array_vec![quotient, X86_REG_RDX, X86_REG_RAX, divisor],
        });

        let rem_op = if is_signed {
            PisOpcode::Rem16Signed
        } else {
            PisOpcode::Rem16Unsigned
        };
        let remainder = ctx.emitter.tmp_op_allocator.alloc(PisSize::B8)?;
        ctx.emitter.emit(PisInsn {
            opcode: rem_op,
            operands: array_vec![quotient, X86_REG_RDX, X86_REG_RAX, divisor],
        });

        ctx.emitter.op_move(ax, quotient);
        ctx.emitter.op_move(dx, remainder);
    } else {
        let div_op = if is_signed {
            PisOpcode::DivSigned
        } else {
            PisOpcode::DivUnsigned
        };

        let rem_op = if is_signed {
            PisOpcode::RemSigned
        } else {
            PisOpcode::RemUnsigned
        };

        let double_operand_size = operand_size.double();

        // combine DX:AX or EDX:EAX or RDX:RAX (low part first)
        let ax_zext = ctx.emitter.op_zext(ax, double_operand_size)?;
        let dx_zext = ctx.emitter.op_zext(dx, double_operand_size)?;
        let shift_amount = PisOp::constant(operand_size.bits() as u64, double_operand_size);
        let dx_shifted = ctx
            .emitter
            .op_binop(PisOpcode::ShiftLeft, dx_zext, shift_amount)?;
        let dividend = ctx.emitter.op_binop(PisOpcode::Or, ax_zext, dx_shifted)?;

        // extend divisor
        let divisor_ext = if is_signed {
            ctx.emitter.op_sext(divisor, double_operand_size)?
        } else {
            ctx.emitter.op_zext(divisor, double_operand_size)?
        };

        // perform division and remainder
        let quotient_full = ctx.emitter.op_binop(div_op, dividend, divisor_ext)?;
        let remainder_full = ctx.emitter.op_binop(rem_op, dividend, divisor_ext)?;

        // truncate results and store
        let quotient = ctx.emitter.op_trunc(quotient_full, operand_size)?;
        let remainder = ctx.emitter.op_trunc(remainder_full, operand_size)?;
        // TODO: Handle division overflow exception (result doesn't fit in AX/EAX/RAX)

        ctx.emitter.op_move(ax, quotient);
        ctx.emitter.op_move(dx, remainder);
    }
    // flags are undefined after DIV/IDIV
    Ok(())
}

/// mnemonic calculation for DIV.
fn lift_div(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 1);
    let value = ops[0].read(ctx)?;
    do_div_ax_dx(ctx, value, false)
}

/// mnemonic calculation for IDIV.
fn lift_idiv(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 1);
    let value = ops[0].read(ctx)?;
    do_div_ax_dx(ctx, value, true)
}

/// mnemonic calculation for XCHG.
fn lift_xchg(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 2);
    assert_eq!(ops[0].size(), ops[1].size());

    let op0_val = ops[0].read(ctx)?;
    let op1_val = ops[1].read(ctx)?;

    // use a temporary variable (tmp operand) if one operand is memory
    // otherwise, direct moves suffice if both are registers.
    // the C code uses a tmp regardless, which is safer.
    let tmp = ctx.emitter.copy_value(op0_val)?;

    ops[0].write(op1_val, ctx);
    ops[1].write(tmp, ctx);

    Ok(())
}

/// lift MOVSXD (needs 64-bit mode check).
fn lift_movsxd(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 2);
    // MOVSD behaves like MOVSXD only in 64-bit mode.
    // in 32-bit mode, 0x63 is ARPL.
    if ctx.cpumode != X86Cpumode::B64 {
        return Err(LiftErr::UnsupportedInsn);
    }

    let dst_size = ops[0].size();
    let src_size = ops[1].size();

    // MOVSD acts as MOVSX only if dst > src. Otherwise it's a NOP/MOV.
    if dst_size > src_size {
        // perform sign extension
        let src_val = ops[1].read(ctx)?;
        let sext_val = ctx.emitter.op_sext(src_val, dst_size)?;
        ops[0].write(sext_val, ctx);
    } else if dst_size == src_size {
        // if sizes are equal, it acts like a MOV
        lift_mov(ctx, ops)?;
    }
    // if dst_size < src_size, it's technically invalid encoding for MOVSXD, handle as needed (e.g., error or NOP)

    Ok(())
}

/// lift MOVSX.
fn lift_movsx(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 2);
    let dst_size = ops[0].size();
    let src_size = ops[1].size();
    assert!(
        dst_size > src_size,
        "Destination size must be larger for MOVSX"
    );

    let src_val = ops[1].read(ctx)?;
    let sext_val = ctx.emitter.op_sext(src_val, dst_size)?;
    ops[0].write(sext_val, ctx);
    Ok(())
}

/// lift MOVZX.
fn lift_movzx(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 2);
    let dst_size = ops[0].size();
    let src_size = ops[1].size();
    assert!(
        dst_size > src_size,
        "Destination size must be larger for MOVZX"
    );

    let src_val = ops[1].read(ctx)?;
    let zext_val = ctx.emitter.op_zext(src_val, dst_size)?;
    ops[0].write(zext_val, ctx);
    Ok(())
}

/// lift CWD/CDQ/CQO.
fn lift_cwd(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 2);
    let dst_op = &ops[0];
    let src_op = &ops[1];

    let src_val = src_op.read(ctx)?;
    let dst_size = dst_op.size();

    // sign extend src_val to dst_size
    let sext_val = ctx.emitter.op_sext(src_val, dst_size)?;

    dst_op.write(sext_val, ctx);

    Ok(())
}

/// push IP onto the stack.
fn push_ip(ctx: &mut Ctx) -> Result<()> {
    // RIP value points *after* the current instruction.
    let cur_insn_end_addr = ctx.args.cur_code_addr();
    let ip_mask = calc_near_branch_ip_mask(ctx);
    let push_value_raw = cur_insn_end_addr & ip_mask;

    // determine the size to push (stack address size)
    let push_size = ctx.stack_addr_size;
    let push_value_op = PisOp::constant(push_value_raw, push_size);

    push(ctx, push_value_op)
}

/// lift CALL.
fn lift_call(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 1);
    // ensure no size override prefixes for branches
    if ctx
        .prefixes
        .has_legacy_prefix(LegacyPrefix::OperandSizeOverride)
        || ctx
            .prefixes
            .has_legacy_prefix(LegacyPrefix::AddressSizeOverride)
    {
        return Err(LiftErr::UnsupportedInsn);
    }

    let target = ops[0].read(ctx)?;

    // push return address (IP after the CALL instruction)
    push_ip(ctx)?;

    // jump to target
    ctx.emit(pis_insn!(JmpCall! target));

    Ok(())
}

/// lift JMP.
fn lift_jmp(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 1);
    // ensure no size override prefixes for branches
    if ctx
        .prefixes
        .has_legacy_prefix(LegacyPrefix::OperandSizeOverride)
        || ctx
            .prefixes
            .has_legacy_prefix(LegacyPrefix::AddressSizeOverride)
    {
        return Err(LiftErr::UnsupportedInsn);
    }

    let target = ops[0].read(ctx)?;
    ctx.emit(pis_insn!(Jmp! target));

    Ok(())
}

/// lift JCC.
fn lift_jcc(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 2);

    let cond = ops[0].read(ctx)?;
    let target = ops[1].read(ctx)?;

    ctx.emit(pis_insn!(JmpCond! target, cond));

    Ok(())
}

/// lift RET.
fn lift_ret(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert!(ops.is_empty());

    // pop return address from stack
    let ret_addr = pop(ctx, ctx.stack_addr_size)?;

    // jump to return address
    ctx.emit(pis_insn!(JmpRet! ret_addr));

    Ok(())
}

/// holds the actual context data for REP prefix handling when the F3 prefix is active.
#[derive(Debug, Clone, Copy)]
struct RepCtxInner {
    /// the PIS instruction index where the loop should jump back to.
    insn_index_at_loop_start: usize,
    /// the PIS instruction index of the initial Jmpcond instruction
    /// (which skips the loop if CX is initially zero) that needs patching.
    jmp_end_insn_idx: usize,
}

/// wrapper struct for REP context, handling the optionality internally.
#[derive(Debug, Clone, Copy)]
struct RepCtx(Option<RepCtxInner>);

/// begin implementing a rep loop. this emits the first half of the rep loop which is at the start
/// of the lifted instruction. after calling this, you should emit your logic for a single iteration
/// of the loop, and then call the rep end function to emit the second half of the rep loop.
fn rep_begin(ctx: &mut Ctx) -> Result<RepCtx> {
    if !ctx.prefixes.has_legacy_prefix(LegacyPrefix::RepzOrRep) {
        return Ok(RepCtx(None));
    }

    // save the instruction index at the start of the loop (before counter check).
    let loop_start_idx = ctx.emitter.insns.len();

    // first, check if `cx` is zero.
    let cx = ctx.decode_reg(SpecificReg::Rcx.reg_encoding(), ctx.addr_size);
    let zero = PisOp::constant(0, ctx.addr_size);
    let cx_equals_zero = ctx.emitter.op_binop(PisOpcode::Equals, cx, zero)?;

    // emit a jump which should skip over the entire code. the offset is currently 0 since we
    // don't know the size of the code, but it will be filled with the correct value later on.
    ctx.emit(pis_insn!(JmpCond! PisOp::constant(0, PisSize::B1), cx_equals_zero));

    // store index of the jump to patch
    let jmp_idx = ctx.emitter.insns.len() - 1;

    let one = PisOp::constant(1, ctx.addr_size);
    ctx.emit(pis_insn!(Sub! cx, cx, one));

    Ok(RepCtx(Some(RepCtxInner {
        insn_index_at_loop_start: loop_start_idx,
        jmp_end_insn_idx: jmp_idx,
    })))
}

/// emits the second half of the rep loop, at the end of the instruction. this should be called
/// after calling the rep begin function and after emitting your code for a single iteration of the
/// rep loop.
fn rep_end(ctx: &mut Ctx, rep_ctx: RepCtx) -> Result<()> {
    let Some(inner_ctx) = rep_ctx.0 else {
        return Ok(());
    };

    // now jump back to the start of the loop, for the next iteration of the loop.
    let loop_start_target = PisOp::constant(inner_ctx.insn_index_at_loop_start as u64, PisSize::B1);
    ctx.emit(pis_insn!(Jmp! loop_start_target));

    // now that we finished emitting the code, update the offset of the jmp instruction at the start
    // of the loop which should jump to the end of the instruction.
    let insn_end_offset = ctx.emitter.insns.len() as u64;
    let jmp_insn = &mut ctx.emitter.insns[inner_ctx.jmp_end_insn_idx];
    jmp_insn.operands[0] = PisOp::constant(insn_end_offset, PisSize::B1);

    Ok(())
}

/// lift STOS.
fn lift_stos(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 1);
    let LiftedOp::Implicit(size) = ops[0] else {
        panic!("expected an implicit operand");
    };

    let operand_size = ops[0].size();

    let rep_ctx = rep_begin(ctx)?;

    let ax = PisOp::reg(X86_REG_RAX.offset.0, operand_size);
    let di = PisOp::reg(X86_REG_RDI.offset.0, ctx.addr_size);
    let increment = PisOp::constant(operand_size.bytes() as u64, ctx.addr_size);

    // store AL/AX/EAX/RAX to [DI/EDI/RDI]
    ctx.emitter.emit(pis_insn!(Store! di, ax));

    // update DI based on DF flag (assuming DF=0 for now, increment)
    // TODO: Implement DF flag check
    ctx.emitter.emit(pis_insn!(Add! di, di, increment));

    rep_end(ctx, rep_ctx)?;

    Ok(())
}

/// lift MOVS.
fn lift_movs(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 1);

    let operand_size = ops[0].size();

    let rep_ctx = rep_begin(ctx)?;

    let si = PisOp::reg(X86_REG_RSI.offset.0, ctx.addr_size);
    let di = PisOp::reg(X86_REG_RDI.offset.0, ctx.addr_size);
    let increment = PisOp::constant(operand_size.bytes() as u64, ctx.addr_size);

    // load from [SI]
    let tmp = ctx.emitter.tmp_op_allocator.alloc(operand_size)?;
    ctx.emitter.emit(pis_insn!(Load! tmp, si));
    // store to [DI]
    ctx.emitter.emit(pis_insn!(Store! di, tmp));

    // update SI and DI based on DF flag (assuming DF=0 for now, increment)
    // TODO: Implement DF flag check
    ctx.emitter.emit(pis_insn!(Add! si, si, increment));
    ctx.emitter.emit(pis_insn!(Add! di, di, increment));

    rep_end(ctx, rep_ctx)?;

    Ok(())
}

/// lift CMPS.
fn lift_cmps(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 1);

    let operand_size = ops[0].size();

    let rep_ctx = rep_begin(ctx)?;

    let si = PisOp::reg(X86_REG_RSI.offset.0, ctx.addr_size);
    let di = PisOp::reg(X86_REG_RDI.offset.0, ctx.addr_size);
    let increment = PisOp::constant(operand_size.bytes() as u64, ctx.addr_size);

    // load from [SI]
    let val_si = ctx.emitter.tmp_op_allocator.alloc(operand_size)?;
    ctx.emitter.emit(pis_insn!(Load! val_si, si));
    // load from [DI]
    let val_di = ctx.emitter.tmp_op_allocator.alloc(operand_size)?;
    ctx.emitter.emit(pis_insn!(Load! val_di, di));

    // compare (updates flags like SUB)
    mnm_calc_sub(ctx, val_si, val_di)?;

    // update SI and DI based on DF flag (assuming DF=0 for now, increment)
    // TODO: Implement DF flag check
    ctx.emitter.emit(pis_insn!(Add! si, si, increment));
    ctx.emitter.emit(pis_insn!(Add! di, di, increment));

    rep_end(ctx, rep_ctx)?;

    Ok(())
}

/// lift LODS.
fn lift_lods(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 1);

    let operand_size = ops[0].size();
    let rep_ctx = rep_begin(ctx)?;

    let ax = PisOp::reg(X86_REG_RAX.offset.0, operand_size);
    let si = PisOp::reg(X86_REG_RSI.offset.0, ctx.addr_size);
    let increment = PisOp::constant(operand_size.bytes() as u64, ctx.addr_size);

    // load from [SI] into AL/AX/EAX/RAX
    ctx.emitter.emit(pis_insn!(Load! ax, si));

    // update SI based on DF flag (assuming DF=0 for now, increment)
    // TODO: Implement DF flag check
    ctx.emitter.emit(pis_insn!(Add! si, si, increment));

    rep_end(ctx, rep_ctx)?;

    Ok(())
}

/// lift SCAS.
fn lift_scas(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert_eq!(ops.len(), 1);
    let operand_size = ops[0].size();

    let rep_ctx = rep_begin(ctx)?;

    let ax = PisOp::reg(X86_REG_RAX.offset.0, operand_size);
    let di = PisOp::reg(X86_REG_RDI.offset.0, ctx.addr_size);
    let increment = PisOp::constant(operand_size.bytes() as u64, ctx.addr_size);

    // load from [DI]
    let val_di = ctx.emitter.tmp_op_allocator.alloc(operand_size)?;
    ctx.emitter.emit(pis_insn!(Load! val_di, di));

    // compare AL/AX/EAX/RAX with [DI] (updates flags like SUB)
    mnm_calc_sub(ctx, ax, val_di)?;

    // update DI based on DF flag (assuming DF=0 for now, increment)
    // TODO: Implement DF flag check
    ctx.emitter.emit(pis_insn!(Add! di, di, increment));

    rep_end(ctx, rep_ctx)?;
    Ok(())
}

/// lift HLT.
fn lift_hlt(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert!(ops.is_empty());
    ctx.emit(pis_insn!(Halt!));
    Ok(())
}

/// lift CMC.
fn lift_cmc(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert!(ops.is_empty());
    // CF = !CF
    let negated_cf = ctx.emitter.op_unop(PisOpcode::CondNeg, X86_REG_FLAGS_CF)?;
    ctx.emitter.op_move(X86_REG_FLAGS_CF, negated_cf);
    Ok(())
}

/// lift CLC.
fn lift_clc(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert!(ops.is_empty());
    ctx.emitter.op_move_zero(X86_REG_FLAGS_CF);
    Ok(())
}

/// lift STC.
fn lift_stc(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert!(ops.is_empty());
    ctx.emitter
        .op_move(X86_REG_FLAGS_CF, PisOp::constant(1, PisSize::B1));
    Ok(())
}

/// lift CLI.
fn lift_cli(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert!(ops.is_empty());
    // requires ring 0. In PIS, just clear the flag.
    ctx.emitter.op_move_zero(X86_REG_FLAGS_IF);
    Ok(())
}

/// lift STI.
fn lift_sti(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert!(ops.is_empty());
    // requires ring 0. In PIS, just set the flag.
    ctx.emitter
        .op_move(X86_REG_FLAGS_IF, PisOp::constant(1, PisSize::B1));
    Ok(())
}

/// lift CLD.
fn lift_cld(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert!(ops.is_empty());
    ctx.emitter.op_move_zero(X86_REG_FLAGS_DF);
    Ok(())
}

/// lift STD.
fn lift_std(ctx: &mut Ctx, ops: &[LiftedOp]) -> Result<()> {
    assert!(ops.is_empty());
    ctx.emitter
        .op_move(X86_REG_FLAGS_DF, PisOp::constant(1, PisSize::B1));
    Ok(())
}

fn lift_mnm(ctx: &mut Ctx, mnemonic: Mnemonic, ops: &[LiftedOp]) -> Result<()> {
    match mnemonic {
        Mnemonic::Unsupported => Err(LiftErr::UnsupportedInsn),
        Mnemonic::Add => lift_binop(ctx, ops, mnm_calc_add, true),
        Mnemonic::Or => lift_binop(ctx, ops, mnm_calc_or, true),
        Mnemonic::Adc => lift_binop(ctx, ops, mnm_calc_adc, true),
        Mnemonic::Sbb => lift_binop(ctx, ops, mnm_calc_sbb, true),
        Mnemonic::And => lift_binop(ctx, ops, mnm_calc_or, true),
        Mnemonic::Sub => lift_binop(ctx, ops, mnm_calc_sub, true),
        Mnemonic::Xor => lift_binop(ctx, ops, mnm_calc_xor, true),
        Mnemonic::Cmp => lift_binop(ctx, ops, mnm_calc_sub, false),
        Mnemonic::Rol => lift_binop(ctx, ops, mnm_calc_rol, true),
        Mnemonic::Ror => lift_binop(ctx, ops, mnm_calc_ror, true),
        Mnemonic::Rcl => lift_binop(ctx, ops, mnm_calc_rcl, true),
        Mnemonic::Rcr => lift_binop(ctx, ops, mnm_calc_rcr, true),
        Mnemonic::Shl => lift_binop(ctx, ops, mnm_calc_shl, true),
        Mnemonic::Shr => lift_binop(ctx, ops, mnm_calc_shr, true),
        Mnemonic::Sar => lift_binop(ctx, ops, mnm_calc_sar, true),
        Mnemonic::Inc => lift_unop(ctx, ops, mnm_calc_inc),
        Mnemonic::Dec => lift_unop(ctx, ops, mnm_calc_dec),
        Mnemonic::Push => lift_push(ctx, ops),
        Mnemonic::Pop => lift_pop(ctx, ops),
        Mnemonic::Movsxd => lift_movsxd(ctx, ops),
        Mnemonic::Imul => lift_imul(ctx, ops),
        Mnemonic::Mul => lift_mul(ctx, ops),
        Mnemonic::Jcc => lift_jcc(ctx, ops),
        Mnemonic::Test => lift_binop(ctx, ops, mnm_calc_and, false),
        Mnemonic::Xchg => lift_xchg(ctx, ops),
        Mnemonic::Mov => lift_mov(ctx, ops),
        Mnemonic::Lea => lift_lea(ctx, ops),
        Mnemonic::Nop => Ok(()),
        Mnemonic::Movsx => lift_movsx(ctx, ops),
        Mnemonic::Cwd => lift_cwd(ctx, ops),
        Mnemonic::Movs => lift_movs(ctx, ops),
        Mnemonic::Cmps => lift_cmps(ctx, ops),
        Mnemonic::Stos => lift_stos(ctx, ops),
        Mnemonic::Lods => lift_lods(ctx, ops),
        Mnemonic::Ret => lift_ret(ctx, ops),
        Mnemonic::Call => lift_call(ctx, ops),
        Mnemonic::Jmp => lift_jmp(ctx, ops),
        Mnemonic::Scas => lift_scas(ctx, ops),
        Mnemonic::Hlt => lift_hlt(ctx, ops),
        Mnemonic::Cmc => lift_cmc(ctx, ops),
        Mnemonic::Not => lift_unop(ctx, ops, mnm_calc_not),
        Mnemonic::Neg => lift_unop(ctx, ops, mnm_calc_neg),
        Mnemonic::Div => lift_div(ctx, ops),
        Mnemonic::Idiv => lift_idiv(ctx, ops),
        Mnemonic::Clc => lift_clc(ctx, ops),
        Mnemonic::Stc => lift_stc(ctx, ops),
        Mnemonic::Cli => lift_cli(ctx, ops),
        Mnemonic::Sti => lift_sti(ctx, ops),
        Mnemonic::Cld => lift_cld(ctx, ops),
        Mnemonic::Std => lift_std(ctx, ops),
    }
}

fn lift_regular_insn_info(ctx: &mut Ctx, insn_info: &RegularInsnInfo) -> Result<()> {
    let mut lifted_ops: ArrayVec<LiftedOp, X86_INSN_MAX_OPS> = ArrayVec::new();
    for op in insn_info.ops {
        lifted_ops.push(lift_op(ctx, op)?);
    }
    lift_mnm(ctx, insn_info.mnemonic, &lifted_ops)
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Modrm {
    pub rm: B3,
    pub reg: B3,
    pub mod_val: B2,
}

#[bitpiece(8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Sib {
    pub base: B3,
    pub index: B3,
    pub scale: B2,
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

fn calc_stack_addr_size(ctx: &CtxPostPrefixes) -> PisSize {
    ctx.cpumode.operand_size()
}

fn calc_addr_size(ctx: &CtxPostPrefixes) -> PisSize {
    let has_size_override = ctx
        .prefixes
        .has_legacy_prefix(LegacyPrefix::AddressSizeOverride);
    match ctx.cpumode {
        super::X86Cpumode::B32 => {
            if has_size_override {
                PisSize::B2
            } else {
                PisSize::B4
            }
        }
        super::X86Cpumode::B64 => {
            if has_size_override {
                PisSize::B4
            } else {
                PisSize::B8
            }
        }
    }
}

pub fn lift_post_prefixes(mut ctx: CtxPostPrefixes) -> Result<LiftRes> {
    let decoded_opcode = decode_opcode(&mut ctx)?;
    let addr_size = calc_addr_size(&ctx);
    let stack_addr_size = calc_stack_addr_size(&ctx);
    let mut final_ctx = Ctx {
        args: ctx.args,
        cpumode: ctx.cpumode,
        prefixes: ctx.prefixes,
        opcode_byte: decoded_opcode.opcode_byte,
        opcode_table: decoded_opcode.opcode_table,
        modrm: None,
        addr_size,
        stack_addr_size,
        emitter: PisEmitter::new(),
    };
    lift_post_opcode_decode(&mut final_ctx)?;
    Ok(LiftRes {
        insns: final_ctx.emitter.insns,
        machine_insn_len: MachineInsnLen {
            bytes: final_ctx.args.code.off(),
        },
    })
}
