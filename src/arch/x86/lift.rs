use super::{
    ctx::{Ctx, CtxPostPrefixes},
    modrm::{modrm_decode_rm_operand, ModrmRmOp},
    prefixes::LegacyPrefix,
    tables::{OpInfo, RegularInsnInfo, SpecificReg},
    tmp_op_allocator::TmpOpAllocator,
    LiftRes, Result, X86Cpumode, X86_INSN_MAX_OPS, X86_REG_FLAGS_CF, X86_REG_FLAGS_OF,
    X86_REG_FLAGS_PF, X86_REG_FLAGS_SF, X86_REG_FLAGS_ZF, X86_REG_RAX, X86_REG_RIP,
};
use crate::{
    arch::x86::tables::{InsnInfo, Mnemonic, RegEncoding},
    cursor::CursorImmExtParams,
    pis_insn,
    utils::array_vec,
    LiftErr, MachineInsnLen, PisEndian, PisInsn, PisOp, PisOpcode, PisSize,
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
        let tmp = ctx.tmp_op_allocator.alloc(self.size)?;
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
            CondKind::BelowEqual => ctx.op_or(X86_REG_FLAGS_ZF, X86_REG_FLAGS_CF),
            CondKind::Sign => Ok(X86_REG_FLAGS_SF),
            CondKind::Parity => Ok(X86_REG_FLAGS_PF),
            CondKind::Lower => ctx.op_xor(X86_REG_FLAGS_SF, X86_REG_FLAGS_OF),
            CondKind::LowerEqual => {
                let lower = ctx.op_xor(X86_REG_FLAGS_SF, X86_REG_FLAGS_OF)?;
                ctx.op_or(lower, X86_REG_FLAGS_ZF)
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

            let extended_reg = ctx.op_zext(reg, extended_size)?;

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
            Ok(LiftedOp::Value(
                ctx.op_and(X86_REG_RIP, PisOp::constant(mask, PisSize::B8))?,
            ))
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
                result = ctx.op_cond_neg(result)?;
            }
            Ok(LiftedOp::Value(result))
        }
    }
}

/// calculates the parity flag value of the given calculation result.
fn calc_pf(ctx: &mut Ctx, calc_res: PisOp) -> Result<PisOp> {
    let low_byte = ctx.op_trunc(calc_res, PisSize::B1)?;
    ctx.op_parity(low_byte)
}

/// calculates the zero flag value of the given calculation result.
fn calc_zf(ctx: &mut Ctx, calc_res: PisOp) -> Result<PisOp> {
    ctx.op_equals(calc_res, PisOp::constant(0, calc_res.size))
}

/// calculates the most significant bit of the given value.
/// the output is a 1 byte conditional expression which indicates whether the sign bit of the given
/// value is enabled.
fn calc_msb(ctx: &mut Ctx, value: PisOp) -> Result<PisOp> {
    // shift it right such that the msb becomes the lsb
    let shift_amount = value.size.bits() - 1;
    let shifted =
        ctx.op_shift_right_unsigned(value, PisOp::constant(shift_amount as u64, value.size))?;

    // truncate it to 1 byte
    ctx.op_trunc(shifted, PisSize::B1)
}

/// calculates the sign flag value of the given calculation result.
fn calc_sf(ctx: &mut Ctx, calc_res: PisOp) -> Result<PisOp> {
    calc_msb(ctx, calc_res)
}

/// updates the parity, zero and sign flags according to the given calculation result.
fn update_parity_zero_sign_flags(ctx: &mut Ctx, calc_res: PisOp) -> Result<()> {
    let pf = calc_pf(ctx, calc_res)?;
    ctx.op_move(X86_REG_FLAGS_PF, pf);

    let zf = calc_zf(ctx, calc_res)?;
    ctx.op_move(X86_REG_FLAGS_ZF, zf);

    let sf = calc_sf(ctx, calc_res)?;
    ctx.op_move(X86_REG_FLAGS_SF, sf);

    Ok(())
}

/// updates the value of the carry flag according to a addtraction operation `a - b`.
fn update_c_f_add(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) {
    ctx.emit(pis_insn!(UnsignedCarry! X86_REG_FLAGS_CF, lhs, rhs));
}

/// updates the value of the overflow flag according to a addition operation `a + b`.
fn update_o_f_add(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) {
    ctx.emit(pis_insn!(SignedCarry! X86_REG_FLAGS_OF, lhs, rhs));
}

/// the mnemonic calculation of the ADD opcode.
fn mnm_calc_add(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    let res = ctx.op_add(lhs, rhs)?;

    update_c_f_add(ctx, lhs, rhs);
    update_o_f_add(ctx, lhs, rhs);
    update_parity_zero_sign_flags(ctx, res)?;

    Ok(res)
}

/// updates the value of the carry flag according to a subtraction operation `a - b`.
fn update_c_f_sub(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) {
    ctx.emit(pis_insn!(LessThanUnsigned! X86_REG_FLAGS_CF, lhs, rhs));
}

/// calculates the value of the overflow flag for a subtraction operation `a - b`.
fn calc_o_f_sub(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp, sub_res: PisOp) -> Result<PisOp> {
    // calculate the sign bit of the subtraction result
    let sub_res_msb = calc_msb(ctx, sub_res)?;

    // check if lhs < rhs
    let lhs_less_than_rhs = ctx.op_less_than_signed(lhs, rhs)?;

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
    ctx.op_xor(sub_res_msb, lhs_less_than_rhs)
}

/// updates the value of the overflow flag according to a subtraction operation `a - b`.
fn update_o_f_sub(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp, sub_res: PisOp) -> Result<()> {
    let o_f = calc_o_f_sub(ctx, lhs, rhs, sub_res)?;
    ctx.op_move(X86_REG_FLAGS_OF, o_f);
    Ok(())
}

/// the mnemonic calculation of the SUB opcode.
fn mnm_calc_sub(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    let res = ctx.op_sub(lhs, rhs)?;

    update_c_f_sub(ctx, lhs, rhs);
    update_o_f_sub(ctx, lhs, rhs, res)?;
    update_parity_zero_sign_flags(ctx, res)?;

    Ok(res)
}

/// the mnemonic calculation of the DEC opcode.
fn mnm_calc_dec(ctx: &mut Ctx, value: PisOp) -> Result<PisOp> {
    let one = PisOp::constant(1, value.size);

    let res = ctx.op_sub(value, one)?;

    // NOTE: the carry flag is not updated when using DEC
    update_o_f_sub(ctx, value, one, res)?;
    update_parity_zero_sign_flags(ctx, res)?;

    Ok(res)
}

/// the mnemonic calculation of the INC opcode.
fn mnm_calc_inc(ctx: &mut Ctx, value: PisOp) -> Result<PisOp> {
    let one = PisOp::constant(1, value.size);

    let res = ctx.op_add(value, one)?;

    // NOTE: the carry flag is not updated when using INC
    update_o_f_add(ctx, value, one);
    update_parity_zero_sign_flags(ctx, res)?;

    Ok(res)
}

/// set the carry flag and overflow flag to zero.
fn zero_c_f_and_o_f(ctx: &mut Ctx) {
    ctx.op_move_zero(X86_REG_FLAGS_CF);
    ctx.op_move_zero(X86_REG_FLAGS_OF);
}

/// the mnemonic calculation of the OR opcode.
fn mnm_calc_or(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    let res = ctx.op_or(lhs, rhs)?;

    zero_c_f_and_o_f(ctx);
    update_parity_zero_sign_flags(ctx, res)?;

    Ok(res)
}

/// the mnemonic calculation of the XOR opcode.
fn mnm_calc_xor(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    let res = ctx.op_xor(lhs, rhs)?;

    zero_c_f_and_o_f(ctx);
    update_parity_zero_sign_flags(ctx, res)?;

    Ok(res)
}

/// the mnemonic calculation of the AND opcode.
fn mnm_calc_and(ctx: &mut Ctx, lhs: PisOp, rhs: PisOp) -> Result<PisOp> {
    let res = ctx.op_and(lhs, rhs)?;

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

fn lift_mnm(ctx: &mut Ctx, mnemonic: Mnemonic, ops: &[LiftedOp]) -> Result<()> {
    match mnemonic {
        Mnemonic::Unsupported => Err(LiftErr::UnsupportedInsn),
        Mnemonic::Add => lift_binop(ctx, ops, mnm_calc_add, true),
        Mnemonic::Or => lift_binop(ctx, ops, mnm_calc_or, true),
        Mnemonic::Adc => todo!(),
        Mnemonic::Sbb => todo!(),
        Mnemonic::And => lift_binop(ctx, ops, mnm_calc_or, true),
        Mnemonic::Sub => lift_binop(ctx, ops, mnm_calc_sub, true),
        Mnemonic::Xor => lift_binop(ctx, ops, mnm_calc_xor, true),
        Mnemonic::Cmp => lift_binop(ctx, ops, mnm_calc_sub, false),
        Mnemonic::Rol => todo!(),
        Mnemonic::Ror => todo!(),
        Mnemonic::Rcl => todo!(),
        Mnemonic::Rcr => todo!(),
        Mnemonic::Shl => todo!(),
        Mnemonic::Shr => todo!(),
        Mnemonic::Sar => todo!(),
        Mnemonic::Inc => lift_unop(ctx, ops, mnm_calc_inc),
        Mnemonic::Dec => lift_unop(ctx, ops, mnm_calc_dec),
        Mnemonic::Push => todo!(),
        Mnemonic::Pop => todo!(),
        Mnemonic::Movsxd => todo!(),
        Mnemonic::Imul => todo!(),
        Mnemonic::Mul => todo!(),
        Mnemonic::Jcc => todo!(),
        Mnemonic::Test => lift_binop(ctx, ops, mnm_calc_and, false),
        Mnemonic::Xchg => todo!(),
        Mnemonic::Mov => lift_mov(ctx, ops),
        Mnemonic::Lea => lift_lea(ctx, ops),
        Mnemonic::Nop => todo!(),
        Mnemonic::Movsx => todo!(),
        Mnemonic::Cwd => todo!(),
        Mnemonic::Movs => todo!(),
        Mnemonic::Cmps => todo!(),
        Mnemonic::Stos => todo!(),
        Mnemonic::Lods => todo!(),
        Mnemonic::Ret => todo!(),
        Mnemonic::Call => todo!(),
        Mnemonic::Jmp => todo!(),
        Mnemonic::Scas => todo!(),
        Mnemonic::Hlt => todo!(),
        Mnemonic::Cmc => todo!(),
        Mnemonic::Not => todo!(),
        Mnemonic::Neg => todo!(),
        Mnemonic::Div => todo!(),
        Mnemonic::Idiv => todo!(),
        Mnemonic::Clc => todo!(),
        Mnemonic::Stc => todo!(),
        Mnemonic::Cli => todo!(),
        Mnemonic::Sti => todo!(),
        Mnemonic::Cld => todo!(),
        Mnemonic::Std => todo!(),
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
        res: LiftRes::new(),
        tmp_op_allocator: TmpOpAllocator::new(),
    };
    lift_post_opcode_decode(&mut final_ctx)?;
    Ok(LiftRes {
        insns: final_ctx.res.insns,
        machine_insn_len: MachineInsnLen {
            bytes: final_ctx.args.code.off(),
        },
    })
}
