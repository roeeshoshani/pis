use bitpiece::BitPiece;

use crate::{pis_insn, utils::array_vec, LiftArgsInternal, PisInsn, PisOp, PisOpcode};

use super::{
    lift::Modrm, prefixes::Prefixes, tables::OpcodeByteTable, tmp_op_allocator::TmpOpAllocator,
    LiftRes, PisSize, Result, X86Cpumode,
};

/// the initial context after just getting the lift args and deciding the desired cpumode
pub struct CtxInitial<'a> {
    pub args: LiftArgsInternal<'a>,
    pub cpumode: X86Cpumode,
}

/// the context after parsing prefixes
pub struct CtxPostPrefixes<'a> {
    pub args: LiftArgsInternal<'a>,
    pub cpumode: X86Cpumode,
    pub prefixes: Prefixes,
}

/// the final context after parsing the instruction's opcode
pub struct Ctx<'a> {
    pub(super) args: LiftArgsInternal<'a>,
    pub(super) cpumode: X86Cpumode,
    pub prefixes: Prefixes,
    pub opcode_byte: u8,
    pub opcode_table: &'static OpcodeByteTable,
    pub modrm: Option<Modrm>,
    pub addr_size: PisSize,
    pub stack_addr_size: PisSize,
    pub res: LiftRes,
    pub tmp_op_allocator: TmpOpAllocator,
}

impl<'a> Ctx<'a> {
    pub fn emit(&mut self, insn: PisInsn) {
        self.res.insns.push(insn);
    }
    pub fn modrm(&mut self) -> Result<Modrm> {
        match self.modrm {
            Some(modrm) => Ok(modrm),
            None => Ok(*self
                .modrm
                .insert(Modrm::from_bits(self.args.code.next_byte()?))),
        }
    }

    /// performs the given binary (two operand) operation on the given 2 operands into a new tmp operand and returns it.
    ///
    /// the provided opcode must be a binary operation opcode, which accepts 3 operands - a dst operand and 2 src operands.
    fn op_binop(&mut self, opcode: PisOpcode, a: PisOp, b: PisOp) -> Result<PisOp> {
        assert_eq!(a.size, b.size);
        let tmp = self.tmp_op_allocator.alloc(a.size)?;

        self.emit(PisInsn {
            opcode,
            operands: array_vec![tmp, a, b],
        });

        Ok(tmp)
    }

    /// performs the given unary (single operand) operation on the given operand into a new tmp operand and returns it.
    ///
    /// the provided opcode must be a unary operation opcode, which accepts 2 operands - a dst operand and a src operand.
    fn op_unop(&mut self, opcode: PisOpcode, x: PisOp) -> Result<PisOp> {
        let tmp = self.tmp_op_allocator.alloc(x.size)?;

        self.emit(PisInsn {
            opcode,
            operands: array_vec![tmp, x],
        });

        Ok(tmp)
    }

    /// performs conditional negation on the given operand into a tmp operand and returns it
    pub fn op_cond_neg(&mut self, x: PisOp) -> Result<PisOp> {
        self.op_unop(PisOpcode::CondNeg, x)
    }

    /// performs a bitwise-not operation on the given operand into a tmp operand and returns it
    pub fn op_not(&mut self, x: PisOp) -> Result<PisOp> {
        self.op_unop(PisOpcode::Not, x)
    }

    /// performs a negation operation on the given operand into a tmp operand and returns it
    pub fn op_neg(&mut self, x: PisOp) -> Result<PisOp> {
        self.op_unop(PisOpcode::Neg, x)
    }

    /// performs parity calculation on the given operand into a tmp operand and returns it
    pub fn op_parity(&mut self, x: PisOp) -> Result<PisOp> {
        self.op_unop(PisOpcode::Parity, x)
    }

    /// moves the src operand into the dst operand
    pub fn op_move(&mut self, dst: PisOp, src: PisOp) {
        self.emit(pis_insn!(Move! dst, src));
    }

    /// moves a value of zero into the given operand
    pub fn op_move_zero(&mut self, dst: PisOp) {
        self.op_move(dst, PisOp::constant(0, dst.size));
    }

    /// zero extends the given operand into a tmp operand and returns it
    pub fn op_zext(&mut self, x: PisOp, new_size: PisSize) -> Result<PisOp> {
        assert!(new_size >= x.size);

        let tmp = self.tmp_op_allocator.alloc(new_size)?;

        self.emit(pis_insn!(Zext! tmp, x));

        Ok(tmp)
    }

    /// truncates the given operand into a tmp operand and returns it
    pub fn op_trunc(&mut self, x: PisOp, new_size: PisSize) -> Result<PisOp> {
        assert!(new_size <= x.size);

        let tmp = self.tmp_op_allocator.alloc(new_size)?;

        self.emit(pis_insn!(Trunc! tmp, x));

        Ok(tmp)
    }

    /// calculates the equality of the given 2 operands into a new tmp operand and returns it.
    pub fn op_equals(&mut self, a: PisOp, b: PisOp) -> Result<PisOp> {
        self.op_binop(PisOpcode::Equals, a, b)
    }

    /// checks if a is less than b when treated as signed integers, stores the result into a new tmp operand and returns it.
    pub fn op_less_than_signed(&mut self, a: PisOp, b: PisOp) -> Result<PisOp> {
        self.op_binop(PisOpcode::LessThanSigned, a, b)
    }

    /// adds the given 2 operands into a new tmp operand and returns it.
    pub fn op_add(&mut self, a: PisOp, b: PisOp) -> Result<PisOp> {
        self.op_binop(PisOpcode::Add, a, b)
    }

    /// subtracts the given 2 operands into a new tmp operand and returns it.
    pub fn op_sub(&mut self, a: PisOp, b: PisOp) -> Result<PisOp> {
        self.op_binop(PisOpcode::Sub, a, b)
    }

    /// calculates `a >> b` into a new tmp operand and returns it. uses an unsigned shift.
    pub fn op_shift_right_unsigned(&mut self, a: PisOp, b: PisOp) -> Result<PisOp> {
        self.op_binop(PisOpcode::ShiftRightUnsigned, a, b)
    }

    /// "bitwise-and"s the given 2 operands into a new tmp operand and returns it.
    pub fn op_and(&mut self, a: PisOp, b: PisOp) -> Result<PisOp> {
        self.op_binop(PisOpcode::And, a, b)
    }

    /// "bitwise-or"s the given 2 operands into a new tmp operand and returns it.
    pub fn op_or(&mut self, a: PisOp, b: PisOp) -> Result<PisOp> {
        self.op_binop(PisOpcode::Or, a, b)
    }

    /// "bitwise-xor"s the given 2 operands into a new tmp operand and returns it.
    pub fn op_xor(&mut self, a: PisOp, b: PisOp) -> Result<PisOp> {
        self.op_binop(PisOpcode::Xor, a, b)
    }

    /// performs an optional add operation on the given 2 operands.
    /// the first operand is mandatory, but the second is optional.
    /// if the second operand is none, the first operand is returned as is.
    /// if the second operand is some value, it is added to the first operand, and the result is stored into a tmp, which is
    /// then returned.
    pub fn op_add_opt(&mut self, a: PisOp, b: Option<PisOp>) -> Result<PisOp> {
        match b {
            Some(b) => self.op_add(a, b),
            None => Ok(a),
        }
    }

    /// adds the given 2 operands into a new tmp operand and returns it.
    pub fn op_mul_unsigned(&mut self, a: PisOp, b: PisOp) -> Result<PisOp> {
        self.op_binop(PisOpcode::MulUnsigned, a, b)
    }
}
