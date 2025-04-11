use bitpiece::BitPiece;

use crate::{utils::array_vec, LiftArgs, PisInsn, PisOp, PisOpcode};

use super::{
    lift::Modrm, prefixes::Prefixes, tables::OpcodeByteTable, tmp_op_allocator::TmpOpAllocator,
    LiftRes, PisSize, Result, X86Cpumode,
};

/// the initial context after just getting the lift args and deciding the desired cpumode
pub struct CtxInitial<'a> {
    pub args: LiftArgs<'a>,
    pub cpumode: X86Cpumode,
}

/// the context after parsing prefixes
pub struct CtxPostPrefixes<'a> {
    pub args: LiftArgs<'a>,
    pub cpumode: X86Cpumode,
    pub prefixes: Prefixes,
}

/// the final context after parsing the instruction's opcode
pub struct Ctx<'a> {
    pub args: LiftArgs<'a>,
    pub cpumode: X86Cpumode,
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

        self.res.insns.push(PisInsn {
            opcode,
            operands: array_vec![tmp.clone(), a, b],
        });

        Ok(tmp)
    }

    /// performs the given unary (single operand) operation on the given operand into a new tmp operand and returns it.
    ///
    /// the provided opcode must be a unary operation opcode, which accepts 2 operands - a dst operand and a src operand.
    fn op_unop(&mut self, opcode: PisOpcode, x: PisOp) -> Result<PisOp> {
        let tmp = self.tmp_op_allocator.alloc(x.size)?;

        self.res.insns.push(PisInsn {
            opcode,
            operands: array_vec![tmp.clone(), x],
        });

        Ok(tmp)
    }

    /// zero extends the given operand into a tmp operand and returns it
    pub fn op_zext(&mut self, x: PisOp, new_size: PisSize) -> Result<PisOp> {
        assert!(new_size >= x.size);

        let tmp = self.tmp_op_allocator.alloc(new_size)?;

        self.res.insns.push(PisInsn {
            opcode: PisOpcode::Zext,
            operands: array_vec![tmp.clone(), x],
        });

        Ok(tmp)
    }

    /// adds the given 2 operands into a new tmp operand and returns it.
    pub fn op_add(&mut self, a: PisOp, b: PisOp) -> Result<PisOp> {
        self.op_binop(PisOpcode::Add, a, b)
    }

    /// "bitwise-and"s the given 2 operands into a new tmp operand and returns it.
    pub fn op_and(&mut self, a: PisOp, b: PisOp) -> Result<PisOp> {
        self.op_binop(PisOpcode::And, a, b)
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
