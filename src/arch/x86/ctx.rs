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

    /// adds the given 2 operands into a new tmp operand and returns it.
    pub fn op_add(&mut self, a: PisOp, b: PisOp) -> Result<PisOp> {
        assert_eq!(a.size, b.size);
        let tmp = self.tmp_op_allocator.alloc(a.size)?;

        self.res.insns.push(PisInsn {
            opcode: PisOpcode::Add,
            operands: array_vec![tmp.clone(), a, b],
        });

        Ok(tmp)
    }

    /// adds the given value to the given destination operand.
    pub fn op_add_assign(&mut self, dst: &mut PisOp, val: PisOp) {
        assert_eq!(dst.size, val.size);

        self.res.insns.push(PisInsn {
            opcode: PisOpcode::Add,
            operands: array_vec![dst.clone(), dst.clone(), val],
        });
    }
}
