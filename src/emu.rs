use std::num::Wrapping;

use thiserror_no_std::Error;

use crate::{PisInsn, PisOp, PisOpcode};

type Result<T> = core::result::Result<T, PisEmuErr>;

pub type W64 = Wrapping<u64>;

/// the max amount of op values
const MAX_OP_VALS: usize = 64 * 1024;

/// the value of an operand
struct OpVal {
    op: PisOp,
    value: W64,
}

/// a binary operator calculation.
type BinopCalc = fn(lhs: W64, rhs: W64) -> W64;

/// an emulator of pis instructions.
pub struct PisEmu {
    op_vals: LimitedVec<OpVal, MAX_OP_VALS>,
}
impl PisEmu {
    pub fn new() -> Self {
        Self {
            op_vals: LimitedVec::new(),
        }
    }
    pub fn read_op(&self, op: PisOp) -> Result<W64> {
        let op_val = self
            .op_vals
            .iter()
            .find(|op_val| op_val.op == op)
            .ok_or(PisEmuErr::ReadUninitOp(op))?;
        Ok(op_val.value)
    }
    pub fn write_op(&mut self, op: PisOp, value: W64) -> Result<()> {
        self.op_vals
            .push(OpVal { op, value })
            .map_err(|_| PisEmuErr::TooManyOpVals)
    }
    fn run_binop(&mut self, insn: PisInsn, calc: BinopCalc) -> Result<()> {
        assert_eq!(insn.operands.len(), 3);

        let lhs = self.read_op(insn.operands[1])?;
        let rhs = self.read_op(insn.operands[2])?;

        let result = calc(lhs, rhs);

        self.write_op(insn.operands[0], result)?;

        Ok(())
    }
    pub fn run(&mut self, insn: PisInsn) -> Result<()> {
        match insn.opcode {
            PisOpcode::Move => {
                assert_eq!(insn.operands.len(), 2);
                let value = self.read_op(insn.operands[1])?;
                self.write_op(insn.operands[0], value)?;
                Ok(())
            }
            PisOpcode::Load => todo!(),
            PisOpcode::Store => todo!(),
            PisOpcode::Add => self.run_binop(insn, |a, b| a + b),
            PisOpcode::And => self.run_binop(insn, |a, b| a & b),
            PisOpcode::MulUnsigned => self.run_binop(insn, |a, b| a * b),
            PisOpcode::Or => self.run_binop(insn, |a, b| (a | b)),
            PisOpcode::Xor => self.run_binop(insn, |a, b| a ^ b),
            PisOpcode::Zext => todo!(),
            PisOpcode::UnsignedCarry => todo!(),
            PisOpcode::SignedCarry => todo!(),
            PisOpcode::Parity => todo!(),
            PisOpcode::Equals => {
                self.run_binop(insn, |a, b| if a == b { Wrapping(1) } else { Wrapping(0) })
            }
            PisOpcode::ShiftRightUnsigned => self.run_binop(insn, |a, b| Wrapping(a.0 >> b.0)),
            PisOpcode::Trunc => todo!(),
            PisOpcode::CondNeg => todo!(),
        }
    }
}

#[derive(Debug, Error)]
pub enum PisEmuErr {
    #[error("attempted to read an uninitialized operand: {0:?}")]
    ReadUninitOp(PisOp),

    #[error("too many operand values")]
    TooManyOpVals,
}

pub struct LimitedVec<T, const MAX_SIZE: usize>(Vec<T>);
impl<T, const MAX_SIZE: usize> LimitedVec<T, MAX_SIZE> {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn push(&mut self, item: T) -> core::result::Result<(), LimitedVecErr> {
        if self.0.len() >= MAX_SIZE {
            return Err(LimitedVecErr);
        }
        self.0.push(item);
        Ok(())
    }
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.0.iter()
    }
}

pub struct LimitedVecErr;
