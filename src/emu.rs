use std::num::Wrapping;

use thiserror_no_std::Error;

use crate::{PisEndian, PisInsn, PisOp, PisOpcode, PisSize, PisSpace};

type Result<T> = core::result::Result<T, PisEmuErr>;

pub type Wu64 = Wrapping<u64>;
pub type Wi64 = Wrapping<i64>;

/// the max amount of op values
const MAX_OP_VALS: usize = 64 * 1024;

/// the max amount of mem values
const MAX_MEM_VALS: usize = 64 * 1024;

/// the value of an operand
struct OpVal {
    op: PisOp,
    value: Wu64,
}

/// the value of a memory byte
struct MemVal {
    addr: Wu64,
    value: u8,
}

/// a safe division operation which returns an error if the divisor is zero.
fn safe_div(a: Wu64, b: Wu64) -> Result<Wu64> {
    if b.0 == 0 {
        Err(PisEmuErr::DivisionByZero)
    } else {
        Ok(a / b)
    }
}

/// a safe remainder operation which returns an error if the divisor is zero.
fn safe_rem(a: Wu64, b: Wu64) -> Result<Wu64> {
    if b.0 == 0 {
        Err(PisEmuErr::DivisionByZero)
    } else {
        Ok(a % b)
    }
}

/// a safe division operation which returns an error if the divisor is zero.
fn safe_div_signed(a: Wi64, b: Wi64) -> Result<Wi64> {
    if b.0 == 0 {
        Err(PisEmuErr::DivisionByZero)
    } else {
        Ok(a / b)
    }
}

/// a safe remainder operation which returns an error if the divisor is zero.
fn safe_rem_signed(a: Wi64, b: Wi64) -> Result<Wi64> {
    if b.0 == 0 {
        Err(PisEmuErr::DivisionByZero)
    } else {
        Ok(a % b)
    }
}

/// an emulator of pis instructions.
pub struct PisEmu {
    op_vals: LimitedVec<OpVal, MAX_OP_VALS>,
    mem_vals: LimitedVec<MemVal, MAX_OP_VALS>,
    endian: PisEndian,
}
impl PisEmu {
    pub fn new(endian: PisEndian) -> Self {
        Self {
            op_vals: LimitedVec::new(),
            mem_vals: LimitedVec::new(),
            endian,
        }
    }
    fn read_mem_byte(&self, addr: Wu64) -> Result<u8> {
        let mem_val = self
            .mem_vals
            .iter()
            .find(|mem_val| mem_val.addr == addr)
            .ok_or(PisEmuErr::ReadUninitMem(addr))?;
        Ok(mem_val.value)
    }
    fn write_mem_byte(&mut self, addr: Wu64, value: u8) -> Result<()> {
        match self
            .mem_vals
            .iter_mut()
            .find(|mem_val| mem_val.addr == addr)
        {
            Some(mem_val) => mem_val.value = value,
            None => {
                self.mem_vals
                    .push(MemVal { addr, value })
                    .map_err(|_| PisEmuErr::TooManyMemVals)?;
            }
        }
        Ok(())
    }
    pub fn read_mem(&self, addr: Wu64, read_size: PisSize) -> Result<Wu64> {
        let size = read_size.bytes() as usize;

        let mut bytes = [0u8; 8];
        for i in 0..size {
            bytes[i] = self.read_mem_byte(addr + Wrapping(i as u64))?;
        }

        // convert bytes back to native endian
        self.endian.reverse_if_not_native(&mut bytes[..size]);

        let value = u64::from_ne_bytes(bytes);

        Ok(Wrapping(value))
    }
    pub fn write_mem(&mut self, addr: Wu64, read_size: PisSize, value: Wu64) -> Result<()> {
        let size = read_size.bytes() as usize;

        let mut bytes = value.0.to_ne_bytes();

        // convert from native endian to the target endian
        self.endian.reverse_if_not_native(&mut bytes[..size]);

        for i in 0..size {
            self.write_mem_byte(addr + Wrapping(i as u64), bytes[i])?;
        }

        Ok(())
    }
    pub fn read_var_op(&self, op: PisOp) -> Result<Wu64> {
        let op_val = self
            .op_vals
            .iter()
            .find(|op_val| op_val.op == op)
            .ok_or(PisEmuErr::ReadUninitOp(op))?;
        Ok(op_val.value)
    }
    pub fn read_op(&self, op: PisOp) -> Result<Wu64> {
        match op.space {
            PisSpace::Reg => self.read_var_op(op),
            PisSpace::Tmp => self.read_var_op(op),
            PisSpace::Const => Ok(Wrapping(op.offset.0)),
            PisSpace::Ram => unreachable!(),
        }
    }
    pub fn write_op(&mut self, op: PisOp, value: Wu64) -> Result<()> {
        match self.op_vals.iter_mut().find(|op_val| op_val.op == op) {
            Some(op_val) => op_val.value = value,
            None => self
                .op_vals
                .push(OpVal { op, value })
                .map_err(|_| PisEmuErr::TooManyOpVals)?,
        }
        Ok(())
    }

    fn run_unop<F>(&mut self, insn: PisInsn, calc: F) -> Result<()>
    where
        F: FnOnce(Wu64) -> Wu64,
    {
        assert_eq!(insn.operands.len(), 2);

        assert_eq!(insn.operands[0].size, insn.operands[1].size);

        let src = self.read_op(insn.operands[1])?;

        let result = calc(src);

        self.write_op(insn.operands[0], result)?;

        Ok(())
    }

    fn run_binop_fallible<F>(&mut self, insn: PisInsn, calc: F) -> Result<()>
    where
        F: FnOnce(Wu64, Wu64) -> Result<Wu64>,
    {
        assert_eq!(insn.operands.len(), 3);

        assert_eq!(insn.operands[0].size, insn.operands[1].size);
        assert_eq!(insn.operands[1].size, insn.operands[2].size);

        let lhs = self.read_op(insn.operands[1])?;
        let rhs = self.read_op(insn.operands[2])?;

        let result = calc(lhs, rhs)?;

        self.write_op(insn.operands[0], result)?;

        Ok(())
    }
    fn run_binop<F>(&mut self, insn: PisInsn, calc: F) -> Result<()>
    where
        F: FnOnce(Wu64, Wu64) -> Wu64,
    {
        self.run_binop_fallible(insn, |a, b| Ok(calc(a, b)))
    }
    fn run_binop_signed_fallible<F>(&mut self, insn: PisInsn, calc: F) -> Result<()>
    where
        F: FnOnce(Wi64, Wi64) -> Result<Wi64>,
    {
        self.run_binop_fallible(insn, |a, b| {
            let a_signed = Wrapping(a.0 as i64);
            let b_signed = Wrapping(b.0 as i64);
            let res = calc(a_signed, b_signed)?;
            Ok(Wrapping(res.0 as u64))
        })
    }
    fn run_binop_signed<F>(&mut self, insn: PisInsn, calc: F) -> Result<()>
    where
        F: FnOnce(Wi64, Wi64) -> Wi64,
    {
        self.run_binop_signed_fallible(insn, |a, b| Ok(calc(a, b)))
    }
    pub fn run(&mut self, insn: PisInsn) -> Result<()> {
        match insn.opcode {
            PisOpcode::Move => {
                assert_eq!(insn.operands.len(), 2);
                let value = self.read_op(insn.operands[1])?;
                self.write_op(insn.operands[0], value)?;
                Ok(())
            }
            PisOpcode::Load => {
                assert_eq!(insn.operands.len(), 2);
                let addr = self.read_op(insn.operands[1])?;
                let value = self.read_mem(addr, insn.operands[0].size)?;
                self.write_op(insn.operands[0], value)?;
                Ok(())
            }
            PisOpcode::Store => todo!(),
            PisOpcode::Add => self.run_binop(insn, |a, b| a + b),
            PisOpcode::And => self.run_binop(insn, |a, b| a & b),
            PisOpcode::Or => self.run_binop(insn, |a, b| (a | b)),
            PisOpcode::Xor => self.run_binop(insn, |a, b| a ^ b),
            PisOpcode::Zext => todo!(),
            PisOpcode::UnsignedCarry => self.run_binop(insn, |a, b| {
                if a.0.checked_add(b.0).is_none() {
                    Wrapping(1)
                } else {
                    Wrapping(0)
                }
            }),
            PisOpcode::SignedCarry => self.run_binop_signed(insn, |a, b| {
                if a.0.checked_add(b.0).is_none() {
                    Wrapping(1)
                } else {
                    Wrapping(0)
                }
            }),
            PisOpcode::Parity => {
                assert_eq!(insn.operands.len(), 2);
                assert_eq!(insn.operands[0].size, PisSize::B1);

                // read the src operand
                let value = self.read_op(insn.operands[1])?.0;
                let bit_len = insn.operands[1].size.bits();

                let mut active_bits_amount = 0;
                for i in 0..bit_len {
                    if (value & 1 << i) != 0 {
                        active_bits_amount += 1;
                    }
                }

                let parity = if active_bits_amount % 2 == 0 {
                    Wrapping(1)
                } else {
                    Wrapping(0)
                };

                self.write_op(insn.operands[0], parity)?;

                Ok(())
            }
            PisOpcode::Equals => {
                self.run_binop(insn, |a, b| if a == b { Wrapping(1) } else { Wrapping(0) })
            }
            PisOpcode::ShiftRightUnsigned => self.run_binop(insn, |a, b| Wrapping(a.0 >> b.0)),
            PisOpcode::Trunc => {
                assert_eq!(insn.operands.len(), 2);

                // make sure that the size is actually decreasing and not increasing
                assert!(insn.operands[0].size <= insn.operands[1].size);

                let value = self.read_op(insn.operands[1])?;

                // mask it to emulate the truncation
                let masked_value = value & Wrapping(insn.operands[0].size.mask());

                self.write_op(insn.operands[0], masked_value)?;

                Ok(())
            }
            PisOpcode::CondNeg => {
                self.run_unop(insn, |a| if a.0 == 0 { Wrapping(1) } else { Wrapping(0) })
            }
            PisOpcode::Sub => self.run_binop(insn, |a, b| a - b),
            PisOpcode::LessThanUnsigned => self.run_binop(insn, |a, b| Wrapping((a < b) as u64)),
            PisOpcode::LessThanSigned => {
                self.run_binop_signed(insn, |a, b| Wrapping((a < b) as i64))
            }
            PisOpcode::Not => self.run_unop(insn, |a| !a),
            PisOpcode::Neg => self.run_unop(insn, |a| -a),
            PisOpcode::MulUnsigned => self.run_binop(insn, |a, b| a * b),
            PisOpcode::MulSigned => self.run_binop_signed(insn, |a, b| a * b),
            PisOpcode::MulOverflowSigned => self.run_binop_signed(insn, |a, b| {
                let overflow = a.0.checked_mul(b.0).is_none();
                Wrapping(overflow as i64)
            }),
            PisOpcode::DivUnsigned => self.run_binop_fallible(insn, |a, b| safe_div(a, b)),
            PisOpcode::DivSigned => {
                self.run_binop_signed_fallible(insn, |a, b| safe_div_signed(a, b))
            }
            PisOpcode::RemUnsigned => self.run_binop_fallible(insn, |a, b| safe_rem(a, b)),
            PisOpcode::RemSigned => {
                self.run_binop_signed_fallible(insn, |a, b| safe_rem_signed(a, b))
            }
            PisOpcode::JmpCall => todo!(),
            PisOpcode::Jmp => todo!(),
            PisOpcode::JmpCond => todo!(),
            PisOpcode::JmpRet => todo!(),
            PisOpcode::Sext => todo!(),
            PisOpcode::Halt => todo!(),
            PisOpcode::ShiftRightSigned => todo!(),
            PisOpcode::ShiftLeft => todo!(),
            PisOpcode::Div16Unsigned => todo!(),
            PisOpcode::Div16Signed => todo!(),
            PisOpcode::Rem16Unsigned => todo!(),
            PisOpcode::Rem16Signed => todo!(),
            PisOpcode::Mul16Unsigned => todo!(),
        }
    }
}

#[derive(Debug, Error)]
pub enum PisEmuErr {
    #[error("attempted to read an uninitialized operand {0:?}")]
    ReadUninitOp(PisOp),

    #[error("attempted to read an uninitialized memory byte at address {0:x}")]
    ReadUninitMem(Wu64),

    #[error("too many operand values")]
    TooManyOpVals,

    #[error("too many memory values")]
    TooManyMemVals,

    #[error("division by zero")]
    DivisionByZero,
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
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, T> {
        self.0.iter_mut()
    }
}

pub struct LimitedVecErr;
