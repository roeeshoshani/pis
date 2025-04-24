use core::net;
use std::num::Wrapping;

use thiserror_no_std::Error;

use crate::{PisAddr, PisEndian, PisInsn, PisOp, PisOpcode, PisSize, PisSpace};

type Result<T> = core::result::Result<T, PisEmuErr>;

pub type Wu64 = Wrapping<u64>;
pub type Wi64 = Wrapping<i64>;

/// the max amount of op values
const MAX_OP_VALS: usize = 64 * 1024;

/// the max amount of mem values
const MAX_MEM_VALS: usize = 64 * 1024;

trait ByteStorageEntry {
    type Addr: ByteStorageAddr;
    fn addr(&self) -> Self::Addr;
    fn val(&self) -> u8;
    fn set_val(&mut self, new_val: u8);
    fn make(addr: Self::Addr, val: u8) -> Self;
}

trait ByteStorageAddr: Eq + Copy {
    fn uninit_err(self) -> PisEmuErr;
    fn offset(&self, offset: u64) -> Self;
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct OpValAddr(PisAddr);
impl ByteStorageAddr for OpValAddr {
    fn uninit_err(self) -> PisEmuErr {
        PisEmuErr::ReadUninitOp(self.0)
    }

    fn offset(&self, offset: u64) -> Self {
        Self(PisAddr {
            space: self.0.space,
            offset: self.0.offset + offset,
        })
    }
}

/// the value of an operand byte
struct OpVal {
    addr: OpValAddr,
    val: u8,
}
impl ByteStorageEntry for OpVal {
    type Addr = OpValAddr;

    fn addr(&self) -> Self::Addr {
        self.addr
    }

    fn val(&self) -> u8 {
        self.val
    }

    fn set_val(&mut self, new_val: u8) {
        self.val = new_val;
    }

    fn make(addr: Self::Addr, val: u8) -> Self {
        Self { addr, val }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
struct MemValAddr(Wu64);
impl ByteStorageAddr for MemValAddr {
    fn uninit_err(self) -> PisEmuErr {
        PisEmuErr::ReadUninitMem(self.0)
    }

    fn offset(&self, offset: u64) -> Self {
        Self(self.0 + Wrapping(offset))
    }
}

/// the value of a memory byte
struct MemVal {
    addr: MemValAddr,
    val: u8,
}
impl ByteStorageEntry for MemVal {
    type Addr = MemValAddr;

    fn addr(&self) -> Self::Addr {
        self.addr
    }

    fn val(&self) -> u8 {
        self.val
    }

    fn set_val(&mut self, new_val: u8) {
        self.val = new_val;
    }

    fn make(addr: Self::Addr, val: u8) -> Self {
        Self { addr, val }
    }
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

/// sign extends the given value from the given original size to 64 bits.
fn sign_extend_64(val: u64, size: PisSize) -> i64 {
    match size {
        PisSize::B1 => val as u8 as i8 as i64,
        PisSize::B2 => val as u16 as i16 as i64,
        PisSize::B4 => val as u32 as i32 as i64,
        PisSize::B8 => val as i64,
        _ => unreachable!(),
    }
}

fn read_multi_byte<E: ByteStorageEntry>(
    storage: &[E],
    endian: PisEndian,
    addr: E::Addr,
    read_size: PisSize,
) -> Result<Wu64> {
    let size = read_size.bytes() as usize;

    let mut bytes = [0u8; 8];
    for i in 0..size {
        let cur_addr = addr.offset(i as u64);
        let entry = storage
            .iter()
            .find(|entry| entry.addr() == cur_addr)
            .ok_or(cur_addr.uninit_err())?;
        bytes[i] = entry.val();
    }

    // convert to little endian
    if endian != PisEndian::Little {
        bytes[..size].reverse();
    }

    let value = u64::from_le_bytes(bytes);

    Ok(Wrapping(value))
}

fn write_multi_byte<const MAX_SIZE: usize, E: ByteStorageEntry>(
    storage: &mut LimitedVec<E, MAX_SIZE>,
    endian: PisEndian,
    addr: E::Addr,
    write_size: PisSize,
    value: Wu64,
) -> Result<()> {
    let size = write_size.bytes() as usize;

    let mut bytes = value.0.to_le_bytes();

    // convert from little endian to the target endian
    if endian != PisEndian::Little {
        bytes[..size].reverse();
    }

    for i in 0..size {
        let cur_addr = addr.offset(i as u64);
        let cur_byte_val = bytes[i];
        match storage.iter_mut().find(|entry| entry.addr() == cur_addr) {
            Some(entry) => entry.set_val(cur_byte_val),
            None => {
                storage
                    .push(E::make(addr, cur_byte_val))
                    .map_err(|_| PisEmuErr::TooManyMemVals)?;
            }
        }
    }

    Ok(())
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
    pub fn read_mem(&self, addr: Wu64, read_size: PisSize) -> Result<Wu64> {
        read_multi_byte(&self.mem_vals.0, self.endian, MemValAddr(addr), read_size)
    }
    pub fn write_mem(&mut self, addr: Wu64, write_size: PisSize, value: Wu64) -> Result<()> {
        write_multi_byte(
            &mut self.mem_vals,
            self.endian,
            MemValAddr(addr),
            write_size,
            value,
        )
    }
    pub fn read_var_op(&self, op: PisOp) -> Result<Wu64> {
        read_multi_byte(&self.op_vals.0, self.endian, OpValAddr(op.addr()), op.size)
    }
    pub fn write_var_op(&mut self, op: PisOp, value: Wu64) -> Result<()> {
        write_multi_byte(
            &mut self.op_vals,
            self.endian,
            OpValAddr(op.addr()),
            op.size,
            value,
        )
    }
    /// reads the value of the given operand.
    pub fn read_op(&self, op: PisOp) -> Result<Wu64> {
        match op.space {
            PisSpace::Reg => self.read_var_op(op),
            PisSpace::Tmp => self.read_var_op(op),
            PisSpace::Const => Ok(Wrapping(op.offset.0)),
            PisSpace::Ram => unreachable!(),
        }
    }
    /// reads the value of the given operand as a signed value.
    pub fn read_op_signed(&self, op: PisOp) -> Result<Wi64> {
        let val = self.read_op(op)?.0;
        Ok(Wrapping(sign_extend_64(val, op.size)))
    }
    /// writes the given value to the given operand.
    pub fn write_op(&mut self, op: PisOp, value: Wu64) -> Result<()> {
        match op.space {
            PisSpace::Reg => self.write_var_op(op, value),
            PisSpace::Tmp => self.write_var_op(op, value),
            PisSpace::Const => unreachable!(),
            PisSpace::Ram => unreachable!(),
        }
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
        assert_eq!(insn.operands.len(), 3);

        assert_eq!(insn.operands[0].size, insn.operands[1].size);
        assert_eq!(insn.operands[1].size, insn.operands[2].size);

        let lhs = self.read_op_signed(insn.operands[1])?;
        let rhs = self.read_op_signed(insn.operands[2])?;

        let result = calc(lhs, rhs)?;

        self.write_op(insn.operands[0], Wrapping(result.0 as u64))?;

        Ok(())
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
            PisOpcode::Sext => {
                assert_eq!(insn.operands.len(), 2);
                let value = self.read_op_signed(insn.operands[1])?;
                self.write_op(insn.operands[0], Wrapping(value.0 as u64))?;
                Ok(())
            }
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
    #[error("attempted to read an uninitialized operand byte at address {0:?}")]
    ReadUninitOp(PisAddr),

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
