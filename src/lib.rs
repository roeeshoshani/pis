#![allow(unused)]

use std::num::NonZeroU8;

use arrayvec::ArrayVec;
use primwrap::Primitive;
use thiserror_no_std::Error;
use tmp_op_allocator::{TmpOpAllocator, TooManyTmpsErr};

mod arch;
mod cursor;
mod emu;
mod error;
mod regs;
mod tmp_op_allocator;
mod utils;

pub use arch::x86::*;
pub use cursor::{CursorErr, PisCursor};
pub use emu::*;
use utils::array_vec;

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash)]
pub struct PisSize {
    pub bytes: NonZeroU8,
}
impl PisSize {
    pub const B1: Self = Self {
        // SAFETY: 1 != 0
        bytes: NonZeroU8::new(1).unwrap(),
    };
    pub const B2: Self = Self {
        // SAFETY: 2 != 0
        bytes: NonZeroU8::new(2).unwrap(),
    };
    pub const B4: Self = Self {
        // SAFETY: 4 != 0
        bytes: NonZeroU8::new(4).unwrap(),
    };
    pub const B8: Self = Self {
        // SAFETY: 8 != 0
        bytes: NonZeroU8::new(8).unwrap(),
    };
    pub const fn bits(&self) -> u32 {
        (self.bytes.get() as u32) * 8
    }
    pub const fn bytes(&self) -> u32 {
        self.bytes.get() as u32
    }
    pub const fn max_unsigned_val(&self) -> u64 {
        let bits = self.bits();

        assert!(bits <= 64);

        if bits == 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        }
    }
    pub const fn mask(&self) -> u64 {
        self.max_unsigned_val()
    }

    pub fn double(&self) -> Self {
        Self {
            bytes: NonZeroU8::new(self.bytes.get() * 2).unwrap(),
        }
    }
}

#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum PisSpace {
    Reg,
    Tmp,
    Const,
    Ram,
}

#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Copy, Hash, Primitive)]
pub struct PisOff(pub u64);

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct PisAddr {
    pub space: PisSpace,
    pub offset: PisOff,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct PisOp {
    pub space: PisSpace,
    pub offset: PisOff,
    pub size: PisSize,
}
impl PisOp {
    pub const fn constant(value: u64, size: PisSize) -> Self {
        Self {
            space: PisSpace::Const,
            offset: PisOff(value),
            size,
        }
    }

    pub const fn reg(offset: u64, size: PisSize) -> Self {
        Self {
            space: PisSpace::Reg,
            offset: PisOff(offset),
            size,
        }
    }

    pub const fn tmp(offset: u64, size: PisSize) -> Self {
        Self {
            space: PisSpace::Tmp,
            offset: PisOff(offset),
            size,
        }
    }

    pub const fn addr(&self) -> PisAddr {
        PisAddr {
            space: self.space,
            offset: self.offset,
        }
    }

    pub const fn with_size(&self, size: PisSize) -> Self {
        Self {
            size,
            space: self.space,
            offset: self.offset,
        }
    }

    pub const fn add_offset(&self, value: u64) -> Self {
        Self {
            offset: PisOff(self.offset.0 + value),
            space: self.space,
            size: self.size,
        }
    }

    pub const fn end_offset(&self) -> PisOff {
        PisOff(self.offset.0 + self.size.bytes.get() as u64)
    }
}

#[non_exhaustive]
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum PisOpcode {
    Move,
    Load,
    Store,
    Add,
    Sub,
    And,
    MulUnsigned,
    MulSigned,
    Mul16Unsigned,
    MulOverflowSigned,
    DivUnsigned,
    DivSigned,
    RemUnsigned,
    RemSigned,
    Div16Unsigned,
    Div16Signed,
    Rem16Unsigned,
    Rem16Signed,
    JmpCall,
    Jmp,
    JmpCond,
    JmpRet,
    Or,
    Xor,
    Zext,
    Sext,
    UnsignedCarry,
    SignedCarry,
    Parity,
    Halt,
    Equals,
    LessThanUnsigned,
    LessThanSigned,
    ShiftRightUnsigned,
    ShiftRightSigned,
    ShiftLeft,

    /// truncate an operand into a smaller size operand by only taking its lower bits>
    Trunc,

    /// negate a conditional value.
    ///
    /// if the value is non-zero, make it zero.
    /// if the value is zero, make it 1.
    CondNeg,
    Not,
    Neg,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ImmExtKind {
    Zero,
    Sign,
}
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum PisEndian {
    Little,
    Big,
}
impl PisEndian {
    #[cfg(target_endian = "little")]
    pub const NATIVE: Self = Self::Little;

    #[cfg(target_endian = "big")]
    pub const NATIVE: Self = Self::Big;

    /// reverses the given byte array if this endian is not equal to the native endian.
    /// this basically performs a conversion from this endian to the native endian and vice versa.
    pub fn reverse_if_not_native(&self, bytes: &mut [u8]) {
        if *self != Self::NATIVE {
            bytes.reverse();
        }
    }

    pub fn bytes_to_u64(&self, bytes: [u8; 8]) -> u64 {
        match self {
            PisEndian::Little => u64::from_le_bytes(bytes),
            PisEndian::Big => u64::from_be_bytes(bytes),
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct PisInsn {
    pub opcode: PisOpcode,
    pub operands: ArrayVec<PisOp, { Self::MAX_OPERANDS }>,
}
impl PisInsn {
    pub const MAX_OPERANDS: usize = 4;
}

#[macro_export]
macro_rules! pis_insn {
    ($opcode: ident! $($operand: expr),*) => {
        crate::PisInsn {
            opcode: crate::PisOpcode::$opcode,
            operands: crate::utils::array_vec![$($operand),*],
        }
    };
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct MachineInsnLen {
    pub bytes: usize,
}

pub type LiftResInsns = ArrayVec<PisInsn, { LiftRes::MAX_INSNS }>;

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct LiftRes {
    pub insns: LiftResInsns,
    pub machine_insn_len: MachineInsnLen,
}
impl LiftRes {
    pub const MAX_INSNS: usize = 64;
    pub fn new() -> Self {
        Self {
            insns: LiftResInsns::new(),
            machine_insn_len: MachineInsnLen { bytes: 0 },
        }
    }
}

struct PisEmitter {
    insns: LiftResInsns,
    tmp_op_allocator: TmpOpAllocator,
}
impl PisEmitter {
    pub fn new() -> Self {
        Self {
            insns: LiftResInsns::new(),
            tmp_op_allocator: TmpOpAllocator::new(),
        }
    }

    pub fn emit(&mut self, insn: PisInsn) {
        self.insns.push(insn);
    }

    /// copies the value of the given operand into a new tmp operand.
    pub fn copy_value(&mut self, x: PisOp) -> Result<PisOp, TooManyTmpsErr> {
        let tmp = self.tmp_op_allocator.alloc(x.size)?;
        self.op_move(tmp, x);
        Ok(tmp)
    }

    /// performs the given binary (two operand) operation on the given 2 operands into a new tmp operand and returns it.
    ///
    /// the provided opcode must be a binary operation opcode, which accepts 3 operands - a dst operand and 2 src operands.
    pub fn op_binop(
        &mut self,
        opcode: PisOpcode,
        lhs: PisOp,
        rhs: PisOp,
    ) -> Result<PisOp, TooManyTmpsErr> {
        assert_eq!(lhs.size, rhs.size);
        let tmp = self.tmp_op_allocator.alloc(lhs.size)?;

        self.emit(PisInsn {
            opcode,
            operands: array_vec![tmp, lhs, rhs],
        });

        Ok(tmp)
    }

    /// performs the given unary (single operand) operation on the given operand into a new tmp operand and returns it.
    ///
    /// the provided opcode must be a unary operation opcode, which accepts 2 operands - a dst operand and a src operand.
    pub fn op_unop(&mut self, opcode: PisOpcode, x: PisOp) -> Result<PisOp, TooManyTmpsErr> {
        let tmp = self.tmp_op_allocator.alloc(x.size)?;

        self.emit(PisInsn {
            opcode,
            operands: array_vec![tmp, x],
        });

        Ok(tmp)
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
    pub fn op_zext(&mut self, x: PisOp, new_size: PisSize) -> Result<PisOp, TooManyTmpsErr> {
        assert!(new_size >= x.size);

        let tmp = self.tmp_op_allocator.alloc(new_size)?;

        self.emit(pis_insn!(Zext! tmp, x));

        Ok(tmp)
    }

    /// sign extends the given operand into a tmp operand and returns it
    pub fn op_sext(&mut self, x: PisOp, new_size: PisSize) -> Result<PisOp, TooManyTmpsErr> {
        assert!(new_size >= x.size);

        let tmp = self.tmp_op_allocator.alloc(new_size)?;

        self.emit(pis_insn!(Sext! tmp, x));

        Ok(tmp)
    }

    /// truncates the given operand into a tmp operand and returns it
    pub fn op_trunc(&mut self, x: PisOp, new_size: PisSize) -> Result<PisOp, TooManyTmpsErr> {
        assert!(new_size <= x.size);

        let tmp = self.tmp_op_allocator.alloc(new_size)?;

        self.emit(pis_insn!(Trunc! tmp, x));

        Ok(tmp)
    }

    /// performs an optional add operation on the given 2 operands.
    /// the first operand is mandatory, but the second is optional.
    /// if the second operand is none, the first operand is returned as is.
    /// if the second operand is some value, it is added to the first operand, and the result is stored into a tmp, which is
    /// then returned.
    pub fn op_add_opt(&mut self, lhs: PisOp, rhs: Option<PisOp>) -> Result<PisOp, TooManyTmpsErr> {
        match rhs {
            Some(rhs) => self.op_binop(PisOpcode::Add, lhs, rhs),
            None => Ok(lhs),
        }
    }
}

#[derive(Debug, Error, Clone)]
#[non_exhaustive]
pub enum LiftErr<T> {
    #[error("early eof, {required_bytes_amount} bytes were required, but only {actual_bytes_amount} were available")]
    EarlyEof {
        required_bytes_amount: usize,
        actual_bytes_amount: usize,
    },

    #[error("unsupported instruction")]
    UnsupportedInsn,

    #[error("too many tmps")]
    TooManyTmps,

    #[error("arch specific error: {0}")]
    ArchSpecific(T),
}
impl<T> From<CursorErr> for LiftErr<T> {
    fn from(value: CursorErr) -> Self {
        let CursorErr::EarlyEof {
            required_bytes_amount,
            actual_bytes_amount,
        } = value;
        Self::EarlyEof {
            required_bytes_amount,
            actual_bytes_amount,
        }
    }
}
impl<T> From<TooManyTmpsErr> for LiftErr<T> {
    fn from(value: TooManyTmpsErr) -> Self {
        Self::TooManyTmps
    }
}

pub struct LiftArgs<'a> {
    pub code: &'a [u8],
    pub machine_code_addr: u64,
}
impl<'a> LiftArgs<'a> {
    fn into_internal(self) -> LiftArgsInternal<'a> {
        LiftArgsInternal {
            code: PisCursor::new(self.code),
            machine_code_addr: self.machine_code_addr,
        }
    }
}

/// internal lift args. the lift args type is designed to be convenient for use by api users.
/// this internal type is designed to be more convenient for internal implementations of the lifters.
struct LiftArgsInternal<'a> {
    pub code: PisCursor<'a>,
    pub machine_code_addr: u64,
}

pub trait PisProcessor {
    type Err;

    fn lift_one(args: LiftArgs) -> Result<LiftRes, LiftErr<Self::Err>>;
}
