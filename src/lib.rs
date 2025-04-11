#![allow(unused)]

use std::num::NonZeroU8;

use arrayvec::ArrayVec;
use primwrap::Primitive;
use thiserror_no_std::Error;
use tmp_op_allocator::TooManyTmpsErr;

mod arch;
mod cursor;
mod error;
mod regs;
mod tmp_op_allocator;
mod utils;

pub use arch::x86::*;
pub use cursor::{CursorError, PisCursor};

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
    And,
    MulUnsigned,
    Or,
    Xor,
    Zext,
    UnsignedCarry,
    SignedCarry,
    Parity,
    Equals,
    ShiftRightUnsigned,

    /// truncate an operand into a smaller size operand by only taking its lower bits>
    Trunc,

    /// negate a conditional value.
    ///
    /// if the value is non-zero, make it zero.
    /// if the value is zero, make it 1.
    CondNeg,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum ImmExtKind {
    Zero,
    Sign,
}
#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum PisEndianness {
    Little,
    Big,
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
    ($opcode: ident! $($operand: expr),+) => {
        crate::PisInsn {
            opcode: crate::PisOpcode::$opcode,
            operands: crate::utils::array_vec![$($operand),+],
        }
    };
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct MachineInsnLen {
    pub bytes: u8,
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
impl<T> From<CursorError> for LiftErr<T> {
    fn from(value: CursorError) -> Self {
        let CursorError::EarlyEof {
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
impl<'a> LiftArgsInternal<'a> {
    /// returns the address in memory where the code cursor currently points to
    pub fn cur_code_addr(&mut self) -> u64 {
        self.machine_code_addr + self.code.off() as u64
    }
}

pub trait PisProcessor {
    type Err;

    fn lift_one(args: LiftArgs) -> Result<LiftRes, LiftErr<Self::Err>>;
}
