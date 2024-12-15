use std::{mem::offset_of, num::NonZeroU8};
mod arch;

use arrayvec::ArrayVec;
use thiserror_no_std::Error;

pub struct PisSize {
    pub bytes: NonZeroU8,
}

#[non_exhaustive]
pub enum PisSpace {
    Reg,
    Tmp,
    Const,
    Ram,
}

pub struct PisOff(pub u64);

pub struct PisOp {
    pub space: PisSpace,
    pub offset: PisOff,
    pub size: PisSize,
}

#[non_exhaustive]
pub enum PisOpcode {
    Add,
    And,
    Or,
    Xor,
}

pub struct PisInsn {
    pub opcode: PisOpcode,
    pub operands: ArrayVec<PisOp, { Self::MAX_OPERANDS }>,
}
impl PisInsn {
    pub const MAX_OPERANDS: usize = 4;
}

pub struct MachineInsnLen {
    pub bytes: u8,
}

pub struct LiftRes {
    pub insns: ArrayVec<PisInsn, { Self::MAX_INSNS }>,
    pub machine_insn_len: MachineInsnLen,
}
impl LiftRes {
    pub const MAX_INSNS: usize = 64;
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LiftErr {
    #[error("early eof")]
    EarlyEof,
}

pub trait PisProcessor {
    fn lift_one(code: &[u8]) -> Result<LiftRes, LiftErr>;
}
