use std::{mem::offset_of, num::NonZeroU8};

use arrayvec::ArrayVec;

pub struct PisSize {
    pub bytes: NonZeroU8,
}

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
