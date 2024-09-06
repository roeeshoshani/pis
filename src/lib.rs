use arrayvec::ArrayVec;

pub mod x86;

pub const TRANSLATION_MAX_INSNS: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperandSpace {
    Ram,
    Const,
    Regs,
    Tmp,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Operand {
    pub addr: OperandAddr,
    pub size: OperandSize,
}
impl core::fmt::Display for Operand {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}:{}", self.addr, self.size as usize)
    }
}
impl Operand {
    pub const fn constant(value: u64, size: OperandSize) -> Self {
        Self {
            addr: OperandAddr {
                space: OperandSpace::Const,
                offset: value,
            },
            size,
        }
    }

    pub const fn negative_constant(absolute_value: u64, size: OperandSize) -> Self {
        let mask = if size.bits() == 64 {
            u64::MAX
        } else {
            (1u64 << size.bits()) - 1
        };
        Self::constant(absolute_value.wrapping_neg() & mask, size)
    }

    pub const fn zero(size: OperandSize) -> Self {
        Self::constant(0, size)
    }

    pub const fn tmp(offset: u64, size: OperandSize) -> Self {
        Self {
            addr: OperandAddr {
                space: OperandSpace::Tmp,
                offset,
            },
            size,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OperandAddr {
    pub space: OperandSpace,
    pub offset: u64,
}
impl core::fmt::Display for OperandAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:?}[0x{:x}]", self.space, self.offset)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OperandSize {
    /// 1 byte
    B1 = 1,
    /// 2 byte
    B2 = 2,
    /// 4 bytes
    B4 = 4,
    /// 8 bytes
    B8 = 8,
}
impl OperandSize {
    pub const fn bytes(&self) -> usize {
        *self as usize
    }
    pub const fn bits(&self) -> usize {
        self.bytes() * 8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    Move,
    Add,
    Store,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Insn {
    pub opcode: Opcode,
    pub operands: [Operand; 2],
}
impl core::fmt::Display for Insn {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:?} {}, {}",
            self.opcode, self.operands[0], self.operands[1]
        )
    }
}
impl Insn {
    pub fn new(opcode: Opcode, first_operand: Operand, second_operand: Operand) -> Self {
        Self {
            opcode,
            operands: [first_operand, second_operand],
        }
    }
}

pub type TranslationInsns = ArrayVec<Insn, TRANSLATION_MAX_INSNS>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Translation {
    pub insns: TranslationInsns,
}
impl core::fmt::Display for Translation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for insn in &self.insns {
            writeln!(f, "{}", insn)?;
        }
        Ok(())
    }
}
impl Translation {
    pub fn new() -> Self {
        Self {
            insns: TranslationInsns::new(),
        }
    }
}

pub trait ArchCtx {
    fn translate(&self, code: &[u8]) -> Translation;
}
