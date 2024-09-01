pub struct OperandSpaceId(pub i32);

pub enum OperandSpace {
    Ram,
    Const,
    Custom(OperandSpaceId),
}

pub struct Operand {
    pub addr: OperandAddr,
    pub size: OperandSize,
}

pub struct OperandAddr {
    pub space: OperandSpace,
    pub offset: u64,
}

pub enum OperandSize {
    /// 1 byte
    B1,
    /// 2 byte
    B2,
    /// 4 bytes
    B4,
    /// 8 bytes
    B8,
}

pub enum Opcode {
    Move,
    Add,
}

pub struct Insn {
    pub opcode: Opcode,
    pub operands: [Operand; 2],
}
