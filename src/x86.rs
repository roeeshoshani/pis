use crate::{Insn, Opcode, Operand, OperandAddr, OperandSize, OperandSpace, Translation};
use bitpiece::{bitpiece, BitPiece, BitStorage};
use paste::paste;

macro_rules! define_reg_operand {
    {$name: ident, $offset: expr, $size: ident} => {
        pub const $name: Operand = Operand {
            addr: OperandAddr {
                space: OperandSpace::Regs,
                offset: $offset,
            },
            size: OperandSize::$size,
        };

    };
}

macro_rules! define_reg_operands_single {
    {$size: literal, $prev_name: ident, $name: ident} => {
        paste! {
            define_reg_operand! {$name, $prev_name.addr.offset + $size, [<B $size>]}
        }
    };
}

macro_rules! define_reg_operands_inner {
    // the case for the last operand
    {$size: literal, $prev_name: ident, $name: ident} => {
        define_reg_operands_single!{$size, $prev_name, $name}
    };

    // the common case of the non-last operand
    {$size: literal, $prev_name: ident, $name: ident, $($names: ident),+} => {
        // define the current operand
        define_reg_operands_inner! {$size, $prev_name, $name}

        // define the rest of the operands
        define_reg_operands_inner! {$size, $name, $($names),+}
    };
}

macro_rules! define_reg_operands {
    {$size: literal, $first_name: ident, $($name: ident),+} => {
        // define the first operand with offset 0
        paste! {
            define_reg_operand! {$first_name, 0, [<B $size>]}
        }

        // define the rest of the operands following it
        define_reg_operands_inner! {$size, $first_name, $($name),+}
    };
}

define_reg_operands! {8, RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI}

#[bitpiece(3)]
#[derive(Debug, Clone, Copy)]
pub enum Reg {
    Rax = 0,
    Rcx = 1,
    Rdx = 2,
    Rbx = 3,
    RspAh = 4,
    RbpCh = 5,
    RsiDh = 6,
    RdiBh = 7,
}
impl Reg {
    pub const MAX_VALUE: Reg = Reg::RdiBh;
    pub fn operand(&self, size: OperandSize) -> Operand {
        Operand {
            addr: OperandAddr {
                space: OperandSpace::Regs,
                offset: *self as u64 * 8,
            },
            size,
        }
    }
}

fn translate_push_reg(reg: Reg) -> Translation {
    let mut translation = Translation::new();
    translation.insns.push(Insn::new(
        Opcode::Add,
        RSP,
        Operand::negative_constant(8, OperandSize::B8),
    ));
    translation
        .insns
        .push(Insn::new(Opcode::Store, RSP, reg.operand(OperandSize::B8)));
    translation
}

pub fn translate(code: &[u8]) -> Translation {
    if code.len() == 1 && code[0] >= 0x50 && code[0] <= 0x50 + Reg::MAX_VALUE as u8 {
        // push reg instruction
        return translate_push_reg(Reg::from_bits(code[0] - 0x50));
    }
    todo!()
}
