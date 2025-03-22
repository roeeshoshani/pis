use arrayvec::ArrayVec;
use const_for::const_for;
use delve::{EnumDisplay, EnumToStr, EnumVariantNames};

use crate::{ImmExtKind, PisSize};

use super::{ctx::Ctx, prefixes::LegacyPrefix, X86Cpumode};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Mnemonic {
    Unsupported,
    Add,
    Or,
    Adc,
    Sbb,
    And,
    Sub,
    Xor,
    Cmp,
    Rol,
    Ror,
    Rcl,
    Rcr,
    Shl,
    Shr,
    Sar,
    Inc,
    Dec,
    Push,
    Pop,
    Movsxd,
    Imul,
    Mul,
    Jcc,
    Test,
    Xchg,
    Mov,
    Lea,
    Nop,
    Movsx,
    Cwd,
    Movs,
    Cmps,
    Stos,
    Lods,
    Ret,
    Call,
    Jmp,
    Scas,
    Hlt,
    Cmc,
    Not,
    Neg,
    Div,
    Idiv,
    Clc,
    Stc,
    Cli,
    Sti,
    Cld,
    Std,
}
const SIMPLE_BINOP_MNEMONICS: [Mnemonic; 8] = [
    Mnemonic::Add,
    Mnemonic::Or,
    Mnemonic::Adc,
    Mnemonic::Sbb,
    Mnemonic::And,
    Mnemonic::Sub,
    Mnemonic::Xor,
    Mnemonic::Cmp,
];

const SHIFT_BINOP_MNEMONICS: [Mnemonic; 8] = [
    Mnemonic::Rol,
    Mnemonic::Ror,
    Mnemonic::Rcl,
    Mnemonic::Rcr,
    Mnemonic::Shl,
    Mnemonic::Shr,
    Mnemonic::Unsupported,
    Mnemonic::Sar,
];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpSizeInfo {
    pub with_operand_size_override: PisSize,
    pub mode_32: PisSize,
    pub mode_64: PisSize,
    pub mode_64_with_rex_w: PisSize,
}
impl OpSizeInfo {
    /// operand size is always 8 bits
    pub const SZ_ALWAYS_8: Self = Self {
        with_operand_size_override: PisSize::B1,
        mode_32: PisSize::B1,
        mode_64: PisSize::B1,
        mode_64_with_rex_w: PisSize::B1,
    };

    /// operand size is always 16 bits
    pub const SZ_ALWAYS_16: Self = Self {
        with_operand_size_override: PisSize::B2,
        mode_32: PisSize::B2,
        mode_64: PisSize::B2,
        mode_64_with_rex_w: PisSize::B2,
    };

    /// the default operand size for instructions that default to 32-bit operands.
    pub const SZ_16_32_64_DEF_32: Self = Self {
        with_operand_size_override: PisSize::B2,
        mode_32: PisSize::B4,
        mode_64: PisSize::B4,
        mode_64_with_rex_w: PisSize::B8,
    };

    /// the default operand size for instructions that default to 64-bit operands.
    pub const SZ_16_32_64_DEF_64: Self = Self {
        with_operand_size_override: PisSize::B2,
        mode_32: PisSize::B4,
        mode_64: PisSize::B8,
        mode_64_with_rex_w: PisSize::B8,
    };

    /// a common size info for immediate encodings that are either 16 or 32 bits.
    pub const SZ_IMM_ENCODING_16_32: Self = Self {
        with_operand_size_override: PisSize::B2,
        mode_32: PisSize::B4,
        mode_64: PisSize::B4,
        mode_64_with_rex_w: PisSize::B4,
    };

    pub fn resolve(&self, ctx: &Ctx) -> PisSize {
        if ctx.prefixes.has_rex_w() {
            self.mode_64_with_rex_w
        } else if ctx
            .prefixes
            .legacy
            .contains(LegacyPrefix::OperandSizeOverride)
        {
            self.with_operand_size_override
        } else {
            match ctx.cpumode {
                X86Cpumode::B32 => self.mode_32,
                X86Cpumode::B64 => self.mode_64,
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImmOpInfo {
    pub encoded_size: OpSizeInfo,
    pub extended_size: OpSizeInfo,
    pub extend_kind: ImmExtKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpecificImmOpInfo {
    pub value: u64,
    pub operand_size: OpSizeInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MemOffsetOpInfo {
    pub mem_operand_size: OpSizeInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EnumVariantNames, EnumToStr)]
pub enum RegEncoding {
    Modrm,
    Opcode,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RegOpInfo {
    pub encoding: RegEncoding,
    pub size: OpSizeInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EnumVariantNames, EnumToStr)]
pub enum SpecificReg {
    Rax,
    Rcx,
    Rdx,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpecificRegOpInfo {
    pub reg: SpecificReg,
    pub size: OpSizeInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ZextSpecificRegOpInfo {
    pub reg: SpecificReg,
    pub size: OpSizeInfo,
    pub extended_size: OpSizeInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RelOpInfo {
    pub size: OpSizeInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EnumDisplay, EnumVariantNames, EnumToStr)]
pub enum OpInfo {
    /// immediate operand
    Imm(ImmOpInfo),

    /// specific immediate which is enforced by the opcode
    SpecificImm(SpecificImmOpInfo),

    /// register operand
    Reg(RegOpInfo),

    /// rm operand
    Rm(OpSizeInfo),

    /// specific register which is enforced by the opcode
    SpecificReg(SpecificRegOpInfo),

    /// zero extended specific register which is enforced by the opcode
    ZextSpecificReg(ZextSpecificRegOpInfo),

    /// relative offset used for relative jumps
    Rel(OpSizeInfo),

    /// memory access by absolute address, for example `mov rcx, [0x1234]`
    MemOffset(MemOffsetOpInfo),

    /// an implicit operand which is not actually specified in the instruction, only its size it relevant.
    Implicit(OpSizeInfo),

    Cond,
}
impl OpInfo {
    pub const RM_8: Self = Self::Rm(OpSizeInfo::SZ_ALWAYS_8);
    pub const RM_16_32_64_DEF_32: Self = Self::Rm(OpSizeInfo::SZ_16_32_64_DEF_32);
    pub const RM_16_32_64_DEF_64: Self = Self::Rm(OpSizeInfo::SZ_16_32_64_DEF_64);
    pub const R_MODRM_8: Self = Self::Reg(RegOpInfo {
        encoding: RegEncoding::Modrm,
        size: OpSizeInfo::SZ_ALWAYS_8,
    });
    pub const R_MODRM_16_32_64_DEF_32: Self = Self::Reg(RegOpInfo {
        encoding: RegEncoding::Modrm,
        size: OpSizeInfo::SZ_16_32_64_DEF_32,
    });
    pub const R_OPCODE_8: Self = Self::Reg(RegOpInfo {
        encoding: RegEncoding::Opcode,
        size: OpSizeInfo::SZ_ALWAYS_8,
    });
    pub const R_OPCODE_16_32_64_DEF_32: Self = Self::Reg(RegOpInfo {
        encoding: RegEncoding::Opcode,
        size: OpSizeInfo::SZ_16_32_64_DEF_32,
    });
    pub const R_OPCODE_16_32_64_DEF_64: Self = Self::Reg(RegOpInfo {
        encoding: RegEncoding::Opcode,
        size: OpSizeInfo::SZ_16_32_64_DEF_64,
    });
    pub const AL: Self = Self::SpecificReg(SpecificRegOpInfo {
        size: OpSizeInfo::SZ_ALWAYS_8,
        reg: SpecificReg::Rax,
    });
    pub const AX_16_32_64_DEF_32: Self = Self::SpecificReg(SpecificRegOpInfo {
        size: OpSizeInfo::SZ_16_32_64_DEF_32,
        reg: SpecificReg::Rax,
    });
    pub const DX_16_32_64_DEF_32: Self = Self::SpecificReg(SpecificRegOpInfo {
        size: OpSizeInfo::SZ_16_32_64_DEF_32,
        reg: SpecificReg::Rdx,
    });
    pub const CL: Self = Self::SpecificReg(SpecificRegOpInfo {
        size: OpSizeInfo::SZ_ALWAYS_8,
        reg: SpecificReg::Rcx,
    });

    /// an 8-bit immediate which should not be sign/zero extended.
    pub const IMM_8_NO_EXT: Self = Self::Imm(ImmOpInfo {
        encoded_size: OpSizeInfo::SZ_ALWAYS_8,
        extended_size: OpSizeInfo::SZ_ALWAYS_8,
        // doesn't matter
        extend_kind: ImmExtKind::Sign,
    });

    /// a 32 bit relative offset
    pub const REL_32: Self = Self::Rel(OpSizeInfo {
        // operand size override is not supported with relative operands, so this is ignored anyway
        with_operand_size_override: PisSize::B2,
        mode_32: PisSize::B4,
        mode_64: PisSize::B4,
        mode_64_with_rex_w: PisSize::B4,
    });
}

pub type Ops = &'static [OpInfo];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegularInsnInfo {
    pub mnemonic: Mnemonic,
    pub ops: Ops,
}
impl RegularInsnInfo {
    pub const UNSUPPORTED: Self = Self {
        mnemonic: Mnemonic::Unsupported,
        ops: &[],
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ModrmRegOpcodeExtInsnInfo {
    pub by_modrm_reg_value: [RegularInsnInfo; 8],
}
impl ModrmRegOpcodeExtInsnInfo {
    pub const fn new_with_same_operands(ops: Ops, mnemonics: [Mnemonic; 8]) -> Self {
        let mut by_reg_value = [RegularInsnInfo::UNSUPPORTED; 8];
        const_for!(i in 0..8 => {
            by_reg_value[i].mnemonic = mnemonics[i];
        });
        Self {
            by_modrm_reg_value: by_reg_value,
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum InsnInfo {
    Regular(RegularInsnInfo),
    ModrmRegOpcodeExt(ModrmRegOpcodeExtInsnInfo),
}

pub type OpcodeByteTable = [InsnInfo; 256];

struct OpcodeByteTableBuilder {
    table: OpcodeByteTable,
    cur_index: usize,
}
impl OpcodeByteTableBuilder {
    const fn new() -> Self {
        Self {
            table: [const { InsnInfo::Regular(RegularInsnInfo::UNSUPPORTED) }; 256],
            cur_index: 0,
        }
    }
    const fn push(&mut self, entry: InsnInfo) {
        self.table[self.cur_index] = entry;
        self.cur_index += 1;
    }
    const fn build(self) -> OpcodeByteTable {
        assert!(self.cur_index == 256);
        self.table
    }
}

const fn simple_binary_op(table: &mut OpcodeByteTableBuilder, mnemonic: Mnemonic) {
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic,
        ops: &[OpInfo::RM_8, OpInfo::R_MODRM_8],
    }));
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic,
        ops: &[OpInfo::RM_16_32_64_DEF_32, OpInfo::R_MODRM_16_32_64_DEF_32],
    }));
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic,
        ops: &[OpInfo::R_MODRM_8, OpInfo::RM_8],
    }));
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic,
        ops: &[OpInfo::R_MODRM_16_32_64_DEF_32, OpInfo::RM_16_32_64_DEF_32],
    }));
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic,
        ops: &[OpInfo::AL, OpInfo::IMM_8_NO_EXT],
    }));
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic,
        ops: &[
            OpInfo::AX_16_32_64_DEF_32,
            OpInfo::Imm(ImmOpInfo {
                encoded_size: OpSizeInfo::SZ_IMM_ENCODING_16_32,
                extended_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                extend_kind: ImmExtKind::Sign,
            }),
        ],
    }));
}

const fn repeat(table: &mut OpcodeByteTableBuilder, amount: usize, entry: InsnInfo) {
    const_for!(i in 0..amount => {
        table.push(entry);
    });
    // table.extend(std::iter::repeat_n(entry, amount))
}

const fn unsupported(table: &mut OpcodeByteTableBuilder, amount: usize) {
    repeat(
        table,
        amount,
        InsnInfo::Regular(RegularInsnInfo::UNSUPPORTED),
    )
}
const fn gen_first_opcode_byte_table() -> OpcodeByteTable {
    let mut table = OpcodeByteTableBuilder::new();

    // 0x00 - 0x05
    assert!(table.cur_index == 0x00);
    simple_binary_op(&mut table, Mnemonic::Add);
    // 0x06 - 0x07
    assert!(table.cur_index == 0x06);
    unsupported(&mut table, 2);
    // 0x08 - 0x0d
    assert!(table.cur_index == 0x08);
    simple_binary_op(&mut table, Mnemonic::Or);
    // 0x0e - 0x0f
    assert!(table.cur_index == 0x0e);
    unsupported(&mut table, 2);
    // 0x10 - 0x15
    assert!(table.cur_index == 0x10);
    simple_binary_op(&mut table, Mnemonic::Adc);
    // 0x16 - 0x17
    assert!(table.cur_index == 0x16);
    unsupported(&mut table, 2);
    // 0x18 - 0x1d
    assert!(table.cur_index == 0x18);
    simple_binary_op(&mut table, Mnemonic::Sbb);
    // 0x1e - 0x1f
    assert!(table.cur_index == 0x1e);
    unsupported(&mut table, 2);
    // 0x20 - 0x25
    assert!(table.cur_index == 0x20);
    simple_binary_op(&mut table, Mnemonic::And);
    // 0x26 - 0x27
    assert!(table.cur_index == 0x26);
    unsupported(&mut table, 2);
    // 0x28 - 0x2d
    assert!(table.cur_index == 0x28);
    simple_binary_op(&mut table, Mnemonic::Sub);
    // 0x2e - 0x2f
    assert!(table.cur_index == 0x2e);
    unsupported(&mut table, 2);
    // 0x30 - 0x35
    assert!(table.cur_index == 0x30);
    simple_binary_op(&mut table, Mnemonic::Xor);
    // 0x36 - 0x37
    assert!(table.cur_index == 0x36);
    unsupported(&mut table, 2);
    // 0x38 - 0x3d
    assert!(table.cur_index == 0x38);
    simple_binary_op(&mut table, Mnemonic::Cmp);
    // 0x3e - 0x3f
    assert!(table.cur_index == 0x3e);
    unsupported(&mut table, 2);
    // 0x40 - 0x47
    assert!(table.cur_index == 0x40);
    repeat(
        &mut table,
        8,
        InsnInfo::Regular(RegularInsnInfo {
            mnemonic: Mnemonic::Inc,
            ops: &[OpInfo::R_OPCODE_16_32_64_DEF_32],
        }),
    );
    // 0x48 - 0x4f
    assert!(table.cur_index == 0x48);
    repeat(
        &mut table,
        8,
        InsnInfo::Regular(RegularInsnInfo {
            mnemonic: Mnemonic::Dec,
            ops: &[OpInfo::R_OPCODE_16_32_64_DEF_32],
        }),
    );
    // 0x50 - 0x57
    assert!(table.cur_index == 0x50);
    repeat(
        &mut table,
        8,
        InsnInfo::Regular(RegularInsnInfo {
            mnemonic: Mnemonic::Push,
            ops: &[OpInfo::R_OPCODE_16_32_64_DEF_64],
        }),
    );
    // 0x58 - 0x5f
    assert!(table.cur_index == 0x58);
    repeat(
        &mut table,
        8,
        InsnInfo::Regular(RegularInsnInfo {
            mnemonic: Mnemonic::Pop,
            ops: &[OpInfo::R_OPCODE_16_32_64_DEF_64],
        }),
    );
    // 0x60 - 0x62
    assert!(table.cur_index == 0x60);
    unsupported(&mut table, 3);
    // 0x63
    assert!(table.cur_index == 0x63);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Movsxd,
        ops: &[
            OpInfo::R_MODRM_16_32_64_DEF_32,
            OpInfo::Rm(OpSizeInfo {
                with_operand_size_override: PisSize::B2,
                mode_32: PisSize::B4,
                mode_64: PisSize::B4,
                mode_64_with_rex_w: PisSize::B4,
            }),
        ],
    }));
    // 0x64 - 0x67
    assert!(table.cur_index == 0x64);
    unsupported(&mut table, 4);
    // 0x68
    assert!(table.cur_index == 0x68);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Push,
        ops: &[OpInfo::Imm(ImmOpInfo {
            encoded_size: OpSizeInfo::SZ_IMM_ENCODING_16_32,
            extended_size: OpSizeInfo::SZ_16_32_64_DEF_64,
            extend_kind: ImmExtKind::Sign,
        })],
    }));
    // 0x69
    assert!(table.cur_index == 0x69);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Imul,
        ops: &[
            OpInfo::R_MODRM_16_32_64_DEF_32,
            OpInfo::RM_16_32_64_DEF_32,
            OpInfo::Imm(ImmOpInfo {
                encoded_size: OpSizeInfo::SZ_IMM_ENCODING_16_32,
                extended_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                extend_kind: ImmExtKind::Sign,
            }),
        ],
    }));
    // 0x6a
    assert!(table.cur_index == 0x6a);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Push,
        ops: &[OpInfo::Imm(ImmOpInfo {
            encoded_size: OpSizeInfo::SZ_ALWAYS_8,
            extended_size: OpSizeInfo::SZ_16_32_64_DEF_64,
            extend_kind: ImmExtKind::Sign,
        })],
    }));
    // 0x6b
    assert!(table.cur_index == 0x6b);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Imul,
        ops: &[
            OpInfo::R_MODRM_16_32_64_DEF_32,
            OpInfo::RM_16_32_64_DEF_32,
            OpInfo::Imm(ImmOpInfo {
                encoded_size: OpSizeInfo::SZ_ALWAYS_8,
                extended_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                extend_kind: ImmExtKind::Sign,
            }),
        ],
    }));
    // 0x6c - 0x6f
    assert!(table.cur_index == 0x6c);
    unsupported(&mut table, 4);
    // 0x70 - 0x7f
    assert!(table.cur_index == 0x70);
    repeat(
        &mut table,
        16,
        InsnInfo::Regular(RegularInsnInfo {
            mnemonic: Mnemonic::Jcc,
            ops: &[OpInfo::Cond, OpInfo::Rel(OpSizeInfo::SZ_ALWAYS_8)],
        }),
    );
    // 0x80
    assert!(table.cur_index == 0x80);
    table.push(InsnInfo::ModrmRegOpcodeExt(
        ModrmRegOpcodeExtInsnInfo::new_with_same_operands(
            &[OpInfo::RM_8, OpInfo::IMM_8_NO_EXT],
            SIMPLE_BINOP_MNEMONICS,
        ),
    ));
    // 0x81
    assert!(table.cur_index == 0x81);
    table.push(InsnInfo::ModrmRegOpcodeExt(
        ModrmRegOpcodeExtInsnInfo::new_with_same_operands(
            &[
                OpInfo::RM_16_32_64_DEF_32,
                OpInfo::Imm(ImmOpInfo {
                    encoded_size: OpSizeInfo::SZ_IMM_ENCODING_16_32,
                    extended_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                    extend_kind: ImmExtKind::Sign,
                }),
            ],
            SIMPLE_BINOP_MNEMONICS,
        ),
    ));
    // 0x82
    assert!(table.cur_index == 0x82);
    unsupported(&mut table, 1);
    // 0x83
    assert!(table.cur_index == 0x83);
    table.push(InsnInfo::ModrmRegOpcodeExt(
        ModrmRegOpcodeExtInsnInfo::new_with_same_operands(
            &[
                OpInfo::RM_16_32_64_DEF_32,
                OpInfo::Imm(ImmOpInfo {
                    encoded_size: OpSizeInfo::SZ_ALWAYS_8,
                    extended_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                    extend_kind: ImmExtKind::Sign,
                }),
            ],
            SIMPLE_BINOP_MNEMONICS,
        ),
    ));
    // 0x84
    assert!(table.cur_index == 0x84);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Test,
        ops: &[OpInfo::RM_8, OpInfo::R_MODRM_8],
    }));
    // 0x85
    assert!(table.cur_index == 0x85);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Test,
        ops: &[OpInfo::RM_16_32_64_DEF_32, OpInfo::R_MODRM_16_32_64_DEF_32],
    }));
    // 0x86
    assert!(table.cur_index == 0x86);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Xchg,
        ops: &[OpInfo::RM_8, OpInfo::R_MODRM_8],
    }));
    // 0x87
    assert!(table.cur_index == 0x87);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Xchg,
        ops: &[OpInfo::RM_16_32_64_DEF_32, OpInfo::R_MODRM_16_32_64_DEF_32],
    }));
    // 0x88
    assert!(table.cur_index == 0x88);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Mov,
        ops: &[OpInfo::RM_8, OpInfo::R_MODRM_8],
    }));
    // 0x89
    assert!(table.cur_index == 0x89);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Mov,
        ops: &[OpInfo::RM_16_32_64_DEF_32, OpInfo::R_MODRM_16_32_64_DEF_32],
    }));
    // 0x8a
    assert!(table.cur_index == 0x8a);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Mov,
        ops: &[OpInfo::R_MODRM_8, OpInfo::RM_8],
    }));
    // 0x8b
    assert!(table.cur_index == 0x8b);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Mov,
        ops: &[OpInfo::R_MODRM_16_32_64_DEF_32, OpInfo::RM_16_32_64_DEF_32],
    }));
    // 0x8c
    assert!(table.cur_index == 0x8c);
    unsupported(&mut table, 1);
    // 0x8d
    assert!(table.cur_index == 0x8d);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Lea,
        ops: &[OpInfo::R_MODRM_16_32_64_DEF_32, OpInfo::RM_16_32_64_DEF_32],
    }));
    // 0x8e
    assert!(table.cur_index == 0x8e);
    unsupported(&mut table, 1);
    // 0x8f
    assert!(table.cur_index == 0x8f);
    table.push(InsnInfo::ModrmRegOpcodeExt(ModrmRegOpcodeExtInsnInfo {
        by_modrm_reg_value: [
            RegularInsnInfo {
                mnemonic: Mnemonic::Pop,
                ops: &[OpInfo::RM_16_32_64_DEF_64],
            },
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
        ],
    }));
    // 0x90
    assert!(table.cur_index == 0x90);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Nop,
        ops: &[],
    }));
    // 0x91 - 0x97
    assert!(table.cur_index == 0x91);
    repeat(
        &mut table,
        7,
        InsnInfo::Regular(RegularInsnInfo {
            mnemonic: Mnemonic::Xchg,
            ops: &[OpInfo::AX_16_32_64_DEF_32, OpInfo::R_OPCODE_16_32_64_DEF_32],
        }),
    );
    // 0x98
    assert!(table.cur_index == 0x98);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Movsx, // this is actually cbw, but this makes life simpler when lifting it
        ops: &[
            OpInfo::AX_16_32_64_DEF_32,
            OpInfo::SpecificReg(SpecificRegOpInfo {
                reg: SpecificReg::Rax,
                size: OpSizeInfo {
                    with_operand_size_override: PisSize::B1,
                    mode_32: PisSize::B2,
                    mode_64: PisSize::B2,
                    mode_64_with_rex_w: PisSize::B4,
                },
            }),
        ],
    }));
    // 0x99
    assert!(table.cur_index == 0x99);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Cwd, // this is cwd/cdq/cqo
        ops: &[OpInfo::DX_16_32_64_DEF_32, OpInfo::AX_16_32_64_DEF_32],
    }));
    // 0x9a - 0x9f
    assert!(table.cur_index == 0x9a);
    unsupported(&mut table, 6);
    // 0xa0
    assert!(table.cur_index == 0xa0);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Mov,
        ops: &[
            OpInfo::AL,
            OpInfo::MemOffset(MemOffsetOpInfo {
                mem_operand_size: OpSizeInfo::SZ_ALWAYS_8,
            }),
        ],
    }));
    // 0xa1
    assert!(table.cur_index == 0xa1);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Mov,
        ops: &[
            OpInfo::AX_16_32_64_DEF_32,
            OpInfo::MemOffset(MemOffsetOpInfo {
                mem_operand_size: OpSizeInfo::SZ_16_32_64_DEF_32,
            }),
        ],
    }));
    // 0xa2
    assert!(table.cur_index == 0xa2);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Mov,
        ops: &[
            OpInfo::MemOffset(MemOffsetOpInfo {
                mem_operand_size: OpSizeInfo::SZ_ALWAYS_8,
            }),
            OpInfo::AL,
        ],
    }));
    // 0xa3
    assert!(table.cur_index == 0xa3);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Mov,
        ops: &[
            OpInfo::MemOffset(MemOffsetOpInfo {
                mem_operand_size: OpSizeInfo::SZ_16_32_64_DEF_32,
            }),
            OpInfo::AX_16_32_64_DEF_32,
        ],
    }));
    // 0xa4
    assert!(table.cur_index == 0xa4);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Movs,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_ALWAYS_8)],
    }));
    // 0xa5
    assert!(table.cur_index == 0xa5);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Movs,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_16_32_64_DEF_32)],
    }));
    // 0xa6
    assert!(table.cur_index == 0xa6);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Cmps,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_ALWAYS_8)],
    }));
    // 0xa7
    assert!(table.cur_index == 0xa7);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Cmps,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_16_32_64_DEF_32)],
    }));
    // 0xa8
    assert!(table.cur_index == 0xa8);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Test,
        ops: &[OpInfo::AL, OpInfo::IMM_8_NO_EXT],
    }));
    // 0xa9
    assert!(table.cur_index == 0xa9);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Test,
        ops: &[
            OpInfo::AX_16_32_64_DEF_32,
            OpInfo::Imm(ImmOpInfo {
                encoded_size: OpSizeInfo::SZ_IMM_ENCODING_16_32,
                extended_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                extend_kind: ImmExtKind::Sign,
            }),
        ],
    }));
    // 0xaa
    assert!(table.cur_index == 0xaa);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Stos,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_ALWAYS_8)],
    }));
    // 0xab
    assert!(table.cur_index == 0xab);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Stos,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_16_32_64_DEF_32)],
    }));
    // 0xac
    assert!(table.cur_index == 0xac);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Lods,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_ALWAYS_8)],
    }));
    // 0xad
    assert!(table.cur_index == 0xad);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Lods,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_16_32_64_DEF_32)],
    }));
    // 0xae
    assert!(table.cur_index == 0xae);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Scas,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_ALWAYS_8)],
    }));
    // 0xaf
    assert!(table.cur_index == 0xaf);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Scas,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_16_32_64_DEF_32)],
    }));
    // 0xb0 - 0xb7
    assert!(table.cur_index == 0xb0);
    repeat(
        &mut table,
        8,
        InsnInfo::Regular(RegularInsnInfo {
            mnemonic: Mnemonic::Mov,
            ops: &[OpInfo::R_OPCODE_8, OpInfo::IMM_8_NO_EXT],
        }),
    );
    // 0xb8 - 0xbf
    assert!(table.cur_index == 0xb8);
    repeat(
        &mut table,
        8,
        InsnInfo::Regular(RegularInsnInfo {
            mnemonic: Mnemonic::Mov,
            ops: &[
                OpInfo::R_OPCODE_16_32_64_DEF_32,
                OpInfo::Imm(ImmOpInfo {
                    encoded_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                    extended_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                    extend_kind: ImmExtKind::Zero,
                }),
            ],
        }),
    );
    // 0xc0
    assert!(table.cur_index == 0xc0);
    table.push(InsnInfo::ModrmRegOpcodeExt(
        ModrmRegOpcodeExtInsnInfo::new_with_same_operands(
            &[OpInfo::RM_8, OpInfo::IMM_8_NO_EXT],
            SHIFT_BINOP_MNEMONICS,
        ),
    ));
    // 0xc1
    assert!(table.cur_index == 0xc1);
    table.push(InsnInfo::ModrmRegOpcodeExt(
        ModrmRegOpcodeExtInsnInfo::new_with_same_operands(
            &[
                OpInfo::RM_16_32_64_DEF_32,
                OpInfo::Imm(ImmOpInfo {
                    encoded_size: OpSizeInfo::SZ_ALWAYS_8,
                    extended_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                    extend_kind: ImmExtKind::Zero,
                }),
            ],
            SHIFT_BINOP_MNEMONICS,
        ),
    ));
    // 0xc2
    assert!(table.cur_index == 0xc2);
    unsupported(&mut table, 1);
    // 0xc3
    assert!(table.cur_index == 0xc3);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Ret,
        ops: &[],
    }));
    // 0xc4 - 0xc5
    assert!(table.cur_index == 0xc4);
    unsupported(&mut table, 2);
    // 0xc6
    assert!(table.cur_index == 0xc6);
    table.push(InsnInfo::ModrmRegOpcodeExt(ModrmRegOpcodeExtInsnInfo {
        by_modrm_reg_value: [
            RegularInsnInfo {
                mnemonic: Mnemonic::Mov,
                ops: &[OpInfo::RM_8, OpInfo::IMM_8_NO_EXT],
            },
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
        ],
    }));
    // 0xc7
    assert!(table.cur_index == 0xc7);
    table.push(InsnInfo::ModrmRegOpcodeExt(ModrmRegOpcodeExtInsnInfo {
        by_modrm_reg_value: [
            RegularInsnInfo {
                mnemonic: Mnemonic::Mov,
                ops: &[
                    OpInfo::RM_16_32_64_DEF_32,
                    OpInfo::Imm(ImmOpInfo {
                        encoded_size: OpSizeInfo::SZ_IMM_ENCODING_16_32,
                        extended_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                        extend_kind: ImmExtKind::Sign,
                    }),
                ],
            },
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
        ],
    }));
    // 0xc8 - 0xcf
    assert!(table.cur_index == 0xc8);
    unsupported(&mut table, 8);
    // 0xd0
    assert!(table.cur_index == 0xd0);
    table.push(InsnInfo::ModrmRegOpcodeExt(
        ModrmRegOpcodeExtInsnInfo::new_with_same_operands(
            &[
                OpInfo::RM_8,
                OpInfo::SpecificImm(SpecificImmOpInfo {
                    value: 1,
                    operand_size: OpSizeInfo::SZ_ALWAYS_8,
                }),
            ],
            SHIFT_BINOP_MNEMONICS,
        ),
    ));
    // 0xd1
    assert!(table.cur_index == 0xd1);
    table.push(InsnInfo::ModrmRegOpcodeExt(
        ModrmRegOpcodeExtInsnInfo::new_with_same_operands(
            &[
                OpInfo::RM_16_32_64_DEF_32,
                OpInfo::SpecificImm(SpecificImmOpInfo {
                    value: 1,
                    operand_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                }),
            ],
            SHIFT_BINOP_MNEMONICS,
        ),
    ));
    // 0xd2
    assert!(table.cur_index == 0xd2);
    table.push(InsnInfo::ModrmRegOpcodeExt(
        ModrmRegOpcodeExtInsnInfo::new_with_same_operands(
            &[OpInfo::RM_8, OpInfo::CL],
            SHIFT_BINOP_MNEMONICS,
        ),
    ));
    // 0xd3
    assert!(table.cur_index == 0xd3);
    table.push(InsnInfo::ModrmRegOpcodeExt(
        ModrmRegOpcodeExtInsnInfo::new_with_same_operands(
            &[
                OpInfo::RM_16_32_64_DEF_32,
                OpInfo::ZextSpecificReg(ZextSpecificRegOpInfo {
                    reg: SpecificReg::Rcx,
                    size: OpSizeInfo::SZ_ALWAYS_8,
                    extended_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                }),
            ],
            SHIFT_BINOP_MNEMONICS,
        ),
    ));
    // 0xd4 - 0xe7
    assert!(table.cur_index == 0xd4);
    unsupported(&mut table, 0x14);
    // 0xe8
    assert!(table.cur_index == 0xe8);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Call,
        ops: &[OpInfo::REL_32],
    }));
    // 0xe9
    assert!(table.cur_index == 0xe9);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Jmp,
        ops: &[OpInfo::REL_32],
    }));
    // 0xea
    assert!(table.cur_index == 0xea);
    unsupported(&mut table, 1);
    // 0xeb
    assert!(table.cur_index == 0xeb);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Jmp,
        ops: &[OpInfo::Rel(OpSizeInfo::SZ_ALWAYS_8)],
    }));
    // 0xec - 0xf3
    assert!(table.cur_index == 0xec);
    unsupported(&mut table, 8);
    // 0xf4
    assert!(table.cur_index == 0xf4);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Hlt,
        ops: &[],
    }));
    // 0xf5
    assert!(table.cur_index == 0xf5);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Cmc,
        ops: &[],
    }));
    // 0xf6
    assert!(table.cur_index == 0xf6);
    table.push(InsnInfo::ModrmRegOpcodeExt(ModrmRegOpcodeExtInsnInfo {
        by_modrm_reg_value: [
            // 0
            RegularInsnInfo {
                mnemonic: Mnemonic::Test,
                ops: &[OpInfo::RM_8, OpInfo::IMM_8_NO_EXT],
            },
            // 1
            RegularInsnInfo::UNSUPPORTED,
            // 2
            RegularInsnInfo {
                mnemonic: Mnemonic::Not,
                ops: &[OpInfo::RM_8],
            },
            // 3
            RegularInsnInfo {
                mnemonic: Mnemonic::Neg,
                ops: &[OpInfo::RM_8],
            },
            // 4
            RegularInsnInfo {
                mnemonic: Mnemonic::Mul,
                ops: &[OpInfo::RM_8],
            },
            // 5
            RegularInsnInfo {
                mnemonic: Mnemonic::Imul,
                ops: &[OpInfo::RM_8],
            },
            // 6
            RegularInsnInfo {
                mnemonic: Mnemonic::Div,
                ops: &[OpInfo::RM_8],
            },
            // 7
            RegularInsnInfo {
                mnemonic: Mnemonic::Idiv,
                ops: &[OpInfo::RM_8],
            },
        ],
    }));
    // 0xf7
    assert!(table.cur_index == 0xf7);
    table.push(InsnInfo::ModrmRegOpcodeExt(ModrmRegOpcodeExtInsnInfo {
        by_modrm_reg_value: [
            // 0
            RegularInsnInfo {
                mnemonic: Mnemonic::Test,
                ops: &[
                    OpInfo::RM_16_32_64_DEF_32,
                    OpInfo::Imm(ImmOpInfo {
                        encoded_size: OpSizeInfo::SZ_IMM_ENCODING_16_32,
                        extended_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                        extend_kind: ImmExtKind::Sign,
                    }),
                ],
            },
            // 1
            RegularInsnInfo::UNSUPPORTED,
            // 2
            RegularInsnInfo {
                mnemonic: Mnemonic::Not,
                ops: &[OpInfo::RM_16_32_64_DEF_32],
            },
            // 3
            RegularInsnInfo {
                mnemonic: Mnemonic::Neg,
                ops: &[OpInfo::RM_16_32_64_DEF_32],
            },
            // 4
            RegularInsnInfo {
                mnemonic: Mnemonic::Mul,
                ops: &[OpInfo::RM_16_32_64_DEF_32],
            },
            // 5
            RegularInsnInfo {
                mnemonic: Mnemonic::Imul,
                ops: &[OpInfo::RM_16_32_64_DEF_32],
            },
            // 6
            RegularInsnInfo {
                mnemonic: Mnemonic::Div,
                ops: &[OpInfo::RM_16_32_64_DEF_32],
            },
            // 7
            RegularInsnInfo {
                mnemonic: Mnemonic::Idiv,
                ops: &[OpInfo::RM_16_32_64_DEF_32],
            },
        ],
    }));
    // 0xf8
    assert!(table.cur_index == 0xf8);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Clc,
        ops: &[],
    }));
    // 0xf9
    assert!(table.cur_index == 0xf9);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Stc,
        ops: &[],
    }));
    // 0xfa
    assert!(table.cur_index == 0xfa);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Cli,
        ops: &[],
    }));
    // 0xfb
    assert!(table.cur_index == 0xfb);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Sti,
        ops: &[],
    }));
    // 0xfc
    assert!(table.cur_index == 0xfc);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Cld,
        ops: &[],
    }));
    // 0xfd
    assert!(table.cur_index == 0xfd);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Std,
        ops: &[],
    }));
    // 0xfe
    assert!(table.cur_index == 0xfe);
    table.push(InsnInfo::ModrmRegOpcodeExt(ModrmRegOpcodeExtInsnInfo {
        by_modrm_reg_value: [
            // 0
            RegularInsnInfo {
                mnemonic: Mnemonic::Inc,
                ops: &[OpInfo::RM_8],
            },
            // 1
            RegularInsnInfo {
                mnemonic: Mnemonic::Dec,
                ops: &[OpInfo::RM_8],
            },
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
            RegularInsnInfo::UNSUPPORTED,
        ],
    }));
    // 0xff
    assert!(table.cur_index == 0xff);
    table.push(InsnInfo::ModrmRegOpcodeExt(ModrmRegOpcodeExtInsnInfo {
        by_modrm_reg_value: [
            // 0
            RegularInsnInfo {
                mnemonic: Mnemonic::Inc,
                ops: &[OpInfo::RM_16_32_64_DEF_32],
            },
            // 1
            RegularInsnInfo {
                mnemonic: Mnemonic::Dec,
                ops: &[OpInfo::RM_16_32_64_DEF_32],
            },
            // 2
            RegularInsnInfo {
                mnemonic: Mnemonic::Call,
                ops: &[OpInfo::Rm(OpSizeInfo {
                    // operand size override is not supported with branch instruction, so this is ignored anyway
                    with_operand_size_override: PisSize::B2,
                    mode_32: PisSize::B4,
                    mode_64: PisSize::B8,
                    mode_64_with_rex_w: PisSize::B8,
                })],
            },
            // 3
            RegularInsnInfo::UNSUPPORTED,
            // 4
            RegularInsnInfo {
                mnemonic: Mnemonic::Jmp,
                ops: &[OpInfo::Rm(OpSizeInfo {
                    // operand size override is not supported with branch instruction, so this is ignored anyway
                    with_operand_size_override: PisSize::B2,
                    mode_32: PisSize::B4,
                    mode_64: PisSize::B8,
                    mode_64_with_rex_w: PisSize::B8,
                })],
            },
            // 5
            RegularInsnInfo::UNSUPPORTED,
            // 6
            RegularInsnInfo {
                mnemonic: Mnemonic::Push,
                ops: &[OpInfo::RM_16_32_64_DEF_64],
            },
            // 7
            RegularInsnInfo::UNSUPPORTED,
        ],
    }));

    assert!(table.cur_index == 0x100);

    table.build()
}

pub const FIRST_OPCODE_BYTE_TABLE: OpcodeByteTable = gen_first_opcode_byte_table();
