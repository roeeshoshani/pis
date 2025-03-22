use arrayvec::ArrayVec;
use delve::{EnumDisplay, EnumToStr, EnumVariantNames};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumVariantNames)]
pub enum OpSize {
    S8 = 8,
    S16 = 16,
    S32 = 32,
    S64 = 64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct OpSizeInfo {
    pub with_operand_size_override: OpSize,
    pub mode_32: OpSize,
    pub mode_64: OpSize,
    pub mode_64_with_rex_w: OpSize,
}
impl OpSizeInfo {
    /// operand size is always 8 bits
    pub const SZ_ALWAYS_8: Self = Self {
        with_operand_size_override: OpSize::S8,
        mode_32: OpSize::S8,
        mode_64: OpSize::S8,
        mode_64_with_rex_w: OpSize::S8,
    };

    /// operand size is always 16 bits
    pub const SZ_ALWAYS_16: Self = Self {
        with_operand_size_override: OpSize::S16,
        mode_32: OpSize::S16,
        mode_64: OpSize::S16,
        mode_64_with_rex_w: OpSize::S16,
    };

    /// the default operand size for instructions that default to 32-bit operands.
    pub const SZ_16_32_64_DEF_32: Self = Self {
        with_operand_size_override: OpSize::S16,
        mode_32: OpSize::S32,
        mode_64: OpSize::S32,
        mode_64_with_rex_w: OpSize::S64,
    };

    /// the default operand size for instructions that default to 64-bit operands.
    pub const SZ_16_32_64_DEF_64: Self = Self {
        with_operand_size_override: OpSize::S16,
        mode_32: OpSize::S32,
        mode_64: OpSize::S64,
        mode_64_with_rex_w: OpSize::S64,
    };

    /// a common size info for immediate encodings that are either 16 or 32 bits.
    pub const SZ_IMM_ENCODING_16_32: Self = Self {
        with_operand_size_override: OpSize::S16,
        mode_32: OpSize::S32,
        mode_64: OpSize::S32,
        mode_64_with_rex_w: OpSize::S32,
    };
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EnumVariantNames, EnumToStr)]
pub enum ImmExtendKind {
    SignExtend,
    ZeroExtend,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ImmOpInfo {
    pub encoded_size: OpSizeInfo,
    pub extended_size: OpSizeInfo,
    pub extend_kind: ImmExtendKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, EnumVariantNames, EnumToStr)]
pub enum SpecificImm {
    Zero,
    One,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SpecificImmOpInfo {
    pub value: SpecificImm,
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
    Rdx,
    Rcx,
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
        extend_kind: ImmExtendKind::SignExtend,
    });

    /// a 32 bit relative offset
    pub const REL_32: Self = Self::Rel(OpSizeInfo {
        // operand size override is not supported with relative operands, so this is ignored anyway
        with_operand_size_override: OpSize::S16,
        mode_32: OpSize::S32,
        mode_64: OpSize::S32,
        mode_64_with_rex_w: OpSize::S32,
    });
}

pub type Ops = &'static [OpInfo];

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
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

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ModrmRegOpcodeExtInsnInfo {
    pub by_reg_value: [RegularInsnInfo; 8],
}
impl ModrmRegOpcodeExtInsnInfo {
    pub fn new_with_same_operands(ops: Ops, mnemonics: [Mnemonic; 8]) -> Self {
        Self {
            by_reg_value: std::array::from_fn(|i| RegularInsnInfo {
                mnemonic: mnemonics[i],
                ops,
            }),
        }
    }
}

#[derive(Debug, Clone)]
pub enum InsnInfo {
    Regular(RegularInsnInfo),
    ModrmRegOpcodeExt(ModrmRegOpcodeExtInsnInfo),
}

pub type OpcodeByteTable = ArrayVec<InsnInfo, 256>;

pub fn simple_binary_op(table: &mut OpcodeByteTable, mnemonic: Mnemonic) {
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
                extend_kind: ImmExtendKind::SignExtend,
            }),
        ],
    }));
}

pub fn repeat(table: &mut OpcodeByteTable, amount: usize, entry: InsnInfo) {
    table.extend(std::iter::repeat_n(entry, amount))
}

pub fn unsupported(table: &mut OpcodeByteTable, amount: usize) {
    repeat(
        table,
        amount,
        InsnInfo::Regular(RegularInsnInfo::UNSUPPORTED),
    )
}
pub fn gen_first_opcode_byte_table() -> OpcodeByteTable {
    let mut table = OpcodeByteTable::new();

    // 0x00 - 0x05
    assert_eq!(table.len(), 0x00);
    simple_binary_op(&mut table, Mnemonic::Add);
    // 0x06 - 0x07
    assert_eq!(table.len(), 0x06);
    unsupported(&mut table, 2);
    // 0x08 - 0x0d
    assert_eq!(table.len(), 0x08);
    simple_binary_op(&mut table, Mnemonic::Or);
    // 0x0e - 0x0f
    assert_eq!(table.len(), 0x0e);
    unsupported(&mut table, 2);
    // 0x10 - 0x15
    assert_eq!(table.len(), 0x10);
    simple_binary_op(&mut table, Mnemonic::Adc);
    // 0x16 - 0x17
    assert_eq!(table.len(), 0x16);
    unsupported(&mut table, 2);
    // 0x18 - 0x1d
    assert_eq!(table.len(), 0x18);
    simple_binary_op(&mut table, Mnemonic::Sbb);
    // 0x1e - 0x1f
    assert_eq!(table.len(), 0x1e);
    unsupported(&mut table, 2);
    // 0x20 - 0x25
    assert_eq!(table.len(), 0x20);
    simple_binary_op(&mut table, Mnemonic::And);
    // 0x26 - 0x27
    assert_eq!(table.len(), 0x26);
    unsupported(&mut table, 2);
    // 0x28 - 0x2d
    assert_eq!(table.len(), 0x28);
    simple_binary_op(&mut table, Mnemonic::Sub);
    // 0x2e - 0x2f
    assert_eq!(table.len(), 0x2e);
    unsupported(&mut table, 2);
    // 0x30 - 0x35
    assert_eq!(table.len(), 0x30);
    simple_binary_op(&mut table, Mnemonic::Xor);
    // 0x36 - 0x37
    assert_eq!(table.len(), 0x36);
    unsupported(&mut table, 2);
    // 0x38 - 0x3d
    assert_eq!(table.len(), 0x38);
    simple_binary_op(&mut table, Mnemonic::Cmp);
    // 0x3e - 0x3f
    assert_eq!(table.len(), 0x3e);
    unsupported(&mut table, 2);
    // 0x40 - 0x47
    assert_eq!(table.len(), 0x40);
    repeat(
        &mut table,
        8,
        InsnInfo::Regular(RegularInsnInfo {
            mnemonic: Mnemonic::Inc,
            ops: &[OpInfo::R_OPCODE_16_32_64_DEF_32],
        }),
    );
    // 0x48 - 0x4f
    assert_eq!(table.len(), 0x48);
    repeat(
        &mut table,
        8,
        InsnInfo::Regular(RegularInsnInfo {
            mnemonic: Mnemonic::Dec,
            ops: &[OpInfo::R_OPCODE_16_32_64_DEF_32],
        }),
    );
    // 0x50 - 0x57
    assert_eq!(table.len(), 0x50);
    repeat(
        &mut table,
        8,
        InsnInfo::Regular(RegularInsnInfo {
            mnemonic: Mnemonic::Push,
            ops: &[OpInfo::R_OPCODE_16_32_64_DEF_64],
        }),
    );
    // 0x58 - 0x5f
    assert_eq!(table.len(), 0x58);
    repeat(
        &mut table,
        8,
        InsnInfo::Regular(RegularInsnInfo {
            mnemonic: Mnemonic::Pop,
            ops: &[OpInfo::R_OPCODE_16_32_64_DEF_64],
        }),
    );
    // 0x60 - 0x62
    assert_eq!(table.len(), 0x60);
    unsupported(&mut table, 3);
    // 0x63
    assert_eq!(table.len(), 0x63);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Movsxd,
        ops: &[
            OpInfo::R_MODRM_16_32_64_DEF_32,
            OpInfo::Rm(OpSizeInfo {
                with_operand_size_override: OpSize::S16,
                mode_32: OpSize::S32,
                mode_64: OpSize::S32,
                mode_64_with_rex_w: OpSize::S32,
            }),
        ],
    }));
    // 0x64 - 0x67
    assert_eq!(table.len(), 0x64);
    unsupported(&mut table, 4);
    // 0x68
    assert_eq!(table.len(), 0x68);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Push,
        ops: &[OpInfo::Imm(ImmOpInfo {
            encoded_size: OpSizeInfo::SZ_IMM_ENCODING_16_32,
            extended_size: OpSizeInfo::SZ_16_32_64_DEF_64,
            extend_kind: ImmExtendKind::SignExtend,
        })],
    }));
    // 0x69
    assert_eq!(table.len(), 0x69);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Imul,
        ops: &[
            OpInfo::R_MODRM_16_32_64_DEF_32,
            OpInfo::RM_16_32_64_DEF_32,
            OpInfo::Imm(ImmOpInfo {
                encoded_size: OpSizeInfo::SZ_IMM_ENCODING_16_32,
                extended_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                extend_kind: ImmExtendKind::SignExtend,
            }),
        ],
    }));
    // 0x6a
    assert_eq!(table.len(), 0x6a);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Push,
        ops: &[OpInfo::Imm(ImmOpInfo {
            encoded_size: OpSizeInfo::SZ_ALWAYS_8,
            extended_size: OpSizeInfo::SZ_16_32_64_DEF_64,
            extend_kind: ImmExtendKind::SignExtend,
        })],
    }));
    // 0x6b
    assert_eq!(table.len(), 0x6b);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Imul,
        ops: &[
            OpInfo::R_MODRM_16_32_64_DEF_32,
            OpInfo::RM_16_32_64_DEF_32,
            OpInfo::Imm(ImmOpInfo {
                encoded_size: OpSizeInfo::SZ_ALWAYS_8,
                extended_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                extend_kind: ImmExtendKind::SignExtend,
            }),
        ],
    }));
    // 0x6c - 0x6f
    assert_eq!(table.len(), 0x6c);
    unsupported(&mut table, 4);
    // 0x70 - 0x7f
    assert_eq!(table.len(), 0x70);
    repeat(
        &mut table,
        16,
        InsnInfo::Regular(RegularInsnInfo {
            mnemonic: Mnemonic::Jcc,
            ops: &[OpInfo::Cond, OpInfo::Rel(OpSizeInfo::SZ_ALWAYS_8)],
        }),
    );
    // 0x80
    assert_eq!(table.len(), 0x80);
    table.push(InsnInfo::ModrmRegOpcodeExt(
        ModrmRegOpcodeExtInsnInfo::new_with_same_operands(
            &[OpInfo::RM_8, OpInfo::IMM_8_NO_EXT],
            SIMPLE_BINOP_MNEMONICS,
        ),
    ));
    // 0x81
    assert_eq!(table.len(), 0x81);
    table.push(InsnInfo::ModrmRegOpcodeExt(
        ModrmRegOpcodeExtInsnInfo::new_with_same_operands(
            &[
                OpInfo::RM_16_32_64_DEF_32,
                OpInfo::Imm(ImmOpInfo {
                    encoded_size: OpSizeInfo::SZ_IMM_ENCODING_16_32,
                    extended_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                    extend_kind: ImmExtendKind::SignExtend,
                }),
            ],
            SIMPLE_BINOP_MNEMONICS,
        ),
    ));
    // 0x82
    assert_eq!(table.len(), 0x82);
    unsupported(&mut table, 1);
    // 0x83
    assert_eq!(table.len(), 0x83);
    table.push(InsnInfo::ModrmRegOpcodeExt(
        ModrmRegOpcodeExtInsnInfo::new_with_same_operands(
            &[
                OpInfo::RM_16_32_64_DEF_32,
                OpInfo::Imm(ImmOpInfo {
                    encoded_size: OpSizeInfo::SZ_ALWAYS_8,
                    extended_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                    extend_kind: ImmExtendKind::SignExtend,
                }),
            ],
            SIMPLE_BINOP_MNEMONICS,
        ),
    ));
    // 0x84
    assert_eq!(table.len(), 0x84);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Test,
        ops: &[OpInfo::RM_8, OpInfo::R_MODRM_8],
    }));
    // 0x85
    assert_eq!(table.len(), 0x85);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Test,
        ops: &[OpInfo::RM_16_32_64_DEF_32, OpInfo::R_MODRM_16_32_64_DEF_32],
    }));
    // 0x86
    assert_eq!(table.len(), 0x86);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Xchg,
        ops: &[OpInfo::RM_8, OpInfo::R_MODRM_8],
    }));
    // 0x87
    assert_eq!(table.len(), 0x87);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Xchg,
        ops: &[OpInfo::RM_16_32_64_DEF_32, OpInfo::R_MODRM_16_32_64_DEF_32],
    }));
    // 0x88
    assert_eq!(table.len(), 0x88);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Mov,
        ops: &[OpInfo::RM_8, OpInfo::R_MODRM_8],
    }));
    // 0x89
    assert_eq!(table.len(), 0x89);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Mov,
        ops: &[OpInfo::RM_16_32_64_DEF_32, OpInfo::R_MODRM_16_32_64_DEF_32],
    }));
    // 0x8a
    assert_eq!(table.len(), 0x8a);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Mov,
        ops: &[OpInfo::R_MODRM_8, OpInfo::RM_8],
    }));
    // 0x8b
    assert_eq!(table.len(), 0x8b);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Mov,
        ops: &[OpInfo::R_MODRM_16_32_64_DEF_32, OpInfo::RM_16_32_64_DEF_32],
    }));
    // 0x8c
    assert_eq!(table.len(), 0x8c);
    unsupported(&mut table, 1);
    // 0x8d
    assert_eq!(table.len(), 0x8d);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Lea,
        ops: &[OpInfo::R_MODRM_16_32_64_DEF_32, OpInfo::RM_16_32_64_DEF_32],
    }));
    // 0x8e
    assert_eq!(table.len(), 0x8e);
    unsupported(&mut table, 1);
    // 0x8f
    assert_eq!(table.len(), 0x8f);
    table.push(InsnInfo::ModrmRegOpcodeExt(ModrmRegOpcodeExtInsnInfo {
        by_reg_value: [
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
    assert_eq!(table.len(), 0x90);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Nop,
        ops: &[],
    }));
    // 0x91 - 0x97
    assert_eq!(table.len(), 0x91);
    repeat(
        &mut table,
        7,
        InsnInfo::Regular(RegularInsnInfo {
            mnemonic: Mnemonic::Xchg,
            ops: &[OpInfo::AX_16_32_64_DEF_32, OpInfo::R_OPCODE_16_32_64_DEF_32],
        }),
    );
    // 0x98
    assert_eq!(table.len(), 0x98);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Movsx, // this is actually cbw, but this makes life simpler when lifting it
        ops: &[
            OpInfo::AX_16_32_64_DEF_32,
            OpInfo::SpecificReg(SpecificRegOpInfo {
                reg: SpecificReg::Rax,
                size: OpSizeInfo {
                    with_operand_size_override: OpSize::S8,
                    mode_32: OpSize::S16,
                    mode_64: OpSize::S16,
                    mode_64_with_rex_w: OpSize::S32,
                },
            }),
        ],
    }));
    // 0x99
    assert_eq!(table.len(), 0x99);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Cwd, // this is cwd/cdq/cqo
        ops: &[OpInfo::DX_16_32_64_DEF_32, OpInfo::AX_16_32_64_DEF_32],
    }));
    // 0x9a - 0x9f
    assert_eq!(table.len(), 0x9a);
    unsupported(&mut table, 6);
    // 0xa0
    assert_eq!(table.len(), 0xa0);
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
    assert_eq!(table.len(), 0xa1);
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
    assert_eq!(table.len(), 0xa2);
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
    assert_eq!(table.len(), 0xa3);
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
    assert_eq!(table.len(), 0xa4);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Movs,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_ALWAYS_8)],
    }));
    // 0xa5
    assert_eq!(table.len(), 0xa5);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Movs,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_16_32_64_DEF_32)],
    }));
    // 0xa6
    assert_eq!(table.len(), 0xa6);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Cmps,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_ALWAYS_8)],
    }));
    // 0xa7
    assert_eq!(table.len(), 0xa7);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Cmps,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_16_32_64_DEF_32)],
    }));
    // 0xa8
    assert_eq!(table.len(), 0xa8);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Test,
        ops: &[OpInfo::AL, OpInfo::IMM_8_NO_EXT],
    }));
    // 0xa9
    assert_eq!(table.len(), 0xa9);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Test,
        ops: &[
            OpInfo::AX_16_32_64_DEF_32,
            OpInfo::Imm(ImmOpInfo {
                encoded_size: OpSizeInfo::SZ_IMM_ENCODING_16_32,
                extended_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                extend_kind: ImmExtendKind::SignExtend,
            }),
        ],
    }));
    // 0xaa
    assert_eq!(table.len(), 0xaa);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Stos,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_ALWAYS_8)],
    }));
    // 0xab
    assert_eq!(table.len(), 0xab);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Stos,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_16_32_64_DEF_32)],
    }));
    // 0xac
    assert_eq!(table.len(), 0xac);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Lods,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_ALWAYS_8)],
    }));
    // 0xad
    assert_eq!(table.len(), 0xad);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Lods,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_16_32_64_DEF_32)],
    }));
    // 0xae
    assert_eq!(table.len(), 0xae);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Scas,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_ALWAYS_8)],
    }));
    // 0xaf
    assert_eq!(table.len(), 0xaf);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Scas,
        ops: &[OpInfo::Implicit(OpSizeInfo::SZ_16_32_64_DEF_32)],
    }));
    // 0xb0 - 0xb7
    assert_eq!(table.len(), 0xb0);
    repeat(
        &mut table,
        8,
        InsnInfo::Regular(RegularInsnInfo {
            mnemonic: Mnemonic::Mov,
            ops: &[OpInfo::R_OPCODE_8, OpInfo::IMM_8_NO_EXT],
        }),
    );
    // 0xb8 - 0xbf
    assert_eq!(table.len(), 0xb8);
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
                    extend_kind: ImmExtendKind::ZeroExtend,
                }),
            ],
        }),
    );
    // 0xc0
    assert_eq!(table.len(), 0xc0);
    table.push(InsnInfo::ModrmRegOpcodeExt(
        ModrmRegOpcodeExtInsnInfo::new_with_same_operands(
            &[OpInfo::RM_8, OpInfo::IMM_8_NO_EXT],
            SHIFT_BINOP_MNEMONICS,
        ),
    ));
    // 0xc1
    assert_eq!(table.len(), 0xc1);
    table.push(InsnInfo::ModrmRegOpcodeExt(
        ModrmRegOpcodeExtInsnInfo::new_with_same_operands(
            &[
                OpInfo::RM_16_32_64_DEF_32,
                OpInfo::Imm(ImmOpInfo {
                    encoded_size: OpSizeInfo::SZ_ALWAYS_8,
                    extended_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                    extend_kind: ImmExtendKind::ZeroExtend,
                }),
            ],
            SHIFT_BINOP_MNEMONICS,
        ),
    ));
    // 0xc2
    assert_eq!(table.len(), 0xc2);
    unsupported(&mut table, 1);
    // 0xc3
    assert_eq!(table.len(), 0xc3);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Ret,
        ops: &[],
    }));
    // 0xc4 - 0xc5
    assert_eq!(table.len(), 0xc4);
    unsupported(&mut table, 2);
    // 0xc6
    assert_eq!(table.len(), 0xc6);
    table.push(InsnInfo::ModrmRegOpcodeExt(ModrmRegOpcodeExtInsnInfo {
        by_reg_value: [
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
    assert_eq!(table.len(), 0xc7);
    table.push(InsnInfo::ModrmRegOpcodeExt(ModrmRegOpcodeExtInsnInfo {
        by_reg_value: [
            RegularInsnInfo {
                mnemonic: Mnemonic::Mov,
                ops: &[
                    OpInfo::RM_16_32_64_DEF_32,
                    OpInfo::Imm(ImmOpInfo {
                        encoded_size: OpSizeInfo::SZ_IMM_ENCODING_16_32,
                        extended_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                        extend_kind: ImmExtendKind::SignExtend,
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
    assert_eq!(table.len(), 0xc8);
    unsupported(&mut table, 8);
    // 0xd0
    assert_eq!(table.len(), 0xd0);
    table.push(InsnInfo::ModrmRegOpcodeExt(
        ModrmRegOpcodeExtInsnInfo::new_with_same_operands(
            &[
                OpInfo::RM_8,
                OpInfo::SpecificImm(SpecificImmOpInfo {
                    value: SpecificImm::One,
                    operand_size: OpSizeInfo::SZ_ALWAYS_8,
                }),
            ],
            SHIFT_BINOP_MNEMONICS,
        ),
    ));
    // 0xd1
    assert_eq!(table.len(), 0xd1);
    table.push(InsnInfo::ModrmRegOpcodeExt(
        ModrmRegOpcodeExtInsnInfo::new_with_same_operands(
            &[
                OpInfo::RM_16_32_64_DEF_32,
                OpInfo::SpecificImm(SpecificImmOpInfo {
                    value: SpecificImm::One,
                    operand_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                }),
            ],
            SHIFT_BINOP_MNEMONICS,
        ),
    ));
    // 0xd2
    assert_eq!(table.len(), 0xd2);
    table.push(InsnInfo::ModrmRegOpcodeExt(
        ModrmRegOpcodeExtInsnInfo::new_with_same_operands(
            &[OpInfo::RM_8, OpInfo::CL],
            SHIFT_BINOP_MNEMONICS,
        ),
    ));
    // 0xd3
    assert_eq!(table.len(), 0xd3);
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
    assert_eq!(table.len(), 0xd4);
    unsupported(&mut table, 0x14);
    // 0xe8
    assert_eq!(table.len(), 0xe8);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Call,
        ops: &[OpInfo::REL_32],
    }));
    // 0xe9
    assert_eq!(table.len(), 0xe9);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Jmp,
        ops: &[OpInfo::REL_32],
    }));
    // 0xea
    assert_eq!(table.len(), 0xea);
    unsupported(&mut table, 1);
    // 0xeb
    assert_eq!(table.len(), 0xeb);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Jmp,
        ops: &[OpInfo::Rel(OpSizeInfo::SZ_ALWAYS_8)],
    }));
    // 0xec - 0xf3
    assert_eq!(table.len(), 0xec);
    unsupported(&mut table, 8);
    // 0xf4
    assert_eq!(table.len(), 0xf4);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Hlt,
        ops: &[],
    }));
    // 0xf5
    assert_eq!(table.len(), 0xf5);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Cmc,
        ops: &[],
    }));
    // 0xf6
    assert_eq!(table.len(), 0xf6);
    table.push(InsnInfo::ModrmRegOpcodeExt(ModrmRegOpcodeExtInsnInfo {
        by_reg_value: [
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
    assert_eq!(table.len(), 0xf7);
    table.push(InsnInfo::ModrmRegOpcodeExt(ModrmRegOpcodeExtInsnInfo {
        by_reg_value: [
            // 0
            RegularInsnInfo {
                mnemonic: Mnemonic::Test,
                ops: &[
                    OpInfo::RM_16_32_64_DEF_32,
                    OpInfo::Imm(ImmOpInfo {
                        encoded_size: OpSizeInfo::SZ_IMM_ENCODING_16_32,
                        extended_size: OpSizeInfo::SZ_16_32_64_DEF_32,
                        extend_kind: ImmExtendKind::SignExtend,
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
    assert_eq!(table.len(), 0xf8);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Clc,
        ops: &[],
    }));
    // 0xf9
    assert_eq!(table.len(), 0xf9);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Stc,
        ops: &[],
    }));
    // 0xfa
    assert_eq!(table.len(), 0xfa);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Cli,
        ops: &[],
    }));
    // 0xfb
    assert_eq!(table.len(), 0xfb);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Sti,
        ops: &[],
    }));
    // 0xfc
    assert_eq!(table.len(), 0xfc);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Cld,
        ops: &[],
    }));
    // 0xfd
    assert_eq!(table.len(), 0xfd);
    table.push(InsnInfo::Regular(RegularInsnInfo {
        mnemonic: Mnemonic::Std,
        ops: &[],
    }));
    // 0xfe
    assert_eq!(table.len(), 0xfe);
    table.push(InsnInfo::ModrmRegOpcodeExt(ModrmRegOpcodeExtInsnInfo {
        by_reg_value: [
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
    assert_eq!(table.len(), 0xff);
    table.push(InsnInfo::ModrmRegOpcodeExt(ModrmRegOpcodeExtInsnInfo {
        by_reg_value: [
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
                    with_operand_size_override: OpSize::S16,
                    mode_32: OpSize::S32,
                    mode_64: OpSize::S64,
                    mode_64_with_rex_w: OpSize::S64,
                })],
            },
            // 3
            RegularInsnInfo::UNSUPPORTED,
            // 4
            RegularInsnInfo {
                mnemonic: Mnemonic::Jmp,
                ops: &[OpInfo::Rm(OpSizeInfo {
                    // operand size override is not supported with branch instruction, so this is ignored anyway
                    with_operand_size_override: OpSize::S16,
                    mode_32: OpSize::S32,
                    mode_64: OpSize::S64,
                    mode_64_with_rex_w: OpSize::S64,
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

    assert_eq!(table.len(), 0x100);

    table
}
