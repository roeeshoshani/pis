use std::path::StripPrefixError;

use crate::{ArchCtx, Insn, Opcode, Operand, OperandAddr, OperandSize, OperandSpace, Translation};
use bitpiece::{bitpiece, BitPiece, BitStorage};
use strum::{EnumIter, IntoEnumIterator};

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
    {$step_size: literal, $size: ident, $prev_name: ident, $name: ident} => {
        define_reg_operand! {$name, $prev_name.addr.offset + $step_size, $size}
    };
}

macro_rules! define_reg_operands_inner {
    // the case for the last operand
    {$step_size: literal, $size: ident, $prev_name: ident, $name: ident} => {
        define_reg_operands_single!{$step_size, $size, $prev_name, $name}
    };

    // the common case of the non-last operand
    {$step_size: literal, $size: ident, $prev_name: ident, $name: ident, $($names: ident),+} => {
        // define the current operand
        define_reg_operands_inner! {$step_size, $size, $prev_name, $name}

        // define the rest of the operands
        define_reg_operands_inner! {$step_size, $size, $name, $($names),+}
    };
}

macro_rules! define_reg_operands {
    {$step_size: literal, $size: ident, $first_name: ident, $($name: ident),+} => {
        // define the first operand with offset 0
        define_reg_operand! {$first_name, 0, $size}

        // define the rest of the operands following it
        define_reg_operands_inner! {$step_size, $size, $first_name, $($name),+}
    };
}

define_reg_operands! {8, B8, RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI}
define_reg_operands! {8, B1, AL, CL, DL, BL, SPL, BPL, SIL, DIL}

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

#[derive(EnumIter, Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum LegacyPrefixGroup {
    Group1,
    Group2,
    Group3,
    Group4,
}
impl LegacyPrefixGroup {
    pub const GROUPS_AMOUNT: usize = 4;
    pub const fn index(&self) -> usize {
        *self as usize
    }
}

#[derive(EnumIter, Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum LegacyPrefix {
    Lock = 0xf0,
    Repnz = 0xf2,
    RepOrRepz = 0xf3,

    CsSegmentOverrideOrBranchNotTaken = 0x2e,
    SsSegmentOverride = 0x36,
    DsSegmentOverrideOrBranchTaken = 0x3e,
    EsSegmentOverride = 0x26,
    FsSegmentOverride = 0x64,
    GsSegmentOverride = 0x65,

    OperandSizeOverride = 0x66,

    AddressSizeOverride = 0x67,
}
impl LegacyPrefix {
    pub const fn group(&self) -> LegacyPrefixGroup {
        match self {
            Self::Lock | Self::Repnz | Self::RepOrRepz => LegacyPrefixGroup::Group1,
            Self::CsSegmentOverrideOrBranchNotTaken
            | Self::SsSegmentOverride
            | Self::DsSegmentOverrideOrBranchTaken
            | Self::EsSegmentOverride
            | Self::FsSegmentOverride
            | Self::GsSegmentOverride => LegacyPrefixGroup::Group2,
            Self::OperandSizeOverride => LegacyPrefixGroup::Group3,
            Self::AddressSizeOverride => LegacyPrefixGroup::Group4,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct InsnLegacyPrefixes {
    pub by_group: [Option<LegacyPrefix>; LegacyPrefixGroup::GROUPS_AMOUNT],
}
impl InsnLegacyPrefixes {
    pub fn add(&mut self, prefix: LegacyPrefix) {
        let group = prefix.group();
        let prefix_entry = &mut self.by_group[group.index()];
        assert!(
            prefix_entry.is_none(),
            "multiple legacy prefixes of the same group {:?} - {:?} and {:?}",
            group,
            prefix_entry.unwrap(),
            prefix
        );

        *prefix_entry = Some(prefix);
    }
    pub fn contains(&self, prefix: LegacyPrefix) -> bool {
        self.by_group[prefix.group().index()] == Some(prefix)
    }
}

fn extract_legacy_prefixes(code: &mut &[u8]) -> InsnLegacyPrefixes {
    let mut prefixes = InsnLegacyPrefixes {
        by_group: [None; LegacyPrefixGroup::GROUPS_AMOUNT],
    };
    while !code.is_empty() {
        let Some(matching_prefix) = LegacyPrefix::iter().find(|prefix| code[0] == *prefix as u8)
        else {
            // non-prefix byte, so we are done parsing the prefixes
            break;
        };

        prefixes.add(matching_prefix);

        // advance by 1 byte
        *code = &code[1..];
    }

    prefixes
}

#[bitpiece(4)]
#[derive(Debug, Clone, Copy)]
pub struct RexPrefix {
    pub w_bit: bool,
    pub r_bit: bool,
    pub x_bit: bool,
    pub b_bit: bool,
}

#[derive(Debug)]
pub struct InsnPrefixes {
    pub legacy: InsnLegacyPrefixes,
    pub rex: Option<RexPrefix>,
}

fn extract_rex_prefix(code: &mut &[u8]) -> Option<RexPrefix> {
    if code[0] & 0xf0 == 0b0100_0000 {
        let rex_prefix = RexPrefix::from_bits(code[0] & 0xf);

        // skip the rex byte
        *code = &code[1..];

        Some(rex_prefix)
    } else {
        None
    }
}

fn extract_prefixes(code: &mut &[u8]) -> InsnPrefixes {
    let legacy = extract_legacy_prefixes(code);
    let rex = extract_rex_prefix(code);
    InsnPrefixes { legacy, rex }
}

pub enum X86CpuMode {
    RealMode,
    ProtectedMode,
    LongMode,
}

pub enum X86SegmentDefaultOperandSize {
    /// 16 bit segment
    B16,
    /// 32 bit segment
    B32,
}

/// contextual information about a translation after parsing the instruction's prefixes.
struct PostPrefixesCtx {
    operand_size: OperandSize,
    address_size: OperandSize,
    prefixes: InsnPrefixes,
}

pub struct X86Ctx {
    /// the cpu mode in which we are executing.
    pub cpu_mode: X86CpuMode,
    /// the code segment's default operand size, determined by the `D` flag in the code segment descriptor.
    pub code_segment_default_operand_size: X86SegmentDefaultOperandSize,
}
impl X86Ctx {
    fn stack_width(&self) -> OperandSize {
        match self.cpu_mode {
            X86CpuMode::RealMode => OperandSize::B2,
            X86CpuMode::ProtectedMode => OperandSize::B4,
            X86CpuMode::LongMode => OperandSize::B8,
        }
    }
    fn stack_pointer_operand_of_size(&self, size: OperandSize) -> Operand {
        match size {
            OperandSize::B1 => todo!(),
            OperandSize::B2 => todo!(),
            OperandSize::B4 => todo!(),
            OperandSize::B8 => todo!(),
        }
    }
    fn translate_push_reg(&self, reg: Reg, ctx: PostPrefixesCtx) -> Translation {
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

    fn resolve_operand_size(&self, prefixes: &InsnPrefixes) -> OperandSize {
        match self.cpu_mode {
            X86CpuMode::RealMode => {
                if prefixes.legacy.contains(LegacyPrefix::OperandSizeOverride) {
                    OperandSize::B4
                } else {
                    OperandSize::B2
                }
            }
            X86CpuMode::ProtectedMode => match self.code_segment_default_operand_size {
                X86SegmentDefaultOperandSize::B16 => {
                    if prefixes.legacy.contains(LegacyPrefix::OperandSizeOverride) {
                        OperandSize::B4
                    } else {
                        OperandSize::B2
                    }
                }
                X86SegmentDefaultOperandSize::B32 => {
                    if prefixes.legacy.contains(LegacyPrefix::OperandSizeOverride) {
                        OperandSize::B2
                    } else {
                        OperandSize::B4
                    }
                }
            },
            X86CpuMode::LongMode => match prefixes.rex {
                Some(rex_prefix) if rex_prefix.w_bit() => OperandSize::B8,
                _ => {
                    if prefixes.legacy.contains(LegacyPrefix::OperandSizeOverride) {
                        OperandSize::B2
                    } else {
                        OperandSize::B4
                    }
                }
            },
        }
    }

    fn resolve_address_size(&self, prefixes: &InsnPrefixes) -> OperandSize {
        match self.cpu_mode {
            X86CpuMode::RealMode => {
                if prefixes.legacy.contains(LegacyPrefix::AddressSizeOverride) {
                    OperandSize::B4
                } else {
                    OperandSize::B2
                }
            }
            X86CpuMode::ProtectedMode => match self.code_segment_default_operand_size {
                X86SegmentDefaultOperandSize::B16 => {
                    if prefixes.legacy.contains(LegacyPrefix::AddressSizeOverride) {
                        OperandSize::B4
                    } else {
                        OperandSize::B2
                    }
                }
                X86SegmentDefaultOperandSize::B32 => {
                    if prefixes.legacy.contains(LegacyPrefix::AddressSizeOverride) {
                        OperandSize::B2
                    } else {
                        OperandSize::B4
                    }
                }
            },
            X86CpuMode::LongMode => match prefixes.rex {
                Some(rex_prefix) if rex_prefix.w_bit() => {
                    if prefixes.legacy.contains(LegacyPrefix::AddressSizeOverride) {
                        OperandSize::B4
                    } else {
                        OperandSize::B8
                    }
                }
                _ => {
                    if prefixes.legacy.contains(LegacyPrefix::AddressSizeOverride) {
                        OperandSize::B2
                    } else {
                        OperandSize::B4
                    }
                }
            },
        }
    }
}
impl ArchCtx for X86Ctx {
    fn translate(&self, mut code: &[u8]) -> Translation {
        let prefixes = extract_prefixes(&mut code);

        let ctx = PostPrefixesCtx {
            operand_size: self.resolve_operand_size(&prefixes),
            address_size: self.resolve_address_size(&prefixes),
            prefixes,
        };

        if code.len() == 1 && (0x50..=0x50 + Reg::MAX_VALUE as u8).contains(&code[0]) {
            return self.translate_push_reg(Reg::from_bits(code[0] - 0x50), ctx);
        }
        todo!()
    }
}
