use std::path::StripPrefixError;

use crate::{Insn, Opcode, Operand, OperandAddr, OperandSize, OperandSpace, Translation};
use bitpiece::{bitpiece, BitPiece, BitStorage};
use paste::paste;
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

pub fn translate(mut code: &[u8]) -> Translation {
    let legacy_prefixes = extract_legacy_prefixes(&mut code);
    println!("prefixes: {:?}", legacy_prefixes);
    if code.len() == 1 && code[0] >= 0x50 && code[0] <= 0x50 + Reg::MAX_VALUE as u8 {
        return translate_push_reg(Reg::from_bits(code[0] - 0x50));
    }
    todo!()
}
