use std::mem::transmute;

use bitpiece::{bitpiece, BitPiece};
use delve::{EnumVariantCount, VariantCount};
use enum_all_values_const::AllValues;

use super::Result;
use crate::{
    cursor::{Cursor, CursorError},
    LiftErr,
};

use super::{ctx::CtxInitial, X86Cpumode, X86LiftErr, X86SpecificLiftErr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, AllValues)]
#[repr(u8)]
pub enum LegacyPrefix {
    // group 1
    Lock = 0xf0,
    RepnzOrBnd = 0xf2,
    RepzOrRep = 0xf3,

    // group 2
    CsSegmentOrBranchNotTaken = 0x2e,
    SsSegment = 0x36,
    DsSegmentOrBranchTaken = 0x3e,
    EsSegment = 0x26,
    FsSegment = 0x64,
    GsSegment = 0x65,

    // group 3
    OperandSizeOverride = 0x66,

    // group 4
    AddressSizeOverride = 0x67,
}
impl LegacyPrefix {
    pub const fn group(&self) -> LegacyPrefixGroup {
        // SAFETY: all values of the enum are less than the length of the array, so this is always safe.
        return BYTE_VALUE_TO_LEGACY_PREFIX_GROUP[*self as usize].unwrap();
    }
    pub const fn byte_value(&self) -> u8 {
        *self as u8
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumVariantCount)]
#[repr(u8)]
pub enum LegacyPrefixGroup {
    Group1 = 0,
    Group2 = 1,
    Group3 = 2,
    Group4 = 3,
}
impl LegacyPrefixGroup {
    pub const fn index(&self) -> usize {
        *self as usize
    }
}

pub const LEGACY_PREFIX_GROUPS_AMOUNT: usize = LegacyPrefixGroup::VARIANT_COUNT;

pub struct LegacyPrefixes {
    pub by_group: [Option<LegacyPrefix>; LEGACY_PREFIX_GROUPS_AMOUNT],
}
impl LegacyPrefixes {
    pub fn contains(&self, prefix: LegacyPrefix) -> bool {
        self.by_group[prefix.group().index()] == Some(prefix)
    }
}

#[bitpiece(4)]
pub struct RexPrefix {
    pub b: bool,
    pub x: bool,
    pub r: bool,
    pub w: bool,
}

pub struct Prefixes {
    legacy: LegacyPrefixes,
    rex: Option<RexPrefix>,
}
impl Prefixes {
    pub fn has_legacy_prefix(&self, prefix: LegacyPrefix) -> bool {
        self.legacy.contains(prefix)
    }
    pub fn has_rex(&self) -> bool {
        self.rex.is_some()
    }
    pub fn has_rex_w(&self) -> bool {
        self.rex.is_some_and(|rex| rex.w())
    }
    pub fn has_rex_r(&self) -> bool {
        self.rex.is_some_and(|rex| rex.r())
    }
    pub fn has_rex_x(&self) -> bool {
        self.rex.is_some_and(|rex| rex.x())
    }
    pub fn has_rex_b(&self) -> bool {
        self.rex.is_some_and(|rex| rex.b())
    }
}

const BYTE_VALUE_TO_LEGACY_PREFIX_GROUP: [Option<LegacyPrefixGroup>; 256] = {
    let mut map = [None; 256];

    // group 1
    map[LegacyPrefix::Lock as usize] = Some(LegacyPrefixGroup::Group1);
    map[LegacyPrefix::RepnzOrBnd as usize] = Some(LegacyPrefixGroup::Group1);
    map[LegacyPrefix::RepzOrRep as usize] = Some(LegacyPrefixGroup::Group1);

    // group 2
    map[LegacyPrefix::CsSegmentOrBranchNotTaken as usize] = Some(LegacyPrefixGroup::Group2);
    map[LegacyPrefix::SsSegment as usize] = Some(LegacyPrefixGroup::Group2);
    map[LegacyPrefix::DsSegmentOrBranchTaken as usize] = Some(LegacyPrefixGroup::Group2);
    map[LegacyPrefix::EsSegment as usize] = Some(LegacyPrefixGroup::Group2);
    map[LegacyPrefix::FsSegment as usize] = Some(LegacyPrefixGroup::Group2);
    map[LegacyPrefix::GsSegment as usize] = Some(LegacyPrefixGroup::Group2);

    // group 3
    map[LegacyPrefix::OperandSizeOverride as usize] = Some(LegacyPrefixGroup::Group3);

    // group 4
    map[LegacyPrefix::AddressSizeOverride as usize] = Some(LegacyPrefixGroup::Group4);

    map
};

fn parse_rex_prefix(ctx: &mut CtxInitial) -> Result<Option<RexPrefix>> {
    // first, decide if rex is even supported
    match ctx.cpumode {
        X86Cpumode::B32 => {
            // in 32-bit mode, rex is not supported. treat it as if there is no rex prefix on the instruction.
            return Ok(None);
        }
        X86Cpumode::B64 => {
            // in 64-bit mode, rex is supported. continue to the rex parsing logic
        }
    }

    // check the first byte at the current cursor position to see if it is a rex prefix.
    // the current cursor position is assumed to be right after parsing legacy prefixes, but before parsing the instruction itself.
    let byte = ctx.args.code.peek_byte()?;

    if (byte & 0xf0) == 0x40 {
        // this byte is a rex prefix
        let rex = RexPrefix::from_bits(byte & 0xf);

        // consume the rex prefix byte
        ctx.args.code.advance_byte()?;

        Ok(Some(rex))
    } else {
        // not a rex prefix
        Ok(None)
    }
}

fn parse_legacy_prefixes(ctx: &mut CtxInitial) -> Result<LegacyPrefixes> {
    let mut prefixes = LegacyPrefixes {
        by_group: [None; LEGACY_PREFIX_GROUPS_AMOUNT],
    };
    loop {
        let code_byte = ctx.args.code.peek_byte()?;
        match BYTE_VALUE_TO_LEGACY_PREFIX_GROUP[code_byte as usize] {
            Some(group) => {
                // SAFETY: if this code byte is associated with a legacy prefix group, then we know that it is a valid legacy prefix
                let prefix: LegacyPrefix = unsafe { transmute(code_byte) };

                let entry = &mut prefixes.by_group[group as usize];

                // make sure that the instruction doesn't use multiple different prefixes of the same group.
                //
                // but, repeating the same prefix multiple times is allowed. it is sometimes used by the compiler to generate
                // NOPs of arbitrary length.
                if let Some(existing_prefix) = *entry {
                    if existing_prefix != prefix {
                        return Err(LiftErr::ArchSpecific(
                            X86SpecificLiftErr::TwoLegacyPrefixesOfSameGroup {
                                prefixes: [existing_prefix, prefix],
                            },
                        ));
                    }
                }

                *entry = Some(prefix);
            }
            None => {
                // current byte is not a legacy prefix, finished parsing legacy prefixes.
                // note that we did not consume the byte as it is not a legacy prefix.
                break;
            }
        }

        // advance to the next byte
        ctx.args.code.advance_byte()?;
    }
    Ok(prefixes)
}

pub fn parse_prefixes(ctx: &mut CtxInitial) -> Result<Prefixes> {
    Ok(Prefixes {
        legacy: parse_legacy_prefixes(ctx)?,
        rex: parse_rex_prefix(ctx)?,
    })
}
