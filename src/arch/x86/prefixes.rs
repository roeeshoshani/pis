use std::mem::transmute;

use bitpiece::{bitpiece, BitPiece};
use delve::{EnumVariantCount, VariantCount};
use enum_all_values_const::AllValues;

use crate::{
    cursor::{Cursor, CursorError},
    LiftErr,
};

use super::{X86Cpumode, X86LiftArgs, X86LiftErr, X86SpecificLiftErr};

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
        return BYTE_VALUE_TO_LEGACY_PREFIX_GROUP[*self as usize].unwrap();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, EnumVariantCount)]
pub enum LegacyPrefixGroup {
    Group1,
    Group2,
    Group3,
    Group4,
}

pub const LEGACY_PREFIX_GROUPS_AMOUNT: usize = LegacyPrefixGroup::VARIANT_COUNT;

pub struct LegacyPrefixes {
    pub by_group: [Option<LegacyPrefix>; LEGACY_PREFIX_GROUPS_AMOUNT],
}

#[bitpiece(4)]
pub struct RexPrefix {
    pub b: bool,
    pub x: bool,
    pub r: bool,
    pub w: bool,
}

pub struct Prefixes {
    pub legacy: LegacyPrefixes,
    pub rex: Option<RexPrefix>,
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

fn parse_rex_prefix(args: &mut X86LiftArgs) -> Result<Option<RexPrefix>, X86LiftErr> {
    // first, decide if rex is even supported
    match args.cpumode {
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
    let byte = args.generic.code.peek_byte()?;

    if (byte & 0xf0) == 0x40 {
        // this byte is a rex prefix
        let rex = RexPrefix::from_bits(byte & 0xf);

        // consume the rex prefix byte
        args.generic.code.advance_byte()?;

        Ok(Some(rex))
    } else {
        // not a rex prefix
        Ok(None)
    }
}

fn parse_legacy_prefixes(args: &mut X86LiftArgs) -> Result<LegacyPrefixes, X86LiftErr> {
    let mut prefixes = LegacyPrefixes {
        by_group: [None; LEGACY_PREFIX_GROUPS_AMOUNT],
    };
    loop {
        let code_byte = args.generic.code.peek_byte()?;
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
        args.generic.code.advance_byte()?;
    }
    Ok(prefixes)
}

pub fn parse_prefixes(args: &mut X86LiftArgs) -> Result<Prefixes, X86LiftErr> {
    Ok(Prefixes {
        legacy: parse_legacy_prefixes(args)?,
        rex: parse_rex_prefix(args)?,
    })
}
