use bitpiece::BitPiece;

use crate::LiftArgs;

use super::{lift::Modrm, prefixes::Prefixes, tables::OpcodeByteTable, Result, X86Cpumode};

/// the initial context after just getting the lift args and deciding the desired cpumode
pub struct CtxInitial<'a> {
    pub args: LiftArgs<'a>,
    pub cpumode: X86Cpumode,
}

/// the context after parsing prefixes
pub struct CtxPostPrefixes<'a> {
    pub args: LiftArgs<'a>,
    pub cpumode: X86Cpumode,
    pub prefixes: Prefixes,
}

/// the final context after parsing the instruction's opcode
pub struct Ctx<'a> {
    pub args: LiftArgs<'a>,
    pub cpumode: X86Cpumode,
    pub prefixes: Prefixes,
    pub opcode_byte: u8,
    pub opcode_table: &'static OpcodeByteTable,
    pub modrm: Option<Modrm>,
}

impl<'a> Ctx<'a> {
    pub fn modrm(&mut self) -> Result<Modrm> {
        if self.modrm.is_none() {
            self.modrm = Some(Modrm::from_bits(self.args.code.next_byte()?));
        }
        Ok(*self.modrm.as_ref().unwrap())
    }
}
