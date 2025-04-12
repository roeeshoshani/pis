use bitpiece::BitPiece;

use crate::{pis_insn, utils::array_vec, LiftArgsInternal, PisEmitter, PisInsn, PisOp, PisOpcode};

use super::{
    lift::Modrm, prefixes::Prefixes, tables::OpcodeByteTable, tmp_op_allocator::TmpOpAllocator,
    LiftRes, PisSize, Result, X86Cpumode,
};

/// the initial context after just getting the lift args and deciding the desired cpumode
pub struct CtxInitial<'a> {
    pub args: LiftArgsInternal<'a>,
    pub cpumode: X86Cpumode,
}

/// the context after parsing prefixes
pub struct CtxPostPrefixes<'a> {
    pub args: LiftArgsInternal<'a>,
    pub cpumode: X86Cpumode,
    pub prefixes: Prefixes,
}

/// the final context after parsing the instruction's opcode
pub struct Ctx<'a> {
    pub(super) args: LiftArgsInternal<'a>,
    pub(super) cpumode: X86Cpumode,
    pub prefixes: Prefixes,
    pub opcode_byte: u8,
    pub opcode_table: &'static OpcodeByteTable,
    pub modrm: Option<Modrm>,
    pub addr_size: PisSize,
    pub stack_addr_size: PisSize,
    pub(super) emitter: PisEmitter,
}

impl<'a> Ctx<'a> {
    pub fn emit(&mut self, insn: PisInsn) {
        self.emitter.emit(insn);
    }
    pub fn modrm(&mut self) -> Result<Modrm> {
        match self.modrm {
            Some(modrm) => Ok(modrm),
            None => Ok(*self
                .modrm
                .insert(Modrm::from_bits(self.args.code.next_byte()?))),
        }
    }
}
