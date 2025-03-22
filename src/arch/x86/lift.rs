use crate::arch::x86::tables::InsnInfo;
use bitpiece::*;

use super::{
    prefixes::Prefixes,
    tables::{OpcodeByteTable, FIRST_OPCODE_BYTE_TABLE},
    X86LiftArgs, X86LiftErr, X86SpecificLiftErr,
};

type Result<T> = core::result::Result<T, X86LiftErr>;

fn lift_opcode_byte(ctx: &mut Ctx, opcode_byte: u8, table: &OpcodeByteTable) -> Result<()> {
    match &table[opcode_byte as usize] {
        InsnInfo::Regular(insn_info) => todo!(),
        InsnInfo::ModrmRegOpcodeExt(insn_info) => {
            let modrm = ctx.modrm()?;
            insn_info.by_modrm_reg_value[modrm.reg()];
            todo!()
        }
    }
    todo!()
}

#[bitpiece(8)]
pub struct Modrm {
    rm: B3,
    reg: B3,
    mod_val: B2,
}

pub struct Ctx<'a> {
    args: &'a mut X86LiftArgs<'a>,
    prefixes: Prefixes,
    modrm: Option<Modrm>,
}
impl<'a> Ctx<'a> {
    fn modrm(&mut self) -> Result<Modrm> {
        if self.modrm.is_none() {
            self.modrm = Some(Modrm::from_bits(self.args.generic.code.next_byte()?));
        }
        Ok(*self.modrm.as_ref().unwrap())
    }
}

pub fn lift(ctx: &mut Ctx) -> Result<()> {
    let first_opcode_byte = ctx.args.generic.code.next_byte()?;
    if first_opcode_byte == 0x0f {
        // 2 or 3 byte opcode
        let second_opcode_byte = ctx.args.generic.code.next_byte()?;
        if second_opcode_byte == 0x38 || second_opcode_byte == 0x3a {
            // 3 byte opcode
            return Err(X86LiftErr::UnsupportedInsn);
        } else {
            // 2 byte opcode
            return Err(X86LiftErr::UnsupportedInsn);
        }
    } else {
        // 1 byte opcode
        lift_opcode_byte(ctx, first_opcode_byte, &FIRST_OPCODE_BYTE_TABLE);
    }
    Ok(())
}
