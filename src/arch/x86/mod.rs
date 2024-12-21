use regs::DefineRegOperandsSpec;

use crate::*;

define_reg_operands! {
    DefineRegOperandsSpec { start_offset: PisOff(0), step_size: 8, size: PisSize::B8 },
    X86_REG_RAX,
    X86_REG_RCX,
    X86_REG_RDX,
    X86_REG_RBX,
    X86_REG_RSP,
    X86_REG_RBP,
    X86_REG_RSI,
    X86_REG_RDI,
    X86_REG_R8,
    X86_REG_R9,
    X86_REG_R10,
    X86_REG_R11,
    X86_REG_R12,
    X86_REG_R13,
    X86_REG_R14,
    X86_REG_R15,
}

define_reg_operands! {
    DefineRegOperandsSpec { start_offset: PisOff(0), step_size: 8, size: PisSize::B4 },
    X86_REG_EAX,
    X86_REG_ECX,
    X86_REG_EDX,
    X86_REG_EBX,
    X86_REG_ESP,
    X86_REG_EBP,
    X86_REG_ESI,
    X86_REG_EDI,
    X86_REG_R8D,
    X86_REG_R9D,
    X86_REG_R10D,
    X86_REG_R11D,
    X86_REG_R12D,
    X86_REG_R13D,
    X86_REG_R14D,
    X86_REG_R15D,
}

define_reg_operands! {
    DefineRegOperandsSpec { start_offset: PisOff(0), step_size: 8, size: PisSize::B2 },
    X86_REG_AX,
    X86_REG_CX,
    X86_REG_DX,
    X86_REG_BX,
    X86_REG_SP,
    X86_REG_BP,
    X86_REG_SI,
    X86_REG_DI,
    X86_REG_R8W,
    X86_REG_R9W,
    X86_REG_R10W,
    X86_REG_R11W,
    X86_REG_R12W,
    X86_REG_R13W,
    X86_REG_R14W,
    X86_REG_R15W,
}

define_reg_operands! {
    DefineRegOperandsSpec { start_offset: PisOff(0), step_size: 8, size: PisSize::B1 },
    X86_REG_AL,
    X86_REG_CL,
    X86_REG_DL,
    X86_REG_BL,
    X86_REG_SPL,
    X86_REG_BPL,
    X86_REG_SIL,
    X86_REG_DIL,
    X86_REG_R8B,
    X86_REG_R9B,
    X86_REG_R10B,
    X86_REG_R11B,
    X86_REG_R12B,
    X86_REG_R13B,
    X86_REG_R14B,
    X86_REG_R15B,
}

define_reg_operands! {
    DefineRegOperandsSpec { start_offset: PisOff(1), step_size: 8, size: PisSize::B1 },
    X86_REG_AH,
    X86_REG_CH,
    X86_REG_DH,
    X86_REG_BH,
}

const GPRS_END_OFFSET: PisOff = X86_REG_R15.end_offset();

define_reg_operands! {
    DefineRegOperandsSpec { start_offset: GPRS_END_OFFSET, step_size: 8, size: PisSize::B8 },
    X86_REG_ES_BASE,
    X86_REG_CS_BASE,
    X86_REG_SS_BASE,
    X86_REG_DS_BASE,
    X86_REG_FS_BASE,
    X86_REG_GS_BASE,
}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum X86LiftError {}

pub struct PisProcessorX86_64;
impl PisProcessor for PisProcessorX86_64 {
    type Err = X86LiftError;

    fn lift_one(code: &[u8], machine_code_addr: u64) -> Result<LiftRes, LiftErr<Self::Err>> {
        todo!()
    }
}
