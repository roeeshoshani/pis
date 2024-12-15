use iced_x86::{Decoder, Instruction, Mnemonic, OpKind};
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
pub enum X86LiftError {
    #[error("invalid instruction")]
    InvalidInstruction,

    #[error("unknown error")]
    Unknown,
}

struct Ctx {
    insn: Instruction,
    result_insns: LiftResInsns,
}
impl Ctx {
    fn new(insn: Instruction) -> Self {
        Self {
            insn,
            result_insns: LiftResInsns::new(),
        }
    }
    fn read_reg_op(&self, op_index: u32) -> PisOp {
        match self.insn.op_register(op_index) {
            iced_x86::Register::AL => X86_REG_AL,
            iced_x86::Register::CL => X86_REG_CL,
            iced_x86::Register::DL => X86_REG_DL,
            iced_x86::Register::BL => X86_REG_BL,
            iced_x86::Register::AH => X86_REG_AH,
            iced_x86::Register::CH => X86_REG_CH,
            iced_x86::Register::DH => X86_REG_DH,
            iced_x86::Register::BH => X86_REG_BH,
            iced_x86::Register::SPL => X86_REG_SPL,
            iced_x86::Register::BPL => X86_REG_BPL,
            iced_x86::Register::SIL => X86_REG_SIL,
            iced_x86::Register::DIL => X86_REG_DIL,
            iced_x86::Register::R8L => X86_REG_R8B,
            iced_x86::Register::R9L => X86_REG_R9B,
            iced_x86::Register::R10L => X86_REG_R10B,
            iced_x86::Register::R11L => X86_REG_R11B,
            iced_x86::Register::R12L => X86_REG_R12B,
            iced_x86::Register::R13L => X86_REG_R13B,
            iced_x86::Register::R14L => X86_REG_R14B,
            iced_x86::Register::R15L => X86_REG_R15B,
            iced_x86::Register::AX => X86_REG_AX,
            iced_x86::Register::CX => X86_REG_CX,
            iced_x86::Register::DX => X86_REG_DX,
            iced_x86::Register::BX => X86_REG_BX,
            iced_x86::Register::SP => X86_REG_SP,
            iced_x86::Register::BP => X86_REG_BP,
            iced_x86::Register::SI => X86_REG_SI,
            iced_x86::Register::DI => X86_REG_DI,
            iced_x86::Register::R8W => X86_REG_R8W,
            iced_x86::Register::R9W => X86_REG_R9W,
            iced_x86::Register::R10W => X86_REG_R10W,
            iced_x86::Register::R11W => X86_REG_R11W,
            iced_x86::Register::R12W => X86_REG_R12W,
            iced_x86::Register::R13W => X86_REG_R13W,
            iced_x86::Register::R14W => X86_REG_R14W,
            iced_x86::Register::R15W => X86_REG_R15W,
            iced_x86::Register::EAX => X86_REG_EAX,
            iced_x86::Register::ECX => X86_REG_ECX,
            iced_x86::Register::EDX => X86_REG_EDX,
            iced_x86::Register::EBX => X86_REG_EBX,
            iced_x86::Register::ESP => X86_REG_ESP,
            iced_x86::Register::EBP => X86_REG_EBP,
            iced_x86::Register::ESI => X86_REG_ESI,
            iced_x86::Register::EDI => X86_REG_EDI,
            iced_x86::Register::R8D => X86_REG_R8D,
            iced_x86::Register::R9D => X86_REG_R9D,
            iced_x86::Register::R10D => X86_REG_R10D,
            iced_x86::Register::R11D => X86_REG_R11D,
            iced_x86::Register::R12D => X86_REG_R12D,
            iced_x86::Register::R13D => X86_REG_R13D,
            iced_x86::Register::R14D => X86_REG_R14D,
            iced_x86::Register::R15D => X86_REG_R15D,
            iced_x86::Register::RAX => X86_REG_RAX,
            iced_x86::Register::RCX => X86_REG_RCX,
            iced_x86::Register::RDX => X86_REG_RDX,
            iced_x86::Register::RBX => X86_REG_RBX,
            iced_x86::Register::RSP => X86_REG_RSP,
            iced_x86::Register::RBP => X86_REG_RBP,
            iced_x86::Register::RSI => X86_REG_RSI,
            iced_x86::Register::RDI => X86_REG_RDI,
            iced_x86::Register::R8 => X86_REG_R8,
            iced_x86::Register::R9 => X86_REG_R9,
            iced_x86::Register::R10 => X86_REG_R10,
            iced_x86::Register::R11 => X86_REG_R11,
            iced_x86::Register::R12 => X86_REG_R12,
            iced_x86::Register::R13 => X86_REG_R13,
            iced_x86::Register::R14 => X86_REG_R14,
            iced_x86::Register::R15 => X86_REG_R15,
            iced_x86::Register::ES => X86_REG_ES_BASE,
            iced_x86::Register::CS => X86_REG_CS_BASE,
            iced_x86::Register::SS => X86_REG_SS_BASE,
            iced_x86::Register::DS => X86_REG_DS_BASE,
            iced_x86::Register::FS => X86_REG_FS_BASE,
            iced_x86::Register::GS => X86_REG_GS_BASE,
            iced_x86::Register::None | iced_x86::Register::RIP | iced_x86::Register::EIP => {
                unreachable!()
            }
            _ => todo!(),
        }
    }
    fn read_op(&mut self, op_index: u32) -> PisOp {
        match self.insn.op_kind(op_index) {
            OpKind::Register => self.read_reg_op(op_index),
            OpKind::NearBranch16 => todo!(),
            OpKind::NearBranch32 => todo!(),
            OpKind::NearBranch64 => todo!(),
            OpKind::FarBranch16 => todo!(),
            OpKind::FarBranch32 => todo!(),
            OpKind::Immediate8 => PisOp::constant(self.insn.immediate8() as u64, PisSize::B1),
            OpKind::Immediate8_2nd => {
                PisOp::constant(self.insn.immediate8_2nd() as u64, PisSize::B1)
            }
            OpKind::Immediate16 => PisOp::constant(self.insn.immediate16() as u64, PisSize::B2),
            OpKind::Immediate32 => PisOp::constant(self.insn.immediate32() as u64, PisSize::B4),
            OpKind::Immediate64 => PisOp::constant(self.insn.immediate64(), PisSize::B8),
            OpKind::Immediate8to16 => {
                PisOp::constant(self.insn.immediate8to16() as u16 as u64, PisSize::B2)
            }
            OpKind::Immediate8to32 => {
                PisOp::constant(self.insn.immediate8to32() as u32 as u64, PisSize::B4)
            }
            OpKind::Immediate8to64 => {
                PisOp::constant(self.insn.immediate8to64() as u64, PisSize::B8)
            }
            OpKind::Immediate32to64 => {
                PisOp::constant(self.insn.immediate32to64() as u64, PisSize::B8)
            }
            OpKind::MemorySegSI => todo!(),
            OpKind::MemorySegESI => todo!(),
            OpKind::MemorySegRSI => todo!(),
            OpKind::MemorySegDI => todo!(),
            OpKind::MemorySegEDI => todo!(),
            OpKind::MemorySegRDI => todo!(),
            OpKind::MemoryESDI => todo!(),
            OpKind::MemoryESEDI => todo!(),
            OpKind::MemoryESRDI => todo!(),
            OpKind::Memory => todo!(),
        };
        todo!()
    }
    fn lift(mut self) -> LiftResInsns {
        match self.insn.mnemonic() {
            Mnemonic::Add => {
                assert_eq!(self.insn.op_count(), 2);
            }
            _ => {}
        }
        self.result_insns
    }
}
pub struct PisProcessorX86_64;
impl PisProcessor for PisProcessorX86_64 {
    type Err = X86LiftError;

    fn lift_one(code: &[u8], machine_code_addr: u64) -> Result<LiftRes, LiftErr<Self::Err>> {
        let mut decoder = Decoder::with_ip(64, code, machine_code_addr, 0);
        let insn = decoder.decode();
        if insn.is_invalid() {
            let err = match decoder.last_error() {
                iced_x86::DecoderError::InvalidInstruction => {
                    LiftErr::ArchSpecific(X86LiftError::InvalidInstruction)
                }
                iced_x86::DecoderError::NoMoreBytes => LiftErr::EarlyEof,
                _ => LiftErr::ArchSpecific(X86LiftError::Unknown),
            };
            return Err(err);
        }

        let insn_len = insn.len();

        let insns = Ctx::new(insn).lift();

        Ok(LiftRes {
            insns,
            machine_insn_len: MachineInsnLen {
                bytes: insn_len as u8,
            },
        })
    }
}
