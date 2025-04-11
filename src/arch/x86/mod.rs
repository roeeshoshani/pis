use std::fs::Permissions;

use crate::{regs::DefineRegOperandsSpec, *};
use ctx::{CtxInitial, CtxPostPrefixes};
use lift::lift_post_prefixes;
use prefixes::{parse_prefixes, LegacyPrefix};
use thiserror_no_std::Error;

mod ctx;
mod lift;
mod modrm;
mod prefixes;
mod tables;

define_reg_operands! {
    DefineRegOperandsSpec { start_offset: PisOff(0), step_size: 8, size: PisSize::B8 },
    // offset 0x00
    X86_REG_RAX,
    // offset 0x08
    X86_REG_RCX,
    // offset 0x10
    X86_REG_RDX,
    // offset 0x18
    X86_REG_RBX,
    // offset 0x20
    X86_REG_RSP,
    // offset 0x28
    X86_REG_RBP,
    // offset 0x30
    X86_REG_RSI,
    // offset 0x38
    X86_REG_RDI,
    // offset 0x40
    X86_REG_R8,
    // offset 0x48
    X86_REG_R9,
    // offset 0x50
    X86_REG_R10,
    // offset 0x58
    X86_REG_R11,
    // offset 0x60
    X86_REG_R12,
    // offset 0x68
    X86_REG_R13,
    // offset 0x70
    X86_REG_R14,
    // offset 0x78
    X86_REG_R15,
    // the RIP register is never emitted from the x86 lifter, but it is used internally during some intermediate representation
    // of instructions when lifting x86 instructions that use rip-relative addressing.
    //
    // you may wonder why this is required. knowing the value of RIP is only possible after we know the full length of the instruction,
    // since RIP represents the end address of the instruction. and, due to our incremental decoding strategy, we only know the full
    // length of the instruction when we finish decoding it.
    // but, sometimes we need to use the value of RIP before we know the full length of the instruction.
    //
    // for example, consider the following instruction:
    // ```
    // 0x1000: c7 05 00 00 00 00 78 56 34 12  mov dword [rip], 0x12345678
    // 0x100a: ...
    // ```
    // when decoding modrm byte (0x05), we see that it uses RIP relative addressing, so the accessed memory address is the value of RIP.
    // but, when decoding the modrm byte, we don't yet know the full length of the instruction, since the modrm byte (along with the 4
    // byte RIP-relative displacement of 0x00000000) is then followed by another immediate operand, which is only going to be decoded
    // later, and we are unaware of its existence at that point.
    // so, in this case, we can just use the RIP register operand.
    //
    // the RIP register operand will then be resolved to its proper value after we finish decoding the entire instruction and know
    // its full length.
    X86_REG_RIP,
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

const SEG_REGS_END_OFFSET: PisOff = X86_REG_GS_BASE.end_offset();
const FLAGS_REG_OFFSET: PisOff = SEG_REGS_END_OFFSET;

define_reg_operand!(X86_REG_RFLAGS, FLAGS_REG_OFFSET, PisSize::B8);
define_reg_operand!(X86_REG_EFLAGS, FLAGS_REG_OFFSET, PisSize::B4);
define_reg_operand!(
    X86_REG_FLAGS_CF,
    PisOff(FLAGS_REG_OFFSET.0 + 0),
    PisSize::B1
);
define_reg_operand!(
    X86_REG_FLAGS_PF,
    PisOff(FLAGS_REG_OFFSET.0 + 2),
    PisSize::B1
);
define_reg_operand!(
    X86_REG_FLAGS_AF,
    PisOff(FLAGS_REG_OFFSET.0 + 4),
    PisSize::B1
);
define_reg_operand!(
    X86_REG_FLAGS_ZF,
    PisOff(FLAGS_REG_OFFSET.0 + 6),
    PisSize::B1
);
define_reg_operand!(
    X86_REG_FLAGS_SF,
    PisOff(FLAGS_REG_OFFSET.0 + 7),
    PisSize::B1
);
define_reg_operand!(
    X86_REG_FLAGS_TF,
    PisOff(FLAGS_REG_OFFSET.0 + 8),
    PisSize::B1
);
define_reg_operand!(
    X86_REG_FLAGS_IF,
    PisOff(FLAGS_REG_OFFSET.0 + 9),
    PisSize::B1
);
define_reg_operand!(
    X86_REG_FLAGS_DF,
    PisOff(FLAGS_REG_OFFSET.0 + 10),
    PisSize::B1
);
define_reg_operand!(
    X86_REG_FLAGS_OF,
    PisOff(FLAGS_REG_OFFSET.0 + 11),
    PisSize::B1
);
define_reg_operand!(
    X86_REG_FLAGS_IOPL,
    PisOff(FLAGS_REG_OFFSET.0 + 12),
    PisSize::B2
);
define_reg_operand!(
    X86_REG_FLAGS_NT,
    PisOff(FLAGS_REG_OFFSET.0 + 14),
    PisSize::B1
);
define_reg_operand!(
    X86_REG_FLAGS_RF,
    PisOff(FLAGS_REG_OFFSET.0 + 16),
    PisSize::B1
);
define_reg_operand!(
    X86_REG_FLAGS_VM,
    PisOff(FLAGS_REG_OFFSET.0 + 17),
    PisSize::B1
);
define_reg_operand!(
    X86_REG_FLAGS_AC,
    PisOff(FLAGS_REG_OFFSET.0 + 18),
    PisSize::B1
);
define_reg_operand!(
    X86_REG_FLAGS_VIF,
    PisOff(FLAGS_REG_OFFSET.0 + 19),
    PisSize::B1
);
define_reg_operand!(
    X86_REG_FLAGS_VIP,
    PisOff(FLAGS_REG_OFFSET.0 + 20),
    PisSize::B1
);
define_reg_operand!(
    X86_REG_FLAGS_ID,
    PisOff(FLAGS_REG_OFFSET.0 + 21),
    PisSize::B1
);

/// the max amount of operands in an x86 instruction.
const X86_INSN_MAX_OPS: usize = 3;

#[derive(Debug, Error)]
pub enum X86SpecificLiftErr {
    TwoLegacyPrefixesOfSameGroup { prefixes: [LegacyPrefix; 2] },
}

pub type X86LiftErr = LiftErr<X86SpecificLiftErr>;

type Result<T> = core::result::Result<T, X86LiftErr>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum X86Cpumode {
    B32,
    B64,
}
impl X86Cpumode {
    fn operand_size(&self) -> PisSize {
        match self {
            X86Cpumode::B32 => PisSize::B4,
            X86Cpumode::B64 => PisSize::B8,
        }
    }
}

fn lift_one_with_cpumode(args: LiftArgs, cpumode: X86Cpumode) -> Result<LiftRes> {
    // parse prefixes
    let mut ctx_initial = CtxInitial {
        cpumode,
        args: args.into_internal(),
    };
    let prefixes = parse_prefixes(&mut ctx_initial)?;

    // continue to parsing the rest of the instruction
    let ctx_post_prefixes = CtxPostPrefixes {
        args: ctx_initial.args,
        cpumode,
        prefixes,
    };
    lift_post_prefixes(ctx_post_prefixes)
}

pub struct PisProcessorX64;
impl PisProcessor for PisProcessorX64 {
    type Err = X86SpecificLiftErr;

    fn lift_one(args: LiftArgs) -> Result<LiftRes> {
        lift_one_with_cpumode(args, X86Cpumode::B64)
    }
}
