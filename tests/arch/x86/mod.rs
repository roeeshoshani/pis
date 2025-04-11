use hex_literal::hex;
use pis::{LiftArgs, LiftRes, PisEmu, PisProcessor, PisProcessorX64};

/// lifts the given array of bytes at the given machine code addr.
fn lift_at(code: &[u8], machine_code_addr: u64) -> LiftRes {
    PisProcessorX64::lift_one(LiftArgs {
        code,
        machine_code_addr,
    })
    .unwrap()
}

/// lifts the given array of bytes
fn lift(code: &[u8]) -> LiftRes {
    lift_at(code, 0)
}

/// lifts the given array of bytes and expects the single lifted instruction to cover the entire buffer.
fn lift_single_insn(code: &[u8]) -> LiftRes {
    let res = lift(code);
    assert_eq!(res.machine_insn_len.bytes as usize, code.len());
    res
}

#[test]
fn lift_add() {
    // add rax, [rbx+rdi*4 - 7]
    let code = hex!("48 03 44 bb f9");
    let res = lift_single_insn(&code);
    let mut emu = PisEmu::new();
    for insn in res.insns {
        emu.run(insn).unwrap();
    }
    todo!()
}
