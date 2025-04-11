use hex_literal::hex;
use pis::{LiftArgs, LiftRes, PisCursor, PisProcessor, PisProcessorX64};

/// lifts the given array of bytes
fn lift(code: &[u8]) -> LiftRes {
    PisProcessorX64::lift_one(LiftArgs {
        code: &mut PisCursor::new(code),
        machine_code_addr: 0,
    })
    .unwrap()
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
    todo!()
}
