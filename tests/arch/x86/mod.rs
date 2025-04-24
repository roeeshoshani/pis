use std::num::Wrapping;

use hex_literal::hex;
use pis::{
    LiftArgs, PisEmu, PisEndian, PisProcessor, PisProcessorX64, PisSize, Wu64, X86_REG_RAX,
    X86_REG_RBX, X86_REG_RDI,
};

const MAGICS: &[Wu64] = &[
    Wrapping(0x74becdd72d47bf77),
    Wrapping(0x3837b6f2373b36da),
    Wrapping(0x51d3155f92922d58),
    Wrapping(0x927193eca4c59385),
    Wrapping(0x6fb79254441d8273),
    Wrapping(0x1ad5fc57679bac1e),
    Wrapping(0x948c1a19f60a41f4),
    Wrapping(0xd311b60b99388431),
    Wrapping(0x9e9663a2fa8efd21),
    Wrapping(0x2f772ef71989a499),
];

fn choose_magics<const AMOUNT: usize>() -> [Wu64; AMOUNT] {
    MAGICS[..AMOUNT].try_into().unwrap()
}

fn run_code(emu: &mut PisEmu, code: &[u8], machine_code_addr: u64) {
    let mut cur = code;
    let mut cur_addr = machine_code_addr;
    while cur.len() > 0 {
        let res = PisProcessorX64::lift_one(LiftArgs {
            code: cur,
            machine_code_addr: cur_addr,
        })
        .unwrap();

        for insn in res.insns {
            emu.run(insn).unwrap();
        }

        cur_addr += res.machine_insn_len.bytes as u64;
        cur = &cur[res.machine_insn_len.bytes..];
    }
}

fn mk_emu() -> PisEmu {
    // x86 is always little endian
    PisEmu::new(PisEndian::Little)
}

#[test]
fn lift_add() {
    // add rax, [rbx + rdi * 4 - 7]
    let code = hex!("48 03 44 bb f9");

    let [rax, rbx, rdi, mem_value] = choose_magics();
    let addr = rbx + rdi * Wrapping(4) - Wrapping(7);
    let result = rax + mem_value;

    let mut emu = mk_emu();
    emu.write_op(X86_REG_RAX, rax).unwrap();
    emu.write_op(X86_REG_RBX, rbx).unwrap();
    emu.write_op(X86_REG_RDI, rdi).unwrap();
    emu.write_mem(addr, PisSize::B8, mem_value).unwrap();

    run_code(&mut emu, &code, 0);

    assert_eq!(emu.read_op(X86_REG_RAX).unwrap(), result);
}

#[test]
fn lift_sub_regs() {
    // mov rax, 0x1234567890abcdef
    // mov ah, 0x00
    let code = hex!("48 B8 EF CD AB 90 78 56 34 12 B4 00");

    let mut emu = mk_emu();

    run_code(&mut emu, &code, 0);

    assert_eq!(
        emu.read_op(X86_REG_RAX).unwrap(),
        Wrapping(0x1234567890ab00ef)
    );
}
