use pis::{
    x86::{X86CpuMode, X86Ctx, X86SegmentDefaultOperandSize},
    ArchCtx,
};

fn main() {
    let ctx = X86Ctx {
        cpu_mode: X86CpuMode::ProtectedMode,
        code_segment_default_operand_size: X86SegmentDefaultOperandSize::B32,
    };
    let res = ctx.translate(&[0x41, 0x51]);
    println!("{}", res);
}
