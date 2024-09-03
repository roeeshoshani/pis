use pis::Context;
fn main() {
    let ctx = Context::new();
    let res = ctx.translate(&[0xf0, 0x66, 0x50]);
    println!("{}", res);
}
