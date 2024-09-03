use pis::Context;
fn main() {
    let ctx = Context::new();
    let res = ctx.translate(&[0x50]);
    println!("{}", res);
}
