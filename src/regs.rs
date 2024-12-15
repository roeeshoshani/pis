use crate::{PisOff, PisSize};

#[macro_export]
macro_rules! define_reg_operand {
    {$name: ident, $offset: expr, $size: expr} => {
        pub const $name: PisOp = PisOp {
            space: PisSpace::Reg,
            offset: $offset,
            size: $size,
        };

    };
}

#[macro_export]
macro_rules! define_reg_operands_single {
    {$step_size: literal, $size: expr, $prev_name: ident, $name: ident} => {
        define_reg_operand! {$name, PisOff($prev_name.offset.0 + $step_size), $size}
    };
}

#[macro_export]
macro_rules! define_reg_operands_inner {
    // the case for the last operand
    {$spec: expr, $prev_name: ident, $name: ident} => {
        define_reg_operand! {$name, PisOff($prev_name.offset.0 + $spec.step_size), $spec.size}
    };

    // the common case of the non-last operand
    {$spec: expr, $prev_name: ident, $name: ident, $($names: ident),+} => {
        // define the current operand
        define_reg_operands_inner! {$spec, $prev_name, $name}

        // define the rest of the operands
        define_reg_operands_inner! {$spec, $name, $($names),+}
    };
}

#[macro_export]
macro_rules! define_reg_operands {
    {$spec: expr, $first_name: ident, $($name: ident),+ $(,)?} => {
        const _: DefineRegOperandsSpec = $spec;

        // define the first operand with offset 0
        define_reg_operand! {$first_name, $spec.start_offset, $spec.size}

        // define the rest of the operands following it
        define_reg_operands_inner! {$spec, $first_name, $($name),+}
    };
}

pub struct DefineRegOperandsSpec {
    pub start_offset: PisOff,
    pub step_size: u64,
    pub size: PisSize,
}
