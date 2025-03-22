use super::{
    tables::{OpcodeByteTable, FIRST_OPCODE_BYTE_TABLE},
    X86LiftArgs, X86LiftErr, X86SpecificLiftErr,
};

fn lift_opcode_byte(opcode_byte: u8, table: &OpcodeByteTable) -> Result<(), X86LiftErr> {
    todo!()
}

pub fn lift(args: &mut X86LiftArgs) -> Result<(), X86LiftErr> {
    let first_opcode_byte = args.generic.code.next_byte()?;
    if first_opcode_byte == 0x0f {
        // 2 or 3 byte opcode
        let second_opcode_byte = args.generic.code.next_byte()?;
        if second_opcode_byte == 0x38 || second_opcode_byte == 0x3a {
            // 3 byte opcode
            return Err(X86LiftErr::UnsupportedInsn);
        } else {
            // 2 byte opcode
            return Err(X86LiftErr::UnsupportedInsn);
        }
    } else {
        // 1 byte opcode
        lift_opcode_byte(first_opcode_byte, &FIRST_OPCODE_BYTE_TABLE);
    }
    Ok(())
}
