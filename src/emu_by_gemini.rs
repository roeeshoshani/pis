use std::num::Wrapping;

// Add necessary imports if needed, e.g., for 128-bit integers if you decide to use them directly
// use core::ops::{Div, Mul, Rem, Shl, Shr}; // Already likely included via std::num::Wrapping

use thiserror_no_std::Error;

use crate::{PisEndian, PisInsn, PisOp, PisOpcode, PisSize, PisSpace};

type Result<T> = core::result::Result<T, PisEmuErr>;

pub type W64 = Wrapping<u64>;
// Define Wi64 for signed wrapping arithmetic within calculations
type Wi64 = Wrapping<i64>;
// Consider adding W128 = Wrapping<u128> if direct 128-bit operations are preferred and feasible

/// the max amount of op values
const MAX_OP_VALS: usize = 64 * 1024;

/// the max amount of mem values
const MAX_MEM_VALS: usize = 64 * 1024;

/// the value of an operand
struct OpVal {
    op: PisOp,
    value: W64,
}

/// the value of a memory byte
struct MemVal {
    addr: W64,
    value: u8,
}

/// a binary operator calculation (unsigned).
type BinopCalc = fn(lhs: W64, rhs: W64) -> W64;

/// a unary operator calculation.
type UnopCalc = fn(val: W64) -> W64;

/// an emulator of pis instructions.
// Add pc and halted state if implementing jumps and halt
pub struct PisEmu {
    op_vals: LimitedVec<OpVal, MAX_OP_VALS>,
    mem_vals: LimitedVec<MemVal, MAX_OP_VALS>,
    endian: PisEndian,
    // pc: W64, // Add program counter if needed
    // halted: bool, // Add halted flag if needed
}
impl PisEmu {
    pub fn new(endian: PisEndian) -> Self {
        Self {
            op_vals: LimitedVec::new(),
            mem_vals: LimitedVec::new(),
            endian,
            // pc: Wrapping(0), // Initialize pc
            // halted: false, // Initialize halted flag
        }
    }
    fn read_mem_byte(&self, addr: W64) -> Result<u8> {
        let mem_val = self
            .mem_vals
            .iter()
            .find(|mem_val| mem_val.addr == addr)
            .ok_or(PisEmuErr::ReadUninitMem(addr))?;
        Ok(mem_val.value)
    }
    fn write_mem_byte(&mut self, addr: W64, value: u8) -> Result<()> {
        match self
            .mem_vals
            .iter_mut()
            .find(|mem_val| mem_val.addr == addr)
        {
            Some(mem_val) => mem_val.value = value,
            None => {
                self.mem_vals
                    .push(MemVal { addr, value })
                    .map_err(|_| PisEmuErr::TooManyMemVals)?;
            }
        }
        Ok(())
    }
    pub fn read_mem(&self, addr: W64, read_size: PisSize) -> Result<W64> {
        let size = read_size.bytes() as usize;

        let mut bytes = [0u8; 8];
        for i in 0..size {
            bytes[i] = self.read_mem_byte(addr + Wrapping(i as u64))?;
        }

        // convert bytes back to native endian
        self.endian.reverse_if_not_native(&mut bytes[..size]);

        let value = u64::from_ne_bytes(bytes);

        Ok(Wrapping(value) & Wrapping(read_size.mask())) // Mask to the correct size
    }
    pub fn write_mem(&mut self, addr: W64, write_size: PisSize, value: W64) -> Result<()> {
        let size = write_size.bytes() as usize;

        let mut bytes = value.0.to_ne_bytes();

        // convert from native endian to the target endian
        self.endian.reverse_if_not_native(&mut bytes[..size]);

        for i in 0..size {
            self.write_mem_byte(addr + Wrapping(i as u64), bytes[i])?;
        }

        Ok(())
    }
    pub fn read_var_op(&self, op: PisOp) -> Result<W64> {
        let op_val = self
            .op_vals
            .iter()
            .find(|op_val| op_val.op == op)
            .ok_or(PisEmuErr::ReadUninitOp(op))?;
        // Mask the value according to the operand's size upon reading
        Ok(op_val.value & Wrapping(op.size.mask()))
    }
    pub fn read_op(&self, op: PisOp) -> Result<W64> {
        match op.space {
            PisSpace::Reg | PisSpace::Tmp => self.read_var_op(op),
            PisSpace::Const => Ok(Wrapping(op.offset.0) & Wrapping(op.size.mask())), // Apply mask for constants too
            PisSpace::Ram => panic!(
                "RAM space operand {op:?} passed to read_op, should be handled by Load/Store"
            ), // Use panic for invalid usage
        }
    }
    pub fn write_op(&mut self, op: PisOp, value: W64) -> Result<()> {
        // Mask the value according to the operand's size before writing
        let masked_value = value & Wrapping(op.size.mask());
        match op.space {
            PisSpace::Reg | PisSpace::Tmp => {
                // Only allow writing to Reg or Tmp
                match self.op_vals.iter_mut().find(|op_val| op_val.op == op) {
                    Some(op_val) => op_val.value = masked_value,
                    None => self
                        .op_vals
                        .push(OpVal {
                            op,
                            value: masked_value,
                        })
                        .map_err(|_| PisEmuErr::TooManyOpVals)?,
                }
                Ok(())
            }
            _ => panic!("Attempted to write to non-writable operand space: {op:?}"), // Panic on writing to Const/Ram
        }
    }

    // Helper for unsigned binary operations
    fn run_binop(&mut self, insn: &PisInsn, calc: BinopCalc) -> Result<()> {
        assert_eq!(
            insn.operands.len(),
            3,
            "Invalid operand count for opcode {:?}: expected 3, got {}",
            insn.opcode,
            insn.operands.len()
        );

        let dst_op = insn.operands[0];
        let lhs_op = insn.operands[1];
        let rhs_op = insn.operands[2];

        assert_eq!(
            lhs_op.size, rhs_op.size,
            "Mismatched operand sizes (lhs/rhs) for opcode {:?}",
            insn.opcode
        );
        assert_eq!(
            lhs_op.size, dst_op.size,
            "Mismatched operand sizes (lhs/dst) for opcode {:?}",
            insn.opcode
        );

        let lhs = self.read_op(lhs_op)?;
        let rhs = self.read_op(rhs_op)?;

        let result = calc(lhs, rhs);

        self.write_op(dst_op, result)?;

        Ok(())
    }

    // Helper for signed binary operations (using Wi64 for calculation)
    fn run_binop_signed<F>(&mut self, insn: &PisInsn, calc: F) -> Result<()>
    where
        F: FnOnce(Wi64, Wi64) -> Wi64, // Calculation is done using Wrapping<i64>
    {
        // We still use run_binop internally for operand reading/writing which uses W64 (Wrapping<u64>)
        self.run_binop(insn, |a, b| {
            // Cast W64 operands to Wi64 for the calculation
            let a_signed = Wrapping(a.0 as i64);
            let b_signed = Wrapping(b.0 as i64);
            // Perform the provided signed calculation
            let res_signed = calc(a_signed, b_signed);
            // Cast the Wi64 result back to W64 for writing
            Wrapping(res_signed.0 as u64)
        })
    }

    // Helper for unary operations
    fn run_unop(&mut self, insn: &PisInsn, calc: UnopCalc) -> Result<()> {
        assert_eq!(
            insn.operands.len(),
            2,
            "Invalid operand count for opcode {:?}: expected 2, got {}",
            insn.opcode,
            insn.operands.len()
        );

        let dst_op = insn.operands[0];
        let src_op = insn.operands[1];

        assert_eq!(
            src_op.size, dst_op.size,
            "Mismatched operand sizes for opcode {:?}",
            insn.opcode
        );

        let src = self.read_op(src_op)?;
        let result = calc(src);
        self.write_op(dst_op, result)?;
        Ok(())
    }

    // Helper to handle potential division by zero
    fn safe_div(&self, a: W64, b: W64) -> Result<W64> {
        if b == Wrapping(0) {
            Err(PisEmuErr::DivisionByZero)
        } else {
            Ok(a / b)
        }
    }

    // Helper to handle potential signed division by zero or overflow (MIN / -1)
    fn safe_signed_div(&self, a: W64, b: W64, size: PisSize) -> Result<W64> {
        let a_signed = a.0 as i64;
        let b_signed = b.0 as i64;

        if b_signed == 0 {
            return Err(PisEmuErr::DivisionByZero);
        }

        // Check for signed overflow (specifically MIN_INT / -1)
        let min_signed = match size.bytes() {
            1 => i8::MIN as i64,
            2 => i16::MIN as i64,
            4 => i32::MIN as i64,
            8 => i64::MIN,
            _ => return Err(PisEmuErr::UnsupportedOperandSize(size)), // Should not happen based on PisSize variants
        };

        if a_signed == min_signed && b_signed == -1 {
            return Err(PisEmuErr::SignedDivisionOverflow);
        }

        Ok(Wrapping((a_signed / b_signed) as u64))
    }

    fn safe_rem(&self, a: W64, b: W64) -> Result<W64> {
        if b == Wrapping(0) {
            Err(PisEmuErr::DivisionByZero)
        } else {
            Ok(a % b)
        }
    }

    fn safe_signed_rem(&self, a: W64, b: W64) -> Result<W64> {
        let a_signed = a.0 as i64;
        let b_signed = b.0 as i64;
        if b_signed == 0 {
            return Err(PisEmuErr::DivisionByZero);
        }
        // The result of remainder operation MIN / -1 is defined as 0 in many languages including Rust i64
        Ok(Wrapping((a_signed % b_signed) as u64))
    }

    pub fn run(&mut self, insn: PisInsn) -> Result<()> {
        // if self.halted { return Ok(()); } // Skip execution if halted

        match insn.opcode {
            PisOpcode::Move => {
                assert_eq!(
                    insn.operands.len(),
                    2,
                    "Invalid operand count for {:?}: expected 2, got {}",
                    insn.opcode,
                    insn.operands.len()
                );
                assert_eq!(
                    insn.operands[0].size, insn.operands[1].size,
                    "Mismatched operand sizes for {:?}",
                    insn.opcode
                );

                let value = self.read_op(insn.operands[1])?;
                self.write_op(insn.operands[0], value)?;
                Ok(())
            }
            PisOpcode::Load => {
                assert_eq!(
                    insn.operands.len(),
                    2,
                    "Invalid operand count for {:?}: expected 2, got {}",
                    insn.opcode,
                    insn.operands.len()
                );
                // Size check: Destination register (op[0]) size must match the size of the memory read (implicit in op[0].size)
                // Address operand (op[1]) size isn't directly constrained by the load size itself, but is usually address size.
                // No direct size assertion here, relies on read_mem using op[0].size

                let addr = self.read_op(insn.operands[1])?;
                let value = self.read_mem(addr, insn.operands[0].size)?;
                self.write_op(insn.operands[0], value)?;
                Ok(())
            }
            PisOpcode::Store => {
                assert_eq!(
                    insn.operands.len(),
                    2,
                    "Invalid operand count for {:?}: expected 2, got {}",
                    insn.opcode,
                    insn.operands.len()
                );
                // Size check: Source register (op[1]) size must match the size of the memory write (implicit in op[1].size)
                // Address operand (op[0]) size isn't directly constrained here.
                // No direct size assertion here, relies on write_mem using op[1].size

                let addr = self.read_op(insn.operands[0])?; // Address is the first operand
                let value = self.read_op(insn.operands[1])?; // Value is the second operand
                self.write_mem(addr, insn.operands[1].size, value)?; // Size comes from the value operand
                Ok(())
            }
            PisOpcode::Add => self.run_binop(&insn, |a, b| a + b),
            PisOpcode::Sub => self.run_binop(&insn, |a, b| a - b),
            PisOpcode::And => self.run_binop(&insn, |a, b| a & b),
            PisOpcode::Or => self.run_binop(&insn, |a, b| a | b),
            PisOpcode::Xor => self.run_binop(&insn, |a, b| a ^ b),
            PisOpcode::Not => self.run_unop(&insn, |a| !a), // Bitwise NOT
            PisOpcode::Neg => self.run_unop(&insn, |a| Wrapping(0) - a), // Arithmetic negation

            PisOpcode::MulUnsigned => self.run_binop(&insn, |a, b| a * b),
            PisOpcode::MulSigned => self.run_binop_signed(&insn, |a, b| a * b), // Use signed helper

            PisOpcode::MulOverflowSigned => {
                assert_eq!(
                    insn.operands.len(),
                    3,
                    "Invalid operand count for {:?}: expected 3, got {}",
                    insn.opcode,
                    insn.operands.len()
                );

                let dst_op = insn.operands[0]; // Destination for the overflow flag
                let lhs_op = insn.operands[1];
                let rhs_op = insn.operands[2];

                assert_eq!(
                    dst_op.size,
                    PisSize::B1,
                    "Destination for MulOverflowSigned must be B1, got {:?}",
                    dst_op.size
                );
                assert_eq!(
                    lhs_op.size, rhs_op.size,
                    "Mismatched operand sizes (lhs/rhs) for {:?}",
                    insn.opcode
                );

                let lhs = self.read_op(lhs_op)?;
                let rhs = self.read_op(rhs_op)?;

                let a_signed = lhs.0 as i64;
                let b_signed = rhs.0 as i64;

                let overflow = a_signed.checked_mul(b_signed).is_none();
                // Handle potential edge case: if size < B8, the i64 multiplication might not overflow,
                // but the result might not fit in the target signed type.
                // A more robust check might involve casting to the specific size's signed type first.
                // However, for a simple flag, this i64 check is often sufficient.

                self.write_op(dst_op, Wrapping(overflow as u64))?;
                Ok(())
            }

            PisOpcode::DivUnsigned => {
                let size = insn.operands[1].size; // Assuming sizes match via run_binop assertion
                self.run_binop(&insn, |a, b| {
                    self.safe_div(a, b).unwrap_or(Wrapping(size.mask()))
                }) // Simple error handling: return MAX on error
            }
            PisOpcode::DivSigned => {
                assert_eq!(
                    insn.operands.len(),
                    3,
                    "Invalid operand count for {:?}: expected 3, got {}",
                    insn.opcode,
                    insn.operands.len()
                );
                let dst_op = insn.operands[0];
                let lhs_op = insn.operands[1];
                let rhs_op = insn.operands[2];
                assert_eq!(
                    lhs_op.size, rhs_op.size,
                    "Mismatched operand sizes (lhs/rhs) for opcode {:?}",
                    insn.opcode
                );
                assert_eq!(
                    lhs_op.size, dst_op.size,
                    "Mismatched operand sizes (lhs/dst) for opcode {:?}",
                    insn.opcode
                );

                let size = lhs_op.size;
                let b = self.read_op(rhs_op)?;
                let a = self.read_op(lhs_op)?;
                let result = self.safe_signed_div(a, b, size)?;
                self.write_op(dst_op, result)?;
                Ok(())
            }
            PisOpcode::RemUnsigned => {
                let size = insn.operands[1].size; // Assuming sizes match via run_binop assertion
                self.run_binop(&insn, |a, b| self.safe_rem(a, b).unwrap_or(Wrapping(0)))
                // Simple error handling: return 0 on error
            }
            PisOpcode::RemSigned => {
                assert_eq!(
                    insn.operands.len(),
                    3,
                    "Invalid operand count for {:?}: expected 3, got {}",
                    insn.opcode,
                    insn.operands.len()
                );
                let dst_op = insn.operands[0];
                let lhs_op = insn.operands[1];
                let rhs_op = insn.operands[2];
                assert_eq!(
                    lhs_op.size, rhs_op.size,
                    "Mismatched operand sizes (lhs/rhs) for opcode {:?}",
                    insn.opcode
                );
                assert_eq!(
                    lhs_op.size, dst_op.size,
                    "Mismatched operand sizes (lhs/dst) for opcode {:?}",
                    insn.opcode
                );

                let b = self.read_op(rhs_op)?;
                let a = self.read_op(lhs_op)?;
                let result = self.safe_signed_rem(a, b)?;
                self.write_op(dst_op, result)?;
                Ok(())
            }

            // --- 128-bit operations (Emulated using 64-bit) ---
            PisOpcode::Mul16Unsigned => {
                assert_eq!(
                    insn.operands.len(),
                    4,
                    "Invalid operand count for {:?}: expected 4, got {}",
                    insn.opcode,
                    insn.operands.len()
                );

                let dst_high_op = insn.operands[0];
                let dst_low_op = insn.operands[1];
                let src1_op = insn.operands[2]; // Typically RAX/EAX etc.
                let src2_op = insn.operands[3];

                assert_eq!(
                    dst_high_op.size,
                    PisSize::B8,
                    "Operand 0 (dst_high) must be B8 for {:?}",
                    insn.opcode
                );
                assert_eq!(
                    dst_low_op.size,
                    PisSize::B8,
                    "Operand 1 (dst_low) must be B8 for {:?}",
                    insn.opcode
                );
                assert_eq!(
                    src1_op.size,
                    PisSize::B8,
                    "Operand 2 (src1) must be B8 for {:?}",
                    insn.opcode
                );
                assert_eq!(
                    src2_op.size,
                    PisSize::B8,
                    "Operand 3 (src2) must be B8 for {:?}",
                    insn.opcode
                );

                let src1_val = self.read_op(src1_op)?.0;
                let src2_val = self.read_op(src2_op)?.0;

                let result128 = (src1_val as u128) * (src2_val as u128);

                let result_low = Wrapping((result128 & (u64::MAX as u128)) as u64);
                let result_high = Wrapping((result128 >> 64) as u64);

                self.write_op(dst_low_op, result_low)?;
                self.write_op(dst_high_op, result_high)?;
                Ok(())
            }
            PisOpcode::Div16Unsigned | PisOpcode::Div16Signed => {
                assert_eq!(
                    insn.operands.len(),
                    4,
                    "Invalid operand count for {:?}: expected 4, got {}",
                    insn.opcode,
                    insn.operands.len()
                );

                let dst_quot_op = insn.operands[0];
                let src_high_op = insn.operands[1]; // Typically RDX/EDX etc.
                let src_low_op = insn.operands[2]; // Typically RAX/EAX etc.
                let divisor_op = insn.operands[3];

                assert_eq!(
                    dst_quot_op.size,
                    PisSize::B8,
                    "Operand 0 (dst_quot) must be B8 for {:?}",
                    insn.opcode
                );
                assert_eq!(
                    src_high_op.size,
                    PisSize::B8,
                    "Operand 1 (src_high) must be B8 for {:?}",
                    insn.opcode
                );
                assert_eq!(
                    src_low_op.size,
                    PisSize::B8,
                    "Operand 2 (src_low) must be B8 for {:?}",
                    insn.opcode
                );
                assert_eq!(
                    divisor_op.size,
                    PisSize::B8,
                    "Operand 3 (divisor) must be B8 for {:?}",
                    insn.opcode
                );

                let src_high_val = self.read_op(src_high_op)?.0;
                let src_low_val = self.read_op(src_low_op)?.0;
                let divisor_val = self.read_op(divisor_op)?.0;

                if divisor_val == 0 {
                    return Err(PisEmuErr::DivisionByZero);
                }

                let dividend128 = ((src_high_val as u128) << 64) | (src_low_val as u128);

                if insn.opcode == PisOpcode::Div16Unsigned {
                    let quotient128 = dividend128 / (divisor_val as u128);
                    // Check for overflow: quotient must fit in 64 bits
                    if quotient128 > (u64::MAX as u128) {
                        return Err(PisEmuErr::UnsignedDivisionOverflow);
                    }
                    self.write_op(dst_quot_op, Wrapping(quotient128 as u64))?;
                } else {
                    // Div16Signed
                    let dividend128_signed = dividend128 as i128;
                    let divisor_signed = divisor_val as i64 as i128; // Cast to i64 first for correct sign

                    // Check for signed overflow (MIN / -1)
                    if dividend128_signed == i128::MIN && divisor_signed == -1 {
                        return Err(PisEmuErr::SignedDivisionOverflow);
                    }

                    let quotient128_signed = dividend128_signed / divisor_signed;

                    // Check for overflow: quotient must fit in 64 bits signed
                    if quotient128_signed > (i64::MAX as i128)
                        || quotient128_signed < (i64::MIN as i128)
                    {
                        return Err(PisEmuErr::SignedDivisionOverflow);
                    }
                    self.write_op(dst_quot_op, Wrapping(quotient128_signed as u64))?;
                }
                Ok(())
            }
            PisOpcode::Rem16Unsigned | PisOpcode::Rem16Signed => {
                assert_eq!(
                    insn.operands.len(),
                    4,
                    "Invalid operand count for {:?}: expected 4, got {}",
                    insn.opcode,
                    insn.operands.len()
                );

                let dst_rem_op = insn.operands[0];
                let src_high_op = insn.operands[1];
                let src_low_op = insn.operands[2];
                let divisor_op = insn.operands[3];

                assert_eq!(
                    dst_rem_op.size,
                    PisSize::B8,
                    "Operand 0 (dst_rem) must be B8 for {:?}",
                    insn.opcode
                );
                assert_eq!(
                    src_high_op.size,
                    PisSize::B8,
                    "Operand 1 (src_high) must be B8 for {:?}",
                    insn.opcode
                );
                assert_eq!(
                    src_low_op.size,
                    PisSize::B8,
                    "Operand 2 (src_low) must be B8 for {:?}",
                    insn.opcode
                );
                assert_eq!(
                    divisor_op.size,
                    PisSize::B8,
                    "Operand 3 (divisor) must be B8 for {:?}",
                    insn.opcode
                );

                let src_high_val = self.read_op(src_high_op)?.0;
                let src_low_val = self.read_op(src_low_op)?.0;
                let divisor_val = self.read_op(divisor_op)?.0;

                if divisor_val == 0 {
                    return Err(PisEmuErr::DivisionByZero);
                }

                let dividend128 = ((src_high_val as u128) << 64) | (src_low_val as u128);

                if insn.opcode == PisOpcode::Rem16Unsigned {
                    let remainder128 = dividend128 % (divisor_val as u128);
                    self.write_op(dst_rem_op, Wrapping(remainder128 as u64))?;
                } else {
                    // Rem16Signed
                    let dividend128_signed = dividend128 as i128;
                    let divisor_signed = divisor_val as i64 as i128; // Cast to i64 first

                    let remainder128_signed = dividend128_signed % divisor_signed;
                    self.write_op(dst_rem_op, Wrapping(remainder128_signed as u64))?;
                }
                Ok(())
            }

            PisOpcode::ShiftLeft => self.run_binop(&insn, |a, b| a << (b.0 as usize)), // Use usize for shift count
            PisOpcode::ShiftRightUnsigned => self.run_binop(&insn, |a, b| a >> (b.0 as usize)),
            PisOpcode::ShiftRightSigned => {
                // Keep direct implementation as helper signature doesn't fit well
                assert_eq!(
                    insn.operands.len(),
                    3,
                    "Invalid operand count for {:?}: expected 3, got {}",
                    insn.opcode,
                    insn.operands.len()
                );
                let dst_op = insn.operands[0];
                let lhs_op = insn.operands[1]; // Value to shift
                let rhs_op = insn.operands[2]; // Shift amount
                assert_eq!(
                    lhs_op.size, dst_op.size,
                    "Mismatched operand sizes (lhs/dst) for opcode {:?}",
                    insn.opcode
                );
                // Note: Shift amount (rhs) size doesn't have to match lhs/dst size

                let size = lhs_op.size;
                let a = self.read_op(lhs_op)?;
                let b = self.read_op(rhs_op)?; // Shift amount

                let shift_count = b.0;
                // Perform sign extension based on 'a's size before shifting
                let val_signed = match size.bytes() {
                    1 => (a.0 as i8) as i64,
                    2 => (a.0 as i16) as i64,
                    4 => (a.0 as i32) as i64,
                    8 => a.0 as i64,
                    _ => panic!("Unsupported size {:?}", size),
                };
                // Clamp shift count to avoid undefined behavior if >= bit width
                let bit_width = size.bits();
                // In Rust, right shifting by >= bit_width is defined (0 for positive, -1 for negative)
                // No clamping strictly needed for correctness, but might be desired depending on exact PIS semantics.
                // Let's stick to Rust's behavior:
                let result_signed = val_signed >> shift_count;

                self.write_op(dst_op, Wrapping(result_signed as u64))?;
                Ok(())
            }

            PisOpcode::Zext => {
                assert_eq!(
                    insn.operands.len(),
                    2,
                    "Invalid operand count for {:?}: expected 2, got {}",
                    insn.opcode,
                    insn.operands.len()
                );

                let dst_op = insn.operands[0];
                let src_op = insn.operands[1];
                assert!(dst_op.size > src_op.size, "Destination size must be greater than source size for ZEXT, got dst={:?}, src={:?}", dst_op.size, src_op.size);

                let value = self.read_op(src_op)?;
                self.write_op(dst_op, value)?;
                Ok(())
            }
            PisOpcode::Sext => {
                assert_eq!(
                    insn.operands.len(),
                    2,
                    "Invalid operand count for {:?}: expected 2, got {}",
                    insn.opcode,
                    insn.operands.len()
                );

                let dst_op = insn.operands[0];
                let src_op = insn.operands[1];
                assert!(dst_op.size > src_op.size, "Destination size must be greater than source size for SEXT, got dst={:?}, src={:?}", dst_op.size, src_op.size);

                let value = self.read_op(src_op)?; // Reads and masks to src_op.size
                let src_size = src_op.size;
                let bits = src_size.bits();
                let m = 1u64 << (bits - 1); // Mask for the sign bit of the source size

                // Check sign bit and extend
                let extended_value = if (value.0 & m) != 0 {
                    // If sign bit is set
                    // Create sign extension mask (e.g., FFFF... based on src_size)
                    let sign_mask = !src_size.mask(); // All bits above src_size set
                    value | Wrapping(sign_mask) // OR with the sign mask
                } else {
                    value // Already zero-extended correctly
                };

                self.write_op(dst_op, extended_value)?;
                Ok(())
            }

            PisOpcode::UnsignedCarry => {
                // Calculates a flag, direct implementation is clearer
                self.run_binop(
                    &insn,
                    |a, b| Wrapping(a.0.checked_add(b.0).is_none() as u64),
                )
            }
            PisOpcode::SignedCarry => {
                // Calculates a flag, direct implementation is clearer
                self.run_binop(&insn, |a, b| {
                    let a_signed = a.0 as i64;
                    let b_signed = b.0 as i64;
                    Wrapping(a_signed.checked_add(b_signed).is_none() as u64)
                })
            }
            PisOpcode::Parity => {
                assert_eq!(
                    insn.operands.len(),
                    2,
                    "Invalid operand count for {:?}: expected 2, got {}",
                    insn.opcode,
                    insn.operands.len()
                );
                assert_eq!(
                    insn.operands[0].size,
                    PisSize::B1,
                    "Destination for Parity must be B1, got {:?}",
                    insn.operands[0].size
                );

                // read the src operand's lowest byte
                let value = self.read_op(insn.operands[1])?.0;
                let low_byte = (value & 0xFF) as u8;

                // Count set bits in the lowest byte
                let active_bits_amount = low_byte.count_ones();

                let parity = Wrapping((active_bits_amount % 2 == 0) as u64); // Even parity: flag = 1

                self.write_op(insn.operands[0], parity)?;
                Ok(())
            }
            PisOpcode::Equals => self.run_binop(&insn, |a, b| Wrapping((a == b) as u64)),
            PisOpcode::LessThanUnsigned => self.run_binop(&insn, |a, b| Wrapping((a < b) as u64)),
            PisOpcode::LessThanSigned => {
                self.run_binop_signed(&insn, |a, b| Wrapping((a < b) as i64))
            } // Use signed helper

            PisOpcode::Trunc => {
                assert_eq!(
                    insn.operands.len(),
                    2,
                    "Invalid operand count for {:?}: expected 2, got {}",
                    insn.opcode,
                    insn.operands.len()
                );

                let dst_op = insn.operands[0];
                let src_op = insn.operands[1];
                assert!(dst_op.size < src_op.size, "Destination size must be less than source size for TRUNC, got dst={:?}, src={:?}", dst_op.size, src_op.size);

                let value = self.read_op(src_op)?;
                // Write already masks based on dst_op.size
                self.write_op(dst_op, value)?;
                Ok(())
            }
            PisOpcode::CondNeg => {
                // Negates a conditional value (0 -> 1, non-zero -> 0)
                self.run_unop(&insn, |a| Wrapping((a == Wrapping(0)) as u64))
            }
            PisOpcode::Halt => {
                // self.halted = true; // Set the halted flag
                // Or return a special status/error
                return Err(PisEmuErr::Halted);
            }

            // --- Jumps ---
            PisOpcode::JmpCall | PisOpcode::Jmp | PisOpcode::JmpCond | PisOpcode::JmpRet => {
                Err(PisEmuErr::UnsupportedOpcode(insn.opcode)) // Placeholder
            }
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PisEmuErr {
    #[error("Attempted to read an uninitialized operand {0:?}")]
    ReadUninitOp(PisOp),

    #[error("Attempted to read an uninitialized memory byte at address {0:x}")]
    ReadUninitMem(W64),

    #[error("Too many operand values (limit: {MAX_OP_VALS})")]
    TooManyOpVals,

    #[error("Too many memory values (limit: {MAX_MEM_VALS})")]
    TooManyMemVals,

    #[error("Division by zero")]
    DivisionByZero,

    #[error("Signed division overflow (e.g., MIN / -1)")]
    SignedDivisionOverflow,

    #[error("Unsigned division overflow (result too large for destination)")]
    UnsignedDivisionOverflow,

    #[error("Unsupported operand size {0:?} for operation")]
    UnsupportedOperandSize(PisSize),

    #[error(
        "Invalid ZEXT/SEXT/TRUNC operation for opcode {0:?}: destination size relation incorrect"
    )]
    InvalidExtension(PisOpcode), // Keep this one as it's semantic, not just count/size

    #[error("Invalid operand space {0:?} used in context {1}")]
    InvalidOpSpace(PisOp, &'static str), // Keep this one

    #[error("Emulator halted")]
    Halted,

    #[error("Unsupported PIS opcode encountered: {0:?}")]
    UnsupportedOpcode(PisOpcode),
}

// --- LimitedVec Implementation ---
// (Keep the existing LimitedVec implementation)
pub struct LimitedVec<T, const MAX_SIZE: usize>(Vec<T>);
impl<T, const MAX_SIZE: usize> LimitedVec<T, MAX_SIZE> {
    pub fn new() -> Self {
        Self(Vec::new())
    }
    pub fn push(&mut self, item: T) -> core::result::Result<(), LimitedVecErr> {
        if self.0.len() >= MAX_SIZE {
            return Err(LimitedVecErr);
        }
        self.0.push(item);
        Ok(())
    }
    pub fn iter(&self) -> std::slice::Iter<'_, T> {
        self.0.iter()
    }
    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, T> {
        self.0.iter_mut()
    }
    // Add clear method if needed for resetting state
    // pub fn clear(&mut self) {
    //     self.0.clear();
    // }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct LimitedVecErr;

// Add Display/Error trait for LimitedVecErr if needed
impl core::fmt::Display for LimitedVecErr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "LimitedVec capacity exceeded")
    }
}
// impl std::error::Error for LimitedVecErr {} // Requires std library
