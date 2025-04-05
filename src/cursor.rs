use thiserror_no_std::Error;

use crate::{ImmExtKind, PisEndianness, PisSize};

pub struct Cursor<'a> {
    data: &'a [u8],
    off: usize,
}
impl<'a> Cursor<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, off: 0 }
    }
    pub fn off(&self) -> usize {
        self.off
    }
    fn check_advance(&self, amount: usize) -> Result<(), CursorError> {
        let new_off = self.off + amount;

        if new_off > self.data.len() {
            Err(CursorError::EarlyEof {
                required_bytes_amount: new_off,
                actual_bytes_amount: self.data.len(),
            })
        } else {
            Ok(())
        }
    }
    pub fn peek_bytes(&self, amount: usize) -> Result<&'a [u8], CursorError> {
        self.check_advance(amount)?;
        Ok(&self.data[self.off..self.off + amount])
    }
    pub fn next_bytes(&mut self, amount: usize) -> Result<&'a [u8], CursorError> {
        let result = self.peek_bytes(amount)?;
        self.off += amount;
        Ok(result)
    }
    pub fn peek_array<const SIZE: usize>(&self) -> Result<[u8; SIZE], CursorError> {
        self.check_advance(SIZE)?;
        Ok(self.data[self.off..self.off + SIZE].try_into().unwrap())
    }
    pub fn next_array<const SIZE: usize>(&mut self) -> Result<[u8; SIZE], CursorError> {
        let result = self.peek_array::<SIZE>()?;
        self.off += SIZE;
        Ok(result)
    }
    pub fn advance(&mut self, amount: usize) -> Result<(), CursorError> {
        self.check_advance(amount)?;
        self.off += amount;
        Ok(())
    }
    pub fn advance_byte(&mut self) -> Result<(), CursorError> {
        self.advance(1)
    }
    pub fn peek_byte(&self) -> Result<u8, CursorError> {
        Ok(self.peek_bytes(1)?[0])
    }
    pub fn next_byte(&mut self) -> Result<u8, CursorError> {
        Ok(self.next_bytes(1)?[0])
    }
    pub fn next_imm(
        &mut self,
        size: PisSize,
        endianness: PisEndianness,
    ) -> Result<u64, CursorError> {
    }
    pub fn next_imm_ext(&mut self, params: CursorImmExtParams) -> Result<u64, CursorError> {
        assert!(params.extended_size >= params.encoded_size);
        let extended_to_64_bits = match params.encoded_size.bytes() {
            1 => {
                let byte = self.next_byte()?;
                match params.ext_kind {
                    ImmExtKind::Zero => byte as u64,
                    ImmExtKind::Sign => byte as i8 as i64 as u64,
                }
            }
            2 => {
                let bytes = self.next_array::<2>()?;
                let value = match params.endianness {
                    PisEndianness::Little => u16::from_le_bytes(bytes),
                    PisEndianness::Big => u16::from_be_bytes(bytes),
                };
                match params.ext_kind {
                    ImmExtKind::Zero => value as u64,
                    ImmExtKind::Sign => value as i16 as i64 as u64,
                }
            }
            4 => {
                let bytes = self.next_array::<4>()?;
                let value = match params.endianness {
                    PisEndianness::Little => u32::from_le_bytes(bytes),
                    PisEndianness::Big => u32::from_be_bytes(bytes),
                };
                match params.ext_kind {
                    ImmExtKind::Zero => value as u64,
                    ImmExtKind::Sign => value as i32 as i64 as u64,
                }
            }
            8 => {
                let bytes = self.next_array::<8>()?;
                let value = match params.endianness {
                    PisEndianness::Little => u64::from_le_bytes(bytes),
                    PisEndianness::Big => u64::from_be_bytes(bytes),
                };
                // no sign extension can be done here since it is already in the maximum supported size
                value
            }
            encoded_size => panic!("unsupported immediate size {}", encoded_size),
        };
        Ok(extended_to_64_bits & params.extended_size.max_unsigned_val())
    }
}

pub struct CursorImmExtParams {
    pub encoded_size: PisSize,
    pub extended_size: PisSize,
    pub ext_kind: ImmExtKind,
    pub endianness: PisEndianness,
}

#[derive(Debug, Error)]
pub enum CursorError {
    EarlyEof {
        required_bytes_amount: usize,
        actual_bytes_amount: usize,
    },
}
