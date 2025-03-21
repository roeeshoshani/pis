use thiserror_no_std::Error;

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
    pub fn advance(&mut self, amount: usize) -> Result<(), CursorError> {
        self.check_advance(amount)?;
        self.off += amount;
        Ok(())
    }
    pub fn peek_byte(&self) -> Result<u8, CursorError> {
        Ok(self.peek_bytes(1)?[0])
    }
    pub fn next_byte(&mut self) -> Result<u8, CursorError> {
        Ok(self.next_bytes(1)?[0])
    }
}

#[derive(Debug, Error)]
pub enum CursorError {
    OffsetOutOfBounds {
        offset: usize,
        data_len: usize,
    },
    EarlyEof {
        required_bytes_amount: usize,
        actual_bytes_amount: usize,
    },
}
