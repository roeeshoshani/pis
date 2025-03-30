use crate::{LiftErr, PisOp, PisSize};
use thiserror_no_std::Error;

pub struct TmpOpAllocator {
    cur_tmp_offset: u64,
}
impl TmpOpAllocator {
    pub fn new() -> Self {
        Self { cur_tmp_offset: 0 }
    }
    pub fn alloc(&mut self, size: PisSize) -> Result<PisOp, TooManyTmpsErr> {
        let result = PisOp::tmp(self.cur_tmp_offset, size);
        self.cur_tmp_offset = self
            .cur_tmp_offset
            .checked_add(size.bytes() as u64)
            .ok_or(TooManyTmpsErr)?;
        Ok(result)
    }
}

#[derive(Error)]
#[error("too many tmps")]
pub struct TooManyTmpsErr;
