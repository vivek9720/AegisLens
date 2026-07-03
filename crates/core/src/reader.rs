use crate::{read_u16_be, read_u16_le, read_u32_be, read_u32_le, AegisError, AegisResult};
#[derive(Debug, Clone)]
pub struct ByteReader<'a> {
    data: &'a [u8],
    pos: usize,
}
impl<'a> ByteReader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    pub fn position(&self) -> usize {
        self.pos
    }
    pub fn len(&self) -> usize {
        self.data.len()
    }
    pub fn remaining_len(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }
    pub fn remaining(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }
    pub fn peek(&self, n: usize) -> AegisResult<&'a [u8]> {
        if self.remaining_len() < n {
            Err(AegisError::Truncated { needed: n, available: self.remaining_len() })
        } else {
            Ok(&self.data[self.pos..self.pos + n])
        }
    }
    pub fn take(&mut self, n: usize) -> AegisResult<&'a [u8]> {
        let out = self.peek(n)?;
        self.pos += n;
        Ok(out)
    }
    pub fn skip(&mut self, n: usize) -> AegisResult<()> {
        self.take(n).map(|_| ())
    }
    pub fn read_u8(&mut self) -> AegisResult<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn read_u16_be(&mut self) -> AegisResult<u16> {
        read_u16_be(self.take(2)?).ok_or(AegisError::Truncated { needed: 2, available: 0 })
    }
    pub fn read_u16_le(&mut self) -> AegisResult<u16> {
        read_u16_le(self.take(2)?).ok_or(AegisError::Truncated { needed: 2, available: 0 })
    }
    pub fn read_u32_be(&mut self) -> AegisResult<u32> {
        read_u32_be(self.take(4)?).ok_or(AegisError::Truncated { needed: 4, available: 0 })
    }
    pub fn read_u32_le(&mut self) -> AegisResult<u32> {
        read_u32_le(self.take(4)?).ok_or(AegisError::Truncated { needed: 4, available: 0 })
    }
}
pub fn safe_slice(data: &[u8], start: usize, len: usize) -> Option<&[u8]> {
    let end = start.checked_add(len)?;
    data.get(start..end)
}
