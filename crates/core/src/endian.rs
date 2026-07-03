pub fn read_u16_be(data: &[u8]) -> Option<u16> {
    Some(u16::from_be_bytes([*data.get(0)?, *data.get(1)?]))
}
pub fn read_u16_le(data: &[u8]) -> Option<u16> {
    Some(u16::from_le_bytes([*data.get(0)?, *data.get(1)?]))
}
pub fn read_u32_be(data: &[u8]) -> Option<u32> {
    Some(u32::from_be_bytes([*data.get(0)?, *data.get(1)?, *data.get(2)?, *data.get(3)?]))
}
pub fn read_u32_le(data: &[u8]) -> Option<u32> {
    Some(u32::from_le_bytes([*data.get(0)?, *data.get(1)?, *data.get(2)?, *data.get(3)?]))
}
pub fn write_u16_be(value: u16, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}
pub fn write_u32_be(value: u32, out: &mut Vec<u8>) {
    out.extend_from_slice(&value.to_be_bytes());
}
pub fn align_up(value: usize, align: usize) -> usize {
    if align == 0 {
        value
    } else {
        let rem = value % align;
        if rem == 0 { value } else { value + (align - rem) }
    }
}
