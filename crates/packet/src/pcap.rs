use aegislens_core::{AegisError, AegisResult, Timestamp};
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PcapEndian {
    Little,
    Big,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapGlobalHeader {
    pub endian: PcapEndian,
    pub nanos_resolution: bool,
    pub version_major: u16,
    pub version_minor: u16,
    pub snaplen: u32,
    pub network: u32,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapPacket<'a> {
    pub timestamp: Timestamp,
    pub captured_len: u32,
    pub original_len: u32,
    pub data: &'a [u8],
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PcapFile<'a> {
    pub header: PcapGlobalHeader,
    pub packets: Vec<PcapPacket<'a>>,
}
impl<'a> PcapFile<'a> {
    pub fn parse(data: &'a [u8]) -> AegisResult<Self> {
        if data.len() < 24 {
            return Err(AegisError::Truncated { needed: 24, available: data.len() });
        }
        let magic = &data[0..4];
        let (endian, nanos_resolution) = match magic {
            [0xd4, 0xc3, 0xb2, 0xa1] => (PcapEndian::Little, false),
            [0xa1, 0xb2, 0xc3, 0xd4] => (PcapEndian::Big, false),
            [0x4d, 0x3c, 0xb2, 0xa1] => (PcapEndian::Little, true),
            [0xa1, 0xb2, 0x3c, 0x4d] => (PcapEndian::Big, true),
            _ => return Err(AegisError::InvalidFormat("unknown pcap magic".to_string())),
        };
        let read16 = |buf: &[u8]| -> u16 { match endian { PcapEndian::Little => u16::from_le_bytes([buf[0], buf[1]]), PcapEndian::Big => u16::from_be_bytes([buf[0], buf[1]]) } };
        let read32 = |buf: &[u8]| -> u32 { match endian { PcapEndian::Little => u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]), PcapEndian::Big => u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) } };
        let header = PcapGlobalHeader { endian, nanos_resolution, version_major: read16(&data[4..6]), version_minor: read16(&data[6..8]), snaplen: read32(&data[16..20]), network: read32(&data[20..24]) };
        let mut packets = Vec::new();
        let mut offset = 24usize;
        while offset < data.len() {
            if data.len() - offset < 16 {
                return Err(AegisError::Truncated { needed: offset + 16, available: data.len() });
            }
            let ts_sec = read32(&data[offset..offset + 4]);
            let ts_frac = read32(&data[offset + 4..offset + 8]);
            let incl_len = read32(&data[offset + 8..offset + 12]);
            let orig_len = read32(&data[offset + 12..offset + 16]);
            offset += 16;
            let end = offset.checked_add(incl_len as usize).ok_or_else(|| AegisError::InvalidFormat("pcap packet length overflow".to_string()))?;
            if end > data.len() {
                return Err(AegisError::Truncated { needed: end, available: data.len() });
            }
            packets.push(PcapPacket { timestamp: Timestamp::from_pcap(ts_sec, ts_frac, nanos_resolution), captured_len: incl_len, original_len: orig_len, data: &data[offset..end] });
            offset = end;
            if packets.len() > 100_000 {
                return Err(AegisError::InvalidFormat("pcap packet count safety limit".to_string()));
            }
        }
        Ok(Self { header, packets })
    }
}
