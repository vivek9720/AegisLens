use aegislens_core::{AegisError, AegisResult};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpSegment<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence: u32,
    pub acknowledgement: u32,
    pub data_offset: u8,
    pub flags: u16,
    pub window: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: &'a [u8],
    pub payload: &'a [u8],
}
impl<'a> TcpSegment<'a> {
    pub fn parse(data: &'a [u8]) -> AegisResult<Self> {
        if data.len() < 20 {
            return Err(AegisError::Truncated { needed: 20, available: data.len() });
        }
        let source_port = u16::from_be_bytes([data[0], data[1]]);
        let destination_port = u16::from_be_bytes([data[2], data[3]]);
        let sequence = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
        let acknowledgement = u32::from_be_bytes([data[8], data[9], data[10], data[11]]);
        let data_offset = data[12] >> 4;
        let header_len = data_offset as usize * 4;
        if header_len < 20 || header_len > data.len() {
            return Err(AegisError::Truncated { needed: header_len.max(20), available: data.len() });
        }
        let flags = (((data[12] & 1) as u16) << 8) | data[13] as u16;
        let window = u16::from_be_bytes([data[14], data[15]]);
        let checksum = u16::from_be_bytes([data[16], data[17]]);
        let urgent_pointer = u16::from_be_bytes([data[18], data[19]]);
        Ok(Self { source_port, destination_port, sequence, acknowledgement, data_offset, flags, window, checksum, urgent_pointer, options: &data[20..header_len], payload: &data[header_len..] })
    }
    pub fn flag_names(&self) -> Vec<&'static str> {
        let mut out = Vec::new();
        for (mask, name) in [(0x100, "ns"), (0x080, "cwr"), (0x040, "ece"), (0x020, "urg"), (0x010, "ack"), (0x008, "psh"), (0x004, "rst"), (0x002, "syn"), (0x001, "fin")] {
            if self.flags & mask != 0 {
                out.push(name);
            }
        }
        out
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpDatagram<'a> {
    pub source_port: u16,
    pub destination_port: u16,
    pub length: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}
impl<'a> UdpDatagram<'a> {
    pub fn parse(data: &'a [u8]) -> AegisResult<Self> {
        if data.len() < 8 {
            return Err(AegisError::Truncated { needed: 8, available: data.len() });
        }
        let source_port = u16::from_be_bytes([data[0], data[1]]);
        let destination_port = u16::from_be_bytes([data[2], data[3]]);
        let length = u16::from_be_bytes([data[4], data[5]]);
        let checksum = u16::from_be_bytes([data[6], data[7]]);
        if length < 8 || length as usize > data.len() {
            return Err(AegisError::Truncated { needed: length as usize, available: data.len() });
        }
        Ok(Self { source_port, destination_port, length, checksum, payload: &data[8..length as usize] })
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportPacket<'a> {
    Tcp(TcpSegment<'a>),
    Udp(UdpDatagram<'a>),
    Other { protocol: u8, payload: &'a [u8] },
}
impl<'a> TransportPacket<'a> {
    pub fn parse(protocol: u8, data: &'a [u8]) -> AegisResult<Self> {
        match protocol {
            6 => Ok(TransportPacket::Tcp(TcpSegment::parse(data)?)),
            17 => Ok(TransportPacket::Udp(UdpDatagram::parse(data)?)),
            _ => Ok(TransportPacket::Other { protocol, payload: data }),
        }
    }
    pub fn ports(&self) -> Option<(u16, u16)> {
        match self {
            TransportPacket::Tcp(t) => Some((t.source_port, t.destination_port)),
            TransportPacket::Udp(u) => Some((u.source_port, u.destination_port)),
            TransportPacket::Other { .. } => None,
        }
    }
}
