use aegislens_core::{classify_ipv4, internet_checksum, AegisError, AegisResult, Ipv4AddrExt};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ipv4Packet<'a> {
    pub version: u8,
    pub ihl: u8,
    pub dscp_ecn: u8,
    pub total_len: u16,
    pub identification: u16,
    pub flags: u8,
    pub fragment_offset: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub checksum: u16,
    pub source: Ipv4AddrExt,
    pub destination: Ipv4AddrExt,
    pub options: &'a [u8],
    pub payload: &'a [u8],
    pub checksum_valid: bool,
}
impl<'a> Ipv4Packet<'a> {
    pub fn parse(data: &'a [u8]) -> AegisResult<Self> {
        if data.len() < 20 {
            return Err(AegisError::Truncated { needed: 20, available: data.len() });
        }
        let version = data[0] >> 4;
        let ihl = data[0] & 0x0f;
        if version != 4 {
            return Err(AegisError::InvalidFormat(format!("unexpected IP version {version}")));
        }
        let header_len = (ihl as usize) * 4;
        if ihl < 5 || data.len() < header_len {
            return Err(AegisError::Truncated { needed: header_len.max(20), available: data.len() });
        }
        let total_len = u16::from_be_bytes([data[2], data[3]]);
        if total_len as usize > data.len() {
            return Err(AegisError::Truncated { needed: total_len as usize, available: data.len() });
        }
        let identification = u16::from_be_bytes([data[4], data[5]]);
        let frag = u16::from_be_bytes([data[6], data[7]]);
        let flags = (frag >> 13) as u8;
        let fragment_offset = frag & 0x1fff;
        let ttl = data[8];
        let protocol = data[9];
        let checksum = u16::from_be_bytes([data[10], data[11]]);
        let source = Ipv4AddrExt::new(data[12], data[13], data[14], data[15]);
        let destination = Ipv4AddrExt::new(data[16], data[17], data[18], data[19]);
        let options = &data[20..header_len];
        let payload_end = total_len as usize;
        let payload = if payload_end >= header_len { &data[header_len..payload_end] } else { &[] };
        let checksum_valid = internet_checksum(&data[..header_len]) == 0;
        Ok(Self { version, ihl, dscp_ecn: data[1], total_len, identification, flags, fragment_offset, ttl, protocol, checksum, source, destination, options, payload, checksum_valid })
    }
    pub fn is_fragmented(&self) -> bool {
        self.fragment_offset != 0 || self.flags & 0b001 != 0
    }
    pub fn path_risk_notes(&self) -> Vec<String> {
        let mut notes = Vec::new();
        if self.ttl <= 1 {
            notes.push("ttl-expiring-near-sensor".to_string());
        }
        if !self.checksum_valid {
            notes.push("invalid-ipv4-checksum".to_string());
        }
        if self.is_fragmented() {
            notes.push("fragmented-ipv4".to_string());
        }
        if classify_ipv4(self.source) == "global" && classify_ipv4(self.destination) == "private" {
            notes.push("inbound-global-to-private".to_string());
        }
        notes
    }
}
