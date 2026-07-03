use aegislens_core::{read_u16_be, AegisError, AegisResult};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacAddress(pub [u8; 6]);
impl MacAddress {
    pub fn is_broadcast(&self) -> bool {
        self.0 == [0xff; 6]
    }
    pub fn is_multicast(&self) -> bool {
        self.0[0] & 1 == 1
    }
    pub fn render(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(":")
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthernetFrame<'a> {
    pub destination: MacAddress,
    pub source: MacAddress,
    pub ethertype: u16,
    pub vlan_tags: Vec<u16>,
    pub payload: &'a [u8],
}
impl<'a> EthernetFrame<'a> {
    pub fn parse(data: &'a [u8]) -> AegisResult<Self> {
        if data.len() < 14 {
            return Err(AegisError::Truncated { needed: 14, available: data.len() });
        }
        let mut dst = [0u8; 6];
        let mut src = [0u8; 6];
        dst.copy_from_slice(&data[0..6]);
        src.copy_from_slice(&data[6..12]);
        let mut offset = 12;
        let mut ethertype = read_u16_be(&data[offset..offset + 2]).unwrap();
        offset += 2;
        let mut vlan_tags = Vec::new();
        while ethertype == 0x8100 || ethertype == 0x88a8 {
            if data.len() < offset + 4 {
                return Err(AegisError::Truncated { needed: offset + 4, available: data.len() });
            }
            vlan_tags.push(read_u16_be(&data[offset..offset + 2]).unwrap());
            ethertype = read_u16_be(&data[offset + 2..offset + 4]).unwrap();
            offset += 4;
        }
        Ok(Self { destination: MacAddress(dst), source: MacAddress(src), ethertype, vlan_tags, payload: &data[offset..] })
    }
    pub fn ethertype_name(&self) -> &'static str {
        match self.ethertype {
            0x0800 => "ipv4",
            0x0806 => "arp",
            0x86dd => "ipv6",
            0x8847 => "mpls-unicast",
            0x8848 => "mpls-multicast",
            _ => "unknown",
        }
    }
}
