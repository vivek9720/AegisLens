use crate::{AegisError, AegisResult};
use std::fmt;
use std::str::FromStr;
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ipv4AddrExt(pub u32);
impl Ipv4AddrExt {
    pub fn new(a: u8, b: u8, c: u8, d: u8) -> Self {
        Self(u32::from_be_bytes([a, b, c, d]))
    }
    pub fn octets(self) -> [u8; 4] {
        self.0.to_be_bytes()
    }
    pub fn is_private(self) -> bool {
        let [a, b, _, _] = self.octets();
        a == 10 || (a == 172 && (16..=31).contains(&b)) || (a == 192 && b == 168)
    }
    pub fn is_loopback(self) -> bool {
        self.octets()[0] == 127
    }
    pub fn is_link_local(self) -> bool {
        let [a, b, _, _] = self.octets();
        a == 169 && b == 254
    }
    pub fn is_multicast(self) -> bool {
        (224..=239).contains(&self.octets()[0])
    }
    pub fn is_global_unicast(self) -> bool {
        !(self.is_private() || self.is_loopback() || self.is_link_local() || self.is_multicast() || self.0 == 0 || self.0 == u32::MAX)
    }
    pub fn network(self, prefix: u8) -> Self {
        Self(self.0 & prefix_to_mask(prefix))
    }
}
impl fmt::Display for Ipv4AddrExt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.octets();
        write!(f, "{a}.{b}.{c}.{d}")
    }
}
impl FromStr for Ipv4AddrExt {
    type Err = AegisError;
    fn from_str(input: &str) -> AegisResult<Self> {
        let parts: Vec<&str> = input.trim().split('.').collect();
        if parts.len() != 4 {
            return Err(AegisError::InvalidFormat(format!("invalid IPv4 address: {input}")));
        }
        let mut octets = [0u8; 4];
        for (idx, part) in parts.iter().enumerate() {
            if part.is_empty() || part.len() > 3 || !part.chars().all(|c| c.is_ascii_digit()) {
                return Err(AegisError::InvalidFormat(format!("invalid IPv4 address: {input}")));
            }
            octets[idx] = part.parse::<u8>().map_err(|_| AegisError::InvalidFormat(format!("invalid IPv4 octet in {input}")))?;
        }
        Ok(Self::new(octets[0], octets[1], octets[2], octets[3]))
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct CidrBlock {
    pub network: Ipv4AddrExt,
    pub prefix: u8,
}
impl CidrBlock {
    pub fn new(address: Ipv4AddrExt, prefix: u8) -> AegisResult<Self> {
        if prefix > 32 {
            return Err(AegisError::InvalidFormat(format!("invalid CIDR prefix {prefix}")));
        }
        Ok(Self { network: address.network(prefix), prefix })
    }
    pub fn contains(self, address: Ipv4AddrExt) -> bool {
        address.network(self.prefix) == self.network
    }
    pub fn size(self) -> u64 {
        if self.prefix == 32 { 1 } else { 1u64 << (32 - self.prefix) }
    }
}
impl fmt::Display for CidrBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.network, self.prefix)
    }
}
impl FromStr for CidrBlock {
    type Err = AegisError;
    fn from_str(input: &str) -> AegisResult<Self> {
        let (addr, prefix) = input.trim().split_once('/').ok_or_else(|| AegisError::InvalidFormat(format!("invalid CIDR block: {input}")))?;
        let address = Ipv4AddrExt::from_str(addr)?;
        let prefix: u8 = prefix.parse().map_err(|_| AegisError::InvalidFormat(format!("invalid CIDR prefix in {input}")))?;
        CidrBlock::new(address, prefix)
    }
}
pub fn prefix_to_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    }
}
pub fn classify_ipv4(address: Ipv4AddrExt) -> &'static str {
    if address.is_private() {
        "private"
    } else if address.is_loopback() {
        "loopback"
    } else if address.is_link_local() {
        "link-local"
    } else if address.is_multicast() {
        "multicast"
    } else if address.is_global_unicast() {
        "global"
    } else {
        "special"
    }
}
