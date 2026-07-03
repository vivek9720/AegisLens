use aegislens_core::{CidrBlock, Ipv4AddrExt};
use std::str::FromStr;
#[test]
fn cidr_contains_private_address() {
    let block = CidrBlock::from_str("192.168.1.0/24").unwrap();
    assert!(block.contains(Ipv4AddrExt::from_str("192.168.1.25").unwrap()));
    assert!(!block.contains(Ipv4AddrExt::from_str("192.168.2.1").unwrap()));
}
