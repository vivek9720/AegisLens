use crate::normalize::{normalize_domain, normalize_hash, normalize_url};
use aegislens_core::{CidrBlock, Ipv4AddrExt};
use std::str::FromStr;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateKind {
    Ip,
    Cidr,
    Domain,
    Url,
    Hash,
    Unknown,
}
pub fn classify_candidate(input: &str) -> CandidateKind {
    let value = input.trim();
    if value.contains('/') && CidrBlock::from_str(value).is_ok() {
        return CandidateKind::Cidr;
    }
    if Ipv4AddrExt::from_str(value).is_ok() {
        return CandidateKind::Ip;
    }
    if normalize_url(value).is_some() {
        return CandidateKind::Url;
    }
    if normalize_hash(value).is_some() {
        return CandidateKind::Hash;
    }
    if normalize_domain(value).is_some() {
        return CandidateKind::Domain;
    }
    CandidateKind::Unknown
}
pub fn confidence_for_candidate(kind: CandidateKind, source_hint: &str) -> u8 {
    let base: u8 = match kind {
        CandidateKind::Ip => 75,
        CandidateKind::Cidr => 80,
        CandidateKind::Domain => 70,
        CandidateKind::Url => 85,
        CandidateKind::Hash => 90,
        CandidateKind::Unknown => 0,
    };
    if source_hint.contains("allow") {
        base.saturating_sub(10)
    } else if source_hint.contains("block") || source_hint.contains("deny") {
        (base + 10).min(100)
    } else {
        base
    }
}
