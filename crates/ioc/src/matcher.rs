use crate::model::{IocKind, IocRecord, IocSet};
use crate::normalize::extract_domain_from_url;
use aegislens_core::{Ipv4AddrExt, MatchDisposition, Severity};
use aegislens_packet::PacketMetadata;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IocMatch {
    pub key: String,
    pub frame_index: usize,
    pub disposition: MatchDisposition,
    pub severity: Severity,
    pub confidence: u8,
    pub reason: String,
}
pub fn match_iocs_to_metadata(set: &IocSet, packets: &[PacketMetadata]) -> Vec<IocMatch> {
    let mut matches = Vec::new();
    for packet in packets {
        for record in &set.records {
            if let Some(reason) = record_matches_packet(record, packet) {
                matches.push(IocMatch { key: record.normalized_key(), frame_index: packet.frame_index, disposition: record.disposition, severity: record.severity, confidence: record.confidence, reason });
            }
        }
    }
    matches
}
fn record_matches_packet(record: &IocRecord, packet: &PacketMetadata) -> Option<String> {
    match &record.kind {
        IocKind::Ip(ip) => matches_ip(*ip, packet).then(|| "endpoint-ip".to_string()),
        IocKind::Cidr(cidr) => {
            let src = packet.source_ip.map(|ip| cidr.contains(ip)).unwrap_or(false);
            let dst = packet.destination_ip.map(|ip| cidr.contains(ip)).unwrap_or(false);
            (src || dst).then(|| "endpoint-cidr".to_string())
        }
        IocKind::Domain(domain) => packet.dns_names.iter().any(|name| domain_matches(domain, name)).then(|| "dns-name".to_string()),
        IocKind::Url(url) => extract_domain_from_url(url).and_then(|domain| packet.dns_names.iter().any(|name| domain_matches(&domain, name)).then(|| "url-host-via-dns".to_string())),
        IocKind::Hash { .. } => None,
    }
}
fn matches_ip(ip: Ipv4AddrExt, packet: &PacketMetadata) -> bool {
    packet.source_ip == Some(ip) || packet.destination_ip == Some(ip)
}
fn domain_matches(ioc: &str, observed: &str) -> bool {
    let ioc = ioc.trim_end_matches('.').to_ascii_lowercase();
    let observed = observed.trim_end_matches('.').to_ascii_lowercase();
    observed == ioc || observed.ends_with(&format!(".{ioc}"))
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IocMatchSummary {
    pub blocked: usize,
    pub allowed: usize,
    pub observed: usize,
    pub highest: Severity,
}
pub fn summarize_matches(matches: &[IocMatch]) -> IocMatchSummary {
    let mut blocked = 0;
    let mut allowed = 0;
    let mut observed = 0;
    let mut highest = Severity::Info;
    for item in matches {
        match item.disposition {
            MatchDisposition::Blocked => blocked += 1,
            MatchDisposition::Allowed => allowed += 1,
            _ => observed += 1,
        }
        highest = highest.max(item.severity);
    }
    IocMatchSummary { blocked, allowed, observed, highest }
}
