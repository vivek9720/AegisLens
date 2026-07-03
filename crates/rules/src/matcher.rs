use crate::IdsRule;
use aegislens_packet::PacketMetadata;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMetadataMatch {
    pub sid: Option<u32>,
    pub frame_index: usize,
    pub reason: String,
}
pub fn match_rules_to_metadata(rules: &[IdsRule], packets: &[PacketMetadata]) -> Vec<RuleMetadataMatch> {
    let mut out = Vec::new();
    for rule in rules {
        for packet in packets {
            if let Some(reason) = matches_metadata(rule, packet) {
                out.push(RuleMetadataMatch { sid: rule.sid(), frame_index: packet.frame_index, reason });
            }
        }
    }
    out
}
pub fn matches_metadata(rule: &IdsRule, packet: &PacketMetadata) -> Option<String> {
    if rule.protocol != "ip" {
        let pkt_proto = packet.protocol.as_deref().unwrap_or("unknown");
        if pkt_proto != rule.protocol {
            return None;
        }
    }
    if let Some(port) = packet.destination_port {
        if !rule.destination_ports.contains(port) {
            return None;
        }
    } else if !rule.destination_ports.any {
        return None;
    }
    if let Some(port) = packet.source_port {
        if !rule.source_ports.contains(port) {
            return None;
        }
    } else if !rule.source_ports.any {
        return None;
    }
    for content in rule.contents() {
        let lower = content.to_ascii_lowercase();
        if lower.contains("dns") && !packet.dns_names.is_empty() {
            return Some("content-hint-dns".to_string());
        }
        if packet.dns_names.iter().any(|name| name.contains(&lower)) {
            return Some("content-hint-domain".to_string());
        }
    }
    Some("protocol-and-port".to_string())
}
