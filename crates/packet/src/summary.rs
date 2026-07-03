use crate::{extract_packet_metadata, PacketMetadata};
use std::collections::BTreeMap;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketSummary {
    pub packet_count: usize,
    pub protocol_counts: BTreeMap<String, usize>,
    pub endpoint_counts: BTreeMap<String, usize>,
    pub dns_names: Vec<String>,
    pub warnings: Vec<String>,
    pub highest_exposure: u8,
}
impl PacketSummary {
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("packets: {}\n", self.packet_count));
        out.push_str("protocols:\n");
        for (proto, count) in &self.protocol_counts {
            out.push_str(&format!("  {proto}: {count}\n"));
        }
        out.push_str("endpoints:\n");
        for (endpoint, count) in self.endpoint_counts.iter().take(20) {
            out.push_str(&format!("  {endpoint}: {count}\n"));
        }
        if !self.dns_names.is_empty() {
            out.push_str("dns:\n");
            for name in &self.dns_names {
                out.push_str(&format!("  {name}\n"));
            }
        }
        if !self.warnings.is_empty() {
            out.push_str("warnings:\n");
            for warning in &self.warnings {
                out.push_str(&format!("  {warning}\n"));
            }
        }
        out.push_str(&format!("highest exposure score: {}\n", self.highest_exposure));
        out
    }
}
pub fn summarize_metadata(items: &[PacketMetadata]) -> PacketSummary {
    let mut protocol_counts = BTreeMap::new();
    let mut endpoint_counts = BTreeMap::new();
    let mut dns_names = Vec::new();
    let mut warnings = Vec::new();
    let mut highest_exposure = 0;
    for item in items {
        *protocol_counts.entry(item.protocol.clone().unwrap_or_else(|| "unknown".to_string())).or_insert(0) += 1;
        *endpoint_counts.entry(item.endpoint_key()).or_insert(0) += 1;
        for name in &item.dns_names {
            if !dns_names.contains(name) {
                dns_names.push(name.clone());
            }
        }
        for note in &item.notes {
            warnings.push(format!("frame {}: {}", item.frame_index, note));
        }
        highest_exposure = highest_exposure.max(item.exposure_score);
    }
    PacketSummary { packet_count: items.len(), protocol_counts, endpoint_counts, dns_names, warnings, highest_exposure }
}
pub fn summarize_capture(data: &[u8]) -> PacketSummary {
    let meta = extract_packet_metadata(data);
    summarize_metadata(&meta)
}
