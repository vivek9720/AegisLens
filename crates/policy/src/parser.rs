use crate::{parse_iptables_line, parse_nft_line, LocalPolicy};
use aegislens_core::split_csv_line;
pub fn parse_policy_text(input: &str) -> LocalPolicy {
    let mut rules = Vec::new();
    let mut settings = Vec::new();
    for (idx, raw) in input.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rule) = parse_iptables_line(idx, line).or_else(|| parse_nft_line(idx, line)) {
            rules.push(rule);
            continue;
        }
        if let Some((key, value)) = parse_setting(line) {
            settings.push((key, value));
        }
    }
    LocalPolicy { rules, settings }
}
fn parse_setting(line: &str) -> Option<(String, String)> {
    if let Some((key, value)) = line.split_once('=') {
        return Some((key.trim().to_ascii_lowercase(), value.trim().trim_matches('"').to_string()));
    }
    if line.starts_with('{') && line.ends_with('}') {
        let inner = &line[1..line.len() - 1];
        if let Some((key, value)) = inner.split_once(':') {
            return Some((key.trim().trim_matches('"').to_ascii_lowercase(), value.trim().trim_matches('"').to_string()));
        }
    }
    if line.contains(',') {
        let fields = split_csv_line(line);
        if fields.len() >= 2 {
            return Some((fields[0].to_ascii_lowercase(), fields[1].clone()));
        }
    }
    None
}
