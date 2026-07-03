use crate::{FirewallRule, PolicyAction};
use aegislens_core::{CidrBlock, Ipv4AddrExt};
use std::str::FromStr;
pub fn parse_iptables_line(index: usize, line: &str) -> Option<FirewallRule> {
    let trimmed = line.trim();
    if !(trimmed.starts_with("-A ") || trimmed.starts_with("-I ")) {
        return None;
    }
    let parts = shell_words(trimmed);
    if parts.len() < 3 {
        return None;
    }
    let mut rule = FirewallRule { index, chain: parts[1].clone(), protocol: None, source: None, destination: None, source_port: None, destination_port: None, action: PolicyAction::Unknown("UNSPECIFIED".to_string()), raw: line.to_string() };
    let mut i = 2;
    while i < parts.len() {
        match parts[i].as_str() {
            "-p" | "--protocol" => {
                if let Some(value) = parts.get(i + 1) { rule.protocol = Some(value.to_ascii_lowercase()); }
                i += 2;
            }
            "-s" | "--source" => {
                if let Some(value) = parts.get(i + 1) { rule.source = parse_cidr_or_ip(value); }
                i += 2;
            }
            "-d" | "--destination" => {
                if let Some(value) = parts.get(i + 1) { rule.destination = parse_cidr_or_ip(value); }
                i += 2;
            }
            "--sport" | "--source-port" => {
                if let Some(value) = parts.get(i + 1) { rule.source_port = value.parse().ok(); }
                i += 2;
            }
            "--dport" | "--destination-port" => {
                if let Some(value) = parts.get(i + 1) { rule.destination_port = value.parse().ok(); }
                i += 2;
            }
            "-j" | "--jump" => {
                if let Some(value) = parts.get(i + 1) { rule.action = PolicyAction::from_token(value); }
                i += 2;
            }
            _ => i += 1,
        }
    }
    Some(rule)
}
pub fn parse_nft_line(index: usize, line: &str) -> Option<FirewallRule> {
    let trimmed = line.trim();
    if !(trimmed.contains(" accept") || trimmed.contains(" drop") || trimmed.contains(" reject") || trimmed.contains(" counter")) {
        return None;
    }
    let tokens = shell_words(trimmed);
    let chain = if let Some(pos) = tokens.iter().position(|t| t == "chain") { tokens.get(pos + 1).cloned().unwrap_or_else(|| "nft".to_string()) } else { "nft".to_string() };
    let mut rule = FirewallRule { index, chain, protocol: None, source: None, destination: None, source_port: None, destination_port: None, action: PolicyAction::Unknown("UNSPECIFIED".to_string()), raw: line.to_string() };
    let mut i = 0;
    while i < tokens.len() {
        match tokens[i].as_str() {
            "ip" if tokens.get(i + 1).map(|s| s.as_str()) == Some("saddr") => {
                if let Some(value) = tokens.get(i + 2) { rule.source = parse_cidr_or_ip(value); }
                i += 3;
            }
            "ip" if tokens.get(i + 1).map(|s| s.as_str()) == Some("daddr") => {
                if let Some(value) = tokens.get(i + 2) { rule.destination = parse_cidr_or_ip(value); }
                i += 3;
            }
            "tcp" | "udp" => {
                rule.protocol = Some(tokens[i].to_string());
                if tokens.get(i + 1).map(|s| s.as_str()) == Some("dport") {
                    rule.destination_port = tokens.get(i + 2).and_then(|v| v.parse().ok());
                    i += 3;
                } else if tokens.get(i + 1).map(|s| s.as_str()) == Some("sport") {
                    rule.source_port = tokens.get(i + 2).and_then(|v| v.parse().ok());
                    i += 3;
                } else {
                    i += 1;
                }
            }
            "accept" | "drop" | "reject" => {
                rule.action = PolicyAction::from_token(&tokens[i]);
                i += 1;
            }
            _ => i += 1,
        }
    }
    Some(rule)
}
pub fn parse_cidr_or_ip(input: &str) -> Option<CidrBlock> {
    if input.contains('/') {
        CidrBlock::from_str(input).ok()
    } else {
        Ipv4AddrExt::from_str(input).ok().and_then(|ip| CidrBlock::new(ip, 32).ok())
    }
}
fn shell_words(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    for ch in input.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            c if c.is_ascii_whitespace() && !in_quotes => {
                if !current.is_empty() {
                    out.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}
