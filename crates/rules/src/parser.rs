use crate::{AddressSpec, IdsRule, PortSpec, RuleAction, RuleOption};
use aegislens_core::{strip_quotes, AegisError, AegisResult};
pub fn parse_rules_file(input: &str) -> Vec<AegisResult<IdsRule>> {
    input.lines().filter_map(|line| {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            None
        } else {
            Some(parse_rule(trimmed))
        }
    }).collect()
}
pub fn parse_rule(input: &str) -> AegisResult<IdsRule> {
    let open = input.find('(').ok_or_else(|| AegisError::InvalidFormat("rule options missing '('".to_string()))?;
    let close = input.rfind(')').ok_or_else(|| AegisError::InvalidFormat("rule options missing ')'".to_string()))?;
    if close <= open {
        return Err(AegisError::InvalidFormat("rule option block is malformed".to_string()));
    }
    let header = input[..open].trim();
    let options = &input[open + 1..close];
    let fields: Vec<&str> = header.split_whitespace().collect();
    if fields.len() != 7 {
        return Err(AegisError::InvalidFormat(format!("rule header expects 7 fields, got {}", fields.len())));
    }
    Ok(IdsRule {
        action: RuleAction::from_token(fields[0]),
        protocol: fields[1].to_ascii_lowercase(),
        source: AddressSpec { raw: fields[2].to_string() },
        source_ports: parse_port_spec(fields[3])?,
        direction: fields[4].to_string(),
        destination: AddressSpec { raw: fields[5].to_string() },
        destination_ports: parse_port_spec(fields[6])?,
        options: parse_options(options),
        raw: input.to_string(),
    })
}
pub fn parse_port_spec(input: &str) -> AegisResult<PortSpec> {
    let mut value = input.trim();
    let mut negated = false;
    if let Some(rest) = value.strip_prefix('!') {
        negated = true;
        value = rest;
    }
    if value.eq_ignore_ascii_case("any") {
        return Ok(PortSpec { any: true, negated, ranges: Vec::new() });
    }
    let mut ranges = Vec::new();
    let list = value.trim_matches(|c| c == '[' || c == ']');
    for part in list.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((start, end)) = part.split_once(':') {
            let start = if start.is_empty() { 0 } else { start.parse::<u16>().map_err(|_| AegisError::InvalidFormat(format!("invalid port {start}")))? };
            let end = if end.is_empty() { u16::MAX } else { end.parse::<u16>().map_err(|_| AegisError::InvalidFormat(format!("invalid port {end}")))? };
            if start > end {
                return Err(AegisError::InvalidFormat(format!("invalid port range {part}")));
            }
            ranges.push((start, end));
        } else {
            let port = part.parse::<u16>().map_err(|_| AegisError::InvalidFormat(format!("invalid port {part}")))?;
            ranges.push((port, port));
        }
    }
    if ranges.is_empty() {
        return Err(AegisError::InvalidFormat(format!("empty port spec {input}")));
    }
    Ok(PortSpec { any: false, negated, ranges })
}
fn parse_options(input: &str) -> Vec<RuleOption> {
    let mut options = Vec::new();
    for item in split_options(input) {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some((key, value)) = trimmed.split_once(':') {
            options.push(RuleOption { key: key.trim().to_ascii_lowercase(), value: Some(strip_quotes(value.trim()).to_string()) });
        } else {
            options.push(RuleOption { key: trimmed.to_ascii_lowercase(), value: None });
        }
    }
    options
}
fn split_options(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escape = false;
    for ch in input.chars() {
        if escape {
            current.push(ch);
            escape = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => escape = true,
            '"' => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ';' if !in_quotes => {
                out.push(current.clone());
                current.clear();
            }
            _ => current.push(ch),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}
