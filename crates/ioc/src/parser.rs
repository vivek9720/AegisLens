use crate::classify::{classify_candidate, confidence_for_candidate, CandidateKind};
use crate::model::{IocKind, IocRecord, IocSet};
use crate::normalize::{normalize_domain, normalize_hash, normalize_url};
use aegislens_core::{split_csv_line, CidrBlock, Ipv4AddrExt, MatchDisposition, Severity};
use std::str::FromStr;
pub fn parse_ioc_text(input: &str) -> IocSet {
    let mut set = IocSet::default();
    for (line_no, raw_line) in input.lines().enumerate() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        for token in tokens_from_line(line) {
            if let Some(record) = parse_ioc_token(&token, line, line_no + 1) {
                set.add(record);
            }
        }
    }
    set
}
fn tokens_from_line(line: &str) -> Vec<String> {
    if line.contains(',') {
        split_csv_line(line)
    } else {
        line.split_whitespace().map(|s| s.trim_matches(|c| c == ';' || c == ',').to_string()).collect()
    }
}
pub fn parse_ioc_token(token: &str, context: &str, line_no: usize) -> Option<IocRecord> {
    let disposition = disposition_from_context(context);
    let source = Some(format!("line:{line_no}"));
    let candidate = classify_candidate(token);
    let kind = match candidate {
        CandidateKind::Ip => IocKind::Ip(Ipv4AddrExt::from_str(token).ok()?),
        CandidateKind::Cidr => IocKind::Cidr(CidrBlock::from_str(token).ok()?),
        CandidateKind::Domain => IocKind::Domain(normalize_domain(token)?),
        CandidateKind::Url => IocKind::Url(normalize_url(token)?),
        CandidateKind::Hash => {
            let (algorithm, value) = normalize_hash(token)?;
            IocKind::Hash { algorithm, value }
        }
        CandidateKind::Unknown => return None,
    };
    let confidence = confidence_for_candidate(candidate, context);
    let severity = severity_from_context(context, confidence);
    let tags = tags_from_context(context);
    Some(IocRecord { kind, disposition, severity, confidence, source, tags })
}
fn disposition_from_context(context: &str) -> MatchDisposition {
    let lower = context.to_ascii_lowercase();
    if lower.contains("allow") || lower.contains("safe") {
        MatchDisposition::Allowed
    } else if lower.contains("block") || lower.contains("deny") || lower.contains("malicious") {
        MatchDisposition::Blocked
    } else {
        MatchDisposition::Observed
    }
}
fn severity_from_context(context: &str, confidence: u8) -> Severity {
    let lower = context.to_ascii_lowercase();
    if lower.contains("critical") || lower.contains("ransom") {
        Severity::Critical
    } else if lower.contains("high") || confidence > 90 {
        Severity::High
    } else if lower.contains("medium") || confidence > 65 {
        Severity::Medium
    } else if lower.contains("low") {
        Severity::Low
    } else {
        Severity::Info
    }
}
fn tags_from_context(context: &str) -> Vec<String> {
    let mut tags = Vec::new();
    for word in context.split(|c: char| !c.is_ascii_alphanumeric() && c != '-') {
        let lower = word.to_ascii_lowercase();
        if matches!(lower.as_str(), "phishing" | "malware" | "c2" | "ransomware" | "scanner" | "botnet" | "allow" | "block") {
            tags.push(lower);
        }
    }
    tags.sort();
    tags.dedup();
    tags
}
