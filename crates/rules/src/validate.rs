use crate::{IdsRule, RuleAction};
use aegislens_core::{Diagnostic, DiagnosticSet, Severity};
pub fn validate_rule(rule: &IdsRule) -> DiagnosticSet {
    let mut set = DiagnosticSet::new();
    if matches!(rule.action, RuleAction::Unknown(_)) {
        set.push(Diagnostic::new(Severity::Medium, "rule.action.unknown", "unknown rule action"));
    }
    if !matches!(rule.protocol.as_str(), "tcp" | "udp" | "icmp" | "ip" | "http" | "dns") {
        set.push(Diagnostic::new(Severity::Low, "rule.protocol.unusual", "unusual rule protocol"));
    }
    if rule.direction != "->" && rule.direction != "<>" {
        set.push(Diagnostic::new(Severity::High, "rule.direction.invalid", "direction must be -> or <>"));
    }
    if rule.sid().is_none() {
        set.push(Diagnostic::new(Severity::Medium, "rule.sid.missing", "rule should contain numeric sid"));
    }
    if rule.rev().is_none() {
        set.push(Diagnostic::new(Severity::Low, "rule.rev.missing", "rule should contain numeric rev"));
    }
    if rule.msg().is_none() {
        set.push(Diagnostic::new(Severity::Low, "rule.msg.missing", "rule should contain msg"));
    }
    for content in rule.contents() {
        if content.is_empty() {
            set.push(Diagnostic::new(Severity::Medium, "rule.content.empty", "content option is empty"));
        }
        if content.len() > 512 {
            set.push(Diagnostic::new(Severity::Low, "rule.content.large", "large content option may be expensive"));
        }
    }
    set
}
pub fn validate_rules(rules: &[IdsRule]) -> DiagnosticSet {
    let mut set = DiagnosticSet::new();
    let mut sids = std::collections::BTreeSet::new();
    for rule in rules {
        set.extend(validate_rule(rule));
        if let Some(sid) = rule.sid() {
            if !sids.insert(sid) {
                set.push(Diagnostic::new(Severity::Medium, "rule.sid.duplicate", format!("duplicate sid {sid}")));
            }
        }
    }
    set
}
