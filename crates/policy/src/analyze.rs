use crate::{FirewallRule, LocalPolicy, PolicyAction};
use aegislens_core::{catalog::port_exposure_score, Diagnostic, DiagnosticSet, Severity};
use std::collections::BTreeMap;
pub fn analyze_policy(policy: &LocalPolicy) -> DiagnosticSet {
    let mut set = DiagnosticSet::new();
    detect_duplicates(policy, &mut set);
    detect_shadowed_rules(policy, &mut set);
    detect_exposed_services(policy, &mut set);
    detect_default_accept(policy, &mut set);
    set
}
fn detect_duplicates(policy: &LocalPolicy, set: &mut DiagnosticSet) {
    let mut seen = BTreeMap::new();
    for rule in &policy.rules {
        let key = rule.normalized_key();
        if let Some(first) = seen.insert(key, rule.index) {
            set.push(Diagnostic::new(Severity::Low, "policy.rule.duplicate", format!("rule {} duplicates rule {}", rule.index, first)).at(rule.index));
        }
    }
}
fn detect_shadowed_rules(policy: &LocalPolicy, set: &mut DiagnosticSet) {
    for (idx, rule) in policy.rules.iter().enumerate() {
        for previous in &policy.rules[..idx] {
            if previous.overlaps(rule) && terminal_action(&previous.action) {
                set.push(Diagnostic::new(Severity::Medium, "policy.rule.shadowed", format!("rule {} may be shadowed by rule {}", rule.index, previous.index)).at(rule.index));
                break;
            }
        }
    }
}
fn detect_exposed_services(policy: &LocalPolicy, set: &mut DiagnosticSet) {
    for rule in &policy.rules {
        if !matches!(rule.action, PolicyAction::Accept) {
            continue;
        }
        if rule.source.is_none() {
            if let Some(port) = rule.destination_port {
                let proto = rule.protocol.as_deref().unwrap_or("tcp");
                let score = port_exposure_score(port, proto);
                if score >= 70 {
                    set.push(Diagnostic::new(Severity::High, "policy.exposure.service", format!("high exposure service {proto}/{port} allowed from any source")).at(rule.index));
                } else if score >= 45 {
                    set.push(Diagnostic::new(Severity::Medium, "policy.exposure.service", format!("sensitive service {proto}/{port} allowed from any source")).at(rule.index));
                }
            }
        }
    }
}
fn detect_default_accept(policy: &LocalPolicy, set: &mut DiagnosticSet) {
    for rule in &policy.rules {
        if rule.source.is_none() && rule.destination.is_none() && rule.destination_port.is_none() && matches!(rule.action, PolicyAction::Accept) {
            set.push(Diagnostic::new(Severity::High, "policy.default.accept", format!("chain {} contains broad accept", rule.chain)).at(rule.index));
        }
    }
}
fn terminal_action(action: &PolicyAction) -> bool {
    matches!(action, PolicyAction::Accept | PolicyAction::Drop | PolicyAction::Reject)
}
pub fn rule_order_score(rules: &[FirewallRule]) -> u8 {
    let mut score = 100u8;
    for (idx, rule) in rules.iter().enumerate() {
        if matches!(rule.action, PolicyAction::Accept) && rule.source.is_none() {
            score = score.saturating_sub((10 + idx.min(5)) as u8);
        }
        if matches!(rule.action, PolicyAction::Drop | PolicyAction::Reject) && idx + 1 == rules.len() {
            score = score.saturating_add(5).min(100);
        }
    }
    score
}
