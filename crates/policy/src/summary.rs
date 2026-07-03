use crate::{analyze_policy, rule_order_score, LocalPolicy, PolicyAction};
use std::collections::BTreeMap;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicySummary {
    pub rule_count: usize,
    pub chain_counts: BTreeMap<String, usize>,
    pub accepts: usize,
    pub drops: usize,
    pub rejects: usize,
    pub order_score: u8,
    pub diagnostics: String,
}
pub fn summarize_policy(policy: &LocalPolicy) -> PolicySummary {
    let mut chain_counts = BTreeMap::new();
    let mut accepts = 0;
    let mut drops = 0;
    let mut rejects = 0;
    for rule in &policy.rules {
        *chain_counts.entry(rule.chain.clone()).or_insert(0) += 1;
        match rule.action {
            PolicyAction::Accept => accepts += 1,
            PolicyAction::Drop => drops += 1,
            PolicyAction::Reject => rejects += 1,
            _ => {}
        }
    }
    let diagnostics = analyze_policy(policy).render_text();
    PolicySummary { rule_count: policy.rules.len(), chain_counts, accepts, drops, rejects, order_score: rule_order_score(&policy.rules), diagnostics }
}
impl PolicySummary {
    pub fn render_text(&self) -> String {
        let mut out = String::new();
        out.push_str(&format!("rules: {}\n", self.rule_count));
        out.push_str(&format!("accept: {} drop: {} reject: {}\n", self.accepts, self.drops, self.rejects));
        out.push_str(&format!("order score: {}\n", self.order_score));
        out.push_str("chains:\n");
        for (chain, count) in &self.chain_counts {
            out.push_str(&format!("  {chain}: {count}\n"));
        }
        if !self.diagnostics.is_empty() {
            out.push_str("diagnostics:\n");
            out.push_str(&self.diagnostics);
        }
        out
    }
}
