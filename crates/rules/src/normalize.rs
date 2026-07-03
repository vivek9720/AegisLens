use crate::{IdsRule, RuleOption};
pub fn normalize_rule(rule: &IdsRule) -> String {
    let mut options = rule.options.clone();
    options.sort_by(|a, b| option_order(&a.key).cmp(&option_order(&b.key)).then(a.key.cmp(&b.key)));
    let option_text = options.iter().map(render_option).collect::<Vec<_>>().join(" ");
    format!("{} {} {} {} {} {} {} ({})", rule.action.as_str(), rule.protocol, rule.source.raw, render_ports(&rule.source_ports), rule.direction, rule.destination.raw, render_ports(&rule.destination_ports), option_text)
}
fn option_order(key: &str) -> u8 {
    match key {
        "msg" => 0,
        "flow" => 1,
        "content" => 2,
        "classtype" => 3,
        "sid" => 4,
        "rev" => 5,
        _ => 10,
    }
}
fn render_option(option: &RuleOption) -> String {
    match &option.value {
        Some(value) if value.chars().any(|c| c.is_ascii_whitespace()) => format!("{}:\"{}\";", option.key, value.replace('"', "\\\"")),
        Some(value) => format!("{}:{};", option.key, value),
        None => format!("{};", option.key),
    }
}
fn render_ports(spec: &crate::PortSpec) -> String {
    if spec.any {
        return if spec.negated { "!any".to_string() } else { "any".to_string() };
    }
    let ranges = spec.ranges.iter().map(|(start, end)| if start == end { start.to_string() } else { format!("{start}:{end}") }).collect::<Vec<_>>().join(",");
    if spec.negated { format!("![{ranges}]") } else if spec.ranges.len() > 1 { format!("[{ranges}]") } else { ranges }
}
