use aegislens_core::Severity;
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuleAction {
    Alert,
    Pass,
    Drop,
    Reject,
    Log,
    Unknown(String),
}
impl RuleAction {
    pub fn from_token(token: &str) -> Self {
        match token.to_ascii_lowercase().as_str() {
            "alert" => RuleAction::Alert,
            "pass" => RuleAction::Pass,
            "drop" => RuleAction::Drop,
            "reject" => RuleAction::Reject,
            "log" => RuleAction::Log,
            other => RuleAction::Unknown(other.to_string()),
        }
    }
    pub fn as_str(&self) -> &str {
        match self {
            RuleAction::Alert => "alert",
            RuleAction::Pass => "pass",
            RuleAction::Drop => "drop",
            RuleAction::Reject => "reject",
            RuleAction::Log => "log",
            RuleAction::Unknown(value) => value.as_str(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortSpec {
    pub any: bool,
    pub negated: bool,
    pub ranges: Vec<(u16, u16)>,
}
impl PortSpec {
    pub fn any() -> Self {
        Self { any: true, negated: false, ranges: Vec::new() }
    }
    pub fn contains(&self, port: u16) -> bool {
        if self.any {
            return !self.negated;
        }
        let hit = self.ranges.iter().any(|(start, end)| port >= *start && port <= *end);
        if self.negated { !hit } else { hit }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressSpec {
    pub raw: String,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleOption {
    pub key: String,
    pub value: Option<String>,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdsRule {
    pub action: RuleAction,
    pub protocol: String,
    pub source: AddressSpec,
    pub source_ports: PortSpec,
    pub direction: String,
    pub destination: AddressSpec,
    pub destination_ports: PortSpec,
    pub options: Vec<RuleOption>,
    pub raw: String,
}
impl IdsRule {
    pub fn option_value(&self, key: &str) -> Option<&str> {
        self.options.iter().find(|opt| opt.key.eq_ignore_ascii_case(key)).and_then(|opt| opt.value.as_deref())
    }
    pub fn sid(&self) -> Option<u32> {
        self.option_value("sid")?.parse().ok()
    }
    pub fn rev(&self) -> Option<u32> {
        self.option_value("rev")?.parse().ok()
    }
    pub fn msg(&self) -> Option<&str> {
        self.option_value("msg")
    }
    pub fn contents(&self) -> Vec<&str> {
        self.options.iter().filter(|opt| opt.key.eq_ignore_ascii_case("content")).filter_map(|opt| opt.value.as_deref()).collect()
    }
    pub fn severity_hint(&self) -> Severity {
        match self.option_value("classtype").unwrap_or("") {
            "attempted-admin" | "trojan-activity" | "successful-admin" => Severity::High,
            "attempted-dos" | "web-application-attack" | "network-scan" => Severity::Medium,
            "policy-violation" | "misc-activity" => Severity::Low,
            _ => Severity::Info,
        }
    }
}
