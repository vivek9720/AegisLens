use aegislens_core::{CidrBlock, MatchDisposition};
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyAction {
    Accept,
    Drop,
    Reject,
    Log,
    Return,
    Unknown(String),
}
impl PolicyAction {
    pub fn from_token(token: &str) -> Self {
        match token.to_ascii_uppercase().as_str() {
            "ACCEPT" | "ALLOW" => PolicyAction::Accept,
            "DROP" | "DENY" => PolicyAction::Drop,
            "REJECT" => PolicyAction::Reject,
            "LOG" => PolicyAction::Log,
            "RETURN" => PolicyAction::Return,
            other => PolicyAction::Unknown(other.to_string()),
        }
    }
    pub fn disposition(&self) -> MatchDisposition {
        match self {
            PolicyAction::Accept => MatchDisposition::Allowed,
            PolicyAction::Drop | PolicyAction::Reject => MatchDisposition::Blocked,
            PolicyAction::Log => MatchDisposition::Observed,
            _ => MatchDisposition::Unknown,
        }
    }
    pub fn as_str(&self) -> &str {
        match self {
            PolicyAction::Accept => "ACCEPT",
            PolicyAction::Drop => "DROP",
            PolicyAction::Reject => "REJECT",
            PolicyAction::Log => "LOG",
            PolicyAction::Return => "RETURN",
            PolicyAction::Unknown(value) => value.as_str(),
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirewallRule {
    pub index: usize,
    pub chain: String,
    pub protocol: Option<String>,
    pub source: Option<CidrBlock>,
    pub destination: Option<CidrBlock>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub action: PolicyAction,
    pub raw: String,
}
impl FirewallRule {
    pub fn overlaps(&self, other: &Self) -> bool {
        if self.chain != other.chain {
            return false;
        }
        if self.protocol.is_some() && other.protocol.is_some() && self.protocol != other.protocol {
            return false;
        }
        if self.destination_port.is_some() && other.destination_port.is_some() && self.destination_port != other.destination_port {
            return false;
        }
        if self.source_port.is_some() && other.source_port.is_some() && self.source_port != other.source_port {
            return false;
        }
        cidr_overlaps(self.source, other.source) && cidr_overlaps(self.destination, other.destination)
    }
    pub fn normalized_key(&self) -> String {
        format!("{}|{:?}|{:?}|{:?}|{:?}|{:?}|{}", self.chain, self.protocol, self.source, self.destination, self.source_port, self.destination_port, self.action.as_str())
    }
}
fn cidr_overlaps(a: Option<CidrBlock>, b: Option<CidrBlock>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.contains(b.network) || b.contains(a.network),
        _ => true,
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalPolicy {
    pub rules: Vec<FirewallRule>,
    pub settings: Vec<(String, String)>,
}
