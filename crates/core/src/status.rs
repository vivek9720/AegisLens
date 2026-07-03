#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}
impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
    pub fn from_score(score: u8) -> Self {
        match score {
            0..=19 => Severity::Info,
            20..=39 => Severity::Low,
            40..=69 => Severity::Medium,
            70..=89 => Severity::High,
            _ => Severity::Critical,
        }
    }
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchDisposition {
    Allowed,
    Blocked,
    Observed,
    Unknown,
}
impl MatchDisposition {
    pub fn strongest(self, other: Self) -> Self {
        use MatchDisposition::*;
        match (self, other) {
            (Blocked, _) | (_, Blocked) => Blocked,
            (Allowed, _) | (_, Allowed) => Allowed,
            (Observed, _) | (_, Observed) => Observed,
            _ => Unknown,
        }
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AegisError {
    Truncated { needed: usize, available: usize },
    InvalidFormat(String),
    Unsupported(String),
    Conflict(String),
}
impl core::fmt::Display for AegisError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AegisError::Truncated { needed, available } => write!(f, "truncated input: needed {needed}, available {available}"),
            AegisError::InvalidFormat(msg) => f.write_str(msg),
            AegisError::Unsupported(msg) => f.write_str(msg),
            AegisError::Conflict(msg) => f.write_str(msg),
        }
    }
}
impl std::error::Error for AegisError {}
pub type AegisResult<T> = Result<T, AegisError>;
