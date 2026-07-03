#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanos: u32,
}
impl Timestamp {
    pub fn new(seconds: i64, nanos: u32) -> Self {
        let extra = nanos / 1_000_000_000;
        let nanos = nanos % 1_000_000_000;
        Self { seconds: seconds + extra as i64, nanos }
    }
    pub fn from_pcap(seconds: u32, micros_or_nanos: u32, nanos_resolution: bool) -> Self {
        if nanos_resolution {
            Self::new(seconds as i64, micros_or_nanos)
        } else {
            Self::new(seconds as i64, micros_or_nanos.saturating_mul(1000))
        }
    }
    pub fn render_compact(&self) -> String {
        format!("{}.{:09}", self.seconds, self.nanos)
    }
}
pub fn parse_duration_seconds(input: &str) -> Option<u64> {
    let trimmed = input.trim();
    let mut digits = String::new();
    let mut suffix = String::new();
    for ch in trimmed.chars() {
        if ch.is_ascii_digit() {
            if !suffix.is_empty() {
                return None;
            }
            digits.push(ch);
        } else if !ch.is_ascii_whitespace() {
            suffix.push(ch.to_ascii_lowercase());
        }
    }
    let value: u64 = digits.parse().ok()?;
    match suffix.as_str() {
        "" | "s" | "sec" | "secs" => Some(value),
        "m" | "min" | "mins" => value.checked_mul(60),
        "h" | "hr" | "hrs" => value.checked_mul(3600),
        "d" | "day" | "days" => value.checked_mul(86_400),
        _ => None,
    }
}
