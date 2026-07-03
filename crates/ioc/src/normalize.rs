use aegislens_core::{lower_ascii, percent_decode_lossy, strip_quotes};
pub fn normalize_domain(input: &str) -> Option<String> {
    let mut value = strip_quotes(input).trim().trim_end_matches('.').to_ascii_lowercase();
    if let Some(rest) = value.strip_prefix("*.") {
        value = rest.to_string();
    }
    if value.is_empty() || value.len() > 253 {
        return None;
    }
    let labels: Vec<&str> = value.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    for label in &labels {
        if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
            return None;
        }
        if !label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
            return None;
        }
    }
    Some(value)
}
pub fn normalize_url(input: &str) -> Option<String> {
    let decoded = percent_decode_lossy(strip_quotes(input).trim());
    let lowered = lower_ascii(&decoded);
    if !(lowered.starts_with("http://") || lowered.starts_with("https://")) {
        return None;
    }
    Some(lowered.trim_end_matches('/').to_string())
}
pub fn normalize_hash(input: &str) -> Option<(String, String)> {
    let value = strip_quotes(input).trim().trim_start_matches("sha256:").trim_start_matches("sha1:").trim_start_matches("md5:").to_ascii_lowercase();
    if !value.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    let algorithm = match value.len() {
        32 => "md5",
        40 => "sha1",
        64 => "sha256",
        96 => "sha384",
        128 => "sha512",
        _ => return None,
    };
    Some((algorithm.to_string(), value))
}
pub fn extract_domain_from_url(url: &str) -> Option<String> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split('/').next().unwrap_or(rest);
    let host = authority.rsplit('@').next().unwrap_or(authority).split(':').next().unwrap_or(authority);
    normalize_domain(host)
}
