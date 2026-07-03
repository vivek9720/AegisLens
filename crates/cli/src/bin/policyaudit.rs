use aegislens_policy::{parse_policy_text, summarize_policy};
use std::env;
use std::fs;
fn main() {
    let path = match env::args().nth(1) {
        Some(path) => path,
        None => {
            eprintln!("usage: policyaudit <firewall-or-policy-file>");
            std::process::exit(2);
        }
    };
    let text = fs::read_to_string(&path).unwrap_or_else(|err| {
        eprintln!("failed to read {path}: {err}");
        std::process::exit(1);
    });
    let policy = parse_policy_text(&text);
    let summary = summarize_policy(&policy);
    print!("{}", summary.render_text());
}
