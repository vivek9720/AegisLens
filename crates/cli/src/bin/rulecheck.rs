use aegislens_rules::{normalize_rule, parse_rules_file, validate_rules, IdsRule};
use std::env;
use std::fs;
fn main() {
    let path = match env::args().nth(1) {
        Some(path) => path,
        None => {
            eprintln!("usage: rulecheck <ids-rule-file>");
            std::process::exit(2);
        }
    };
    let text = fs::read_to_string(&path).unwrap_or_else(|err| {
        eprintln!("failed to read {path}: {err}");
        std::process::exit(1);
    });
    let mut rules: Vec<IdsRule> = Vec::new();
    for parsed in parse_rules_file(&text) {
        match parsed {
            Ok(rule) => rules.push(rule),
            Err(err) => eprintln!("parse error: {err}"),
        }
    }
    let diagnostics = validate_rules(&rules);
    println!("rules: {}", rules.len());
    print!("{}", diagnostics.render_text());
    for rule in &rules {
        println!("{}", normalize_rule(rule));
    }
}
