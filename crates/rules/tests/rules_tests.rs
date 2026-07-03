use aegislens_rules::{parse_rule, validate_rule};
#[test]
fn parses_valid_rule() {
    let rule = parse_rule("alert tcp any any -> any 80 (msg:\"web hit\"; content:\"GET\"; sid:1001; rev:1; classtype:web-application-activity;)").unwrap();
    assert_eq!(rule.sid(), Some(1001));
    assert!(!validate_rule(&rule).has_errors());
}
