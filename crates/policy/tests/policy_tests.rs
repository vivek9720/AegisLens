use aegislens_policy::{analyze_policy, parse_policy_text};
#[test]
fn broad_admin_allow_is_flagged() {
    let policy = parse_policy_text("-A INPUT -p tcp --dport 22 -j ACCEPT\n-A INPUT -j DROP\n");
    let diagnostics = analyze_policy(&policy);
    assert!(diagnostics.iter().any(|d| d.code == "policy.exposure.service"));
}
