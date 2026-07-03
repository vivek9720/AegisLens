use aegislens_ioc::parse_ioc_text;
#[test]
fn parses_ioc_list_and_detects_duplicate() {
    let set = parse_ioc_text("block 203.0.113.5 malware\n203.0.113.5\nexample.com\n");
    assert_eq!(set.records.len(), 2);
    assert_eq!(set.duplicates.len(), 1);
}
