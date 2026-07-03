use std::io::Read;
fn exercise(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let parsed = aegislens_rules::parse_rules_file(text);
        let rules: Vec<_> = parsed.into_iter().filter_map(Result::ok).collect();
        let _ = aegislens_rules::validate_rules(&rules);
        for rule in &rules { let _ = aegislens_rules::normalize_rule(rule); }
        let packets = aegislens_packet::extract_packet_metadata(data);
        let _ = aegislens_rules::match_rules_to_metadata(&rules, &packets);
    }
}
fn main() {
    let mut data = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut data);
    exercise(&data);
}
#[no_mangle]
pub extern "C" fn LLVMFuzzerTestOneInput(data: *const u8, size: usize) -> i32 {
    if data.is_null() {
        return 0;
    }
    // The C fuzzing ABI provides a raw pointer and size; the null check above guards conversion.
    let bytes = unsafe { std::slice::from_raw_parts(data, size) };
    exercise(bytes);
    0
}
