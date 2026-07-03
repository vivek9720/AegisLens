use std::io::Read;
fn exercise(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let set = aegislens_ioc::parse_ioc_text(text);
        let packets = aegislens_packet::extract_packet_metadata(data);
        let matches = aegislens_ioc::match_iocs_to_metadata(&set, &packets);
        let _ = aegislens_ioc::summarize_matches(&matches);
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
