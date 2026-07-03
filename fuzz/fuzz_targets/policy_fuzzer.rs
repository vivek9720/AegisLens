use std::io::Read;
fn exercise(data: &[u8]) {
    if let Ok(text) = std::str::from_utf8(data) {
        let policy = aegislens_policy::parse_policy_text(text);
        let _ = aegislens_policy::analyze_policy(&policy);
        let _ = aegislens_policy::summarize_policy(&policy);
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
