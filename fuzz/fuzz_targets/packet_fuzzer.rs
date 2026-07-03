use std::io::Read;
fn exercise(data: &[u8]) {
    let _ = aegislens_packet::extract_packet_metadata(data);
    let _ = aegislens_packet::summarize_capture(data);
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
