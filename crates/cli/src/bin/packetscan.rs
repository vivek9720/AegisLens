use aegislens_packet::{extract_packet_metadata, summarize_metadata};
use std::env;
use std::fs;
fn main() {
    let path = match env::args().nth(1) {
        Some(path) => path,
        None => {
            eprintln!("usage: packetscan <pcap-or-frame-file>");
            std::process::exit(2);
        }
    };
    let data = match fs::read(&path) {
        Ok(data) => data,
        Err(err) => {
            eprintln!("failed to read {path}: {err}");
            std::process::exit(1);
        }
    };
    let metadata = extract_packet_metadata(&data);
    let summary = summarize_metadata(&metadata);
    print!("{}", summary.render_text());
}
