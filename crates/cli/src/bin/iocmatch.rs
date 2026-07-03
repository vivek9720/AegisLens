use aegislens_ioc::{match_iocs_to_metadata, parse_ioc_text, summarize_matches};
use aegislens_packet::extract_packet_metadata;
use std::env;
use std::fs;
fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("usage: iocmatch <ioc-file> <pcap-or-frame-file>");
        std::process::exit(2);
    }
    let ioc_text = fs::read_to_string(&args[1]).unwrap_or_else(|err| {
        eprintln!("failed to read {}: {err}", args[1]);
        std::process::exit(1);
    });
    let packet_data = fs::read(&args[2]).unwrap_or_else(|err| {
        eprintln!("failed to read {}: {err}", args[2]);
        std::process::exit(1);
    });
    let iocs = parse_ioc_text(&ioc_text);
    let metadata = extract_packet_metadata(&packet_data);
    let matches = match_iocs_to_metadata(&iocs, &metadata);
    let summary = summarize_matches(&matches);
    println!("matches: {} blocked={} allowed={} observed={} highest={}", matches.len(), summary.blocked, summary.allowed, summary.observed, summary.highest.as_str());
    for item in matches {
        println!("frame={} {} {}", item.frame_index, item.key, item.reason);
    }
}
