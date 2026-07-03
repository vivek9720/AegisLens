use aegislens_packet::summarize_capture;
#[test]
fn malformed_capture_does_not_panic() {
    let summary = summarize_capture(b"not a pcap");
    assert_eq!(summary.packet_count, 1);
}
