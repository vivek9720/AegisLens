use crate::{DnsMessage, EthernetFrame, Ipv4Packet, PcapFile, TransportPacket};
use aegislens_core::{catalog::{port_exposure_score, protocol_name}, Ipv4AddrExt};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PacketMetadata {
    pub frame_index: usize,
    pub source_ip: Option<Ipv4AddrExt>,
    pub destination_ip: Option<Ipv4AddrExt>,
    pub protocol: Option<String>,
    pub source_port: Option<u16>,
    pub destination_port: Option<u16>,
    pub dns_names: Vec<String>,
    pub notes: Vec<String>,
    pub exposure_score: u8,
}
impl PacketMetadata {
    pub fn endpoint_key(&self) -> String {
        format!("{}:{}>{}:{}:{}",
            self.source_ip.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
            self.source_port.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
            self.destination_ip.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
            self.destination_port.map(|v| v.to_string()).unwrap_or_else(|| "-".to_string()),
            self.protocol.as_deref().unwrap_or("unknown"))
    }
}
pub fn extract_packet_metadata(data: &[u8]) -> Vec<PacketMetadata> {
    if let Ok(pcap) = PcapFile::parse(data) {
        pcap.packets.iter().enumerate().map(|(idx, pkt)| extract_frame_metadata(idx, pkt.data)).collect()
    } else {
        vec![extract_frame_metadata(0, data)]
    }
}
pub fn extract_frame_metadata(frame_index: usize, data: &[u8]) -> PacketMetadata {
    let mut meta = PacketMetadata { frame_index, source_ip: None, destination_ip: None, protocol: None, source_port: None, destination_port: None, dns_names: Vec::new(), notes: Vec::new(), exposure_score: 0 };
    let frame = match EthernetFrame::parse(data) {
        Ok(frame) => frame,
        Err(err) => {
            meta.notes.push(format!("ethernet-parse-error:{err}"));
            return meta;
        }
    };
    if frame.ethertype != 0x0800 {
        meta.notes.push(format!("non-ipv4-ethertype:{}", frame.ethertype_name()));
        return meta;
    }
    let ipv4 = match Ipv4Packet::parse(frame.payload) {
        Ok(packet) => packet,
        Err(err) => {
            meta.notes.push(format!("ipv4-parse-error:{err}"));
            return meta;
        }
    };
    meta.source_ip = Some(ipv4.source);
    meta.destination_ip = Some(ipv4.destination);
    meta.protocol = Some(protocol_name(ipv4.protocol).to_string());
    meta.notes.extend(ipv4.path_risk_notes());
    match TransportPacket::parse(ipv4.protocol, ipv4.payload) {
        Ok(transport) => {
            if let Some((src, dst)) = transport.ports() {
                meta.source_port = Some(src);
                meta.destination_port = Some(dst);
                meta.exposure_score = port_exposure_score(dst, meta.protocol.as_deref().unwrap_or("tcp"));
            }
            match transport {
                TransportPacket::Udp(udp) if udp.source_port == 53 || udp.destination_port == 53 => {
                    if let Ok(dns) = DnsMessage::parse(udp.payload) {
                        meta.dns_names = dns.queried_names();
                    }
                }
                TransportPacket::Tcp(tcp) if tcp.source_port == 53 || tcp.destination_port == 53 => {
                    if tcp.payload.len() > 2 {
                        let dns_len = u16::from_be_bytes([tcp.payload[0], tcp.payload[1]]) as usize;
                        if tcp.payload.len() >= 2 + dns_len {
                            if let Ok(dns) = DnsMessage::parse(&tcp.payload[2..2 + dns_len]) {
                                meta.dns_names = dns.queried_names();
                            }
                        }
                    }
                }
                _ => {}
            }
        }
        Err(err) => meta.notes.push(format!("transport-parse-error:{err}")),
    }
    meta
}
