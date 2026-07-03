use aegislens_core::{catalog::dns_record_name, AegisError, AegisResult, ByteReader};
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    pub id: u16,
    pub flags: u16,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsRecord {
    pub name: String,
    pub rrtype: u16,
    pub class: u16,
    pub ttl: u32,
    pub data_len: u16,
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub header: DnsHeader,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
}
impl DnsMessage {
    pub fn parse(data: &[u8]) -> AegisResult<Self> {
        let mut reader = ByteReader::new(data);
        if data.len() < 12 {
            return Err(AegisError::Truncated { needed: 12, available: data.len() });
        }
        let header = DnsHeader {
            id: reader.read_u16_be()?,
            flags: reader.read_u16_be()?,
            qdcount: reader.read_u16_be()?,
            ancount: reader.read_u16_be()?,
            nscount: reader.read_u16_be()?,
            arcount: reader.read_u16_be()?,
        };
        let mut questions = Vec::new();
        for _ in 0..header.qdcount.min(64) {
            let name = read_name(data, &mut reader, 0)?;
            let qtype = reader.read_u16_be()?;
            let qclass = reader.read_u16_be()?;
            questions.push(DnsQuestion { name, qtype, qclass });
        }
        let answers = read_records(data, &mut reader, header.ancount)?;
        let authorities = read_records(data, &mut reader, header.nscount)?;
        let additionals = read_records(data, &mut reader, header.arcount)?;
        Ok(Self { header, questions, answers, authorities, additionals })
    }
    pub fn queried_names(&self) -> Vec<String> {
        self.questions.iter().map(|q| q.name.clone()).collect()
    }
    pub fn summary(&self) -> String {
        let names = self.questions.iter().map(|q| format!("{}:{}", q.name, dns_record_name(q.qtype))).collect::<Vec<_>>().join(",");
        format!("dns id={} q={} an={} [{}]", self.header.id, self.header.qdcount, self.header.ancount, names)
    }
}
fn read_records(data: &[u8], reader: &mut ByteReader<'_>, count: u16) -> AegisResult<Vec<DnsRecord>> {
    let mut records = Vec::new();
    for _ in 0..count.min(128) {
        let name = read_name(data, reader, 0)?;
        let rrtype = reader.read_u16_be()?;
        let class = reader.read_u16_be()?;
        let ttl = reader.read_u32_be()?;
        let data_len = reader.read_u16_be()?;
        reader.skip(data_len as usize)?;
        records.push(DnsRecord { name, rrtype, class, ttl, data_len });
    }
    Ok(records)
}
fn read_name(data: &[u8], reader: &mut ByteReader<'_>, depth: u8) -> AegisResult<String> {
    if depth > 12 {
        return Err(AegisError::InvalidFormat("dns compression pointer recursion limit".to_string()));
    }
    let mut labels = Vec::new();
    loop {
        let len = reader.read_u8()?;
        if len == 0 {
            break;
        }
        if len & 0xc0 == 0xc0 {
            let next = reader.read_u8()?;
            let offset = (((len & 0x3f) as usize) << 8) | next as usize;
            if offset >= data.len() {
                return Err(AegisError::InvalidFormat("dns compression pointer out of range".to_string()));
            }
            let mut fork = ByteReader::new(&data[offset..]);
            labels.push(read_name(data, &mut fork, depth + 1)?);
            break;
        }
        if len > 63 {
            return Err(AegisError::InvalidFormat("dns label longer than 63 octets".to_string()));
        }
        let raw = reader.take(len as usize)?;
        labels.push(String::from_utf8_lossy(raw).to_ascii_lowercase());
    }
    Ok(labels.join("."))
}
