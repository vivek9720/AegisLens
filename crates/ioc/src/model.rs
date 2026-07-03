use aegislens_core::{CidrBlock, Ipv4AddrExt, MatchDisposition, Severity};
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IocKind {
    Ip(Ipv4AddrExt),
    Cidr(CidrBlock),
    Domain(String),
    Url(String),
    Hash { algorithm: String, value: String },
}
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IocRecord {
    pub kind: IocKind,
    pub disposition: MatchDisposition,
    pub severity: Severity,
    pub confidence: u8,
    pub source: Option<String>,
    pub tags: Vec<String>,
}
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IocSet {
    pub records: Vec<IocRecord>,
    pub duplicates: Vec<String>,
}
impl IocSet {
    pub fn add(&mut self, record: IocRecord) {
        let key = record.normalized_key();
        if self.records.iter().any(|existing| existing.normalized_key() == key) {
            self.duplicates.push(key);
        } else {
            self.records.push(record);
        }
    }
}
impl IocRecord {
    pub fn normalized_key(&self) -> String {
        match &self.kind {
            IocKind::Ip(ip) => format!("ip:{ip}"),
            IocKind::Cidr(cidr) => format!("cidr:{cidr}"),
            IocKind::Domain(domain) => format!("domain:{}", domain.to_ascii_lowercase()),
            IocKind::Url(url) => format!("url:{}", url.to_ascii_lowercase()),
            IocKind::Hash { algorithm, value } => format!("hash:{}:{}", algorithm.to_ascii_lowercase(), value.to_ascii_lowercase()),
        }
    }
}
