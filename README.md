# AegisLens

AegisLens is an offline defensive cybersecurity toolkit for inspecting local packet captures, IOC lists, IDS signatures, and firewall policy exports. It is designed for security engineers and system administrators who need deterministic local analysis without network calls or external services.

## Use Cases

- Summarize PCAP traffic and extract IPv4, TCP, UDP, and DNS metadata.
- Normalize IOC files containing IP addresses, domains, URLs, hashes, and CIDR ranges.
- Match local IOCs against packet metadata from captures.
- Validate Snort/Suricata-style IDS signature subsets.
- Audit iptables-style and nftables-style firewall rules for duplicates, shadows, and broad exposure.

## Supported Artifact Formats

- Classic PCAP captures with Ethernet and IPv4 payloads.
- TCP, UDP, and DNS packet data.
- IOC text, CSV-like lists, and tagged allow/block entries.
- IDS signatures with action, protocol, addresses, ports, direction, msg, content, sid, rev, and classtype.
- Firewall exports using common iptables and nftables command-line syntax.
- Simple INI, JSON-line, and CSV-like local policy settings.

## Architecture

- `aegislens-core`: byte readers, endian helpers, diagnostics, checksums, string utilities, time parsing, and IPv4/CIDR helpers.
- `aegislens-packet`: PCAP, Ethernet, IPv4, TCP, UDP, DNS parsing, metadata extraction, and summaries.
- `aegislens-ioc`: IOC classification, normalization, duplicate detection, allow/block handling, and packet metadata matching.
- `aegislens-rules`: IDS rule lexing, parsing, normalization, validation, and metadata matching helpers.
- `aegislens-policy`: firewall and local policy parsing, ordering analysis, duplicate/shadow detection, and summaries.
- `aegislens-cli`: command-line tools backed by the library crates.

## CLI Usage

```sh
cargo run -p aegislens-cli --bin packetscan -- sample.pcap
cargo run -p aegislens-cli --bin iocmatch -- iocs.txt sample.pcap
cargo run -p aegislens-cli --bin rulecheck -- rules.rules
cargo run -p aegislens-cli --bin policyaudit -- firewall.rules
```

## Build

```sh
cargo build --workspace
```

## Test

```sh
cargo test --workspace
```

## Developer QA And Robustness Testing

The `fuzz/` workspace contains parser robustness targets for packet, IOC, IDS rule, and policy paths. They read raw bytes and call real library code. The targets also run as stdin-driven binaries for local smoke checks.

```sh
cargo build --manifest-path fuzz/Cargo.toml --release --bins
Get-Content fuzz/corpus/ioc_fuzzer/ip_iocs.txt | target/release/ioc_fuzzer
```

## Seed Corpus

The seed corpus includes small PCAPs, representative IOC lists, IDS rule samples, and firewall policies. These seeds are intentionally small and human-reviewable so parser behavior remains transparent.

## Manual Review Checklist

- Confirm new parsers reject malformed inputs without panics.
- Confirm CLI tools read only local files.
- Confirm rule and policy diagnostics are understandable to operators.
- Confirm new logic is original, deterministic, and dependency-light.
- Confirm sample artifacts do not contain credentials or environment-specific paths.
