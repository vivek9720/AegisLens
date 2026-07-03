#!/bin/bash -eu
ROOT="${SRC:-$(pwd)}"
cd "$ROOT"
export CARGO_NET_OFFLINE=true
export CARGO_TARGET_DIR="$ROOT/target"
cargo build --manifest-path fuzz/Cargo.toml --release --bins
mkdir -p "$OUT"
cp target/release/packet_fuzzer "$OUT/packet_fuzzer"
cp target/release/ioc_fuzzer "$OUT/ioc_fuzzer"
cp target/release/rules_fuzzer "$OUT/rules_fuzzer"
cp target/release/policy_fuzzer "$OUT/policy_fuzzer"
