#!/usr/bin/env sh
set -eu

cargo fmt --all --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings

vector_output=$(mktemp)
trap 'rm -f "$vector_output"' EXIT
cargo run --locked --quiet --example slip0044_vectors > "$vector_output"
diff -u docs/slip-0044/vectors-mainnet-proposal.json "$vector_output"
