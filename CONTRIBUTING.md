# Contributing

Use Rust 1.85 or newer. Before proposing a change, run:

```sh
./scripts/verify-release.sh
```

Cryptographic compatibility changes require deterministic public test vectors,
restore tests and an independent Unftcoin Core verification. Never commit real
mnemonics, private keys, RPC credentials or user-derived blockchain data.
