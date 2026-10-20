# Independent verification with Unftcoin Core

Verified on 2026-10-05 with the locally built Unftcoin Core v29.0.0.

The wallet-generated account xpub was passed to Core; no mnemonic or private
key was needed by Core.

```text
pkh(v1wAP9JaTdn8eoVmGRurijFY5Fkw2vyWusgQzJDFauRYowhiqjzob2xEpzAR5LdhWiRGv13kCMMhkyYMuTLasn1WsGJWeKQBNaKtGmnFpk1iRRM/0/*)#8mh2dd3p
```

`deriveaddresses` over `[0,1]` returned:

```text
MN3nQ1LBvTrdR5km1EhMGcPCLoKd16iYV9
MV1oxLJ6rtQm7KXcjm51EkU17hhB2raUt8
```

The change descriptor was:

```text
pkh(v1wAP9JaTdn8eoVmGRurijFY5Fkw2vyWusgQzJDFauRYowhiqjzob2xEpzAR5LdhWiRGv13kCMMhkyYMuTLasn1WsGJWeKQBNaKtGmnFpk1iRRM/1/*)#k0jtscpe
```

Its index zero address was:

```text
MVULj1PKig6C9YEuVCF8BcM4qZbpfJae1k
```

Core decoded external address zero's script as:

```text
hex:     76a9149b33471c97a44ce5955508d4599154cb0be9bf4988ac
asm:     OP_DUP OP_HASH160 9b33471c97a44ce5955508d4599154cb0be9bf49 OP_EQUALVERIFY OP_CHECKSIG
type:    pubkeyhash
address: MN3nQ1LBvTrdR5km1EhMGcPCLoKd16iYV9
```

This proves agreement for extended-key decoding, receiving/change derivation,
P2PKH address encoding and `scriptPubKey`. Account discovery and P2PKH signing
are covered by the crate test suite, while the funded signing flow is recorded
in [`core-e2e-regtest.md`](core-e2e-regtest.md).
