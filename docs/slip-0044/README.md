# UNFTChain SLIP-0044 dossier

Status: technically complete candidate dossier. Checked on 2026-10-21.

Nothing in this directory claims that `10002` is reserved or assigned. It is
only an available candidate observed in the current upstream registry. Recheck
the registry and open pull requests immediately before submission.

## Proposed mainnet profile

- project: [UNFTChain](https://www.unftchain.com/)
- symbol: `UNFT`
- candidate coin type: `10002`
- path: `m/44'/10002'/account'/change/address_index`
- curve: secp256k1
- address type: compressed-key P2PKH
- Mainnet P2PKH version byte: `50` (`0x32`)
- external/receiving chain: `0`
- internal/change chain: `1`

Purpose, coin type and account are hardened. Change and address index are
normal (non-hardened) children. Candidate `10002` remains mutable until the
upstream maintainers accept an allocation.

## Testnet and provisional profiles

These profiles are deliberately distinct:

| Use | Path | Address type | Status |
| --- | --- | --- | --- |
| Mainnet BIP44 proposal | `m/44'/10002'/account'/change/index` | P2PKH, prefix 50 | candidate only |
| Testnet BIP44 | `m/44'/1'/account'/change/index` | P2PKH, prefix 111 | SLIP-0044 shared testnet coin type |
| Existing MVP testnet | `m/84'/424242'/account'/change/index` | P2WPKH, HRP `ut` | named development profile |
| Existing Core reference | `m/84'/0'/account'/change/index` | P2WPKH, HRP `uc`/`ut` | compatibility reference only |

The application must never reinterpret an MVP wallet under the eventual
mainnet allocation. Profile, network, purpose and coin type are recovery
metadata.

## Implementation audit

Implemented and tested in `unft-wallet-core`:

- BIP39 English 24-word mnemonic and optional passphrase;
- BIP39 seed and BIP32/secp256k1 master key;
- exact BIP44 account path;
- hardened purpose, coin type and account levels;
- non-hardened receiving and change branches;
- UNFTChain P2PKH address and `scriptPubKey` generation;
- deterministic restore producing identical addresses;
- network mismatch rejection;
- UNFT Core-compatible extended account key serialization;
- fixed-address discovery for the existing BIP84 profile with gap limit 20;
- BIP44 discovery across consecutive accounts;
- history-based address use, including fully-spent zero-balance addresses;
- independent discovery of change for every discovered account;
- bounded address/account scanning with gap limit 20 by default;
- P2PKH construction, deterministic coin selection, review/approval and local
  legacy `SIGHASH_ALL` signing;
- funded regtest reception, spending, change and post-spend restoration against
  Unftcoin Core.

See [`core-e2e-regtest.md`](core-e2e-regtest.md) for the funded integration
evidence.

## Reproduce vectors

All mnemonic and private material in the vector file is public test material
and must never hold funds.

```sh
git clone https://github.com/NandoUNFT/unft-wallet-core.git
cd unft-wallet-core
git checkout v0.1.0-slip44-candidate.2
./verify-release.sh
```

Expected output is committed as
[`vectors-mainnet-proposal.json`](vectors-mainnet-proposal.json). Independent
Core verification is recorded in [`core-verification.md`](core-verification.md).

## Submission gate

Before opening the upstream PR:

1. publish the prepared annotated release tag
   [`v0.1.0-slip44-candidate.2`](https://github.com/NandoUNFT/unft-wallet-core/tree/v0.1.0-slip44-candidate.2);
2. recheck `UNFT`, `UNFTChain`, candidate `10002`, and pending upstream PRs;
3. regenerate vectors from the published tag;
4. make the one-line upstream change in `slip-0044.patch`.
