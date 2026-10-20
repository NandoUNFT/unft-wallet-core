# Draft upstream pull request

The implementation references below are immutable links to the prepared
`v0.1.0-slip44-candidate.2` release tag.

## Title

Add UNFTChain (UNFT) coin type 10002

## Body

This adds a proposed SLIP-0044 coin type for UNFTChain.

- Project: https://www.unftchain.com/
- Wallet implementation: [`bip44.rs`](https://github.com/NandoUNFT/unft-wallet-core/blob/v0.1.0-slip44-candidate.2/src/bip44.rs),
  [`bip44_discovery.rs`](https://github.com/NandoUNFT/unft-wallet-core/blob/v0.1.0-slip44-candidate.2/src/bip44_discovery.rs) and
  [`bip44_transaction.rs`](https://github.com/NandoUNFT/unft-wallet-core/blob/v0.1.0-slip44-candidate.2/src/bip44_transaction.rs)
- BIP44 compatibility specification: [`docs/slip-0044/README.md`](https://github.com/NandoUNFT/unft-wallet-core/blob/v0.1.0-slip44-candidate.2/docs/slip-0044/README.md)
- Deterministic vectors: [`vectors-mainnet-proposal.json`](https://github.com/NandoUNFT/unft-wallet-core/blob/v0.1.0-slip44-candidate.2/docs/slip-0044/vectors-mainnet-proposal.json)
- Core verification: [`core-e2e-regtest.md`](https://github.com/NandoUNFT/unft-wallet-core/blob/v0.1.0-slip44-candidate.2/docs/slip-0044/core-e2e-regtest.md)
- Reproducibility: [`verify-release.sh`](https://github.com/NandoUNFT/unft-wallet-core/blob/v0.1.0-slip44-candidate.2/verify-release.sh)
- Tagged source: [`v0.1.0-slip44-candidate.2`](https://github.com/NandoUNFT/unft-wallet-core/tree/v0.1.0-slip44-candidate.2)

The implementation uses BIP39, BIP32/secp256k1 and the BIP44 path
`m/44'/10002'/account'/change/address_index`. Purpose, coin type and account
are hardened; change and address index are non-hardened. Receiving is branch 0
and change is branch 1. UNFTChain Mainnet addresses for this profile are
compressed-key P2PKH.

Testnet uses the registry's shared testnet coin type 1 and is not represented
by this new row. Historical development profiles are documented separately and
are not silently migrated.

At the time of the final pre-submission check, neither `UNFT`, `UNFTChain` nor
coin type `10002` appeared in the registry. We understand that this PR requests
an allocation; it does not claim that the number is reserved or already
assigned, and we can change the proposed value if maintainers request it.
