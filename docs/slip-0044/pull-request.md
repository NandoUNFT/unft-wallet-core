# Draft upstream pull request

The implementation references below are repository-relative so this dossier
contains no speculative hosting URL. When the repository is published, use
permalinks to the tagged files in the final upstream PR.

## Title

Add UNFTChain (UNFT) coin type 10002

## Body

This adds a proposed SLIP-0044 coin type for UNFTChain.

- Project: https://www.unftchain.com/
- Wallet implementation: `src/bip44.rs`, `src/bip44_discovery.rs` and
  `src/bip44_transaction.rs`
- BIP44 compatibility specification: `docs/slip-0044/README.md`
- Deterministic vectors: `docs/slip-0044/vectors-mainnet-proposal.json`
- Core verification: `docs/slip-0044/core-e2e-regtest.md`
- Reproducibility: `verify-release.sh`
- Release: `<published immutable release URL>`

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
