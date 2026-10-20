# unft-wallet-core

Platform-neutral cryptographic core for UNFT Wallet.

Current milestone:

- create a 24-word BIP39 wallet;
- restore it deterministically;
- derive BIP32/BIP84 P2WPKH addresses;
- derive the explicit BIP44/P2PKH Mainnet proposal and shared Testnet profile;
- encode UNFT Mainnet (`uc`) and Testnet (`ut`) addresses;
- build deterministic version-2 P2WPKH transactions with opt-in RBF;
- calculate fees and change without floating-point amounts;
- select eligible UTXOs deterministically and expose a reviewable proposal;
- enforce the application payment flow through pending and approved states;
- sign every input locally using BIP143 and `SIGHASH_ALL`;
- return broadcast-ready raw transaction, TXID and WTXID;
- serialize an authenticated encrypted keystore;
- maintain a separate, deletable cache of public chain and NFT data;
- expose platform-neutral chain and NFT data-source contracts;
- rebuild a deleted cache through bounded BIP44-style gap-limit discovery;
- resolve confirmed cache UTXOs back to verified HD paths before selection;
- keep the SLIP-44 coin type explicit until UNFT receives an assignment.

The MVP has a named `development-testnet` profile using provisional coin type
`424242`. It is accepted only on UNFT Testnet and is authenticated inside new
keystores. It is intentionally distinct from the legacy Core reference profile
and from the future production profile.

Network adapter implementations, filesystem persistence, NFT transfers and
platform bindings remain separate milestones.

## Coin type safety

There is no production default coin type. Every wallet configuration must
provide one explicitly. Coin type `0` can be enabled only through the named
legacy compatibility constructor and must not be used for new production
wallets.

Coin type `424242` is also reserved by this implementation: callers cannot
select it as an arbitrary explicit coin type and must use
`WalletConfig::development_testnet(account)`. Mainnet configurations using it
are rejected.

Application integrations should follow the stateful flow documented in
[`docs/payment-flow.md`](docs/payment-flow.md).

Account discovery and P2PKH signing are implemented and tested. The
SLIP-0044 dossier remains a candidate until the repository has immutable
public release links and the proposed coin type is accepted upstream. See
[`docs/slip-0044/README.md`](docs/slip-0044/README.md).

## Verification

This repository is a standalone crate. Run the complete reproducibility check
with:

```sh
./verify-release.sh
```
