# Wallet chain-adapter architecture

The wallet kernel owns account lifecycle, encrypted storage, backup, approval
state and presentation models. Chain adapters own derivation, addresses,
public-chain queries, fee semantics, transaction construction, signing and
broadcast serialization.

`UtxoChainAdapter` uses inputs, outpoints, change and UTXO-specific signing.
`EvmChainAdapter` is deliberately separate and will use accounts, nonces, gas
and EVM transaction envelopes. Neither family inherits the other's transaction
model.

UNFTChain is the first operational adapter. Mainnet and Testnet4 identities are
bound to exact chain IDs and genesis hashes. An adapter must reject a backend
whose complete `NetworkIdentity` differs from the selected wallet network.

`PublicChainBackend` accepts only public addresses, cursors and signed raw
transactions. Mnemonics, seeds, private keys, xprvs and account xpubs are not
part of its type-level contract.

The next compatibility proof will add one real Bitcoin-compatible UTXO adapter.
Only after that boundary is proven will an independent EVM adapter be added.
