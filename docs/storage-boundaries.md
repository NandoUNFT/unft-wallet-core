# Storage boundaries

`unft-wallet-core` treats secret wallet state and public chain state as two
independent stores.

## Encrypted keystore

The keystore is irreconstructible without the recovery phrase and contains:

- BIP39 mnemonic;
- optional BIP39 passphrase;
- network;
- SLIP-44 coin type;
- account index;
- wallet profile (`development_testnet`, legacy reference, or explicit coin type);
- birthday height;
- schema and cryptographic format versions.

Version 1 uses Argon2id followed by XChaCha20-Poly1305. Encryption parameters,
salt and nonce are public; mnemonic and wallet configuration are authenticated
and encrypted. The library returns serialized bytes but performs no filesystem
write, so each platform can use atomic writes and its native secure storage.

## Local blockchain cache

The cache is not part of the encrypted keystore. It may contain only public,
reconstructible data such as derived addresses, UTXOs, transactions, balances,
NFT state and synchronization cursors.

Deleting the entire cache must leave wallet recovery and deterministic address
derivation unchanged. No secret or irreplaceable counter may be stored only in
the cache.

The reference cache is serialized public state, not a backup. A platform may
replace it with SQLite or another local database as long as it preserves the
same deletion and reconstruction guarantees.

## Cache reconstruction

`discover_wallet` rebuilds a new cache directly from the mnemonic-derived
account. It scans the external (`/0`) and change (`/1`) branches independently,
stopping only after the configured number of consecutive unused addresses.
The default gap limit is 20, the default request batch is 20 addresses, and the
default safety ceiling is 10,000 addresses per branch.

The returned last-used and next-address indices are public synchronization
state. They are deliberately excluded from the encrypted keystore because they
can always be rediscovered. A restore cannot discover activity placed beyond
an uninterrupted gap equal to the configured limit; clients must therefore
avoid issuing addresses beyond that gap.

For discovery, `ChainDataSource::query_addresses` must return exactly one
snapshot for every requested address, including unused addresses. Missing,
duplicate or unsolicited snapshots are rejected rather than interpreted as
unused.

HD paths stored beside cached addresses are also reconstructible metadata. A
cached UTXO is exposed for coin selection only when it is confirmed, satisfies
the requested confirmation depth, and its cached address and script match a
fresh derivation from the unlocked wallet. Unconfirmed, immature, locked,
unmapped or tampered entries are never returned as spendable inputs.

## Network adapters

`ChainDataSource` and `NftDataSource` are implemented outside the cryptographic
core. Platform adapters must sanitize logs and must not persist addresses, raw
transactions, request bodies or IP-to-address associations on UNFT servers.
Address discovery necessarily submits related addresses in batches, so API
infrastructure must also avoid retaining whole batches or correlation keys.
