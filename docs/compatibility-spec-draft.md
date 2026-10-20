# UNFT Wallet Compatibility Spec — Draft

Status: development-only; not frozen; not for real funds.

The separate BIP44/SLIP-0044 application profile and its provisional vectors
are documented in [`slip-0044/README.md`](slip-0044/README.md). It does not
replace or reinterpret the MVP BIP84 development profile below.

## MVP development profile

Until UNFT receives its SLIP-0044 assignment, the interoperable MVP profile is:

- profile identifier: `development_testnet`;
- network: UNFT Testnet only;
- provisional coin type: `424242`;
- derivation: `m/84'/424242'/account'/change/index`;
- address HRP: `ut`.

Coin type `424242` is not an application for, reservation of, or claim over a
SLIP-0044 number. Mainnet use is forbidden. Implementations must preserve the
profile identifier in encrypted recovery state and must not reinterpret these
wallets using the future assigned UNFT coin type.

## Cryptographic profile

- mnemonic: BIP39 English, 24 words;
- optional BIP39 passphrase;
- seed: PBKDF2-HMAC-SHA512 as defined by BIP39;
- hierarchy: BIP32 over secp256k1;
- address profile: BIP84 P2WPKH;
- derivation: `m/84'/coin_type'/account'/change/index`;
- external chain: `change = 0`;
- internal/change chain: `change = 1`;
- Mainnet Bech32 HRP: `uc`;
- Testnet Bech32 HRP: `ut`.

## Transaction profile

- transaction version: `2`;
- lock time: `0` in the initial profile;
- sequence: `0xfffffffd` (opt-in RBF, no locktime);
- input type: native P2WPKH;
- signature hash: BIP143 `SIGHASH_ALL`;
- signature: deterministic ECDSA/secp256k1 with low-S normalization;
- amounts and fees: integer base units only;
- signed output: Bitcoin-compatible witness serialization, TXID and WTXID.

The implementation verifies that every input script matches the locally
derived key before signing. It never signs an input merely because a caller
provides a derivation path.

## SLIP-44 status

UNFT does not yet have an assigned SLIP-44 coin type. The implementation keeps
the value explicit. Coin type `0` is available only as a named legacy Core
reference profile and is not the production default.

The normative v1 vectors will be generated only after the UNFT allocation is
accepted into SLIP-44.

Separate development vectors may be published for the MVP and must be labelled
non-production.
