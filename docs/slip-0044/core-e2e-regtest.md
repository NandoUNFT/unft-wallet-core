# Unftcoin Core funded regtest verification

Date: 2026-10-06

Core: locally built Unftcoin Core v29.0.0, isolated datadir, `-regtest
-haszki`, RPC bound to localhost. No production chain or funds were involved.

## Flow

1. Core generated more than 36 blocks to mature test coinbase funds.
2. Core sent `1.00000000` test UNFT to wallet-core BIP44 external address 0.
3. The funding transaction was mined.
4. wallet-core built and signed a P2PKH transaction locally.
5. Core accepted it through `sendrawtransaction` and mined it.
6. A new blank watch-only Core wallet imported account descriptors and rescanned
   from genesis, simulating restoration after device loss.

## Evidence

| Item | Value |
| --- | --- |
| Profile | testnet BIP44 `m/44'/1'/0'` |
| Source | `mwJUtDhZByTTG1r9BmvkTqA6uWX41S3WJq` (`/0/0`) |
| Funding TXID | `af6baccc69843cbbdb64a2aa67eaa8a13f8d9cd9f1ed336cc885300509edf20c` |
| Funding outpoint | `:1`, `100000000` base units |
| Spend TXID | `d39a4289baa5609b34b4cc07b83f483e74c5948531948139c182e88624301629` |
| Recipient | `mj57V6669A5eBR73QxYpo3WNSks1ujGfQ7` (`/0/1`) |
| Recipient value | `50000000` base units |
| Change | `n2zSJUqyphyGMVtDDKNro2szffaFZ8gFXn` (`/1/0`) |
| Change value | `49999000` base units |
| Fee | `1000` base units |
| Confirmed funding height | 60 |
| Confirmed spend height | 61 |

Core decoded the input as a P2PKH `scriptSig` containing a DER ECDSA signature
with `SIGHASH_ALL` and the compressed public key. Core reported TXID equal to
wallet-core's locally calculated TXID.

After descriptor import and genesis rescan, the new wallet reported:

- the original external address with its `1.00000000` receive history even
  though that outpoint was fully spent;
- recipient `/0/1` with `0.50000000`;
- change `/1/0` with `0.49999000`;
- the confirmed spending transaction and fee `0.00001000`.

The reproducible transaction generator is
`examples/bip44_core_spend.rs`. RPC credentials and the isolated datadir are
deliberately not part of the repository.
