use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::{AddressChain, Result, SpendableUtxo, UnftNetwork, WalletError, WalletSecrets};

const CACHE_SCHEMA: &str = "unft-blockchain-cache-v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmationStatus {
    Confirmed,
    Unconfirmed,
    Immature,
    Locked,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub script_pub_key: Vec<u8>,
    pub status: ConfirmationStatus,
    pub block_height: Option<u64>,
    pub confirmations: u64,
    pub coinbase: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CachedTransaction {
    pub txid: String,
    pub block_height: Option<u64>,
    pub confirmations: u64,
    pub timestamp: Option<u64>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddressSnapshot {
    pub address: String,
    pub used: bool,
    pub utxos: Vec<Utxo>,
    pub transactions: Vec<CachedTransaction>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AddressDerivation {
    pub chain: AddressChain,
    pub index: u32,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct NftRecord {
    pub nft_id: String,
    pub owner: String,
    pub status: String,
    pub mint_txid: String,
    pub last_txid: String,
    pub metadata_content_id: Option<String>,
    pub metadata_hash: Option<String>,
    pub asset_hash: Option<String>,
    pub block_height: Option<u64>,
    pub confirmations: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Balance {
    pub confirmed: u64,
    pub unconfirmed: u64,
    pub immature: u64,
    pub locked: u64,
}

impl Balance {
    pub fn spendable(self) -> u64 {
        self.confirmed
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BlockchainCache {
    schema: String,
    network: UnftNetwork,
    tip_height: Option<u64>,
    tip_hash: Option<String>,
    observed_at: Option<u64>,
    addresses: BTreeMap<String, AddressSnapshot>,
    #[serde(default)]
    derivations: BTreeMap<String, AddressDerivation>,
    nfts: BTreeMap<String, NftRecord>,
}

impl BlockchainCache {
    pub fn new(network: UnftNetwork) -> Self {
        Self {
            schema: CACHE_SCHEMA.to_owned(),
            network,
            tip_height: None,
            tip_hash: None,
            observed_at: None,
            addresses: BTreeMap::new(),
            derivations: BTreeMap::new(),
            nfts: BTreeMap::new(),
        }
    }

    pub const fn network(&self) -> UnftNetwork {
        self.network
    }

    pub const fn tip_height(&self) -> Option<u64> {
        self.tip_height
    }

    pub fn address(&self, address: &str) -> Option<&AddressSnapshot> {
        self.addresses.get(address)
    }

    pub fn addresses(&self) -> impl Iterator<Item = &AddressSnapshot> {
        self.addresses.values()
    }

    pub fn address_derivation(&self, address: &str) -> Option<AddressDerivation> {
        self.derivations.get(address).copied()
    }

    pub fn spendable_utxos(
        &self,
        wallet: &WalletSecrets,
        minimum_confirmations: u64,
    ) -> Result<Vec<SpendableUtxo>> {
        if self.network != wallet.config().network {
            return Err(WalletError::CacheNetworkMismatch);
        }
        let mut by_outpoint = BTreeMap::new();
        for (address, snapshot) in &self.addresses {
            let Some(derivation) = self.derivations.get(address) else {
                continue;
            };
            let derived = wallet.derive_address(derivation.chain, derivation.index)?;
            if derived.address != *address {
                return Err(WalletError::InvalidCache);
            }
            for utxo in &snapshot.utxos {
                if utxo.status != ConfirmationStatus::Confirmed
                    || utxo.confirmations < minimum_confirmations
                {
                    continue;
                }
                if utxo.script_pub_key != derived.script_pub_key {
                    return Err(WalletError::InvalidCache);
                }
                let spendable = SpendableUtxo {
                    txid: utxo.txid.clone(),
                    vout: utxo.vout,
                    value: utxo.value,
                    script_pub_key: utxo.script_pub_key.clone(),
                    chain: derivation.chain,
                    address_index: derivation.index,
                };
                let outpoint = (utxo.txid.clone(), utxo.vout);
                if let Some(previous) = by_outpoint.insert(outpoint, spendable.clone())
                    && previous != spendable
                {
                    return Err(WalletError::InvalidCache);
                }
            }
        }
        Ok(by_outpoint.into_values().collect())
    }

    pub fn nfts(&self) -> impl Iterator<Item = &NftRecord> {
        self.nfts.values()
    }

    pub fn balance(&self) -> Result<Balance> {
        let mut seen = BTreeSet::new();
        self.addresses
            .values()
            .try_fold(Balance::default(), |mut balance, snapshot| {
                for utxo in &snapshot.utxos {
                    if !seen.insert((utxo.txid.as_str(), utxo.vout)) {
                        continue;
                    }
                    let target = match utxo.status {
                        ConfirmationStatus::Confirmed => &mut balance.confirmed,
                        ConfirmationStatus::Unconfirmed => &mut balance.unconfirmed,
                        ConfirmationStatus::Immature => &mut balance.immature,
                        ConfirmationStatus::Locked => &mut balance.locked,
                    };
                    *target = target
                        .checked_add(utxo.value)
                        .ok_or(WalletError::AmountOverflow)?;
                }
                Ok(balance)
            })
    }

    pub fn clear(self) -> Self {
        Self::new(self.network)
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| WalletError::CacheSerialization)
    }

    pub fn from_bytes(bytes: &[u8], expected_network: UnftNetwork) -> Result<Self> {
        let cache: Self = serde_json::from_slice(bytes).map_err(|_| WalletError::InvalidCache)?;
        if cache.schema != CACHE_SCHEMA {
            return Err(WalletError::InvalidCache);
        }
        if cache.network != expected_network {
            return Err(WalletError::CacheNetworkMismatch);
        }
        Ok(cache)
    }

    pub(crate) fn replace_addresses(&mut self, snapshots: Vec<AddressSnapshot>) {
        for snapshot in snapshots {
            self.addresses.insert(snapshot.address.clone(), snapshot);
        }
    }

    pub(crate) fn set_address_derivation(
        &mut self,
        address: String,
        derivation: AddressDerivation,
    ) {
        self.derivations.insert(address, derivation);
    }

    pub(crate) fn replace_nfts(&mut self, nfts: Vec<NftRecord>) {
        self.nfts = nfts
            .into_iter()
            .map(|nft| (nft.nft_id.clone(), nft))
            .collect();
    }

    pub(crate) fn set_tip(&mut self, height: u64, hash: String, observed_at: u64) {
        self.tip_height = Some(height);
        self.tip_hash = Some(hash);
        self.observed_at = Some(observed_at);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoinType, WalletConfig, restore_wallet};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn wallet() -> WalletSecrets {
        restore_wallet(
            MNEMONIC,
            "TREZOR",
            WalletConfig::new(UnftNetwork::Mainnet, CoinType::legacy_core_reference(), 0).unwrap(),
        )
        .unwrap()
    }

    fn snapshot() -> AddressSnapshot {
        AddressSnapshot {
            address: "uc1qtest".to_owned(),
            used: true,
            utxos: vec![
                Utxo {
                    txid: "11".repeat(32),
                    vout: 0,
                    value: 100,
                    script_pub_key: vec![0, 20],
                    status: ConfirmationStatus::Confirmed,
                    block_height: Some(1),
                    confirmations: 10,
                    coinbase: false,
                },
                Utxo {
                    txid: "22".repeat(32),
                    vout: 1,
                    value: 5,
                    script_pub_key: vec![0, 20],
                    status: ConfirmationStatus::Unconfirmed,
                    block_height: None,
                    confirmations: 0,
                    coinbase: false,
                },
            ],
            transactions: vec![],
        }
    }

    #[test]
    fn serializes_rebuildable_public_state() {
        let mut cache = BlockchainCache::new(UnftNetwork::Mainnet);
        cache.replace_addresses(vec![snapshot()]);
        cache.set_tip(10, "aa".repeat(32), 123);
        let encoded = cache.to_bytes().unwrap();
        let decoded = BlockchainCache::from_bytes(&encoded, UnftNetwork::Mainnet).unwrap();
        assert_eq!(decoded, cache);
        assert_eq!(
            decoded.balance().unwrap(),
            Balance {
                confirmed: 100,
                unconfirmed: 5,
                immature: 0,
                locked: 0,
            }
        );
    }

    #[test]
    fn clearing_cache_removes_all_chain_state() {
        let mut cache = BlockchainCache::new(UnftNetwork::Mainnet);
        cache.replace_addresses(vec![snapshot()]);
        let cleared = cache.clear();
        assert_eq!(cleared.balance().unwrap(), Balance::default());
        assert_eq!(cleared.addresses().count(), 0);
        assert_eq!(cleared.tip_height(), None);
    }

    #[test]
    fn rejects_cache_from_another_network() {
        let encoded = BlockchainCache::new(UnftNetwork::Testnet)
            .to_bytes()
            .unwrap();
        assert!(matches!(
            BlockchainCache::from_bytes(&encoded, UnftNetwork::Mainnet),
            Err(WalletError::CacheNetworkMismatch)
        ));
    }

    #[test]
    fn exposes_only_confirmed_owned_utxos_with_required_depth() {
        let wallet = wallet();
        let derived = wallet.derive_address(AddressChain::Change, 7).unwrap();
        let address = derived.address;
        let script_pub_key = derived.script_pub_key;
        let mut cache = BlockchainCache::new(UnftNetwork::Mainnet);
        cache.set_address_derivation(
            address.clone(),
            AddressDerivation {
                chain: AddressChain::Change,
                index: 7,
            },
        );
        cache.replace_addresses(vec![AddressSnapshot {
            address,
            used: true,
            utxos: vec![
                Utxo {
                    txid: "33".repeat(32),
                    vout: 0,
                    value: 500,
                    script_pub_key: script_pub_key.clone(),
                    status: ConfirmationStatus::Confirmed,
                    block_height: Some(10),
                    confirmations: 6,
                    coinbase: false,
                },
                Utxo {
                    txid: "44".repeat(32),
                    vout: 1,
                    value: 600,
                    script_pub_key: script_pub_key.clone(),
                    status: ConfirmationStatus::Confirmed,
                    block_height: Some(11),
                    confirmations: 1,
                    coinbase: false,
                },
                Utxo {
                    txid: "55".repeat(32),
                    vout: 0,
                    value: 700,
                    script_pub_key: script_pub_key.clone(),
                    status: ConfirmationStatus::Immature,
                    block_height: Some(12),
                    confirmations: 100,
                    coinbase: true,
                },
                Utxo {
                    txid: "66".repeat(32),
                    vout: 0,
                    value: 800,
                    script_pub_key,
                    status: ConfirmationStatus::Unconfirmed,
                    block_height: None,
                    confirmations: 0,
                    coinbase: false,
                },
            ],
            transactions: vec![],
        }]);

        let spendable = cache.spendable_utxos(&wallet, 2).unwrap();
        assert_eq!(spendable.len(), 1);
        assert_eq!(spendable[0].value, 500);
        assert_eq!(spendable[0].chain, AddressChain::Change);
        assert_eq!(spendable[0].address_index, 7);
    }

    #[test]
    fn address_without_derivation_is_never_exposed_for_signing() {
        let mut cache = BlockchainCache::new(UnftNetwork::Mainnet);
        cache.replace_addresses(vec![snapshot()]);
        assert!(cache.spendable_utxos(&wallet(), 0).unwrap().is_empty());
    }

    #[test]
    fn rejects_tampered_derivation_metadata_before_selection() {
        let wallet = wallet();
        let derived = wallet.derive_address(AddressChain::Change, 7).unwrap();
        let mut cache = BlockchainCache::new(UnftNetwork::Mainnet);
        cache.set_address_derivation(
            derived.address.clone(),
            AddressDerivation {
                chain: AddressChain::External,
                index: 7,
            },
        );
        cache.replace_addresses(vec![AddressSnapshot {
            address: derived.address,
            used: true,
            utxos: vec![],
            transactions: vec![],
        }]);
        assert!(matches!(
            cache.spendable_utxos(&wallet, 0),
            Err(WalletError::InvalidCache)
        ));
    }
}
