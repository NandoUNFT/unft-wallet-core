use std::collections::{BTreeMap, BTreeSet};

use crate::{
    AddressChain, AddressDerivation, AddressSnapshot, Balance, BlockchainCache, NftRecord, Result,
    SignedTransaction, UnftNetwork, WalletError, WalletSecrets,
};

const DEFAULT_GAP_LIMIT: u32 = 20;
const DEFAULT_DISCOVERY_BATCH_SIZE: u32 = 20;
const DEFAULT_MAX_ADDRESSES_PER_CHAIN: u32 = 10_000;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainTip {
    pub height: u64,
    pub block_hash: String,
    pub observed_at: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BroadcastReceipt {
    pub txid: String,
    pub accepted: bool,
    pub already_known: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeeEstimates {
    pub minimum_relay: u64,
    pub economy: u64,
    pub normal: u64,
    pub priority: u64,
    pub observed_at_height: u64,
}

pub trait FeeDataSource {
    fn network(&self) -> UnftNetwork;
    fn estimates(&self) -> Result<FeeEstimates>;
}

pub trait BroadcastDataSource {
    fn network(&self) -> UnftNetwork;
    fn broadcast(&self, raw_transaction: &str) -> Result<BroadcastReceipt>;
}

/// Platform-provided access to public UNFTChain data.
///
/// Implementations must not persist request bodies, addresses, raw
/// transactions or IP-to-address associations. The core deliberately has no
/// HTTP client or server credentials.
pub trait ChainDataSource {
    fn network(&self) -> UnftNetwork;
    fn tip(&self) -> Result<ChainTip>;
    fn query_addresses(&self, addresses: &[String]) -> Result<Vec<AddressSnapshot>>;
    fn broadcast(&self, raw_transaction: &str) -> Result<BroadcastReceipt>;
}

impl<T: ChainDataSource> BroadcastDataSource for T {
    fn network(&self) -> UnftNetwork {
        ChainDataSource::network(self)
    }

    fn broadcast(&self, raw_transaction: &str) -> Result<BroadcastReceipt> {
        ChainDataSource::broadcast(self, raw_transaction)
    }
}

/// Platform-provided access to the public, reconstructible NFT index.
pub trait NftDataSource {
    fn network(&self) -> UnftNetwork;
    fn list_by_owners(&self, owners: &[String]) -> Result<Vec<NftRecord>>;
}

/// Public, reconstructible controls for deterministic HD account discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveryOptions {
    pub gap_limit: u32,
    pub batch_size: u32,
    pub max_addresses_per_chain: u32,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            gap_limit: DEFAULT_GAP_LIMIT,
            batch_size: DEFAULT_DISCOVERY_BATCH_SIZE,
            max_addresses_per_chain: DEFAULT_MAX_ADDRESSES_PER_CHAIN,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChainDiscovery {
    pub last_used_index: Option<u32>,
    pub next_index: u32,
    pub scanned: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiscoveryResult {
    pub cache: BlockchainCache,
    pub external: ChainDiscovery,
    pub change: ChainDiscovery,
}

/// Reconstructs all public wallet state from an empty cache.
///
/// Both BIP84 chains are scanned independently until `gap_limit`
/// consecutive unused addresses are observed. The returned indices are cache
/// metadata and must never be stored in the encrypted keystore.
pub fn discover_wallet(
    wallet: &WalletSecrets,
    source: &impl ChainDataSource,
    options: DiscoveryOptions,
) -> Result<DiscoveryResult> {
    validate_discovery_options(options)?;
    ensure_network(wallet.config().network, source.network())?;

    let mut cache = BlockchainCache::new(wallet.config().network);
    let external = discover_chain(wallet, source, &mut cache, AddressChain::External, options)?;
    let change = discover_chain(wallet, source, &mut cache, AddressChain::Change, options)?;
    let tip = source.tip()?;
    cache.set_tip(tip.height, tip.block_hash, tip.observed_at);

    Ok(DiscoveryResult {
        cache,
        external,
        change,
    })
}

fn validate_discovery_options(options: DiscoveryOptions) -> Result<()> {
    if options.gap_limit == 0
        || options.batch_size == 0
        || options.max_addresses_per_chain < options.gap_limit
    {
        return Err(WalletError::InvalidDiscoveryOptions);
    }
    Ok(())
}

fn discover_chain(
    wallet: &WalletSecrets,
    source: &impl ChainDataSource,
    cache: &mut BlockchainCache,
    chain: AddressChain,
    options: DiscoveryOptions,
) -> Result<ChainDiscovery> {
    let mut next_to_scan = 0_u32;
    let mut unused_run = 0_u32;
    let mut last_used_index = None;

    while unused_run < options.gap_limit {
        let remaining = options
            .max_addresses_per_chain
            .checked_sub(next_to_scan)
            .ok_or(WalletError::DiscoveryLimitReached)?;
        if remaining == 0 {
            return Err(WalletError::DiscoveryLimitReached);
        }
        let batch_len = options.batch_size.min(remaining);
        let derived = (next_to_scan..next_to_scan + batch_len)
            .map(|index| {
                wallet
                    .derive_address(chain, index)
                    .map(|address| (index, address.address))
            })
            .collect::<Result<Vec<_>>>()?;
        let requested = derived
            .iter()
            .map(|(_, address)| address.clone())
            .collect::<Vec<_>>();
        let snapshots = source.query_addresses(&requested)?;
        let mut by_address = validate_complete_response(&requested, snapshots)?;

        for (index, address) in derived {
            let snapshot = by_address
                .remove(&address)
                .ok_or(WalletError::InvalidDataSourceResponse)?;
            if !snapshot.used && (!snapshot.utxos.is_empty() || !snapshot.transactions.is_empty()) {
                return Err(WalletError::InvalidDataSourceResponse);
            }
            let expected_script = wallet.derive_address(chain, index)?.script_pub_key;
            if snapshot
                .utxos
                .iter()
                .any(|utxo| utxo.script_pub_key != expected_script)
            {
                return Err(WalletError::InvalidDataSourceResponse);
            }
            if snapshot.used {
                last_used_index = Some(index);
                unused_run = 0;
            } else {
                unused_run = unused_run
                    .checked_add(1)
                    .ok_or(WalletError::DiscoveryLimitReached)?;
            }
            cache.set_address_derivation(address, AddressDerivation { chain, index });
            cache.replace_addresses(vec![snapshot]);
        }
        next_to_scan = next_to_scan
            .checked_add(batch_len)
            .ok_or(WalletError::DiscoveryLimitReached)?;
    }

    Ok(ChainDiscovery {
        last_used_index,
        next_index: last_used_index.map_or(0, |index| index + 1),
        scanned: next_to_scan,
    })
}

fn validate_complete_response(
    requested: &[String],
    snapshots: Vec<AddressSnapshot>,
) -> Result<BTreeMap<String, AddressSnapshot>> {
    if snapshots.len() != requested.len() {
        return Err(WalletError::InvalidDataSourceResponse);
    }
    let requested = requested.iter().collect::<BTreeSet<_>>();
    let mut returned = BTreeMap::new();
    for snapshot in snapshots {
        if !requested.contains(&snapshot.address) || returned.contains_key(&snapshot.address) {
            return Err(WalletError::InvalidDataSourceResponse);
        }
        returned.insert(snapshot.address.clone(), snapshot);
    }
    Ok(returned)
}

pub fn refresh_addresses(
    cache: &mut BlockchainCache,
    source: &impl ChainDataSource,
    addresses: &[String],
) -> Result<()> {
    ensure_network(cache.network(), source.network())?;
    let snapshots = source.query_addresses(addresses)?;
    let requested = addresses.iter().collect::<BTreeSet<_>>();
    let mut returned = BTreeSet::new();
    if snapshots.iter().any(|snapshot| {
        !requested.contains(&snapshot.address) || !returned.insert(snapshot.address.as_str())
    }) {
        return Err(WalletError::InvalidDataSourceResponse);
    }
    let tip = source.tip()?;
    cache.replace_addresses(snapshots);
    cache.set_tip(tip.height, tip.block_hash, tip.observed_at);
    Ok(())
}

pub fn get_balance(cache: &BlockchainCache) -> Result<Balance> {
    cache.balance()
}

pub fn broadcast(
    wallet_network: UnftNetwork,
    source: &impl BroadcastDataSource,
    transaction: &SignedTransaction,
) -> Result<BroadcastReceipt> {
    ensure_network(wallet_network, source.network())?;
    let receipt = source.broadcast(&transaction.raw_hex)?;
    if receipt.txid != transaction.txid {
        return Err(WalletError::DataSourceUnavailable);
    }
    Ok(receipt)
}

pub fn get_fee_estimates(
    wallet_network: UnftNetwork,
    source: &impl FeeDataSource,
) -> Result<FeeEstimates> {
    ensure_network(wallet_network, source.network())?;
    let estimates = source.estimates()?;
    if estimates.minimum_relay == 0
        || estimates.economy < estimates.minimum_relay
        || estimates.normal < estimates.economy
        || estimates.priority < estimates.normal
    {
        return Err(WalletError::InvalidDataSourceResponse);
    }
    Ok(estimates)
}

pub fn nft_list(
    cache: &mut BlockchainCache,
    source: &impl NftDataSource,
    owners: &[String],
) -> Result<Vec<NftRecord>> {
    ensure_network(cache.network(), source.network())?;
    let nfts = source.list_by_owners(owners)?;
    cache.replace_nfts(nfts.clone());
    Ok(nfts)
}

fn ensure_network(expected: UnftNetwork, actual: UnftNetwork) -> Result<()> {
    if expected != actual {
        return Err(WalletError::CacheNetworkMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CachedTransaction, ConfirmationStatus, Utxo, WalletConfig, restore_wallet};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    struct FakeChain {
        network: UnftNetwork,
    }

    impl ChainDataSource for FakeChain {
        fn network(&self) -> UnftNetwork {
            self.network
        }

        fn tip(&self) -> Result<ChainTip> {
            Ok(ChainTip {
                height: 42,
                block_hash: "aa".repeat(32),
                observed_at: 100,
            })
        }

        fn query_addresses(&self, addresses: &[String]) -> Result<Vec<AddressSnapshot>> {
            Ok(addresses
                .iter()
                .map(|address| AddressSnapshot {
                    address: address.clone(),
                    used: true,
                    utxos: vec![Utxo {
                        txid: "11".repeat(32),
                        vout: 0,
                        value: 25,
                        script_pub_key: vec![0, 20],
                        status: ConfirmationStatus::Confirmed,
                        block_height: Some(40),
                        confirmations: 3,
                        coinbase: false,
                    }],
                    transactions: vec![CachedTransaction {
                        txid: "11".repeat(32),
                        block_height: Some(40),
                        confirmations: 3,
                        timestamp: Some(90),
                    }],
                })
                .collect())
        }

        fn broadcast(&self, _raw_transaction: &str) -> Result<BroadcastReceipt> {
            Err(WalletError::DataSourceUnavailable)
        }
    }

    #[test]
    fn refreshes_disposable_cache_from_data_source() {
        let source = FakeChain {
            network: UnftNetwork::Mainnet,
        };
        let mut cache = BlockchainCache::new(UnftNetwork::Mainnet);
        refresh_addresses(&mut cache, &source, &["uc1qtest".to_owned()]).unwrap();
        assert_eq!(cache.tip_height(), Some(42));
        assert_eq!(get_balance(&cache).unwrap().confirmed, 25);
    }

    #[test]
    fn refuses_cross_network_data() {
        let source = FakeChain {
            network: UnftNetwork::Testnet,
        };
        let mut cache = BlockchainCache::new(UnftNetwork::Mainnet);
        assert!(matches!(
            refresh_addresses(&mut cache, &source, &["uc1qtest".to_owned()]),
            Err(WalletError::CacheNetworkMismatch)
        ));
    }

    struct DiscoveryChain {
        network: UnftNetwork,
        used: BTreeSet<String>,
        omit_last: bool,
    }

    impl ChainDataSource for DiscoveryChain {
        fn network(&self) -> UnftNetwork {
            self.network
        }

        fn tip(&self) -> Result<ChainTip> {
            Ok(ChainTip {
                height: 500,
                block_hash: "bb".repeat(32),
                observed_at: 200,
            })
        }

        fn query_addresses(&self, addresses: &[String]) -> Result<Vec<AddressSnapshot>> {
            let len = if self.omit_last {
                addresses.len().saturating_sub(1)
            } else {
                addresses.len()
            };
            Ok(addresses[..len]
                .iter()
                .map(|address| AddressSnapshot {
                    address: address.clone(),
                    used: self.used.contains(address),
                    utxos: vec![],
                    transactions: vec![],
                })
                .collect())
        }

        fn broadcast(&self, _raw_transaction: &str) -> Result<BroadcastReceipt> {
            Err(WalletError::DataSourceUnavailable)
        }
    }

    fn discovery_wallet() -> WalletSecrets {
        let config = WalletConfig::development_testnet(0).unwrap();
        restore_wallet(MNEMONIC, "", config).unwrap()
    }

    #[test]
    fn rebuilds_deleted_cache_and_recovers_both_hd_chains() {
        let wallet = discovery_wallet();
        let external_0 = wallet
            .derive_address(AddressChain::External, 0)
            .unwrap()
            .address;
        let external_21 = wallet
            .derive_address(AddressChain::External, 21)
            .unwrap()
            .address;
        let change_3 = wallet
            .derive_address(AddressChain::Change, 3)
            .unwrap()
            .address;
        let source = DiscoveryChain {
            network: UnftNetwork::Testnet,
            used: [external_0, external_21, change_3].into_iter().collect(),
            omit_last: false,
        };

        let result = discover_wallet(
            &wallet,
            &source,
            DiscoveryOptions {
                gap_limit: 20,
                batch_size: 10,
                max_addresses_per_chain: 100,
            },
        )
        .unwrap();

        assert_eq!(result.external.last_used_index, Some(21));
        assert_eq!(result.external.next_index, 22);
        assert_eq!(result.external.scanned, 50);
        assert_eq!(result.change.last_used_index, Some(3));
        assert_eq!(result.change.next_index, 4);
        assert_eq!(result.change.scanned, 30);
        assert_eq!(result.cache.addresses().count(), 80);
        assert_eq!(result.cache.tip_height(), Some(500));
    }

    #[test]
    fn discovery_requires_a_complete_exact_response() {
        let wallet = discovery_wallet();
        let source = DiscoveryChain {
            network: UnftNetwork::Testnet,
            used: BTreeSet::new(),
            omit_last: true,
        };
        assert!(matches!(
            discover_wallet(&wallet, &source, DiscoveryOptions::default()),
            Err(WalletError::InvalidDataSourceResponse)
        ));
    }

    #[test]
    fn discovery_stops_at_configured_safety_limit() {
        let wallet = discovery_wallet();
        let used = (0..20)
            .map(|index| {
                wallet
                    .derive_address(AddressChain::External, index)
                    .unwrap()
                    .address
            })
            .collect();
        let source = DiscoveryChain {
            network: UnftNetwork::Testnet,
            used,
            omit_last: false,
        };
        assert!(matches!(
            discover_wallet(
                &wallet,
                &source,
                DiscoveryOptions {
                    gap_limit: 5,
                    batch_size: 5,
                    max_addresses_per_chain: 20,
                }
            ),
            Err(WalletError::DiscoveryLimitReached)
        ));
    }

    #[test]
    fn discovery_rejects_invalid_options_and_cross_network_source() {
        let wallet = discovery_wallet();
        let source = DiscoveryChain {
            network: UnftNetwork::Mainnet,
            used: BTreeSet::new(),
            omit_last: false,
        };
        assert!(matches!(
            discover_wallet(&wallet, &source, DiscoveryOptions::default()),
            Err(WalletError::CacheNetworkMismatch)
        ));

        let source = DiscoveryChain {
            network: UnftNetwork::Testnet,
            used: BTreeSet::new(),
            omit_last: false,
        };
        assert!(matches!(
            discover_wallet(
                &wallet,
                &source,
                DiscoveryOptions {
                    gap_limit: 0,
                    ..DiscoveryOptions::default()
                }
            ),
            Err(WalletError::InvalidDiscoveryOptions)
        ));
    }

    struct FakeFees {
        network: UnftNetwork,
        estimates: FeeEstimates,
    }

    impl FeeDataSource for FakeFees {
        fn network(&self) -> UnftNetwork {
            self.network
        }

        fn estimates(&self) -> Result<FeeEstimates> {
            Ok(self.estimates)
        }
    }

    #[test]
    fn validates_ordered_nonzero_fee_estimates() {
        let valid = FakeFees {
            network: UnftNetwork::Mainnet,
            estimates: FeeEstimates {
                minimum_relay: 1,
                economy: 1,
                normal: 2,
                priority: 5,
                observed_at_height: 100,
            },
        };
        assert_eq!(
            get_fee_estimates(UnftNetwork::Mainnet, &valid).unwrap(),
            valid.estimates
        );

        let invalid = FakeFees {
            network: UnftNetwork::Mainnet,
            estimates: FeeEstimates {
                minimum_relay: 2,
                economy: 1,
                normal: 5,
                priority: 3,
                observed_at_height: 100,
            },
        };
        assert!(matches!(
            get_fee_estimates(UnftNetwork::Mainnet, &invalid),
            Err(WalletError::InvalidDataSourceResponse)
        ));
        assert!(matches!(
            get_fee_estimates(UnftNetwork::Testnet, &valid),
            Err(WalletError::CacheNetworkMismatch)
        ));
    }
}
