use std::collections::{BTreeMap, BTreeSet};

use crate::{
    AddressChain, AddressSnapshot, Bip44Config, Bip44DerivedAddress, Bip44SpendableUtxo,
    ChainDataSource, ChainTip, ConfirmationStatus, Result, UnftNetwork, WalletError, WalletSecrets,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bip44DiscoveryOptions {
    pub gap_limit: u32,
    pub batch_size: u32,
    pub max_accounts: u32,
    pub max_addresses_per_chain: u32,
}

impl Default for Bip44DiscoveryOptions {
    fn default() -> Self {
        Self {
            gap_limit: 20,
            batch_size: 20,
            max_accounts: 100,
            max_addresses_per_chain: 10_000,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bip44AddressRecord {
    pub account: u32,
    pub chain: AddressChain,
    pub index: u32,
    pub derived: Bip44DerivedAddress,
    pub snapshot: AddressSnapshot,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bip44AccountDiscovery {
    pub account: u32,
    pub external_last_used: Option<u32>,
    pub change_last_used: Option<u32>,
    pub external_scanned: u32,
    pub change_scanned: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bip44DiscoveryResult {
    pub network: UnftNetwork,
    pub coin_type: u32,
    pub tip: ChainTip,
    pub accounts: Vec<Bip44AccountDiscovery>,
    pub addresses: Vec<Bip44AddressRecord>,
    pub stopped_at_unused_account: u32,
}

impl Bip44DiscoveryResult {
    pub fn spendable_utxos(&self, minimum_confirmations: u64) -> Result<Vec<Bip44SpendableUtxo>> {
        let mut outpoints = BTreeMap::new();
        for record in &self.addresses {
            for utxo in &record.snapshot.utxos {
                if utxo.status != ConfirmationStatus::Confirmed
                    || utxo.confirmations < minimum_confirmations
                {
                    continue;
                }
                if utxo.script_pub_key != record.derived.script_pub_key {
                    return Err(WalletError::InvalidDataSourceResponse);
                }
                let spendable = Bip44SpendableUtxo {
                    txid: utxo.txid.clone(),
                    vout: utxo.vout,
                    value: utxo.value,
                    script_pub_key: utxo.script_pub_key.clone(),
                    account: record.account,
                    chain: record.chain,
                    address_index: record.index,
                };
                if let Some(previous) =
                    outpoints.insert((utxo.txid.clone(), utxo.vout), spendable.clone())
                    && previous != spendable
                {
                    return Err(WalletError::InvalidDataSourceResponse);
                }
            }
        }
        Ok(outpoints.into_values().collect())
    }
}

pub fn discover_bip44_wallet(
    wallet: &WalletSecrets,
    coin_type: u32,
    source: &impl ChainDataSource,
    options: Bip44DiscoveryOptions,
) -> Result<Bip44DiscoveryResult> {
    validate_options(options)?;
    let network = wallet.config().network;
    if source.network() != network {
        return Err(WalletError::CacheNetworkMismatch);
    }

    let mut accounts = Vec::new();
    let mut addresses = Vec::new();
    for account in 0..options.max_accounts {
        let config = Bip44Config::for_discovery(network, coin_type, account)?;
        let external = scan_chain(wallet, config, AddressChain::External, source, options)?;
        if external.last_used.is_none() {
            return Ok(Bip44DiscoveryResult {
                network,
                coin_type,
                tip: source.tip()?,
                accounts,
                addresses,
                stopped_at_unused_account: account,
            });
        }
        let change = scan_chain(wallet, config, AddressChain::Change, source, options)?;
        accounts.push(Bip44AccountDiscovery {
            account,
            external_last_used: external.last_used,
            change_last_used: change.last_used,
            external_scanned: external.scanned,
            change_scanned: change.scanned,
        });
        addresses.extend(external.records);
        addresses.extend(change.records);
    }
    Err(WalletError::DiscoveryLimitReached)
}

struct ChainScan {
    last_used: Option<u32>,
    scanned: u32,
    records: Vec<Bip44AddressRecord>,
}

fn scan_chain(
    wallet: &WalletSecrets,
    config: Bip44Config,
    chain: AddressChain,
    source: &impl ChainDataSource,
    options: Bip44DiscoveryOptions,
) -> Result<ChainScan> {
    let mut next: u32 = 0;
    let mut gap: u32 = 0;
    let mut last_used = None;
    let mut records = Vec::new();
    while gap < options.gap_limit {
        let remaining = options
            .max_addresses_per_chain
            .checked_sub(next)
            .ok_or(WalletError::DiscoveryLimitReached)?;
        if remaining == 0 {
            return Err(WalletError::DiscoveryLimitReached);
        }
        let count = options.batch_size.min(remaining);
        let derived = (next..next + count)
            .map(|index| {
                wallet
                    .derive_bip44_address(config, chain, index)
                    .map(|address| (index, address))
            })
            .collect::<Result<Vec<_>>>()?;
        let requested = derived
            .iter()
            .map(|(_, item)| item.address.clone())
            .collect::<Vec<_>>();
        let mut returned = exact_response(&requested, source.query_addresses(&requested)?)?;

        for (index, item) in derived {
            let snapshot = returned
                .remove(&item.address)
                .ok_or(WalletError::InvalidDataSourceResponse)?;
            if snapshot
                .utxos
                .iter()
                .any(|utxo| utxo.script_pub_key != item.script_pub_key)
            {
                return Err(WalletError::InvalidDataSourceResponse);
            }
            let active =
                snapshot.used || !snapshot.transactions.is_empty() || !snapshot.utxos.is_empty();
            if active {
                last_used = Some(index);
                gap = 0;
            } else {
                gap = gap
                    .checked_add(1)
                    .ok_or(WalletError::DiscoveryLimitReached)?;
            }
            records.push(Bip44AddressRecord {
                account: config.account,
                chain,
                index,
                derived: item,
                snapshot,
            });
        }
        next = next
            .checked_add(count)
            .ok_or(WalletError::DiscoveryLimitReached)?;
    }
    Ok(ChainScan {
        last_used,
        scanned: next,
        records,
    })
}

fn exact_response(
    requested: &[String],
    snapshots: Vec<AddressSnapshot>,
) -> Result<BTreeMap<String, AddressSnapshot>> {
    if requested.len() != snapshots.len() {
        return Err(WalletError::InvalidDataSourceResponse);
    }
    let requested = requested.iter().collect::<BTreeSet<_>>();
    let mut result = BTreeMap::new();
    for snapshot in snapshots {
        if !requested.contains(&snapshot.address)
            || result.insert(snapshot.address.clone(), snapshot).is_some()
        {
            return Err(WalletError::InvalidDataSourceResponse);
        }
    }
    Ok(result)
}

fn validate_options(options: Bip44DiscoveryOptions) -> Result<()> {
    if options.gap_limit == 0
        || options.batch_size == 0
        || options.max_accounts == 0
        || options.max_addresses_per_chain < options.gap_limit
    {
        return Err(WalletError::InvalidDiscoveryOptions);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;
    use crate::{BroadcastReceipt, CachedTransaction, CoinType, WalletConfig, restore_wallet};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    struct HistorySource {
        active: BTreeSet<String>,
    }

    impl ChainDataSource for HistorySource {
        fn network(&self) -> UnftNetwork {
            UnftNetwork::Mainnet
        }

        fn tip(&self) -> Result<ChainTip> {
            Ok(ChainTip {
                height: 321,
                block_hash: "ab".repeat(32),
                observed_at: 1,
            })
        }

        fn query_addresses(&self, addresses: &[String]) -> Result<Vec<AddressSnapshot>> {
            Ok(addresses
                .iter()
                .map(|address| AddressSnapshot {
                    address: address.clone(),
                    // Deliberately false: history must be authoritative even
                    // after every output was spent and balance became zero.
                    used: false,
                    utxos: vec![],
                    transactions: self
                        .active
                        .contains(address)
                        .then(|| CachedTransaction {
                            txid: "11".repeat(32),
                            block_height: Some(100),
                            confirmations: 222,
                            timestamp: Some(1),
                        })
                        .into_iter()
                        .collect(),
                })
                .collect())
        }

        fn broadcast(&self, _raw_transaction: &str) -> Result<BroadcastReceipt> {
            Err(WalletError::DataSourceUnavailable)
        }
    }

    fn wallet() -> WalletSecrets {
        restore_wallet(
            MNEMONIC,
            "TREZOR",
            WalletConfig::new(UnftNetwork::Mainnet, CoinType::legacy_core_reference(), 0).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn restores_zero_balance_history_across_accounts_and_change() {
        let wallet = wallet();
        let mut active = BTreeSet::new();
        for (account, chain, index) in [
            (0, AddressChain::External, 2),
            (0, AddressChain::Change, 2),
            (1, AddressChain::External, 0),
            (1, AddressChain::Change, 1),
        ] {
            let config = Bip44Config::mainnet_proposal(account).unwrap();
            active.insert(
                wallet
                    .derive_bip44_address(config, chain, index)
                    .unwrap()
                    .address,
            );
        }
        let result = discover_bip44_wallet(
            &wallet,
            crate::PROPOSED_MAINNET_COIN_TYPE,
            &HistorySource { active },
            Bip44DiscoveryOptions {
                gap_limit: 3,
                batch_size: 1,
                max_accounts: 5,
                max_addresses_per_chain: 20,
            },
        )
        .unwrap();

        assert_eq!(result.accounts.len(), 2);
        assert_eq!(result.stopped_at_unused_account, 2);
        assert_eq!(result.accounts[0].external_last_used, Some(2));
        assert_eq!(result.accounts[0].change_last_used, Some(2));
        assert_eq!(result.accounts[0].external_scanned, 6);
        assert_eq!(result.accounts[0].change_scanned, 6);
        assert_eq!(result.accounts[1].external_last_used, Some(0));
        assert_eq!(result.accounts[1].change_last_used, Some(1));
        assert!(result.addresses.iter().any(|record| {
            record.account == 0
                && record.chain == AddressChain::External
                && record.index == 2
                && record.snapshot.utxos.is_empty()
                && !record.snapshot.transactions.is_empty()
        }));
    }

    #[test]
    fn enforces_address_and_account_safety_limits() {
        let wallet = wallet();
        let config = Bip44Config::mainnet_proposal(0).unwrap();
        let active = (0..3)
            .map(|index| {
                wallet
                    .derive_bip44_address(config, AddressChain::External, index)
                    .unwrap()
                    .address
            })
            .collect();
        assert!(matches!(
            discover_bip44_wallet(
                &wallet,
                crate::PROPOSED_MAINNET_COIN_TYPE,
                &HistorySource { active },
                Bip44DiscoveryOptions {
                    gap_limit: 3,
                    batch_size: 1,
                    max_accounts: 2,
                    max_addresses_per_chain: 3,
                }
            ),
            Err(WalletError::DiscoveryLimitReached)
        ));
    }
}
