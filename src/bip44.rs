//! Explicit BIP44/P2PKH compatibility profile for UNFTChain.
//!
//! The proposed mainnet coin type is deliberately labelled as a proposal. It
//! is not an assignment and must not be frozen before the SLIP-0044 maintainers
//! accept it. Testnet uses SLIP-0044 coin type 1 ("Testnet, all coins").

use std::str::FromStr;

use bitcoin::{
    bip32::{ChildNumber, DerivationPath, Xpriv, Xpub},
    hashes::{Hash, hash160},
    key::Secp256k1,
};

use crate::{AddressChain, Result, UnftNetwork, WalletError, WalletSecrets};

const HARDENED_LIMIT: u32 = 1 << 31;

/// Candidate checked as unused in the upstream SLIP-0044 registry on
/// 2026-10-05. This is a proposal only, not a reservation or assignment.
pub const PROPOSED_MAINNET_COIN_TYPE: u32 = 10_002;

/// SLIP-0044's shared value for test networks.
pub const TESTNET_COIN_TYPE: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Bip44Config {
    pub network: UnftNetwork,
    pub coin_type: u32,
    pub account: u32,
}

impl Bip44Config {
    pub fn mainnet_proposal(account: u32) -> Result<Self> {
        Self::new(UnftNetwork::Mainnet, PROPOSED_MAINNET_COIN_TYPE, account)
    }

    pub fn testnet(account: u32) -> Result<Self> {
        Self::new(UnftNetwork::Testnet, TESTNET_COIN_TYPE, account)
    }

    fn new(network: UnftNetwork, coin_type: u32, account: u32) -> Result<Self> {
        if coin_type >= HARDENED_LIMIT {
            return Err(WalletError::InvalidCoinType);
        }
        if account >= HARDENED_LIMIT {
            return Err(WalletError::InvalidAccount);
        }
        Ok(Self {
            network,
            coin_type,
            account,
        })
    }

    pub(crate) fn for_discovery(
        network: UnftNetwork,
        coin_type: u32,
        account: u32,
    ) -> Result<Self> {
        Self::new(network, coin_type, account)
    }

    pub fn account_path(self) -> String {
        format!("m/44'/{}'/{}'", self.coin_type, self.account)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bip44DerivedAddress {
    pub path: String,
    pub address: String,
    pub public_key: [u8; 33],
    pub script_pub_key: Vec<u8>,
}

impl WalletSecrets {
    /// Returns the BIP32 account node for the explicit BIP44 profile.
    pub fn bip44_account_xpriv(&self, config: Bip44Config) -> Result<Xpriv> {
        self.ensure_bip44_network(config)?;
        let secp = Secp256k1::new();
        Ok(self
            .master_xpriv()?
            .derive_priv(&secp, &DerivationPath::from_str(&config.account_path())?)?)
    }

    pub fn bip44_account_xpub(&self, config: Bip44Config) -> Result<Xpub> {
        let secp = Secp256k1::new();
        Ok(Xpub::from_priv(&secp, &self.bip44_account_xpriv(config)?))
    }

    pub(crate) fn derive_bip44_private_key(
        &self,
        config: Bip44Config,
        chain: AddressChain,
        index: u32,
    ) -> Result<bitcoin::secp256k1::SecretKey> {
        if index >= HARDENED_LIMIT {
            return Err(WalletError::InvalidAddressIndex);
        }
        let chain_index = match chain {
            AddressChain::External => 0,
            AddressChain::Change => 1,
        };
        let secp = Secp256k1::new();
        let suffix = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(chain_index)?,
            ChildNumber::from_normal_idx(index)?,
        ]);
        Ok(self
            .bip44_account_xpriv(config)?
            .derive_priv(&secp, &suffix)?
            .private_key)
    }

    /// Derives a compressed-key P2PKH address at
    /// `m/44'/coin_type'/account'/change/address_index`.
    pub fn derive_bip44_address(
        &self,
        config: Bip44Config,
        chain: AddressChain,
        index: u32,
    ) -> Result<Bip44DerivedAddress> {
        self.ensure_bip44_network(config)?;
        if index >= HARDENED_LIMIT {
            return Err(WalletError::InvalidAddressIndex);
        }

        let chain_index = match chain {
            AddressChain::External => 0,
            AddressChain::Change => 1,
        };
        let secp = Secp256k1::new();
        let account = self.bip44_account_xpriv(config)?;
        let suffix = DerivationPath::from(vec![
            ChildNumber::from_normal_idx(chain_index)?,
            ChildNumber::from_normal_idx(index)?,
        ]);
        let child = account.derive_priv(&secp, &suffix)?;
        let public_key = child.private_key.public_key(&secp).serialize();
        let pubkey_hash = hash160::Hash::hash(&public_key).to_byte_array();

        let mut payload = Vec::with_capacity(21);
        payload.push(config.network.p2pkh_prefix());
        payload.extend_from_slice(&pubkey_hash);

        let mut script_pub_key = Vec::with_capacity(25);
        script_pub_key.extend_from_slice(&[0x76, 0xa9, 0x14]);
        script_pub_key.extend_from_slice(&pubkey_hash);
        script_pub_key.extend_from_slice(&[0x88, 0xac]);

        Ok(Bip44DerivedAddress {
            path: format!("{}/{chain_index}/{index}", config.account_path()),
            address: base58ck::encode_check(&payload),
            public_key,
            script_pub_key,
        })
    }

    /// Serializes the test-vector account key with UNFT Core's network-specific
    /// extended-private-key prefix. Never send this value to a backend.
    pub fn bip44_account_unft_xpriv(&self, config: Bip44Config) -> Result<String> {
        let mut encoded = self.bip44_account_xpriv(config)?.encode();
        encoded[..4].copy_from_slice(&config.network.ext_private_key_prefix());
        Ok(base58ck::encode_check(&encoded))
    }

    pub fn bip44_account_unft_xpub(&self, config: Bip44Config) -> Result<String> {
        let mut encoded = self.bip44_account_xpub(config)?.encode();
        encoded[..4].copy_from_slice(&config.network.ext_public_key_prefix());
        Ok(base58ck::encode_check(&encoded))
    }

    fn ensure_bip44_network(&self, config: Bip44Config) -> Result<()> {
        if self.config().network != config.network {
            return Err(WalletError::Bip44NetworkMismatch);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoinType, WalletConfig, restore_wallet};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn mainnet_wallet() -> WalletSecrets {
        let config =
            WalletConfig::new(UnftNetwork::Mainnet, CoinType::legacy_core_reference(), 0).unwrap();
        restore_wallet(MNEMONIC, "TREZOR", config).unwrap()
    }

    #[test]
    fn bip44_levels_and_chains_are_exact() {
        let wallet = mainnet_wallet();
        let config = Bip44Config::mainnet_proposal(0).unwrap();
        assert_eq!(config.account_path(), "m/44'/10002'/0'");
        assert_eq!(
            wallet
                .derive_bip44_address(config, AddressChain::External, 0)
                .unwrap()
                .path,
            "m/44'/10002'/0'/0/0"
        );
        assert_eq!(
            wallet
                .derive_bip44_address(config, AddressChain::Change, 0)
                .unwrap()
                .path,
            "m/44'/10002'/0'/1/0"
        );
    }

    #[test]
    fn restoring_the_same_seed_reproduces_bip44_addresses() {
        let first = mainnet_wallet();
        let second = mainnet_wallet();
        let config = Bip44Config::mainnet_proposal(0).unwrap();
        for chain in [AddressChain::External, AddressChain::Change] {
            for index in 0..3 {
                assert_eq!(
                    first.derive_bip44_address(config, chain, index).unwrap(),
                    second.derive_bip44_address(config, chain, index).unwrap()
                );
            }
        }
    }

    #[test]
    fn matches_published_mainnet_proposal_vectors() {
        let wallet = mainnet_wallet();
        let config = Bip44Config::mainnet_proposal(0).unwrap();
        let external_0 = wallet
            .derive_bip44_address(config, AddressChain::External, 0)
            .unwrap();
        let external_1 = wallet
            .derive_bip44_address(config, AddressChain::External, 1)
            .unwrap();
        let change_0 = wallet
            .derive_bip44_address(config, AddressChain::Change, 0)
            .unwrap();

        assert_eq!(external_0.address, "MN3nQ1LBvTrdR5km1EhMGcPCLoKd16iYV9");
        assert_eq!(
            hex::encode(external_0.script_pub_key),
            "76a9149b33471c97a44ce5955508d4599154cb0be9bf4988ac"
        );
        assert_eq!(external_1.address, "MV1oxLJ6rtQm7KXcjm51EkU17hhB2raUt8");
        assert_eq!(change_0.address, "MVULj1PKig6C9YEuVCF8BcM4qZbpfJae1k");
        assert_eq!(
            wallet.bip44_account_unft_xpub(config).unwrap(),
            "v1wAP9JaTdn8eoVmGRurijFY5Fkw2vyWusgQzJDFauRYowhiqjzob2xEpzAR5LdhWiRGv13kCMMhkyYMuTLasn1WsGJWeKQBNaKtGmnFpk1iRRM"
        );
    }

    #[test]
    fn mainnet_and_testnet_profiles_cannot_be_mixed() {
        let wallet = mainnet_wallet();
        assert!(matches!(
            wallet.derive_bip44_address(
                Bip44Config::testnet(0).unwrap(),
                AddressChain::External,
                0
            ),
            Err(WalletError::Bip44NetworkMismatch)
        ));
    }
}
