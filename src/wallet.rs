use std::str::FromStr;

use bech32::Hrp;
use bip39::{Language, Mnemonic};
use bitcoin::{
    NetworkKind,
    bip32::{ChildNumber, DerivationPath, Xpriv, Xpub},
    hashes::{Hash, hash160},
    key::Secp256k1,
};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Result, UnftNetwork, WalletError};

const HARDENED_LIMIT: u32 = 1 << 31;
pub const DEVELOPMENT_TESTNET_COIN_TYPE: u32 = 424_242;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoinType(u32);

impl CoinType {
    /// Creates a production coin type. Bitcoin's registered value `0` is
    /// deliberately rejected.
    pub fn new(value: u32) -> Result<Self> {
        if value == 0 {
            return Err(WalletError::BitcoinCoinTypeReserved);
        }
        if value == DEVELOPMENT_TESTNET_COIN_TYPE {
            return Err(WalletError::DevelopmentCoinTypeReserved);
        }
        if value >= HARDENED_LIMIT {
            return Err(WalletError::InvalidCoinType);
        }
        Ok(Self(value))
    }

    /// Reference profile for existing UNFT Core descriptors. It is not the
    /// coin type for new UNFT Wallets.
    pub const fn legacy_core_reference() -> Self {
        Self(0)
    }

    const fn development_testnet() -> Self {
        Self(DEVELOPMENT_TESTNET_COIN_TYPE)
    }

    pub const fn value(self) -> u32 {
        self.0
    }

    pub(crate) const fn from_keystore(value: u32) -> Result<Self> {
        if value >= HARDENED_LIMIT {
            return Err(WalletError::InvalidCoinType);
        }
        Ok(Self(value))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletProfile {
    ExplicitCoinType,
    LegacyCoreReference,
    DevelopmentTestnet,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WalletConfig {
    pub network: UnftNetwork,
    pub coin_type: CoinType,
    pub account: u32,
    pub profile: WalletProfile,
}

impl WalletConfig {
    pub fn new(network: UnftNetwork, coin_type: CoinType, account: u32) -> Result<Self> {
        if account >= HARDENED_LIMIT {
            return Err(WalletError::InvalidAccount);
        }
        let profile = match coin_type.value() {
            0 => WalletProfile::LegacyCoreReference,
            DEVELOPMENT_TESTNET_COIN_TYPE => {
                if network != UnftNetwork::Testnet {
                    return Err(WalletError::DevelopmentProfileRequiresTestnet);
                }
                WalletProfile::DevelopmentTestnet
            }
            _ => WalletProfile::ExplicitCoinType,
        };
        Ok(Self {
            network,
            coin_type,
            account,
            profile,
        })
    }

    pub fn development_testnet(account: u32) -> Result<Self> {
        Self::new(
            UnftNetwork::Testnet,
            CoinType::development_testnet(),
            account,
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressChain {
    External,
    Change,
}

impl AddressChain {
    const fn index(self) -> u32 {
        match self {
            Self::External => 0,
            Self::Change => 1,
        }
    }
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct WalletSecrets {
    mnemonic: String,
    passphrase: String,
    #[zeroize(skip)]
    config: WalletConfig,
}

impl WalletSecrets {
    pub fn mnemonic(&self) -> &str {
        &self.mnemonic
    }

    pub const fn config(&self) -> WalletConfig {
        self.config
    }

    pub(crate) fn passphrase(&self) -> &str {
        &self.passphrase
    }

    pub fn account_path(&self) -> String {
        format!(
            "m/84'/{}'/{}'",
            self.config.coin_type.value(),
            self.config.account
        )
    }

    pub fn account_xpub(&self) -> Result<Xpub> {
        let secp = Secp256k1::new();
        let master = self.master_xpriv()?;
        let account = master.derive_priv(&secp, &self.account_derivation_path()?)?;
        Ok(Xpub::from_priv(&secp, &account))
    }

    pub fn derive_address(&self, chain: AddressChain, index: u32) -> Result<DerivedAddress> {
        if index >= HARDENED_LIMIT {
            return Err(WalletError::InvalidAddressIndex);
        }

        let secp = Secp256k1::new();
        let master = self.master_xpriv()?;
        let mut children: Vec<ChildNumber> = self.account_derivation_path()?.into();
        children.push(ChildNumber::from_normal_idx(chain.index())?);
        children.push(ChildNumber::from_normal_idx(index)?);
        let child = master.derive_priv(&secp, &DerivationPath::from(children))?;
        let public_key = child.private_key.public_key(&secp);
        let witness_program = hash160::Hash::hash(&public_key.serialize()).to_byte_array();
        let hrp =
            Hrp::parse(self.config.network.bech32_hrp()).expect("static UNFT HRP must be valid");
        let address = bech32::segwit::encode_v0(hrp, &witness_program)?;

        let mut script_pub_key = Vec::with_capacity(22);
        script_pub_key.extend_from_slice(&[0x00, 0x14]);
        script_pub_key.extend_from_slice(&witness_program);

        Ok(DerivedAddress {
            path: format!("{}/{}/{}", self.account_path(), chain.index(), index),
            address,
            public_key: public_key.serialize(),
            script_pub_key,
        })
    }

    pub(crate) fn derive_private_key(
        &self,
        chain: AddressChain,
        index: u32,
    ) -> Result<bitcoin::secp256k1::SecretKey> {
        if index >= HARDENED_LIMIT {
            return Err(WalletError::InvalidAddressIndex);
        }
        let secp = Secp256k1::new();
        let master = self.master_xpriv()?;
        let mut children: Vec<ChildNumber> = self.account_derivation_path()?.into();
        children.push(ChildNumber::from_normal_idx(chain.index())?);
        children.push(ChildNumber::from_normal_idx(index)?);
        Ok(master
            .derive_priv(&secp, &DerivationPath::from(children))?
            .private_key)
    }

    pub(crate) fn master_xpriv(&self) -> Result<Xpriv> {
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &self.mnemonic)?;
        let seed = mnemonic.to_seed_normalized(&self.passphrase);
        let result = Xpriv::new_master(NetworkKind::Main, &seed)
            .expect("a 64-byte BIP39 seed is always a valid BIP32 input");
        Ok(result)
    }

    fn account_derivation_path(&self) -> Result<DerivationPath> {
        Ok(DerivationPath::from_str(&self.account_path())?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DerivedAddress {
    pub path: String,
    pub address: String,
    pub public_key: [u8; 33],
    pub script_pub_key: Vec<u8>,
}

pub fn create_wallet(config: WalletConfig, passphrase: impl Into<String>) -> Result<WalletSecrets> {
    let mnemonic = Mnemonic::generate_in(Language::English, 24)?;
    Ok(WalletSecrets {
        mnemonic: mnemonic.to_string(),
        passphrase: passphrase.into(),
        config,
    })
}

pub fn restore_wallet(
    mnemonic: &str,
    passphrase: impl Into<String>,
    config: WalletConfig,
) -> Result<WalletSecrets> {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic)?;
    Ok(WalletSecrets {
        mnemonic: mnemonic.to_string(),
        passphrase: passphrase.into(),
        config,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn reference_wallet() -> WalletSecrets {
        let config =
            WalletConfig::new(UnftNetwork::Mainnet, CoinType::legacy_core_reference(), 0).unwrap();
        restore_wallet(MNEMONIC, "TREZOR", config).unwrap()
    }

    #[test]
    fn rejects_bitcoin_coin_type_for_new_wallets() {
        assert!(matches!(
            CoinType::new(0),
            Err(WalletError::BitcoinCoinTypeReserved)
        ));
    }

    #[test]
    fn development_profile_is_explicit_and_testnet_only() {
        assert!(matches!(
            CoinType::new(DEVELOPMENT_TESTNET_COIN_TYPE),
            Err(WalletError::DevelopmentCoinTypeReserved)
        ));
        let config = WalletConfig::development_testnet(0).unwrap();
        assert_eq!(config.network, UnftNetwork::Testnet);
        assert_eq!(config.coin_type.value(), DEVELOPMENT_TESTNET_COIN_TYPE);
        assert_eq!(config.profile, WalletProfile::DevelopmentTestnet);
        assert!(matches!(
            WalletConfig::new(
                UnftNetwork::Mainnet,
                CoinType::from_keystore(DEVELOPMENT_TESTNET_COIN_TYPE).unwrap(),
                0,
            ),
            Err(WalletError::DevelopmentProfileRequiresTestnet)
        ));
    }

    #[test]
    fn creates_and_restores_24_word_wallet() {
        let config = WalletConfig::development_testnet(0).unwrap();
        let created = create_wallet(config, "").unwrap();
        assert_eq!(created.mnemonic().split_whitespace().count(), 24);
        let restored = restore_wallet(created.mnemonic(), "", config).unwrap();
        assert_eq!(
            created.derive_address(AddressChain::External, 0).unwrap(),
            restored.derive_address(AddressChain::External, 0).unwrap()
        );
    }

    #[test]
    fn matches_core_verified_legacy_reference_vector() {
        let wallet = reference_wallet();
        let external_0 = wallet.derive_address(AddressChain::External, 0).unwrap();
        let external_1 = wallet.derive_address(AddressChain::External, 1).unwrap();
        let change_0 = wallet.derive_address(AddressChain::Change, 0).unwrap();

        assert_eq!(external_0.path, "m/84'/0'/0'/0/0");
        assert_eq!(
            external_0.address,
            "uc1q8ee9jp2ga509lae7xdcu88j0elzlyv0kpqjjam"
        );
        assert_eq!(
            hex::encode(external_0.script_pub_key),
            "00143e72590548ed1e5ff73e3371c39e4fcfc5f231f6"
        );
        assert_eq!(
            external_1.address,
            "uc1qd7w406p33gdnmmxznme2gcle57facy6vz86295"
        );
        assert_eq!(
            change_0.address,
            "uc1qnmrl80zw0pm8vyc3zqzqswf7aexxwgyfed55z4"
        );
    }

    #[test]
    fn testnet_uses_unft_hrp() {
        let config =
            WalletConfig::new(UnftNetwork::Testnet, CoinType::legacy_core_reference(), 0).unwrap();
        let wallet = restore_wallet(MNEMONIC, "TREZOR", config).unwrap();
        assert!(
            wallet
                .derive_address(AddressChain::External, 0)
                .unwrap()
                .address
                .starts_with("ut1q")
        );
    }
}
