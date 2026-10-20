//! Chain-family boundaries for the multichain wallet.
//!
//! Backends operate only on public addresses, transaction identifiers and raw
//! signed transactions. Secret-bearing account types are deliberately absent
//! from [`PublicChainBackend`].

use crate::{
    AddressChain, DerivedAddress, Result, SignedTransaction, UnftNetwork, UnsignedTransaction,
    WalletSecrets,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChainFamily {
    BitcoinCompatibleUtxo,
    Evm,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NetworkIdentity {
    pub family: ChainFamily,
    pub chain_id: &'static str,
    pub network: &'static str,
    pub genesis_hash: &'static str,
}

impl NetworkIdentity {
    pub fn matches(self, backend: Self) -> bool {
        self == backend
    }
}

/// Public-only backend boundary. It cannot accept a mnemonic, seed, xprv,
/// private key or account xpub.
pub trait PublicChainBackend {
    type Balance;
    type HistoryPage;
    type FeeQuote;
    type BroadcastReceipt;

    fn identity(&self) -> NetworkIdentity;
    fn balance(&self, addresses: &[String]) -> Result<Self::Balance>;
    fn history(&self, addresses: &[String], cursor: Option<&str>) -> Result<Self::HistoryPage>;
    fn fees(&self) -> Result<Self::FeeQuote>;
    fn broadcast(&self, signed_raw_transaction: &str) -> Result<Self::BroadcastReceipt>;
}

/// Operations shared by Bitcoin-like UTXO adapters. Transaction types remain
/// UTXO-specific and are not shared with EVM adapters.
pub trait UtxoChainAdapter {
    type BuildRequest;

    fn identity(&self) -> NetworkIdentity;
    fn derive_address(
        &self,
        wallet: &WalletSecrets,
        chain: AddressChain,
        index: u32,
    ) -> Result<DerivedAddress>;
    fn build_transaction(&self, request: Self::BuildRequest) -> Result<UnsignedTransaction>;
    fn sign_transaction(
        &self,
        wallet: &WalletSecrets,
        transaction: UnsignedTransaction,
    ) -> Result<SignedTransaction>;
}

/// Separate contract for account/nonce/gas-based chains. It intentionally has
/// no UTXO, outpoint, change-output or BIP143 concepts.
pub trait EvmChainAdapter {
    type Account;
    type Address;
    type BuildRequest;
    type UnsignedTransaction;
    type SignedTransaction;

    fn identity(&self) -> NetworkIdentity;
    fn derive_address(&self, account: &Self::Account, index: u32) -> Result<Self::Address>;
    fn build_transaction(&self, request: Self::BuildRequest) -> Result<Self::UnsignedTransaction>;
    fn sign_transaction(
        &self,
        account: &Self::Account,
        transaction: Self::UnsignedTransaction,
    ) -> Result<Self::SignedTransaction>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnftChainAdapter {
    network: UnftNetwork,
}

impl UnftChainAdapter {
    pub const fn new(network: UnftNetwork) -> Self {
        Self { network }
    }

    pub const fn identity(self) -> NetworkIdentity {
        self.network.identity()
    }

    pub fn validate_backend(self, backend: NetworkIdentity) -> Result<()> {
        if !self.identity().matches(backend) {
            return Err(crate::WalletError::BackendNetworkMismatch);
        }
        Ok(())
    }
}

impl UtxoChainAdapter for UnftChainAdapter {
    type BuildRequest = crate::BuildTransaction;

    fn identity(&self) -> NetworkIdentity {
        (*self).identity()
    }

    fn derive_address(
        &self,
        wallet: &WalletSecrets,
        chain: AddressChain,
        index: u32,
    ) -> Result<DerivedAddress> {
        if wallet.config().network != self.network {
            return Err(crate::WalletError::BackendNetworkMismatch);
        }
        wallet.derive_address(chain, index)
    }

    fn build_transaction(&self, request: Self::BuildRequest) -> Result<UnsignedTransaction> {
        crate::build_transaction(request)
    }

    fn sign_transaction(
        &self,
        wallet: &WalletSecrets,
        transaction: UnsignedTransaction,
    ) -> Result<SignedTransaction> {
        if wallet.config().network != self.network {
            return Err(crate::WalletError::BackendNetworkMismatch);
        }
        crate::sign_transaction(wallet, transaction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unft_network_identity_includes_genesis_and_chain_id() {
        let testnet = UnftChainAdapter::new(UnftNetwork::Testnet);
        assert_eq!(testnet.identity().chain_id, "unft-testnet4-porepool-V2");
        assert_eq!(testnet.identity().network, "testnet4");
        assert_ne!(
            testnet.identity(),
            UnftChainAdapter::new(UnftNetwork::Mainnet).identity()
        );
        assert!(testnet.validate_backend(testnet.identity()).is_ok());
        assert!(
            testnet
                .validate_backend(UnftChainAdapter::new(UnftNetwork::Mainnet).identity())
                .is_err()
        );
    }
}
