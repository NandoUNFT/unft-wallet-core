//! Platform-neutral, non-custodial wallet primitives for UNFTChain.
//!
//! This crate performs no network requests and persists no data. Callers must
//! store [`WalletSecrets`] in an encrypted keystore and treat derived chain
//! data as a separate, disposable cache.

mod adapter;
mod bip44;
mod bip44_discovery;
mod bip44_transaction;
mod cache;
mod datasource;
mod error;
mod keystore;
mod network;
mod transaction;
mod wallet;

pub use adapter::{
    ChainFamily, EvmChainAdapter, NetworkIdentity, PublicChainBackend, UnftChainAdapter,
    UtxoChainAdapter,
};
pub use bip44::{Bip44Config, Bip44DerivedAddress, PROPOSED_MAINNET_COIN_TYPE, TESTNET_COIN_TYPE};
pub use bip44_discovery::{
    Bip44AccountDiscovery, Bip44AddressRecord, Bip44DiscoveryOptions, Bip44DiscoveryResult,
    discover_bip44_wallet,
};
pub use bip44_transaction::{
    Bip44ApprovedTransaction, Bip44BuildTransaction, Bip44PrepareTransaction,
    Bip44PreparedTransaction, Bip44SpendableUtxo, Bip44TransactionReview, Bip44UnsignedTransaction,
    build_bip44_transaction, prepare_bip44_transaction, sign_bip44_approved_transaction,
    sign_bip44_transaction,
};
pub use cache::{
    AddressDerivation, AddressSnapshot, Balance, BlockchainCache, CachedTransaction,
    ConfirmationStatus, NftRecord, Utxo,
};
pub use datasource::{
    BroadcastDataSource, BroadcastReceipt, ChainDataSource, ChainDiscovery, ChainTip,
    DiscoveryOptions, DiscoveryResult, FeeDataSource, FeeEstimates, NftDataSource, broadcast,
    discover_wallet, get_balance, get_fee_estimates, nft_list, refresh_addresses,
};
pub use error::{Result, WalletError};
pub use keystore::{EncryptedKeystore, KdfParameters, UnlockedKeystore};
pub use network::UnftNetwork;
pub use transaction::{
    ApprovedTransaction, BuildTransaction, FeePolicy, Payment, PrepareTransaction,
    PrepareWalletPayment, PreparedTransaction, SignedTransaction, SpendableUtxo, TransactionReview,
    UnsignedTransaction, build_transaction, prepare_transaction, prepare_wallet_payment,
    sign_approved_transaction, sign_transaction,
};
pub use wallet::{
    AddressChain, CoinType, DEVELOPMENT_TESTNET_COIN_TYPE, DerivedAddress, WalletConfig,
    WalletProfile, WalletSecrets, create_wallet, restore_wallet,
};
