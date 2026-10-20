use thiserror::Error;

pub type Result<T> = std::result::Result<T, WalletError>;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("invalid BIP39 mnemonic: {0}")]
    InvalidMnemonic(#[from] bip39::Error),

    #[error("invalid derivation path: {0}")]
    InvalidDerivationPath(#[from] bitcoin::bip32::Error),

    #[error("address index must be below 2^31")]
    InvalidAddressIndex,

    #[error("account index must be below 2^31")]
    InvalidAccount,

    #[error("coin type must be below 2^31")]
    InvalidCoinType,

    #[error(
        "coin type 0 is reserved for Bitcoin; use the explicit legacy profile only for compatibility checks"
    )]
    BitcoinCoinTypeReserved,

    #[error(
        "development coin type 424242 is reserved for the explicit UNFT Testnet development profile"
    )]
    DevelopmentCoinTypeReserved,

    #[error("the development wallet profile is valid only on UNFT Testnet")]
    DevelopmentProfileRequiresTestnet,

    #[error("BIP44 configuration does not match the wallet network")]
    Bip44NetworkMismatch,

    #[error("bech32 encoding failed: {0}")]
    AddressEncoding(#[from] bech32::segwit::EncodeError),

    #[error("destination is not a valid UNFT P2WPKH address")]
    InvalidDestinationAddress,

    #[error("transaction must contain at least one input and one recipient")]
    EmptyTransaction,

    #[error("transaction contains a duplicate input")]
    DuplicateInput,

    #[error("transaction contains a zero-valued input or recipient, or an empty script")]
    InvalidTransactionEntry,

    #[error("coin selection input limit must be positive")]
    InvalidInputLimit,

    #[error("coin selection reached its input limit before funding the payment")]
    CoinSelectionLimitReached,

    #[error("review confirmation does not match the prepared transaction")]
    InvalidReviewConfirmation,

    #[error("transaction amount overflow")]
    AmountOverflow,

    #[error("inputs do not cover recipients and fee")]
    InsufficientFunds,

    #[error("fee rate must be positive")]
    InvalidFeeRate,

    #[error("input {0} does not belong to its declared derivation path")]
    InputOwnershipMismatch(usize),

    #[error("invalid transaction id: {0}")]
    InvalidTxid(#[from] bitcoin::hex::HexToArrayError),

    #[error("could not produce P2WPKH signature hash: {0}")]
    Sighash(#[from] bitcoin::sighash::P2wpkhError),

    #[error("could not produce legacy P2PKH signature hash: {0}")]
    LegacySighash(#[from] bitcoin::transaction::InputsIndexError),

    #[error("keystore serialization failed")]
    KeystoreSerialization,

    #[error("unsupported or malformed keystore")]
    InvalidKeystore,

    #[error("keystore password is empty")]
    EmptyKeystorePassword,

    #[error("keystore password is incorrect or data was modified")]
    KeystoreAuthentication,

    #[error("keystore key derivation failed")]
    KeystoreKdf,

    #[error("secure random generation failed")]
    SecureRandom,

    #[error("blockchain cache serialization failed")]
    CacheSerialization,

    #[error("unsupported or malformed blockchain cache")]
    InvalidCache,

    #[error("cache network does not match wallet network")]
    CacheNetworkMismatch,

    #[error("data source is temporarily unavailable")]
    DataSourceUnavailable,

    #[error("data source returned inconsistent data")]
    InvalidDataSourceResponse,

    #[error("invalid HD discovery options")]
    InvalidDiscoveryOptions,

    #[error("HD discovery reached its address limit before finding the required gap")]
    DiscoveryLimitReached,

    #[error("backend identity does not match the selected chain and network")]
    BackendNetworkMismatch,
}
