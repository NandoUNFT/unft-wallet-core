use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{
    CoinType, Result, UnftNetwork, WalletConfig, WalletError, WalletProfile, WalletSecrets,
    restore_wallet,
};

const MAGIC: &str = "UNFT-WALLET-KEYSTORE";
const FORMAT_VERSION: u32 = 1;
const AAD: &[u8] = b"UNFT-WALLET-KEYSTORE\x00v1";
const SALT_LENGTH: usize = 16;
const NONCE_LENGTH: usize = 24;
const KEY_LENGTH: usize = 32;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct KdfParameters {
    /// Argon2 memory in KiB.
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for KdfParameters {
    fn default() -> Self {
        Self {
            memory_kib: 64 * 1024,
            iterations: 3,
            parallelism: 1,
        }
    }
}

impl KdfParameters {
    fn validate(self) -> Result<Self> {
        // Bounds prevent a malicious file from forcing negligible security or
        // unreasonable resource use before authentication can be checked.
        if !(19 * 1024..=256 * 1024).contains(&self.memory_kib)
            || !(2..=10).contains(&self.iterations)
            || !(1..=8).contains(&self.parallelism)
        {
            return Err(WalletError::InvalidKeystore);
        }
        Ok(self)
    }
}

#[derive(Debug)]
pub struct UnlockedKeystore {
    pub wallet: WalletSecrets,
    pub birthday_height: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct EncryptedKeystore {
    magic: String,
    version: u32,
    cipher: String,
    kdf: String,
    kdf_parameters: KdfParameters,
    salt: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct PlaintextKeystore {
    schema: String,
    mnemonic: String,
    bip39_passphrase: String,
    network: UnftNetwork,
    coin_type: u32,
    account: u32,
    #[serde(default)]
    wallet_profile: Option<WalletProfile>,
    birthday_height: u64,
}

impl Drop for PlaintextKeystore {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.mnemonic.zeroize();
        self.bip39_passphrase.zeroize();
    }
}

impl EncryptedKeystore {
    pub fn encrypt(wallet: &WalletSecrets, birthday_height: u64, password: &[u8]) -> Result<Self> {
        Self::encrypt_with_parameters(wallet, birthday_height, password, KdfParameters::default())
    }

    pub fn encrypt_with_parameters(
        wallet: &WalletSecrets,
        birthday_height: u64,
        password: &[u8],
        kdf_parameters: KdfParameters,
    ) -> Result<Self> {
        if password.is_empty() {
            return Err(WalletError::EmptyKeystorePassword);
        }
        let kdf_parameters = kdf_parameters.validate()?;
        let mut salt = vec![0u8; SALT_LENGTH];
        let mut nonce = vec![0u8; NONCE_LENGTH];
        getrandom::fill(&mut salt).map_err(|_| WalletError::SecureRandom)?;
        getrandom::fill(&mut nonce).map_err(|_| WalletError::SecureRandom)?;

        let plaintext = PlaintextKeystore {
            schema: "unft-wallet-secrets-v1".to_owned(),
            mnemonic: wallet.mnemonic().to_owned(),
            bip39_passphrase: wallet.passphrase().to_owned(),
            network: wallet.config().network,
            coin_type: wallet.config().coin_type.value(),
            account: wallet.config().account,
            wallet_profile: Some(wallet.config().profile),
            birthday_height,
        };
        let plaintext = Zeroizing::new(
            serde_json::to_vec(&plaintext).map_err(|_| WalletError::KeystoreSerialization)?,
        );
        let key = derive_key(password, &salt, kdf_parameters)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| WalletError::KeystoreKdf)?;
        let ciphertext = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                chacha20poly1305::aead::Payload {
                    msg: plaintext.as_ref(),
                    aad: AAD,
                },
            )
            .map_err(|_| WalletError::KeystoreAuthentication)?;

        Ok(Self {
            magic: MAGIC.to_owned(),
            version: FORMAT_VERSION,
            cipher: "xchacha20-poly1305".to_owned(),
            kdf: "argon2id".to_owned(),
            kdf_parameters,
            salt,
            nonce,
            ciphertext,
        })
    }

    pub fn unlock(&self, password: &[u8]) -> Result<UnlockedKeystore> {
        if password.is_empty() {
            return Err(WalletError::EmptyKeystorePassword);
        }
        self.validate_header()?;
        let key = derive_key(password, &self.salt, self.kdf_parameters)?;
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref())
            .map_err(|_| WalletError::KeystoreKdf)?;
        let plaintext = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&self.nonce),
                    chacha20poly1305::aead::Payload {
                        msg: &self.ciphertext,
                        aad: AAD,
                    },
                )
                .map_err(|_| WalletError::KeystoreAuthentication)?,
        );
        let decoded: PlaintextKeystore =
            serde_json::from_slice(plaintext.as_ref()).map_err(|_| WalletError::InvalidKeystore)?;
        if decoded.schema != "unft-wallet-secrets-v1" {
            return Err(WalletError::InvalidKeystore);
        }
        let config = WalletConfig::new(
            decoded.network,
            CoinType::from_keystore(decoded.coin_type)?,
            decoded.account,
        )?;
        if decoded
            .wallet_profile
            .is_some_and(|profile| profile != config.profile)
        {
            return Err(WalletError::InvalidKeystore);
        }
        let wallet = restore_wallet(&decoded.mnemonic, decoded.bip39_passphrase.clone(), config)?;
        Ok(UnlockedKeystore {
            wallet,
            birthday_height: decoded.birthday_height,
        })
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| WalletError::KeystoreSerialization)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let keystore: Self =
            serde_json::from_slice(bytes).map_err(|_| WalletError::InvalidKeystore)?;
        keystore.validate_header()?;
        Ok(keystore)
    }

    pub const fn kdf_parameters(&self) -> KdfParameters {
        self.kdf_parameters
    }

    fn validate_header(&self) -> Result<()> {
        if self.magic != MAGIC
            || self.version != FORMAT_VERSION
            || self.cipher != "xchacha20-poly1305"
            || self.kdf != "argon2id"
            || self.salt.len() != SALT_LENGTH
            || self.nonce.len() != NONCE_LENGTH
            || self.ciphertext.is_empty()
        {
            return Err(WalletError::InvalidKeystore);
        }
        self.kdf_parameters.validate()?;
        Ok(())
    }
}

fn derive_key(
    password: &[u8],
    salt: &[u8],
    parameters: KdfParameters,
) -> Result<Zeroizing<[u8; KEY_LENGTH]>> {
    let params = Params::new(
        parameters.memory_kib,
        parameters.iterations,
        parameters.parallelism,
        Some(KEY_LENGTH),
    )
    .map_err(|_| WalletError::KeystoreKdf)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = Zeroizing::new([0u8; KEY_LENGTH]);
    argon2
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|_| WalletError::KeystoreKdf)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{AddressChain, WalletConfig};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    const TEST_KDF: KdfParameters = KdfParameters {
        memory_kib: 19 * 1024,
        iterations: 2,
        parallelism: 1,
    };

    fn wallet() -> WalletSecrets {
        let config = WalletConfig::development_testnet(0).unwrap();
        restore_wallet(MNEMONIC, "TREZOR", config).unwrap()
    }

    #[test]
    fn round_trip_preserves_recovery_material() {
        let wallet = wallet();
        let expected = wallet.derive_address(AddressChain::External, 0).unwrap();
        let encrypted = EncryptedKeystore::encrypt_with_parameters(
            &wallet,
            12_345,
            b"correct horse battery staple",
            TEST_KDF,
        )
        .unwrap();
        let serialized = encrypted.to_bytes().unwrap();
        assert!(!serialized.windows(7).any(|window| window == b"abandon"));

        let parsed = EncryptedKeystore::from_bytes(&serialized).unwrap();
        let unlocked = parsed.unlock(b"correct horse battery staple").unwrap();
        assert_eq!(unlocked.birthday_height, 12_345);
        assert_eq!(
            unlocked
                .wallet
                .derive_address(AddressChain::External, 0)
                .unwrap(),
            expected
        );
    }

    #[test]
    fn rejects_wrong_password_and_tampering() {
        let wallet = wallet();
        let mut encrypted =
            EncryptedKeystore::encrypt_with_parameters(&wallet, 0, b"correct password", TEST_KDF)
                .unwrap();
        assert!(matches!(
            encrypted.unlock(b"wrong password"),
            Err(WalletError::KeystoreAuthentication)
        ));
        encrypted.ciphertext[0] ^= 1;
        assert!(matches!(
            encrypted.unlock(b"correct password"),
            Err(WalletError::KeystoreAuthentication)
        ));
    }

    #[test]
    fn rejects_empty_password_and_hostile_kdf_parameters() {
        let wallet = wallet();
        assert!(matches!(
            EncryptedKeystore::encrypt(&wallet, 0, b""),
            Err(WalletError::EmptyKeystorePassword)
        ));
        let invalid = KdfParameters {
            memory_kib: u32::MAX,
            iterations: u32::MAX,
            parallelism: u32::MAX,
        };
        assert!(matches!(
            EncryptedKeystore::encrypt_with_parameters(&wallet, 0, b"password", invalid),
            Err(WalletError::InvalidKeystore)
        ));
    }
}
