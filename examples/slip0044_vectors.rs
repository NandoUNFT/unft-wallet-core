//! Reproducible SLIP-0044 dossier vectors. All material is public test data.

use bip39::{Language, Mnemonic};
use bitcoin::{NetworkKind, bip32::Xpriv};
use serde_json::json;
use unft_wallet_core::{
    AddressChain, Bip44Config, CoinType, UnftNetwork, WalletConfig, restore_wallet,
};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
const PASSPHRASE: &str = "TREZOR";

fn main() {
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, MNEMONIC).unwrap();
    let seed = mnemonic.to_seed_normalized(PASSPHRASE);
    let master = Xpriv::new_master(NetworkKind::Main, &seed).unwrap();
    let wallet = restore_wallet(
        MNEMONIC,
        PASSPHRASE,
        WalletConfig::new(UnftNetwork::Mainnet, CoinType::legacy_core_reference(), 0).unwrap(),
    )
    .unwrap();
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

    let output = json!({
        "warning": "PUBLIC TEST VECTOR ONLY - NEVER USE THIS MNEMONIC FOR FUNDS",
        "status": "candidate coin type; not reserved or assigned",
        "coin_type": 10002,
        "mnemonic": MNEMONIC,
        "bip39_passphrase": PASSPHRASE,
        "seed_hex": hex::encode(seed),
        "master": {
            "private_key_hex": master.private_key.display_secret().to_string(),
            "chain_code_hex": master.chain_code.to_string(),
        },
        "account": {
            "path": config.account_path(),
            "unft_xpriv": wallet.bip44_account_unft_xpriv(config).unwrap(),
            "unft_xpub": wallet.bip44_account_unft_xpub(config).unwrap(),
        },
        "external_0": {
            "path": external_0.path,
            "address": external_0.address,
            "public_key_hex": hex::encode(external_0.public_key),
            "script_pub_key_hex": hex::encode(external_0.script_pub_key),
        },
        "external_1": {
            "path": external_1.path,
            "address": external_1.address,
            "public_key_hex": hex::encode(external_1.public_key),
            "script_pub_key_hex": hex::encode(external_1.script_pub_key),
        },
        "change_0": {
            "path": change_0.path,
            "address": change_0.address,
            "public_key_hex": hex::encode(change_0.public_key),
            "script_pub_key_hex": hex::encode(change_0.script_pub_key),
        },
    });
    println!("{}", serde_json::to_string_pretty(&output).unwrap());
}
