//! Creates a testnet/regtest P2PKH spend for cross-checking with Unftcoin Core.
//! All mnemonic material is fixed public test data.

use std::env;

use serde_json::json;
use unft_wallet_core::{
    AddressChain, Bip44BuildTransaction, Bip44Config, Bip44SpendableUtxo, CoinType, FeePolicy,
    Payment, UnftNetwork, WalletConfig, build_bip44_transaction, restore_wallet,
    sign_bip44_transaction,
};

const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

fn main() {
    let args = env::args().collect::<Vec<_>>();
    assert_eq!(args.len(), 4, "usage: bip44_core_spend TXID VOUT VALUE_SAT");
    let vout = args[2].parse::<u32>().unwrap();
    let value = args[3].parse::<u64>().unwrap();
    let wallet = restore_wallet(
        MNEMONIC,
        "TREZOR",
        WalletConfig::new(UnftNetwork::Testnet, CoinType::legacy_core_reference(), 0).unwrap(),
    )
    .unwrap();
    let config = Bip44Config::testnet(0).unwrap();
    let source = wallet
        .derive_bip44_address(config, AddressChain::External, 0)
        .unwrap();
    let recipient = wallet
        .derive_bip44_address(config, AddressChain::External, 1)
        .unwrap();
    let change = wallet
        .derive_bip44_address(config, AddressChain::Change, 0)
        .unwrap();
    let fee = 1_000;
    let send_value = value / 2;
    let unsigned = build_bip44_transaction(Bip44BuildTransaction {
        coin_type: config.coin_type,
        inputs: vec![Bip44SpendableUtxo {
            txid: args[1].clone(),
            vout,
            value,
            script_pub_key: source.script_pub_key,
            account: 0,
            chain: AddressChain::External,
            address_index: 0,
        }],
        recipients: vec![Payment::to_bip44_derived(send_value, &recipient)],
        change: Some(change.clone()),
        fee_policy: FeePolicy::Exact(fee),
    })
    .unwrap();
    let signed = sign_bip44_transaction(&wallet, unsigned).unwrap();
    let mut regtest_xpub = wallet.bip44_account_xpub(config).unwrap().encode();
    regtest_xpub[..4].copy_from_slice(&[0x04, 0x35, 0x87, 0xcf]);
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "account_xpub": wallet.bip44_account_unft_xpub(config).unwrap(),
            "regtest_tpub": base58ck::encode_check(&regtest_xpub),
            "source": source.address,
            "recipient": recipient.address,
            "change": change.address,
            "fee_sat": fee,
            "raw_hex": signed.raw_hex,
            "txid": signed.txid,
        }))
        .unwrap()
    );
}
