use std::{collections::BTreeSet, str::FromStr};

use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime,
    consensus::encode,
    ecdsa,
    hashes::{Hash, HashEngine, sha256},
    key::Secp256k1,
    script::Builder,
    secp256k1::Message,
    sighash::{EcdsaSighashType, SighashCache},
    transaction::Version,
};

use crate::{
    AddressChain, Bip44Config, Bip44DerivedAddress, FeePolicy, Payment, Result, SignedTransaction,
    UnftNetwork, WalletError, WalletSecrets,
};

const P2PKH_INPUT_MAX_BYTES: u64 = 148;
const P2PKH_OUTPUT_BYTES: u64 = 34;
const TX_OVERHEAD_BYTES: u64 = 10;
const P2PKH_DUST_LIMIT: u64 = 546;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bip44SpendableUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub script_pub_key: Vec<u8>,
    pub account: u32,
    pub chain: AddressChain,
    pub address_index: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bip44BuildTransaction {
    pub coin_type: u32,
    pub inputs: Vec<Bip44SpendableUtxo>,
    pub recipients: Vec<Payment>,
    pub change: Option<Bip44DerivedAddress>,
    pub fee_policy: FeePolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bip44PrepareTransaction {
    pub coin_type: u32,
    pub eligible_inputs: Vec<Bip44SpendableUtxo>,
    pub recipients: Vec<Payment>,
    pub change: Bip44DerivedAddress,
    pub fee_policy: FeePolicy,
    pub max_inputs: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Bip44TransactionReview {
    pub selected_inputs: Vec<Bip44SpendableUtxo>,
    pub input_total: u64,
    pub recipients: Vec<Payment>,
    pub recipient_total: u64,
    pub fee: u64,
    pub change: u64,
    pub change_address: Option<String>,
    pub estimated_signed_vbytes: u64,
}

#[derive(Clone, Debug)]
pub struct Bip44UnsignedTransaction {
    transaction: Transaction,
    coin_type: u32,
    inputs: Vec<Bip44SpendableUtxo>,
    pub fee: u64,
    pub change: u64,
    pub estimated_signed_vbytes: u64,
}

impl Bip44UnsignedTransaction {
    pub fn raw_hex(&self) -> String {
        encode::serialize_hex(&self.transaction)
    }

    pub fn txid(&self) -> String {
        self.transaction.compute_txid().to_string()
    }
}

#[derive(Clone, Debug)]
pub struct Bip44PreparedTransaction {
    unsigned: Bip44UnsignedTransaction,
    review: Bip44TransactionReview,
    review_id: String,
}

impl Bip44PreparedTransaction {
    pub const fn review(&self) -> &Bip44TransactionReview {
        &self.review
    }

    pub fn review_id(&self) -> &str {
        &self.review_id
    }

    pub fn approve(self, reviewed_id: &str) -> Result<Bip44ApprovedTransaction> {
        if reviewed_id != self.review_id {
            return Err(WalletError::InvalidReviewConfirmation);
        }
        Ok(Bip44ApprovedTransaction {
            unsigned: self.unsigned,
            review: self.review,
            review_id: self.review_id,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Bip44ApprovedTransaction {
    unsigned: Bip44UnsignedTransaction,
    review: Bip44TransactionReview,
    review_id: String,
}

impl Bip44ApprovedTransaction {
    pub const fn review(&self) -> &Bip44TransactionReview {
        &self.review
    }

    pub fn review_id(&self) -> &str {
        &self.review_id
    }
}

impl Payment {
    pub fn to_bip44_address(value: u64, address: &str, network: UnftNetwork) -> Result<Self> {
        let payload =
            base58ck::decode_check(address).map_err(|_| WalletError::InvalidDestinationAddress)?;
        if payload.len() != 21 || payload[0] != network.p2pkh_prefix() {
            return Err(WalletError::InvalidDestinationAddress);
        }
        let mut script_pub_key = Vec::with_capacity(25);
        script_pub_key.extend_from_slice(&[0x76, 0xa9, 0x14]);
        script_pub_key.extend_from_slice(&payload[1..]);
        script_pub_key.extend_from_slice(&[0x88, 0xac]);
        Ok(Self {
            value,
            script_pub_key,
        })
    }

    pub fn to_bip44_derived(value: u64, destination: &Bip44DerivedAddress) -> Self {
        Self {
            value,
            script_pub_key: destination.script_pub_key.clone(),
        }
    }
}

pub fn prepare_bip44_transaction(
    request: Bip44PrepareTransaction,
) -> Result<Bip44PreparedTransaction> {
    if request.max_inputs == 0 {
        return Err(WalletError::InvalidInputLimit);
    }
    validate_payments(&request.recipients)?;
    validate_inputs(&request.eligible_inputs)?;
    let recipient_total = sum(request.recipients.iter().map(|item| item.value))?;
    let change_address = request.change.address.clone();
    let mut candidates = request.eligible_inputs;
    candidates.sort_by(|left, right| {
        right
            .value
            .cmp(&left.value)
            .then_with(|| left.txid.cmp(&right.txid))
            .then_with(|| left.vout.cmp(&right.vout))
    });

    let mut selected = Vec::new();
    let mut input_total = 0_u64;
    for candidate in candidates {
        if selected.len() == request.max_inputs {
            return Err(WalletError::CoinSelectionLimitReached);
        }
        input_total = input_total
            .checked_add(candidate.value)
            .ok_or(WalletError::AmountOverflow)?;
        selected.push(candidate);
        match build_bip44_transaction(Bip44BuildTransaction {
            coin_type: request.coin_type,
            inputs: selected.clone(),
            recipients: request.recipients.clone(),
            change: Some(request.change.clone()),
            fee_policy: request.fee_policy,
        }) {
            Ok(unsigned) => {
                let review = Bip44TransactionReview {
                    selected_inputs: selected,
                    input_total,
                    recipients: request.recipients,
                    recipient_total,
                    fee: unsigned.fee,
                    change: unsigned.change,
                    change_address: (unsigned.change > 0).then_some(change_address),
                    estimated_signed_vbytes: unsigned.estimated_signed_vbytes,
                };
                let review_id = review_id(&unsigned, &review);
                return Ok(Bip44PreparedTransaction {
                    unsigned,
                    review,
                    review_id,
                });
            }
            Err(WalletError::InsufficientFunds) => {}
            Err(error) => return Err(error),
        }
    }
    Err(WalletError::InsufficientFunds)
}

pub fn build_bip44_transaction(request: Bip44BuildTransaction) -> Result<Bip44UnsignedTransaction> {
    if request.inputs.is_empty() || request.recipients.is_empty() {
        return Err(WalletError::EmptyTransaction);
    }
    validate_inputs(&request.inputs)?;
    validate_payments(&request.recipients)?;
    let input_total = sum(request.inputs.iter().map(|item| item.value))?;
    let recipient_total = sum(request.recipients.iter().map(|item| item.value))?;
    let vbytes = estimate_vbytes(
        request.inputs.len(),
        request.recipients.len() + usize::from(request.change.is_some()),
    );
    let mut fee = fee_for(request.fee_policy, vbytes)?;
    let remainder = input_total
        .checked_sub(recipient_total)
        .and_then(|value| value.checked_sub(fee))
        .ok_or(WalletError::InsufficientFunds)?;
    let mut outputs = request
        .recipients
        .iter()
        .map(|payment| TxOut {
            value: Amount::from_sat(payment.value),
            script_pubkey: ScriptBuf::from_bytes(payment.script_pub_key.clone()),
        })
        .collect::<Vec<_>>();
    let change = if let Some(change) = request.change {
        if remainder >= P2PKH_DUST_LIMIT {
            outputs.push(TxOut {
                value: Amount::from_sat(remainder),
                script_pubkey: ScriptBuf::from_bytes(change.script_pub_key),
            });
            remainder
        } else {
            fee = fee
                .checked_add(remainder)
                .ok_or(WalletError::AmountOverflow)?;
            0
        }
    } else {
        fee = fee
            .checked_add(remainder)
            .ok_or(WalletError::AmountOverflow)?;
        0
    };
    let inputs = request.inputs;
    let transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: inputs
            .iter()
            .map(|utxo| {
                Ok(TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_str(&utxo.txid)?,
                        vout: utxo.vout,
                    },
                    script_sig: ScriptBuf::new(),
                    sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                    witness: Witness::new(),
                })
            })
            .collect::<Result<Vec<_>>>()?,
        output: outputs,
    };
    Ok(Bip44UnsignedTransaction {
        transaction,
        coin_type: request.coin_type,
        inputs,
        fee,
        change,
        estimated_signed_vbytes: vbytes,
    })
}

pub fn sign_bip44_approved_transaction(
    wallet: &WalletSecrets,
    approved: Bip44ApprovedTransaction,
) -> Result<SignedTransaction> {
    sign_bip44_transaction(wallet, approved.unsigned)
}

pub fn sign_bip44_transaction(
    wallet: &WalletSecrets,
    unsigned: Bip44UnsignedTransaction,
) -> Result<SignedTransaction> {
    let secp = Secp256k1::new();
    let mut transaction = unsigned.transaction;
    for (input_index, utxo) in unsigned.inputs.iter().enumerate() {
        let config =
            Bip44Config::for_discovery(wallet.config().network, unsigned.coin_type, utxo.account)?;
        let derived = wallet.derive_bip44_address(config, utxo.chain, utxo.address_index)?;
        if derived.script_pub_key != utxo.script_pub_key {
            return Err(WalletError::InputOwnershipMismatch(input_index));
        }
        let secret = wallet.derive_bip44_private_key(config, utxo.chain, utxo.address_index)?;
        let public = secret.public_key(&secp);
        let script = ScriptBuf::from_bytes(utxo.script_pub_key.clone());
        let sighash_type = EcdsaSighashType::All;
        let sighash = SighashCache::new(&transaction).legacy_signature_hash(
            input_index,
            &script,
            sighash_type.to_u32(),
        )?;
        let signature = ecdsa::Signature {
            signature: secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &secret),
            sighash_type,
        };
        transaction.input[input_index].script_sig = Builder::new()
            .push_slice(signature.serialize())
            .push_slice(public.serialize())
            .into_script();
    }
    Ok(SignedTransaction {
        raw_hex: encode::serialize_hex(&transaction),
        txid: transaction.compute_txid().to_string(),
        wtxid: transaction.compute_wtxid().to_string(),
        fee: unsigned.fee,
        vbytes: transaction.vsize() as u64,
    })
}

fn review_id(unsigned: &Bip44UnsignedTransaction, review: &Bip44TransactionReview) -> String {
    let mut engine = sha256::Hash::engine();
    engine.input(b"UNFT Wallet BIP44 transaction review v1\0");
    engine.input(&encode::serialize(&unsigned.transaction));
    engine.input(&review.input_total.to_le_bytes());
    engine.input(&review.recipient_total.to_le_bytes());
    engine.input(&review.fee.to_le_bytes());
    engine.input(&review.change.to_le_bytes());
    sha256::Hash::from_engine(engine).to_string()
}

fn validate_inputs(inputs: &[Bip44SpendableUtxo]) -> Result<()> {
    let mut outpoints = BTreeSet::new();
    for input in inputs {
        if input.value == 0 || input.script_pub_key.is_empty() {
            return Err(WalletError::InvalidTransactionEntry);
        }
        if !outpoints.insert((input.txid.as_str(), input.vout)) {
            return Err(WalletError::DuplicateInput);
        }
    }
    Ok(())
}

fn validate_payments(payments: &[Payment]) -> Result<()> {
    if payments
        .iter()
        .any(|payment| payment.value == 0 || payment.script_pub_key.is_empty())
    {
        return Err(WalletError::InvalidTransactionEntry);
    }
    Ok(())
}

fn estimate_vbytes(inputs: usize, outputs: usize) -> u64 {
    TX_OVERHEAD_BYTES + P2PKH_INPUT_MAX_BYTES * inputs as u64 + P2PKH_OUTPUT_BYTES * outputs as u64
}

fn fee_for(policy: FeePolicy, vbytes: u64) -> Result<u64> {
    match policy {
        FeePolicy::Exact(value) => Ok(value),
        FeePolicy::RatePerVbyte(0) => Err(WalletError::InvalidFeeRate),
        FeePolicy::RatePerVbyte(rate) => {
            rate.checked_mul(vbytes).ok_or(WalletError::AmountOverflow)
        }
    }
}

fn sum(mut values: impl Iterator<Item = u64>) -> Result<u64> {
    values.try_fold(0_u64, |total, value| {
        total.checked_add(value).ok_or(WalletError::AmountOverflow)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CoinType, WalletConfig, restore_wallet};

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

    fn wallet() -> WalletSecrets {
        restore_wallet(
            MNEMONIC,
            "TREZOR",
            WalletConfig::new(UnftNetwork::Mainnet, CoinType::legacy_core_reference(), 0).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn builds_reviews_and_signs_p2pkh_with_change() {
        let wallet = wallet();
        let config = Bip44Config::mainnet_proposal(0).unwrap();
        let source = wallet
            .derive_bip44_address(config, AddressChain::External, 0)
            .unwrap();
        let destination = wallet
            .derive_bip44_address(config, AddressChain::External, 1)
            .unwrap();
        let change = wallet
            .derive_bip44_address(config, AddressChain::Change, 0)
            .unwrap();
        let pending = prepare_bip44_transaction(Bip44PrepareTransaction {
            coin_type: config.coin_type,
            eligible_inputs: vec![Bip44SpendableUtxo {
                txid: "11".repeat(32),
                vout: 0,
                value: 100_000,
                script_pub_key: source.script_pub_key,
                account: 0,
                chain: AddressChain::External,
                address_index: 0,
            }],
            recipients: vec![Payment::to_bip44_derived(60_000, &destination)],
            change: change.clone(),
            fee_policy: FeePolicy::Exact(1_000),
            max_inputs: 10,
        })
        .unwrap();
        assert_eq!(pending.review().change, 39_000);
        assert_eq!(pending.review().change_address, Some(change.address));
        let review_id = pending.review_id().to_owned();
        let approved = pending.approve(&review_id).unwrap();
        let signed = sign_bip44_approved_transaction(&wallet, approved).unwrap();
        assert_eq!(signed.fee, 1_000);
        assert_eq!(signed.txid, signed.wtxid);
        assert!(signed.raw_hex.starts_with("0200000001"));
    }

    #[test]
    fn rejects_wrong_path_and_cross_network_destination() {
        let wallet = wallet();
        let config = Bip44Config::mainnet_proposal(0).unwrap();
        let source = wallet
            .derive_bip44_address(config, AddressChain::External, 1)
            .unwrap();
        let destination = wallet
            .derive_bip44_address(config, AddressChain::External, 2)
            .unwrap();
        assert!(matches!(
            Payment::to_bip44_address(1, &destination.address, UnftNetwork::Testnet),
            Err(WalletError::InvalidDestinationAddress)
        ));
        let unsigned = build_bip44_transaction(Bip44BuildTransaction {
            coin_type: config.coin_type,
            inputs: vec![Bip44SpendableUtxo {
                txid: "22".repeat(32),
                vout: 0,
                value: 100_000,
                script_pub_key: source.script_pub_key,
                account: 0,
                chain: AddressChain::External,
                address_index: 0,
            }],
            recipients: vec![Payment::to_bip44_derived(99_000, &destination)],
            change: None,
            fee_policy: FeePolicy::Exact(1_000),
        })
        .unwrap();
        assert!(matches!(
            sign_bip44_transaction(&wallet, unsigned),
            Err(WalletError::InputOwnershipMismatch(0))
        ));
    }
}
