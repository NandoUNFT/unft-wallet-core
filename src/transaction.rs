use std::{collections::BTreeSet, str::FromStr};

use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    absolute::LockTime,
    consensus::encode,
    ecdsa,
    hashes::{Hash, HashEngine, sha256},
    key::Secp256k1,
    secp256k1::Message,
    sighash::{EcdsaSighashType, SighashCache},
    transaction::Version,
};

use crate::{
    AddressChain, BlockchainCache, DerivedAddress, Result, UnftNetwork, WalletError, WalletSecrets,
};

/// Conservative upper-bound estimate for a signed P2WPKH input.
const P2WPKH_MAX_WITNESS_BYTES: u64 = 109;
const TX_OVERHEAD_BASE_BYTES: u64 = 10;
const INPUT_BASE_BYTES: u64 = 41;
const P2WPKH_OUTPUT_BYTES: u64 = 31;
const SEGWIT_MARKER_FLAG_WEIGHT: u64 = 2;
const DEFAULT_DUST_LIMIT: u64 = 294;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpendableUtxo {
    pub txid: String,
    pub vout: u32,
    pub value: u64,
    pub script_pub_key: Vec<u8>,
    pub chain: AddressChain,
    pub address_index: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Payment {
    pub value: u64,
    pub script_pub_key: Vec<u8>,
}

impl Payment {
    pub fn to_address(value: u64, destination: &DerivedAddress) -> Self {
        Self {
            value,
            script_pub_key: destination.script_pub_key.clone(),
        }
    }

    pub fn to_unft_address(value: u64, address: &str, network: UnftNetwork) -> Result<Self> {
        let (hrp, witness_version, witness_program) =
            bech32::segwit::decode(address).map_err(|_| WalletError::InvalidDestinationAddress)?;
        if hrp.as_str() != network.bech32_hrp()
            || witness_version != bech32::segwit::VERSION_0
            || witness_program.len() != 20
        {
            return Err(WalletError::InvalidDestinationAddress);
        }
        let mut script_pub_key = Vec::with_capacity(22);
        script_pub_key.extend_from_slice(&[0x00, 0x14]);
        script_pub_key.extend_from_slice(&witness_program);
        Ok(Self {
            value,
            script_pub_key,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeePolicy {
    /// Exact fee, useful for reproducible test vectors and advanced callers.
    Exact(u64),
    /// Base units per virtual byte. Estimation uses the maximum standard DER
    /// signature size so it does not underpay because of signature length.
    RatePerVbyte(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuildTransaction {
    pub inputs: Vec<SpendableUtxo>,
    pub recipients: Vec<Payment>,
    pub change: Option<DerivedAddress>,
    pub fee_policy: FeePolicy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareTransaction {
    /// Inputs already filtered by the caller as locally spendable.
    pub eligible_inputs: Vec<SpendableUtxo>,
    pub recipients: Vec<Payment>,
    pub change: DerivedAddress,
    pub fee_policy: FeePolicy,
    pub max_inputs: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrepareWalletPayment {
    pub recipients: Vec<Payment>,
    pub change: DerivedAddress,
    pub fee_policy: FeePolicy,
    pub minimum_confirmations: u64,
    pub max_inputs: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TransactionReview {
    pub input_count: usize,
    pub input_total: u64,
    pub selected_inputs: Vec<SpendableUtxo>,
    pub recipient_count: usize,
    pub recipient_total: u64,
    pub recipients: Vec<Payment>,
    pub fee: u64,
    pub change: u64,
    pub change_address: Option<String>,
    pub estimated_signed_vbytes: u64,
}

#[derive(Clone, Debug)]
pub struct PreparedTransaction {
    unsigned: UnsignedTransaction,
    review: TransactionReview,
    review_id: String,
}

impl PreparedTransaction {
    pub const fn review(&self) -> &TransactionReview {
        &self.review
    }

    /// Commitment to the exact transaction and review amounts shown to the
    /// user. Platforms must retain and return this value after confirmation.
    pub fn review_id(&self) -> &str {
        &self.review_id
    }

    pub fn approve(self, reviewed_id: &str) -> Result<ApprovedTransaction> {
        if reviewed_id != self.review_id {
            return Err(WalletError::InvalidReviewConfirmation);
        }
        Ok(ApprovedTransaction {
            unsigned: self.unsigned,
            review: self.review,
            review_id: self.review_id,
        })
    }
}

#[derive(Clone, Debug)]
pub struct ApprovedTransaction {
    unsigned: UnsignedTransaction,
    review: TransactionReview,
    review_id: String,
}

impl ApprovedTransaction {
    pub const fn review(&self) -> &TransactionReview {
        &self.review
    }

    pub fn review_id(&self) -> &str {
        &self.review_id
    }
}

#[derive(Clone, Debug)]
pub struct UnsignedTransaction {
    transaction: Transaction,
    inputs: Vec<SpendableUtxo>,
    pub fee: u64,
    pub change: u64,
    pub estimated_signed_vbytes: u64,
}

impl UnsignedTransaction {
    pub fn raw_hex(&self) -> String {
        encode::serialize_hex(&self.transaction)
    }

    pub fn txid(&self) -> String {
        self.transaction.compute_txid().to_string()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedTransaction {
    pub raw_hex: String,
    pub txid: String,
    pub wtxid: String,
    pub fee: u64,
    pub vbytes: u64,
}

/// High-level entry point from disposable chain cache to a reviewable payment.
pub fn prepare_wallet_payment(
    wallet: &WalletSecrets,
    cache: &BlockchainCache,
    request: PrepareWalletPayment,
) -> Result<PreparedTransaction> {
    let eligible_inputs = cache.spendable_utxos(wallet, request.minimum_confirmations)?;
    prepare_transaction(PrepareTransaction {
        eligible_inputs,
        recipients: request.recipients,
        change: request.change,
        fee_policy: request.fee_policy,
        max_inputs: request.max_inputs,
    })
}

/// Selects eligible UTXOs deterministically and returns a proposal that can be
/// reviewed without exposing private key material or producing signatures.
pub fn prepare_transaction(request: PrepareTransaction) -> Result<PreparedTransaction> {
    if request.max_inputs == 0 {
        return Err(WalletError::InvalidInputLimit);
    }
    validate_recipients(&request.recipients)?;
    validate_inputs(&request.eligible_inputs)?;

    let recipient_total = checked_sum(request.recipients.iter().map(|output| output.value))?;
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

        let attempt = build_transaction(BuildTransaction {
            inputs: selected.clone(),
            recipients: request.recipients.clone(),
            change: Some(request.change.clone()),
            fee_policy: request.fee_policy,
        });
        match attempt {
            Ok(unsigned) => {
                let review = TransactionReview {
                    input_count: selected.len(),
                    input_total,
                    selected_inputs: selected.clone(),
                    recipient_count: request.recipients.len(),
                    recipient_total,
                    recipients: request.recipients.clone(),
                    fee: unsigned.fee,
                    change: unsigned.change,
                    change_address: (unsigned.change > 0).then(|| change_address.clone()),
                    estimated_signed_vbytes: unsigned.estimated_signed_vbytes,
                };
                let review_id = transaction_review_id(&unsigned, &review);
                return Ok(PreparedTransaction {
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

/// Signs only a proposal that has passed the explicit review transition.
pub fn sign_approved_transaction(
    wallet: &WalletSecrets,
    approved: ApprovedTransaction,
) -> Result<SignedTransaction> {
    sign_transaction(wallet, approved.unsigned)
}

fn transaction_review_id(unsigned: &UnsignedTransaction, review: &TransactionReview) -> String {
    let mut engine = sha256::Hash::engine();
    engine.input(b"UNFT Wallet transaction review v1\0");
    engine.input(&encode::serialize(&unsigned.transaction));
    engine.input(&review.input_total.to_le_bytes());
    engine.input(&review.recipient_total.to_le_bytes());
    engine.input(&review.fee.to_le_bytes());
    engine.input(&review.change.to_le_bytes());
    sha256::Hash::from_engine(engine).to_string()
}

pub fn build_transaction(request: BuildTransaction) -> Result<UnsignedTransaction> {
    if request.inputs.is_empty() || request.recipients.is_empty() {
        return Err(WalletError::EmptyTransaction);
    }
    validate_inputs(&request.inputs)?;
    validate_recipients(&request.recipients)?;

    let input_total = checked_sum(request.inputs.iter().map(|input| input.value))?;
    let recipient_total = checked_sum(request.recipients.iter().map(|output| output.value))?;
    let with_change_vbytes = estimate_signed_vbytes(
        request.inputs.len(),
        request.recipients.len() + usize::from(request.change.is_some()),
    );
    let mut fee = fee_for(request.fee_policy, with_change_vbytes)?;
    let mut remainder = input_total
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

    let mut change = 0;
    if let Some(change_address) = request.change {
        if remainder >= DEFAULT_DUST_LIMIT {
            change = remainder;
            outputs.push(TxOut {
                value: Amount::from_sat(change),
                script_pubkey: ScriptBuf::from_bytes(change_address.script_pub_key),
            });
            remainder = 0;
        } else {
            fee = fee
                .checked_add(remainder)
                .ok_or(WalletError::AmountOverflow)?;
            remainder = 0;
        }
    } else {
        fee = fee
            .checked_add(remainder)
            .ok_or(WalletError::AmountOverflow)?;
        remainder = 0;
    }
    debug_assert_eq!(remainder, 0);

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

    Ok(UnsignedTransaction {
        transaction,
        inputs,
        fee,
        change,
        estimated_signed_vbytes: with_change_vbytes,
    })
}

fn validate_inputs(inputs: &[SpendableUtxo]) -> Result<()> {
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

fn validate_recipients(recipients: &[Payment]) -> Result<()> {
    if recipients
        .iter()
        .any(|payment| payment.value == 0 || payment.script_pub_key.is_empty())
    {
        return Err(WalletError::InvalidTransactionEntry);
    }
    Ok(())
}

pub fn sign_transaction(
    wallet: &WalletSecrets,
    unsigned: UnsignedTransaction,
) -> Result<SignedTransaction> {
    let secp = Secp256k1::new();
    let mut transaction = unsigned.transaction;

    for (input_index, utxo) in unsigned.inputs.iter().enumerate() {
        let derived = wallet.derive_address(utxo.chain, utxo.address_index)?;
        if derived.script_pub_key != utxo.script_pub_key {
            return Err(WalletError::InputOwnershipMismatch(input_index));
        }

        let secret_key = wallet.derive_private_key(utxo.chain, utxo.address_index)?;
        let public_key = secret_key.public_key(&secp);
        let script_pubkey = ScriptBuf::from_bytes(utxo.script_pub_key.clone());
        let sighash_type = EcdsaSighashType::All;
        let mut cache = SighashCache::new(&mut transaction);
        let sighash = cache.p2wpkh_signature_hash(
            input_index,
            &script_pubkey,
            Amount::from_sat(utxo.value),
            sighash_type,
        )?;
        let message = Message::from_digest(sighash.to_byte_array());
        let signature = secp.sign_ecdsa(&message, &secret_key);
        let signature = ecdsa::Signature {
            signature,
            sighash_type,
        };
        *cache
            .witness_mut(input_index)
            .expect("input index came from the transaction") =
            Witness::p2wpkh(&signature, &public_key);
    }

    let raw_hex = encode::serialize_hex(&transaction);
    Ok(SignedTransaction {
        txid: transaction.compute_txid().to_string(),
        wtxid: transaction.compute_wtxid().to_string(),
        fee: unsigned.fee,
        vbytes: transaction.vsize() as u64,
        raw_hex,
    })
}

fn fee_for(policy: FeePolicy, estimated_vbytes: u64) -> Result<u64> {
    match policy {
        FeePolicy::Exact(fee) => Ok(fee),
        FeePolicy::RatePerVbyte(0) => Err(WalletError::InvalidFeeRate),
        FeePolicy::RatePerVbyte(rate) => rate
            .checked_mul(estimated_vbytes)
            .ok_or(WalletError::AmountOverflow),
    }
}

fn estimate_signed_vbytes(inputs: usize, outputs: usize) -> u64 {
    let base = TX_OVERHEAD_BASE_BYTES
        + INPUT_BASE_BYTES * inputs as u64
        + P2WPKH_OUTPUT_BYTES * outputs as u64;
    let weight = base * 4 + SEGWIT_MARKER_FLAG_WEIGHT + P2WPKH_MAX_WITNESS_BYTES * inputs as u64;
    weight.div_ceil(4)
}

fn checked_sum(mut values: impl Iterator<Item = u64>) -> Result<u64> {
    values.try_fold(0u64, |sum, value| {
        sum.checked_add(value).ok_or(WalletError::AmountOverflow)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        AddressDerivation, AddressSnapshot, CoinType, ConfirmationStatus, UnftNetwork, Utxo,
        WalletConfig, restore_wallet,
    };

    const MNEMONIC: &str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";
    const SIGNED_VECTOR: &str = "0200000000010111111111111111111111111111111111111111111111111111111111111111110000000000fdffffff01905f0100000000001600146f9d57e8318a1b3decc29ef2a463f9a793dc134c02483045022100fad14841d06aa1288ab235e06927efd1757606a87c4d690ba0a8b303b5de981902204b660e4e089371a69f8839674fae949ce171b13027bd06fdecb7214ab8c5c49b01210222aecea7761c6deca89fc2002134452eb614a8dd3a4146716ab7f581a54fac8200000000";

    fn reference_wallet() -> WalletSecrets {
        let config =
            WalletConfig::new(UnftNetwork::Mainnet, CoinType::legacy_core_reference(), 0).unwrap();
        restore_wallet(MNEMONIC, "TREZOR", config).unwrap()
    }

    #[test]
    fn builds_and_signs_core_verified_vector() {
        let wallet = reference_wallet();
        let source = wallet.derive_address(AddressChain::External, 0).unwrap();
        let destination = wallet.derive_address(AddressChain::External, 1).unwrap();
        let unsigned = build_transaction(BuildTransaction {
            inputs: vec![SpendableUtxo {
                txid: "11".repeat(32),
                vout: 0,
                value: 100_000,
                script_pub_key: source.script_pub_key,
                chain: AddressChain::External,
                address_index: 0,
            }],
            recipients: vec![Payment::to_address(90_000, &destination)],
            change: None,
            fee_policy: FeePolicy::Exact(10_000),
        })
        .unwrap();

        assert_eq!(unsigned.fee, 10_000);
        let signed = sign_transaction(&wallet, unsigned).unwrap();
        assert_eq!(signed.raw_hex, SIGNED_VECTOR);
        assert_eq!(
            signed.txid,
            "da517ef54014db94c20c1eb2ce5430b085e39e0e341e355680bc5889f26026be"
        );
        assert_eq!(
            signed.wtxid,
            "5ab83c5bd56ce2afa63676b92197ff964b49385efad327dd23accb9806b1249b"
        );
    }

    #[test]
    fn parses_only_network_correct_p2wpkh_destinations() {
        let wallet = reference_wallet();
        let destination = wallet.derive_address(AddressChain::External, 1).unwrap();
        let payment =
            Payment::to_unft_address(90_000, &destination.address, UnftNetwork::Mainnet).unwrap();
        assert_eq!(payment.script_pub_key, destination.script_pub_key);
        assert!(matches!(
            Payment::to_unft_address(90_000, &destination.address, UnftNetwork::Testnet),
            Err(WalletError::InvalidDestinationAddress)
        ));
        assert!(matches!(
            Payment::to_unft_address(90_000, "uc1invalid", UnftNetwork::Mainnet),
            Err(WalletError::InvalidDestinationAddress)
        ));
    }

    #[test]
    fn calculates_rate_fee_and_change() {
        let wallet = reference_wallet();
        let source = wallet.derive_address(AddressChain::External, 0).unwrap();
        let destination = wallet.derive_address(AddressChain::External, 1).unwrap();
        let change = wallet.derive_address(AddressChain::Change, 0).unwrap();
        let unsigned = build_transaction(BuildTransaction {
            inputs: vec![SpendableUtxo {
                txid: "22".repeat(32),
                vout: 1,
                value: 100_000,
                script_pub_key: source.script_pub_key,
                chain: AddressChain::External,
                address_index: 0,
            }],
            recipients: vec![Payment::to_address(50_000, &destination)],
            change: Some(change),
            fee_policy: FeePolicy::RatePerVbyte(2),
        })
        .unwrap();

        assert_eq!(unsigned.estimated_signed_vbytes, 141);
        assert_eq!(unsigned.fee, 282);
        assert_eq!(unsigned.change, 49_718);
    }

    #[test]
    fn refuses_input_not_owned_by_declared_path() {
        let wallet = reference_wallet();
        let destination = wallet.derive_address(AddressChain::External, 1).unwrap();
        let unsigned = build_transaction(BuildTransaction {
            inputs: vec![SpendableUtxo {
                txid: "33".repeat(32),
                vout: 0,
                value: 100_000,
                script_pub_key: destination.script_pub_key.clone(),
                chain: AddressChain::External,
                address_index: 0,
            }],
            recipients: vec![Payment::to_address(90_000, &destination)],
            change: None,
            fee_policy: FeePolicy::Exact(10_000),
        })
        .unwrap();

        assert!(matches!(
            sign_transaction(&wallet, unsigned),
            Err(WalletError::InputOwnershipMismatch(0))
        ));
    }

    #[test]
    fn prepares_reviewable_payment_with_deterministic_selection() {
        let wallet = reference_wallet();
        let source_0 = wallet.derive_address(AddressChain::External, 0).unwrap();
        let source_1 = wallet.derive_address(AddressChain::External, 1).unwrap();
        let destination = wallet.derive_address(AddressChain::External, 2).unwrap();
        let change = wallet.derive_address(AddressChain::Change, 0).unwrap();
        let prepared = prepare_transaction(PrepareTransaction {
            eligible_inputs: vec![
                SpendableUtxo {
                    txid: "22".repeat(32),
                    vout: 0,
                    value: 30_000,
                    script_pub_key: source_1.script_pub_key,
                    chain: AddressChain::External,
                    address_index: 1,
                },
                SpendableUtxo {
                    txid: "11".repeat(32),
                    vout: 0,
                    value: 80_000,
                    script_pub_key: source_0.script_pub_key,
                    chain: AddressChain::External,
                    address_index: 0,
                },
            ],
            recipients: vec![Payment::to_address(50_000, &destination)],
            change: change.clone(),
            fee_policy: FeePolicy::RatePerVbyte(2),
            max_inputs: 10,
        })
        .unwrap();

        assert_eq!(prepared.review().input_count, 1);
        assert_eq!(prepared.review().input_total, 80_000);
        assert_eq!(prepared.review().selected_inputs[0].txid, "11".repeat(32));
        assert_eq!(prepared.review().recipient_count, 1);
        assert_eq!(prepared.review().recipient_total, 50_000);
        assert_eq!(prepared.review().recipients[0].value, 50_000);
        assert_eq!(prepared.review().fee, 282);
        assert_eq!(prepared.review().change, 29_718);
        assert_eq!(
            prepared.review().change_address.as_deref(),
            Some(change.address.as_str())
        );
        assert_eq!(prepared.review().estimated_signed_vbytes, 141);
        assert!(matches!(
            prepared.clone().approve("not-the-displayed-review-id"),
            Err(WalletError::InvalidReviewConfirmation)
        ));
        let review_id = prepared.review_id().to_owned();
        let approved = prepared.approve(&review_id).unwrap();
        assert_eq!(approved.review_id(), review_id);
        assert_eq!(approved.review().fee, 282);
        let signed = sign_approved_transaction(&wallet, approved).unwrap();
        assert_eq!(signed.fee, 282);
    }

    #[test]
    fn selection_adds_inputs_until_payment_is_funded() {
        let wallet = reference_wallet();
        let source_0 = wallet.derive_address(AddressChain::External, 0).unwrap();
        let source_1 = wallet.derive_address(AddressChain::External, 1).unwrap();
        let destination = wallet.derive_address(AddressChain::External, 2).unwrap();
        let change = wallet.derive_address(AddressChain::Change, 0).unwrap();
        let prepared = prepare_transaction(PrepareTransaction {
            eligible_inputs: vec![
                SpendableUtxo {
                    txid: "11".repeat(32),
                    vout: 0,
                    value: 30_000,
                    script_pub_key: source_0.script_pub_key,
                    chain: AddressChain::External,
                    address_index: 0,
                },
                SpendableUtxo {
                    txid: "22".repeat(32),
                    vout: 1,
                    value: 30_000,
                    script_pub_key: source_1.script_pub_key,
                    chain: AddressChain::External,
                    address_index: 1,
                },
            ],
            recipients: vec![Payment::to_address(50_000, &destination)],
            change,
            fee_policy: FeePolicy::Exact(1_000),
            max_inputs: 2,
        })
        .unwrap();

        assert_eq!(prepared.review().input_count, 2);
        assert_eq!(prepared.review().change, 9_000);
    }

    #[test]
    fn rejects_duplicate_inputs_and_selection_limit() {
        let wallet = reference_wallet();
        let source = wallet.derive_address(AddressChain::External, 0).unwrap();
        let destination = wallet.derive_address(AddressChain::External, 1).unwrap();
        let change = wallet.derive_address(AddressChain::Change, 0).unwrap();
        let input = SpendableUtxo {
            txid: "11".repeat(32),
            vout: 0,
            value: 30_000,
            script_pub_key: source.script_pub_key,
            chain: AddressChain::External,
            address_index: 0,
        };
        assert!(matches!(
            prepare_transaction(PrepareTransaction {
                eligible_inputs: vec![input.clone(), input],
                recipients: vec![Payment::to_address(50_000, &destination)],
                change: change.clone(),
                fee_policy: FeePolicy::Exact(1_000),
                max_inputs: 2,
            }),
            Err(WalletError::DuplicateInput)
        ));

        let second_source = wallet.derive_address(AddressChain::External, 2).unwrap();
        assert!(matches!(
            prepare_transaction(PrepareTransaction {
                eligible_inputs: vec![
                    SpendableUtxo {
                        txid: "22".repeat(32),
                        vout: 0,
                        value: 30_000,
                        script_pub_key: second_source.script_pub_key.clone(),
                        chain: AddressChain::External,
                        address_index: 2,
                    },
                    SpendableUtxo {
                        txid: "33".repeat(32),
                        vout: 0,
                        value: 30_000,
                        script_pub_key: second_source.script_pub_key,
                        chain: AddressChain::External,
                        address_index: 2,
                    },
                ],
                recipients: vec![Payment::to_address(50_000, &destination)],
                change,
                fee_policy: FeePolicy::Exact(1_000),
                max_inputs: 1,
            }),
            Err(WalletError::CoinSelectionLimitReached)
        ));
    }

    #[test]
    fn rejects_zero_value_and_empty_script_entries() {
        let wallet = reference_wallet();
        let source = wallet.derive_address(AddressChain::External, 0).unwrap();
        let change = wallet.derive_address(AddressChain::Change, 0).unwrap();
        assert!(matches!(
            prepare_transaction(PrepareTransaction {
                eligible_inputs: vec![SpendableUtxo {
                    txid: "11".repeat(32),
                    vout: 0,
                    value: 10_000,
                    script_pub_key: source.script_pub_key,
                    chain: AddressChain::External,
                    address_index: 0,
                }],
                recipients: vec![Payment {
                    value: 0,
                    script_pub_key: vec![],
                }],
                change,
                fee_policy: FeePolicy::Exact(1_000),
                max_inputs: 1,
            }),
            Err(WalletError::InvalidTransactionEntry)
        ));
    }

    #[test]
    fn high_level_flow_uses_only_verified_cache_funds() {
        let wallet = reference_wallet();
        let source = wallet.derive_address(AddressChain::External, 0).unwrap();
        let destination = wallet.derive_address(AddressChain::External, 1).unwrap();
        let change = wallet.derive_address(AddressChain::Change, 0).unwrap();
        let mut cache = BlockchainCache::new(UnftNetwork::Mainnet);
        cache.set_address_derivation(
            source.address.clone(),
            AddressDerivation {
                chain: AddressChain::External,
                index: 0,
            },
        );
        cache.replace_addresses(vec![AddressSnapshot {
            address: source.address,
            used: true,
            utxos: vec![Utxo {
                txid: "77".repeat(32),
                vout: 0,
                value: 100_000,
                script_pub_key: source.script_pub_key,
                status: ConfirmationStatus::Confirmed,
                block_height: Some(100),
                confirmations: 6,
                coinbase: false,
            }],
            transactions: vec![],
        }]);

        let pending = prepare_wallet_payment(
            &wallet,
            &cache,
            PrepareWalletPayment {
                recipients: vec![Payment::to_address(90_000, &destination)],
                change,
                fee_policy: FeePolicy::Exact(1_000),
                minimum_confirmations: 2,
                max_inputs: 10,
            },
        )
        .unwrap();
        assert_eq!(pending.review().input_total, 100_000);
        assert_eq!(pending.review().change, 9_000);

        let review_id = pending.review_id().to_owned();
        let approved = pending.approve(&review_id).unwrap();
        let signed = sign_approved_transaction(&wallet, approved).unwrap();
        assert_eq!(signed.fee, 1_000);
    }
}
