use bitcoin::{
    Address, Amount, Transaction, Txid, TapLeafHash, TapSighashType, Witness,
    taproot::{ControlBlock, LeafVersion, TaprootMerkleBranch},OutPoint,TxIn,TxOut
};
use std::io::Error;
use hex;
use super::config_taproot_htlc::ConfigTaprootHTLC;
use super::tx_utils::{build_transaction, build_input, build_output, compute_taproot_sighash, sign_schnorr, derive_keypair, DEFAULT_FEE};
use super::utils::{fetch_utxos_for_address, Utxo};
use super::htlc_config::create_taproot_htlc;

/// Redeems a Taproot HTLC output using the preimage.
///
/// # Arguments
/// - `htlc_config`: HTLC configuration.
/// - `preimage`: Hex-encoded preimage matching the secret hash.
/// - `receiver_private_key`: Receiver's private key (hex-encoded).
/// - `prev_txid`: Previous transaction ID.
/// - `amount`: Amount in the HTLC output.
/// - `transfer_to_address`: Destination address for funds.
/// - `vout`: Output index of the previous transaction.
///
/// # Returns
/// - `Result<Transaction, Error>`: Signed transaction or an error.
pub fn redeem_taproot_htlc(
    htlc_config: ConfigTaprootHTLC,
    preimage: &str,
    receiver_private_key: &str,
    prev_txid: Txid,
    amount: Amount,
    transfer_to_address: &Address,
    vout: u32,
) -> Result<Transaction, Error> {
    let secp = bitcoin::secp256k1::Secp256k1::new();

    // Compute Merkle branch for redeem path
    let merkle_branch = compute_merkle_branch(&htlc_config, "redeem")?;
    let control_block = create_control_block(&htlc_config, merkle_branch)?;

    // Derive keypair
    let keypair = derive_keypair(receiver_private_key)?;

    // Build transaction
    let input = build_input(OutPoint::new(prev_txid, vout), None);
    let output = build_output(amount - DEFAULT_FEE, transfer_to_address);
    let mut tx = build_transaction(vec![input], vec![output]);

    // Compute sighash
    let prevouts = [TxOut {
        value: amount,
        script_pubkey: htlc_config.address.script_pubkey(),
    }];
    let leaf_hash = TapLeafHash::from_script(&htlc_config.redeem_config.redeem_script, LeafVersion::TapScript);
    let message = compute_taproot_sighash(&tx, 0, &prevouts, leaf_hash, TapSighashType::Default).unwrap();

    // Sign
    let signature = sign_schnorr(&secp, &message, &keypair);

    let preimage_hex = hex::decode(preimage).unwrap();
    // Construct witness
    let mut witness = Witness::new();
    witness.push(signature.as_ref());    
    witness.push(preimage_hex);  
    witness.push(htlc_config.redeem_config.redeem_script.to_bytes());   
    witness.push(&control_block.serialize());     

    // Assign witness
    tx.input[0].witness = witness;

    Ok(tx)
}

/// Refunds a Taproot HTLC output after the timelock expires.
///
/// # Arguments
/// - `htlc_config`: HTLC configuration.
/// - `sender_private_key`: Sender's private key (hex-encoded).
/// - `prev_txid`: Previous transaction ID.
/// - `refund_amount`: Amount to refund.
/// - `refund_to_address`: Destination address for refunded funds.
/// - `vout`: Output index of the previous transaction.
/// - `block_num_lock`: Block height for the timelock.
///
/// # Returns
/// - `Option<Transaction>`: Signed transaction or None if signing fails.
pub fn refund_taproot_htlc(
    htlc_config: ConfigTaprootHTLC,
    sender_private_key: &str,
    prev_txid: Txid,
    refund_amount: Amount,
    refund_to_address: &Address,
    vout: u32,
    block_num_lock: u32,
) -> Result<Transaction, Error> {
    let secp = bitcoin::secp256k1::Secp256k1::new();

    // Compute Merkle branch for refund path
    let merkle_branch = compute_merkle_branch(&htlc_config, "refund")?;
    let control_block = create_control_block(&htlc_config, merkle_branch)?;

    // Derive keypair
    let keypair = derive_keypair(sender_private_key)?;

    // Build transaction
    let input = build_input(OutPoint::new(prev_txid, vout), Some(block_num_lock));
    let output = build_output(refund_amount - DEFAULT_FEE, refund_to_address);
    let mut tx = build_transaction(vec![input], vec![output]);

    // Compute sighash
    let prevouts = [TxOut {
        value: refund_amount,
        script_pubkey: htlc_config.address.script_pubkey(),
    }];
    let leaf_hash = TapLeafHash::from_script(&htlc_config.refund_config.refund_script, LeafVersion::TapScript);
    let msg = compute_taproot_sighash(&tx, 0, &prevouts, leaf_hash, TapSighashType::Default).unwrap();

    // Sign
    let signature = sign_schnorr(&secp, &msg, &keypair);

    // Construct witness
    // Construct witness for refund path
    let mut witness = Witness::new();
    witness.push(signature.as_ref());             // Schnorr signature
    witness.push(htlc_config.refund_config.refund_script.as_bytes());  // Refund script
    witness.push(&control_block.serialize());     // Control block

    // Assign witness
    tx.input[0].witness = witness;

    Ok(tx)
}

/// Checks for a redeemable UTXO for the HTLC.
///
/// # Arguments
/// - `amount`: Expected amount in satoshis.
/// - `secret_hash`: Secret hash for the HTLC.
/// - `sender_pubkey`: Sender's public key.
/// - `receiver_pubkey`: Receiver's public key.
/// - `lock_time`: Lock time in seconds.
/// - `network`: Bitcoin network.
/// - `internal_key`: Optional internal key.
///
/// # Returns
/// - `Result<(ConfigTaprootHTLC, String, u64, u32), Error>`: HTLC config, txid, block time, and vout.
pub async fn check_redeem_taproot_htlc(
    amount: u64,
    secret_hash: &str,
    sender_pubkey: &str,
    receiver_pubkey: &str,
    lock_time: u32,
    network: bitcoin::KnownHrp,
    internal_key: Option<bitcoin::XOnlyPublicKey>,
) -> Result<(ConfigTaprootHTLC, String, u64, u32), Error> {
    let config = create_taproot_htlc(
        secret_hash,
        sender_pubkey,
        receiver_pubkey,
        lock_time,
        network,
        internal_key,
    )?;

    let utxos = fetch_utxos_for_address(&config.address).await?;
    if utxos.is_empty() {
        return Err(Error::new(std::io::ErrorKind::NotFound, "No UTXOs found for the address"));
    }

    let redeemable_utxo = utxos
        .into_iter()
        .find(|utxo| utxo.value == amount && utxo.status.confirmed)
        .ok_or_else(|| Error::new(std::io::ErrorKind::NotFound, "No confirmed UTXO with specified amount"))?;

    Ok((
        config,
        redeemable_utxo.txid,
        redeemable_utxo.status.block_time,
        redeemable_utxo.vout,
    ))
}

// Helper functions
fn compute_merkle_branch(htlc_config: &ConfigTaprootHTLC, path: &str) -> Result<TaprootMerkleBranch, Error> {
    let hash_hex = match path {
        "redeem" => htlc_config.refund_config.refund_leaf.to_string(),
        "refund" => htlc_config.redeem_config.redeem_leaf.to_string(),
        _ => return Err(Error::new(std::io::ErrorKind::InvalidInput, "Invalid path")),
    };
    let hash_bytes: [u8; 32] = hex::decode(hash_hex)
        .map_err(|_| Error::new(std::io::ErrorKind::InvalidInput, "Invalid hex string"))?
        .try_into()
        .map_err(|_| Error::new(std::io::ErrorKind::InvalidInput, "Hex string must be 32 bytes"))?;
    TaprootMerkleBranch::decode(&hash_bytes)
        .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))
}

fn create_control_block(
    htlc_config: &ConfigTaprootHTLC,
    merkle_branch: TaprootMerkleBranch,
) -> Result<ControlBlock, Error> {
    Ok(ControlBlock {
        leaf_version: LeafVersion::TapScript,
        output_key_parity: htlc_config.root_config.parity,
        internal_key: htlc_config.root_config.internal_key,
        merkle_branch,
    })
}

fn build_redeem_witness(
    signature: Vec<u8>,
    preimage: &str,
    redeem_script: &bitcoin::ScriptBuf,
    control_block: &ControlBlock,
) -> Result<Witness, Error> {
    let preimage_bytes = hex::decode(preimage)
        .map_err(|_| Error::new(std::io::ErrorKind::InvalidInput, "Invalid preimage hex"))?;
    let mut witness = Witness::new();
    witness.push(signature);
    witness.push(preimage_bytes);
    witness.push(redeem_script.to_bytes());
    witness.push(control_block.serialize());
    Ok(witness)
}

fn build_refund_witness(
    signature: Vec<u8>,
    refund_script: &bitcoin::ScriptBuf,
    control_block: &ControlBlock,
) -> Result<Witness, Error> {
    let mut witness = Witness::new();
    witness.push(signature);
    witness.push(refund_script.to_bytes());
    witness.push(control_block.serialize());
    Ok(witness)
}