use bitcoin::{opcodes, Address, Amount, KnownHrp, Network, OutPoint, ScriptBuf, Sequence, TapNodeHash, TapSighashType, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey};
use bitcoin::blockdata;
use bitcoin::key::{Parity, TapTweak, Keypair};
use bitcoin::address::{NetworkUnchecked, NetworkChecked};
use bitcoin::sighash::SighashCache;
use std::str::FromStr;
use bitcoin::secp256k1::{Secp256k1, SecretKey, Message};
use hex;
use bitcoin::script::PushBytesBuf;
use serde_json::json;
use std::fs::File;
use std::io::Write;
use rand::Rng;
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootError, TaprootMerkleBranch};
use bitcoin::EcdsaSighashType;
use bitcoin::absolute::{LockTime,Time};
use ldk_node::lightning_invoice::Bolt11Invoice;
use serde::{Deserialize, Serialize};
use serde_json;
use reqwest;

use crate::config_taproot_htlc::{ConfigTaprootHTLC,ConfigTaprootHTLCBuilder};
use std::io::Error;

const BLOCK_TIME_SECONDS:u32 = 60;

#[derive(Debug, Serialize, Deserialize)]
struct UtxoStatus {
    confirmed: bool,
    block_height: u32,
    block_hash: String,
    block_time: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct Utxo {
    txid: String,
    vout: u32,
    status: UtxoStatus,
    value: u64,
}

#[derive(Debug)]
pub struct AddressUtxos {
    pub utxos: Vec<Utxo>,
}

impl AddressUtxos {
    pub async fn fetch(address: &Address) -> Result<Self, Box<dyn std::error::Error>> {
        let url = format!("https://mutinynet.com/api/address/{}/utxo", address);
        
        let response = reqwest::get(&url).await?;
        let utxos: Vec<Utxo> = response.json().await?;
        
        Ok(AddressUtxos { utxos })
    }
}

async fn fetch_utxos() -> Result<Vec<Utxo>, Box<dyn std::error::Error>> {
    let url = "https://mutinynet.com/api/address/tb1pu8ysre22dcl6qy5m5w7mjwutw73w4u24slcdh4myq06uhr6q29dqwc3ckt/utxo";
    
    // Make HTTP GET request
    let response = reqwest::get(url).await?;
    let utxos: Vec<Utxo> = response.json().await?;
    
    Ok(utxos)
}

pub fn create_taproot_htlc(
    secret_hash: &str,
    sender_pubkey: &str,
    receiver_pubkey: &str,
    lock_time: u32,
    network: KnownHrp,
    internal_key: Option<XOnlyPublicKey>,
) -> Result<Address, Error> {
    // Parse sender and receiver public keys
    let sender_xonly = XOnlyPublicKey::from_str(sender_pubkey)
        .map_err(|_| Error::new(std::io::ErrorKind::InvalidInput, "Invalid sender pubkey"))?;
    let receiver_xonly = XOnlyPublicKey::from_str(receiver_pubkey)
        .map_err(|_| Error::new(std::io::ErrorKind::InvalidInput, "Invalid receiver pubkey"))?;

    // Configure HTLC using builder pattern
    let mut builder = ConfigTaprootHTLCBuilder::new()
        .with_redeem_config(secret_hash, &receiver_xonly)
        .with_refund_config(lock_time as i64, &sender_xonly); // Cast u32 to i64 for compatibility

    // Set optional internal key
    // if let Some(key) = internal_key {
    //     builder = builder.with_internal_key(key);
    // }

    // Build the configuration and generate the address
    let config = builder
        .with_merkel_root()?
        .with_address(network)
        .build()?;

    Ok(config.address)
}

/// Redeems a Taproot HTLC output by constructing and signing a transaction using the preimage.
///
/// This function spends the HTLC via the redeem path, requiring the preimage that matches
/// the secret hash in the redeem script.
///
/// # Arguments
/// - `htlc_config`: The HTLC configuration containing address, scripts, and root details.
/// - `preimage`: Hex-encoded preimage matching the secret hash in the redeem script.
/// - `receiver_private_key`: Hex-encoded private key of the receiver for signing.
/// - `prev_txid`: Transaction ID of the HTLC funding output.
/// - `amount`: Amount in the HTLC output (in satoshis).
/// - `transfer_to_address`: Destination address for the redeemed funds.
/// - `fee`: Transaction fee to deduct (in satoshis).
///
/// # Returns
/// - `Ok(Transaction)`: The signed transaction ready to broadcast.
/// - `Err(Error)`: If key parsing, preimage decoding, or signing fails.
///
/// # Errors
/// Returns an `io::Error` if:
/// - The receiver private key is invalid.
/// - The preimage hex string is invalid.
/// - The amount is insufficient to cover the fee.
/// - Sighash computation fails.
pub fn redeem_taproot_htlc(htlc_config:ConfigTaprootHTLC,preimage: &str, receiver_private_key: &str,prev_txid:Txid, amount:Amount, transfer_to_address:&Address,vout:u32) -> Result<Transaction, Error> {
    let secp = Secp256k1::new();

    // Compute Merkle branch for redeem path (using refund leaf as sibling)
    let hash_hex = htlc_config.refund_config.refund_leaf.to_string();
    let hash_bytes: [u8; 32] = hex::decode(hash_hex)
        .expect("Invalid hex string")
        .try_into()
        .expect("Hex string must be 32 bytes");
    let merkle_branch = TaprootMerkleBranch::decode(&hash_bytes)
        .map_err(|e: TaprootError| format!("Failed to decode Merkle branch: {}", e))
        .unwrap();

    // Create control block for Taproot script spend
    let control_block = ControlBlock {
        leaf_version: LeafVersion::TapScript,
        output_key_parity: htlc_config.root_config.parity,
        internal_key: htlc_config.root_config.internal_key,
        merkle_branch,
    };

    // Derive receiver's keypair for signing
    let receiver_secret_key = SecretKey::from_str(receiver_private_key).expect("Invalid private key");
    let key_pair = Keypair::from_secret_key(&secp, &receiver_secret_key);

    // Construct a basic transaction
    let prevout_txid = prev_txid;
    let prevout = OutPoint::new(prevout_txid, vout);
    let input = TxIn {
        previous_output: prevout,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::default(),
    };


    let output = TxOut {
        value: amount - Amount::from_sat(200), // 0.001 BTC
        script_pubkey: transfer_to_address.script_pubkey(),
    };

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    };

    // Compute Taproot sighash for script spend
    let mut sighash_cache = SighashCache::new(&tx);
    let sighash = sighash_cache.taproot_script_spend_signature_hash(
        0,
        &bitcoin::sighash::Prevouts::All(&[TxOut {
            value: amount, // Previous output amount
            script_pubkey: htlc_config.address.script_pubkey(),
        }]),
        TapLeafHash::from_script(&htlc_config.redeem_config.redeem_script, LeafVersion::TapScript),
        TapSighashType::Default,
    ).expect("Failed to compute sighash");

    // Sign the transaction with Schnorr
    let msg = Message::from_digest_slice(&sighash[..]).unwrap();
    let signature = secp.sign_schnorr_no_aux_rand(&msg, &key_pair);

    let preimage_hex = hex::decode(preimage).unwrap();
    println!("preimage hex {:?}",preimage_hex);
    // Construct witness for redeem path
    let mut witness = Witness::new();
    witness.push(signature.as_ref());    
    witness.push(preimage_hex);  
    witness.push(htlc_config.redeem_config.redeem_script.to_bytes());   
    witness.push(&control_block.serialize());     

    println!("redeem_taproot_witness {:?}",witness);

    tx.input[0].witness = witness;
    // let tx_hex = bitcoin::consensus::encode::serialize_hex(&tx);
    // println!("redeem hex : {}",tx_hex);
    
    return Ok(tx); // Placeholder return (could return the output address if needed)
}

pub async fn check_redeem_taproot_htlc( 
    amount: u64,
    secret_hash: &str,
    sender_pubkey: &str,
    receiver_pubkey: &str,
    lock_time: u32,
    network: KnownHrp,
    internal_key: Option<XOnlyPublicKey>,) -> Result<(ConfigTaprootHTLC,String,String,u32),Error> {
        // Parse sender and receiver public keys
        let sender_xonly = XOnlyPublicKey::from_str(sender_pubkey)
        .map_err(|_| Error::new(std::io::ErrorKind::InvalidInput, "Invalid sender pubkey"))?;
        let receiver_xonly = XOnlyPublicKey::from_str(receiver_pubkey)
        .map_err(|_| Error::new(std::io::ErrorKind::InvalidInput, "Invalid receiver pubkey"))?;

        // Configure HTLC using builder pattern
        let mut builder = ConfigTaprootHTLCBuilder::new()
        .with_redeem_config(secret_hash, &receiver_xonly)
        .with_refund_config(lock_time as i64, &sender_xonly); // Cast u32 to i64 for compatibility

        // Set optional internal key
        // if let Some(key) = internal_key {
        //     builder = builder.with_internal_key(key);
        // }

        // Build the configuration and generate the address
        let config = builder
            .with_merkel_root()?
            .with_address(network)
            .build()?;

        let address_utxo = AddressUtxos::fetch(&config.address).await.unwrap();
        let utxos = address_utxo.utxos;

        //Searching for mainnet trx
        if utxos.len() == 0 {
            return Err(Error::new(std::io::ErrorKind::InvalidData, "Transction not found in mainnet"))
        }

        //checking amount 
        let mut option_redeem_able_utxo:Option<Utxo>;
        option_redeem_able_utxo = None;

        for utxo in utxos{
            if utxo.value == amount && utxo.status.confirmed == true {
                option_redeem_able_utxo = Some(utxo);
                break;
            }
        }

        let redeem_able_utxo = option_redeem_able_utxo.expect("No Confirmed trx found with same amout");

        let block_timestamp = redeem_able_utxo.status.block_hash;

        
        Ok((config,redeem_able_utxo.txid,block_timestamp,redeem_able_utxo.vout))
    }

fn refund_taproot_htlc(htlc_config:ConfigTaprootHTLC,sender_private_key: &str,prev_txid:Txid, refund_amount: Amount,refund_to_address:&Address,vout:u32) -> Option<Transaction> {
    let secp = Secp256k1::new();

    // Compute Merkle branch for refund path (using redeem leaf as sibling)
    let hash_hex = htlc_config.redeem_config.redeem_leaf.to_string();
    let hash_bytes: [u8; 32] = hex::decode(hash_hex)
        .expect("Invalid hex string")
        .try_into()
        .expect("Hex string must be 32 bytes");
    let merkle_branch = TaprootMerkleBranch::decode(&hash_bytes)
        .map_err(|e: TaprootError| format!("Failed to decode Merkle branch: {}", e))
        .unwrap();
    println!("Merkle Branch: {:?}", merkle_branch);

    // Create control block for Taproot script spend
    let control_block = ControlBlock {
        leaf_version: LeafVersion::TapScript,
        output_key_parity: htlc_config.root_config.parity,
        internal_key: htlc_config.root_config.internal_key,
        merkle_branch,
    };
    // println!("Control Block: {:?}", control_block);

    // Derive sender's keypair for signing
    let sender_secret_key = SecretKey::from_str(sender_private_key).expect("Invalid private key");
    let key_pair = Keypair::from_secret_key(&secp, &sender_secret_key);

    // Construct a basic transaction
    let prevout_txid = prev_txid;
    let prevout = OutPoint::new(prevout_txid, vout);
    let input = TxIn {
        previous_output: prevout,
        script_sig: ScriptBuf::new(),
        sequence: Sequence::from_height(7), // Note: Should reflect timelock in practice
        witness: Witness::default(),
    };

    let output = TxOut {
        value: refund_amount-Amount::from_sat(1000), // 0.001 BTC
        script_pubkey: refund_to_address.script_pubkey(),
    };

    let mut tx = Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
        input: vec![input],
        output: vec![output],
    };

    // Compute Taproot sighash for script spend
    let mut sighash_cache = SighashCache::new(&tx);
    let sighash = sighash_cache.taproot_script_spend_signature_hash(
        0,
        &bitcoin::sighash::Prevouts::All(&[TxOut {
            value: refund_amount, // Previous output amount
            script_pubkey: htlc_config.address.script_pubkey(),
        }]),
        TapLeafHash::from_script(&htlc_config.refund_config.refund_script, LeafVersion::TapScript),
        TapSighashType::Default,
    ).expect("Failed to compute sighash");

    // Sign the transaction with Schnorr
    let msg = Message::from_digest_slice(&sighash[..]).unwrap();
    let signature = secp.sign_schnorr_no_aux_rand(&msg, &key_pair);

    // Construct witness for refund path
    let mut witness = Witness::new();
    witness.push(signature.as_ref());             // Schnorr signature
    witness.push(htlc_config.refund_config.refund_script.as_bytes());  // Refund script
    witness.push(&control_block.serialize());     // Control block
    // println!("Witness: {:?}", witness);

    tx.input[0].witness = witness;

    return Some(tx);
}