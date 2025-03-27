use bitcoin::{opcodes, Address, Amount, KnownHrp, Network, OutPoint, ScriptBuf, Sequence, TapNodeHash, TapSighashType, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey};
use bitcoin::blockdata;
use bitcoin::key::{Parity, TapTweak, Keypair};
use bitcoin::address::{NetworkUnchecked, NetworkChecked};
use bitcoin::sighash::SighashCache;
use std::str::FromStr;
use bitcoin::secp256k1::{Secp256k1, SecretKey, Message};
use hex;
use bitcoin::script::PushBytesBuf;
use serde::Deserialize;
use serde_json::json;
use std::fs::File;
use std::io::Write;
use rand::Rng;
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootError, TaprootMerkleBranch};
use bitcoin::EcdsaSighashType;
use bitcoin::absolute::{LockTime,Time};

use crate::config_taproot_htlc::{ConfigTaprootHTLC,ConfigTaprootHTLCBuilder};
use std::io::Error;

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

