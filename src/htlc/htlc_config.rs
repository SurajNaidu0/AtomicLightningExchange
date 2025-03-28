use bitcoin::{Address, KnownHrp, XOnlyPublicKey};
use std::io::Error;
use std::str::FromStr;

// Assuming ConfigTaprootHTLC and ConfigTaprootHTLCBuilder are defined elsewhere
use super::config_taproot_htlc::{ConfigTaprootHTLC,ConfigTaprootHTLCBuilder};

/// Creates a Taproot HTLC configuration.
///
/// # Arguments
/// - `secret_hash`: Hex-encoded hash of the secret for the redeem path.
/// - `sender_pubkey`: Sender's X-only public key (hex-encoded).
/// - `receiver_pubkey`: Receiver's X-only public key (hex-encoded).
/// - `lock_time`: Lock time in seconds for the refund path.
/// - `network`: The Bitcoin network (e.g., Testnet, Mutinynet).
/// - `internal_key`: Optional internal key for Taproot.
///
/// # Returns
/// - `Result<ConfigTaprootHTLC, Error>`: The HTLC configuration or an error.
pub fn create_taproot_htlc(
    secret_hash: &str,
    sender_pubkey: &str,
    receiver_pubkey: &str,
    lock_time: u32,
    network: KnownHrp,
    internal_key: Option<XOnlyPublicKey>,
) -> Result<ConfigTaprootHTLC, Error> {
    let sender_xonly = XOnlyPublicKey::from_str(sender_pubkey)
        .map_err(|_| Error::new(std::io::ErrorKind::InvalidInput, "Invalid sender pubkey"))?;
    let receiver_xonly = XOnlyPublicKey::from_str(receiver_pubkey)
        .map_err(|_| Error::new(std::io::ErrorKind::InvalidInput, "Invalid receiver pubkey"))?;

    let mut builder = ConfigTaprootHTLCBuilder::new()
        .with_redeem_config(secret_hash, &receiver_xonly)
        .with_refund_config(lock_time as i64, &sender_xonly);

    if let Some(key) = internal_key {
        builder = builder.with_internal_key(key);
    }

    builder
        .with_merkel_root()?
        .with_address(network)
        .build()
}