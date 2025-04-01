use bitcoin::Address;
use serde::{Deserialize, Serialize};
use std::io::Error;

#[derive(Debug, Serialize, Deserialize)]
pub struct UtxoStatus {
    pub confirmed: bool,
    pub block_height: u32,
    pub block_hash: String,
    pub block_time: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Utxo {
    pub txid: String,
    pub vout: u32,
    pub status: UtxoStatus,
    pub value: u64,
}

/// Fetches UTXOs for a given address.
pub async fn fetch_utxos_for_address(address: &Address) -> Result<Vec<Utxo>, Error> {
    let url = format!("https://mutinynet.com/api/address/{}/utxo", address);
    let response = reqwest::get(&url)
        .await
        .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    let utxos: Vec<Utxo> = response
        .json()
        .await
        .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;
    Ok(utxos)
}

// Broadcasts a raw transaction hex to the Mutinynet API and returns the transaction ID on success.
pub async fn broadcast_trx(trx_raw_hex: &str) -> Result<String, Error> {
    let client = reqwest::Client::new();
    let response = client
        .post("https://mutinynet.com/api/tx")
        .body(trx_raw_hex.to_string())  // Convert &str to String
        .send()
        .await
        .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;

    if response.status().is_success() {
        let txid = response
            .text()
            .await
            .map_err(|e| Error::new(std::io::ErrorKind::Other, e.to_string()))?;
        Ok(txid)
    } else {
        let status = response.status();
        let error_message = response.text().await.unwrap_or_default();
        Err(Error::new(
            std::io::ErrorKind::Other,
            format!("Broadcast failed with status {}: {}", status, error_message),
        ))
    }
}