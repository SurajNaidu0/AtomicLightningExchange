use ldk_node::bitcoin::secp256k1::PublicKey;
use lightning::ln::types::ChannelId;
use ldk_node::lightning::offers::offer::Offer;
use std::ops::{Div, Sub};

#[derive(Debug, Clone, Copy, PartialEq, PartialOrd)]
pub struct Bitcoin {
    pub sats: u64, // Stored in Satoshis for precision
}

impl Bitcoin {
    const SATS_IN_BTC: u64 = 100_000_000;

    pub fn from_sats(sats: u64) -> Self {
        Self { sats }
    }

    pub fn from_btc(btc: f64) -> Self {
        let sats = (btc * Self::SATS_IN_BTC as f64).round() as u64;
        Self::from_sats(sats)
    }

    pub fn to_btc(self) -> f64 {
        self.sats as f64 / Self::SATS_IN_BTC as f64
    }
}

impl Sub for Bitcoin {
    type Output = Bitcoin;

    fn sub(self, other: Bitcoin) -> Bitcoin {
        Bitcoin::from_sats(self.sats.saturating_sub(other.sats))
    }
}

impl std::fmt::Display for Bitcoin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let btc_value = self.to_btc();

        // Format the value to 8 decimal places with spaces
        let formatted_btc = format!("{:.8}", btc_value);
        let with_spaces = formatted_btc
            .chars()
            .enumerate()
            .map(|(i, c)| if i == 4 || i == 7 { format!(" {}", c) } else { c.to_string() })
            .collect::<String>();

        write!(f, "{}btc", with_spaces)
    }
}

