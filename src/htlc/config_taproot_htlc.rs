use bitcoin::{opcodes, Address, Amount, KnownHrp, Network, OutPoint, ScriptBuf, Sequence, TapNodeHash, TapSighashType, Transaction, TxIn, TxOut, Txid, Witness, XOnlyPublicKey};
use bitcoin::blockdata;
use bitcoin::key::{Keypair, Parity, TapTweak, TweakedPublicKey};
use bitcoin::address::{NetworkUnchecked, NetworkChecked};
use bitcoin::sighash::SighashCache;
use std::str::FromStr;
use bitcoin::secp256k1::{Secp256k1, SecretKey, Message};
use hex;
use bitcoin::script::PushBytesBuf;
use serde::Deserialize;
use serde_json::json;
use std::fs::File;
use std::io::{Error, Write};
use rand::Rng;
use bitcoin::taproot::{ControlBlock, LeafVersion, TapLeafHash, TaprootError, TaprootMerkleBranch};
use bitcoin::EcdsaSighashType;
use bitcoin::absolute::{LockTime,Time};



// Final configuration struct with non-optional fields
#[derive(Debug)]
pub struct ConfigTaprootHTLC {
    pub address: Address,
    pub root_config: MerkelRoot,
    pub redeem_config: RedeemConfigHTLC,
    pub refund_config: RefundConfigHTLC,
}

// Merkel root configuration
#[derive(Debug)]
pub struct MerkelRoot {
    pub merkel_root: TapNodeHash,
    pub parity: Parity,
    pub internal_key: XOnlyPublicKey,
    pub tweaked_public_key: TweakedPublicKey,
}

// Redeem configuration for HTLC
#[derive(Debug)]
pub struct RedeemConfigHTLC {
    pub redeem_leaf: TapNodeHash,
    pub redeem_script: ScriptBuf,
}

// Refund configuration for HTLC
#[derive(Debug)]
pub struct RefundConfigHTLC {
    pub refund_leaf: TapNodeHash,
    pub refund_script: ScriptBuf,
}

// Builder for ConfigTaprootHTLC
pub struct ConfigTaprootHTLCBuilder {
    internal_key: Option<XOnlyPublicKey>,
    redeem_config: Option<RedeemConfigHTLC>,
    refund_config: Option<RefundConfigHTLC>,
    root_config: Option<MerkelRoot>,
    address: Option<Address>,
}

impl ConfigTaprootHTLCBuilder {
    /// Creates a new builder with all fields unset.
    pub fn new() -> Self {
        Self {
            internal_key: None,
            redeem_config: None,
            refund_config: None,
            root_config: None,
            address: None,
        }
    }

    /// Sets a custom internal key (optional).
    pub fn with_internal_key(mut self, internal_key: XOnlyPublicKey) -> Self {
        self.internal_key = Some(internal_key);
        self
    }

    /// Sets the redeem configuration with a secret hash and receiver's public key.
    pub fn with_redeem_config(mut self, secret_hash: &str, receiver_xonly_pubkey: &XOnlyPublicKey) -> Self {
        let redeem_config = RedeemConfigHTLC::set_redeem_script(secret_hash, receiver_xonly_pubkey);
        self.redeem_config = Some(redeem_config);
        self
    }

    /// Sets the refund configuration with a lock time and sender's public key.
    pub fn with_refund_config(mut self, lock_time: i64, sender_xonly_pubkey: &XOnlyPublicKey) -> Self {
        let refund_config = RefundConfigHTLC::set_refund_script(lock_time, sender_xonly_pubkey);
        self.refund_config = Some(refund_config);
        self
    }

    /// Sets the Merkel root, requiring redeem and refund configs to be set.
    pub fn with_merkel_root(mut self) -> Result<Self, Error> {
        if self.redeem_config.is_none() || self.refund_config.is_none() {
            return Err(Error::new(std::io::ErrorKind::InvalidInput, "redeem and refund config must be set"));
        }
        let internal_key = self.internal_key.unwrap_or_else(|| {
            XOnlyPublicKey::from_str("0000000000000000000000000000000000000000000000000000000000000001")
                .expect("Invalid NUMS point")
        });
        let redeem_leaf = self.redeem_config.as_ref().unwrap().redeem_leaf;
        let refund_leaf = self.refund_config.as_ref().unwrap().refund_leaf;
        let merkel_root = TapNodeHash::from_node_hashes(redeem_leaf, refund_leaf);
        let secp = Secp256k1::new();
        let (tweaked_public_key, parity) = internal_key.tap_tweak(&secp, Some(merkel_root));
        let root_config = MerkelRoot {
            merkel_root,
            parity,
            internal_key,
            tweaked_public_key,
        };
        self.root_config = Some(root_config);
        Ok(self)
    }

    /// Sets the Taproot address, requiring the Merkel root to be set.
    pub fn with_address(mut self, hrp: KnownHrp) -> Self {
        if self.root_config.is_none() {
            panic!("root_config must be set before setting address");
        }
        let address = Address::p2tr_tweaked(self.root_config.as_ref().unwrap().tweaked_public_key, hrp);
        self.address = Some(address);
        self
    }

    /// Builds the final ConfigTaprootHTLC, ensuring all fields are set.
    pub fn build(self) -> Result<ConfigTaprootHTLC, Error> {
        Ok(ConfigTaprootHTLC {
            address: self.address.ok_or(Error::new(std::io::ErrorKind::InvalidInput, "address must be set"))?,
            root_config: self.root_config.ok_or(Error::new(std::io::ErrorKind::InvalidInput, "root_config must be set"))?,
            redeem_config: self.redeem_config.ok_or(Error::new(std::io::ErrorKind::InvalidInput, "redeem_config must be set"))?,
            refund_config: self.refund_config.ok_or(Error::new(std::io::ErrorKind::InvalidInput, "refund_config must be set"))?,
        })
    }
}

impl RedeemConfigHTLC {
    fn set_redeem_script(secret_hash: &str, receiver_xonly_pubkey: &XOnlyPublicKey) -> Self {
        let redeem_script_builder = ScriptBuf::builder()
            .push_opcode(opcodes::all::OP_SHA256)
            .push_slice(PushBytesBuf::try_from(hex::decode(secret_hash).expect("Invalid secret hash hex")).unwrap())
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_x_only_key(receiver_xonly_pubkey)
            .push_opcode(opcodes::all::OP_CHECKSIG);
        let redeem_script = redeem_script_builder.into_script();
        let leaf_version = LeafVersion::TapScript;
        let redeem_leaf = TapNodeHash::from_script(&redeem_script, leaf_version);
        Self { redeem_leaf, redeem_script }
    }
}

impl RefundConfigHTLC {
    fn set_refund_script(lock_time: i64, sender_xonly_pubkey: &XOnlyPublicKey) -> Self {
        let refund_script_builder = ScriptBuf::builder()
            .push_int(lock_time)
            .push_opcode(opcodes::all::OP_CSV)
            .push_opcode(opcodes::all::OP_DROP)
            .push_x_only_key(sender_xonly_pubkey)
            .push_opcode(opcodes::all::OP_CHECKSIG);
        let refund_script = refund_script_builder.into_script();
        let leaf_version = LeafVersion::TapScript;
        let refund_leaf = TapNodeHash::from_script(&refund_script, leaf_version);
        Self { refund_leaf, refund_script }
    }
}