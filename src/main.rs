mod types;
mod htlc;
//To-Do
//10% sending lightning to fix 
//fix rpc 
//check sendinding time lock
use std::{
    io::{self, Write},
    str::FromStr,
    time::{Duration, Instant},
};

use ldk_node::{
    bitcoin::{secp256k1::PublicKey, Network, address::Address},
    lightning::ln::msgs::SocketAddress,
    lightning_invoice::{Bolt11Invoice, SignedRawBolt11Invoice},
    Builder, Node,
};
use ldk_node::payment::{PaymentStatus, PaymentKind};
use types::Bitcoin;
use bitcoin::{Amount, KnownHrp};
use bitcoin::address::NetworkUnchecked;





async fn make_node(seed: [u8; 64], alias: &str, port: u16) -> ldk_node::Node {
    let mut builder = Builder::new();
    builder.set_entropy_seed_bytes(seed.to_vec()).unwrap();
    builder.set_network(Network::Signet);
    builder.set_chain_source_esplora("https://mutinynet.com/api/".to_string(), None);
    builder.set_gossip_source_rgs("https://mutinynet.ltbl.io/snapshot".to_string());
    builder.set_storage_dir_path(("./data/".to_owned() + alias).to_string());
     //local_host
    let _ = builder.set_listening_addresses(vec![format!("127.0.0.1:{}", port).parse().unwrap()]);
    //public
    // let _ = builder.set_listening_addresses(vec![format!("0.0.0.0:{}", port).parse().unwrap()]);
    let _ = builder.set_node_alias("some_alias".to_string());

    let node = builder.build().unwrap();
    node.start().unwrap();
    let public_key = node.node_id();
    let listening_addresses = node.listening_addresses().unwrap();
    println!("Listening on: {:?}", listening_addresses);
    if let Some(first_address) = listening_addresses.first() {
        println!("\nActor Role: {}\nPublic Key: {}\nInternet Address: {}\n", alias, public_key, first_address);
    } else {
        println!("No listening addresses found");
    }
    node
}

fn get_user_input(prompt: &str) -> (String, Option<String>, Vec<String>) {
    let mut input = String::new();
    print!("{}", prompt);
    io::stdout().flush().unwrap();
    io::stdin().read_line(&mut input).unwrap();

    let input = input.trim().to_string();
    let mut parts = input.split_whitespace();
    let command = parts.next().map(|s| s.to_string());
    let args: Vec<String> = parts.map(|s| s.to_string()).collect();

    (input, command, args)
}

async fn run_node_cli(node: Node, role: &str) {
    loop {
        let (input, command, args) = get_user_input(&format!("Enter command for {}: ", role));

        match (command.as_deref(), args.as_slice()) {
            (Some("onchaintransfer"), args) => {
                if args.len() != 2 {
                    println!("Error: 'onchaintransfer' requires <destination_address> and <sats>");
                    continue;
                }
                let destination_address = match Address::from_str(&args[0]) {
                    Ok(addr) => addr.require_network(Network::Signet).unwrap(),
                    Err(_) => {
                        println!("Invalid bitcoin address");
                        continue;
                    }
                };
                let sats: u64 = args[1].parse().unwrap();
                match node.onchain_payment().send_to_address(&destination_address, sats) {
                    Ok(txid) => println!("On-chain transfer successful. Transaction ID: {}", txid),
                    Err(e) => println!("Error sending on-chain transfer: {:?}", e),
                }
            }
            (Some("getaddress"), []) => {
                match node.onchain_payment().new_address() {
                    Ok(fund_addr) => println!("{} Funding Address: {}", role, fund_addr),
                    Err(e) => println!("Error getting funding address: {:?}", e),
                }
            }
            (Some("openchannel"), args) => {
                if args.len() != 3 {
                    println!("Error: 'openchannel' requires <node_id>, <listening_address>, and <sats>");
                    continue;
                }
                let node_id: PublicKey = args[0].parse().unwrap();
                let net_address: SocketAddress = args[1].parse().unwrap();
                let sats: u64 = args[2].parse().unwrap();

                match node.open_announced_channel(node_id, net_address, sats, None, None) {
                    Ok(_) => println!("Channel opened to {} with no push amount", args[0]),
                    Err(e) => println!("Failed to open channel: {:?}", e),
                }
            }
            (Some("balance"), []) => {
                let balances = node.list_balances();
                let onchain_balance = Bitcoin::from_sats(balances.total_onchain_balance_sats);
                let lightning_balance = Bitcoin::from_sats(balances.total_lightning_balance_sats);
                println!("{} On-Chain Balance: {}", role, onchain_balance);
                println!("{} Lightning Balance: {}", role, lightning_balance);
            }
            (Some("closeallchannels"), []) => {
                for channel in node.list_channels().iter() {
                    let _ = node.close_channel(&channel.user_channel_id, channel.counterparty_node_id);
                }
                println!("Closing all channels.");
            }
            (Some("channelinfo"), []) => {
                let channels = node.list_channels();
                if channels.is_empty() {
                    println!("No channels found.");
                } else {
                    println!("{} Channels:", role);
                    for channel in channels.iter() {
                        println!("--------------------------------------------");
                        println!("Channel ID: {}", channel.channel_id);
                        println!("Channel Value: {} sats", channel.channel_value_sats);
                        println!("Spendable (Outbound) Balance: {} sats", channel.outbound_capacity_msat / 1000);
                        println!("Receivable (Inbound) Balance: {} sats", channel.inbound_capacity_msat / 1000);
                        println!("Channel Ready?: {}", channel.is_channel_ready);
                        println!("Is Usable?: {}", channel.is_usable);
                        println!("Max Htlc Spendable: {} sats",channel.counterparty_outbound_htlc_maximum_msat.unwrap()/1000);
                        if !channel.is_usable {
                            println!("Channel not usable. Possible reasons:");
                            if !channel.is_channel_ready {
                                println!("- Channel not yet ready (still confirming/pending)");
                            }
                            if channel.outbound_capacity_msat == 0 {
                                println!("- No outbound capacity");
                            }
                        }
                    }
                    println!("--------------------------------------------");
                }
            }
            (Some("getinvoice"), [sats]) => {
                if let Ok(sats_value) = sats.parse::<u64>() {
                    let msats = sats_value * 1000;
                    match node.bolt11_payment().receive(msats, "test invoice", 6000) {
                        Ok(inv) => {
                            let payment_hash = inv.payment_hash();
                            println!("{} Invoice: {} //// paymenthash: {}", role, inv, payment_hash)
                        }
                        Err(e) => println!("Error creating invoice: {:?}", e),
                    }
                } else {
                    println!("Invalid sats value provided");
                }
            }
            (Some("payinvoice"), [invoice_str]) => {
                match invoice_str.parse::<Bolt11Invoice>() {
                    Ok(invoice) => match node.bolt11_payment().send(&invoice, None) {
                        Ok(payment_id) => {
                            println!("Payment sent from {} with payment_id: {}", role, payment_id);
                            println!("Waiting for payment to complete...");
                            let start_time = Instant::now();
                            let timeout = Duration::from_secs(30);

                            loop {
                                if start_time.elapsed() > timeout {
                                    println!("Timeout waiting for payment to complete");
                                    break;
                                }
                                match node.payment(&payment_id) {
                                    Some(payment) => match payment.status {
                                        PaymentStatus::Succeeded => {
                                            println!("Payment succeeded!");
                                            if let PaymentKind::Bolt11 { hash, preimage, secret, .. } = payment.kind {
                                                println!("Payment hash: {}", hash);
                                                if let Some(preimage) = preimage {
                                                    println!("Payment preimage: {}", preimage);
                                                } else {
                                                    println!("No preimage available");
                                                }
                                                if let Some(secret) = secret {
                                                    println!("Payment secret: {}", secret);
                                                } else {
                                                    println!("No payment secret available");
                                                }
                                            }
                                            break;
                                        }
                                        PaymentStatus::Failed => {
                                            println!("Payment failed");
                                            break;
                                        }
                                        PaymentStatus::Pending => {
                                            println!("Payment still pending...");
                                            std::thread::sleep(Duration::from_millis(500));
                                        }
                                    },
                                    None => {
                                        println!("Payment not found");
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) => println!("Error sending payment from {}: {:?}", role, e),
                    },
                    Err(e) => println!("Error parsing invoice: {:?}", e),
                }
            }
            (Some("atomicswapsend"), [amount_str, recipient_pubkey_str, sender_refund_publickey, block_num_lock]) => {
                // Parse inputs
                let sats_value: u64 = match amount_str.parse() {
                    Ok(val) => val,
                    Err(_) => {
                        println!("Error: Invalid amount in satoshis");
                        continue;
                    }
                };
                let block_num_lock: u32 = block_num_lock.parse().expect("lock_time has to be u32");

                if block_num_lock <= 3 {
                    println!("redeemer should at least get 3 more block time before refund can be tried. Try setting block_num_lock above 3");
                    continue;
                }

                // Generate Lightning invoice (amount in millisatoshis)
                let msats = sats_value * 1000;

                let mut payment_hash: Option<ldk_node::bitcoin::hashes::sha256::Hash> = None;

                let expiry_time = block_num_lock * 60 - 3 * 60;
                match node.bolt11_payment().receive(msats, "test invoice", expiry_time) {
                    Ok(inv) => {
                        let hash = inv.payment_hash();
                        payment_hash = Some(*hash);
                        println!(
                            "{} Invoice: {} //// paymenthash: {}",
                            role,
                            inv,
                            hash
                        );
                    }
                    Err(e) => println!("Error creating invoice: {:?}", e),
                }

                if let Some(hash) = payment_hash {
                    let hash_str = hash.to_string();
                    let sender_pubkey = sender_refund_publickey.as_str();
                    let receiver_pubkey = recipient_pubkey_str.as_str();
                    println!("Payment hash: {}", hash_str);
                    // Getting address
                    let htlc_config = htlc::htlc_config::create_taproot_htlc(
                        hash_str.as_str(),
                        sender_pubkey,
                        receiver_pubkey,
                        block_num_lock,
                        KnownHrp::Testnets,
                        None
                    ).expect("Error while creating an address");

                    println!("Htlc address is {}", htlc_config.address);

                    match node.onchain_payment().send_to_address(&htlc_config.address, sats_value) {
                        Ok(txid) => println!("On-chain transfer successful. Transaction ID: {}", txid),
                        Err(e) => println!("Error sending on-chain transfer: {:?}", e),
                    }
                } else {
                    println!("No payment hash was created.");
                }
            }
            (Some("atomicswapredeem"), [invoice, amount_str, recipient_pubkey_str, sender_refund_publickey, block_num_lock]) => {
                let sats_value: u64 = match amount_str.parse() {
                    Ok(val) => val,
                    Err(_) => {
                        println!("Error: Invalid amount in satoshis");
                        continue;
                    }
                };

                let block_num_lock: u32 = block_num_lock.parse().expect("lock_time has to be u32");

                let signed = invoice.parse::<SignedRawBolt11Invoice>().unwrap();
                let invoice = Bolt11Invoice::from_signed(signed).unwrap();

                let secret_hash = invoice.payment_hash().to_string();
                let (htlc_config, txid, block_timestamp, vout) = htlc::htlc_operations::check_redeem_taproot_htlc(
                    sats_value,
                    secret_hash.as_str(),
                    sender_refund_publickey.as_str(),
                    recipient_pubkey_str.as_str(),
                    block_num_lock,
                    KnownHrp::Testnets,
                    None
                ).await.expect("Error in creating config");

                println!("Found the HTLC transaction ID on the chain: {} and verified its legitimacy.", txid);

                // Prompt user to continue with redemption
                let (continue_input, _, _) = get_user_input("Do you want to continue redeeming the HTLC? (yes/no): ");
                if continue_input.trim().to_lowercase() != "yes" {
                    println!("Redemption aborted by user.");
                    continue;
                }

                // Prompt user for private key
                let (private_key_input, _, _) = get_user_input("Enter your private key to redeem the HTLC: ");
                let private_key = private_key_input.trim().to_string();

                // Prompt user for sender address
                let (send_address, _, _) = get_user_input("Enter the redeem address: ");
                let send_address = send_address.trim().to_string();
                let output_address: Address<NetworkUnchecked> = send_address.as_str().parse().unwrap();
                let output_address = match output_address.require_network(Network::Testnet) {
                    Ok(addr) => addr,
                    Err(e) => {
                        println!("Error: Address is not valid for Testnet: {:?}", e);
                        continue;
                    }
                };

                match node.bolt11_payment().send(&invoice, None) {
                    Ok(payment_id) => {
                        println!("Payment sent from {} with payment_id: {}", role, payment_id);
                        println!("Waiting for payment to complete...");
                        let start_time = Instant::now();
                        let timeout = Duration::from_secs(30);

                        loop {
                            if start_time.elapsed() > timeout {
                                println!("Timeout waiting for payment to complete");
                                break;
                            }
                            match node.payment(&payment_id) {
                                Some(payment) => match payment.status {
                                    PaymentStatus::Succeeded => {
                                        println!("Payment succeeded!");
                                        if let PaymentKind::Bolt11 { preimage, .. } = payment.kind {
                                            if let Some(preimage) = preimage {
                                                println!("Payment preimage: {}", preimage);
                                                let preimage_string = preimage.to_string();
                                                let prevout_txid = bitcoin::Txid::from_str(&txid).unwrap();
                                                let raw_tx = htlc::htlc_operations::redeem_taproot_htlc(
                                                    htlc_config,
                                                    preimage_string.as_str(),
                                                    private_key.as_str(),
                                                    prevout_txid,
                                                    Amount::from_sat(sats_value),
                                                    &output_address,
                                                    vout
                                                ).expect("Error while redeeming but funds were sent; use preimage to redeem manually");
                                                let tx_hex = bitcoin::consensus::encode::serialize_hex(&raw_tx);
                                                // println!("redeem hex: {}", tx_hex);
                                                let broadcast_hash = htlc::utils::broadcast_trx(tx_hex.as_str()).await.expect("redeem trx broadcast failed");
                println!("Trx was sucessfully broadcasted : {}",broadcast_hash);
                                                
                                            } else {
                                                println!("No preimage available");
                                            }
                                        }
                                        break;
                                    }
                                    PaymentStatus::Failed => {
                                        println!("Payment failed");
                                        break;
                                    }
                                    PaymentStatus::Pending => {
                                        println!("Payment still pending...");
                                        std::thread::sleep(Duration::from_millis(500));
                                    }
                                },
                                None => {
                                    println!("Payment not found");
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => println!("Error sending payment from {}: {:?}", role, e),
                }
            }
            (Some("atomicswaprefund"), [payment_hash, amount_str, recipient_pubkey_str, sender_refund_publickey, block_num_lock]) => {
                // Parse inputs
                let sats_value: u64 = match amount_str.parse() {
                    Ok(val) => val,
                    Err(_) => {
                        println!("Error: Invalid amount in satoshis");
                        continue;
                    }
                };
                let block_num_lock: u32 = block_num_lock.parse().expect("lock_time has to be u32");

                let htlc_config = htlc::htlc_config::create_taproot_htlc(
                    payment_hash.as_str(),
                    sender_refund_publickey.as_str(),
                    recipient_pubkey_str.as_str(),
                    block_num_lock,
                    KnownHrp::Testnets,
                    None
                ).expect("Error while creating an address");

                let utxos = htlc::utils::fetch_utxos_for_address(&htlc_config.address).await.unwrap();
                if utxos.is_empty() {
                    println!("utxo is empty");
                    continue;
                }

                let refund_able_utxo = utxos
                    .into_iter()
                    .find(|utxo| utxo.value == sats_value && utxo.status.confirmed).unwrap();

                // Prompt user for private key
                let (private_key_input, _, _) = get_user_input("Enter your private key to refund the HTLC: ");
                let private_key = private_key_input.trim().to_string();

                // Prompt user for refund address
                let (send_address, _, _) = get_user_input("Enter the refund address: ");
                let send_address = send_address.trim().to_string();
                let output_address: Address<NetworkUnchecked> = send_address.as_str().parse().unwrap();
                let output_address = match output_address.require_network(Network::Testnet) {
                    Ok(addr) => addr,
                    Err(e) => {
                        println!("Error: Address is not valid for Testnet: {:?}", e);
                        continue;
                    }
                };

                // Convert txid and vout
                let txid = refund_able_utxo.txid;
                let prevout_txid = bitcoin::Txid::from_str(&txid).unwrap();
                let vout = refund_able_utxo.vout;

                let raw_tx = htlc::htlc_operations::refund_taproot_htlc(
                    htlc_config,
                    private_key.as_str(),
                    prevout_txid,
                    Amount::from_sat(sats_value),
                    &output_address,
                    vout,
                    block_num_lock
                ).unwrap();
                let tx_hex = bitcoin::consensus::encode::serialize_hex(&raw_tx);
                // println!("refund hex: {}", tx_hex);
                // Broadcasting the trx
                let broadcast_hash = htlc::utils::broadcast_trx(tx_hex.as_str()).await.expect("redeem trx broadcast failed");
                println!("Trx was sucessfully broadcasted : {}",broadcast_hash);
            }
            (Some("exit"), _) => break,
            _ => println!("Unknown command or incorrect arguments: {}", input),
        }
    }
}

#[tokio::main]
async fn main() {
    println!("Hello, world!");
    #[cfg(feature = "alice")]
    {
        let seed: [u8; 64] = [
            255, 232, 2, 49, 170, 219, 110, 2, 166, 115, 242, 99, 7, 199, 80, 230, 23, 7, 167, 123,
            130, 68, 101, 17, 37, 141, 176, 251, 173, 101, 120, 131, 168, 106, 244, 208, 119, 178,
            74, 203, 192, 61, 244, 217, 182, 197, 137, 14, 8, 101, 228, 194, 242, 61, 208, 169, 33,
            202, 132, 24, 84, 112, 234, 135,
        ];
        let node = make_node(seed, "Alice", 9000).await;
        run_node_cli(node, "Alice").await;
    }
    #[cfg(feature = "bob")]
    {
        let seed = [
            189, 147, 230, 36, 129, 64, 32, 57, 86, 203, 182, 103, 156, 178, 15, 136, 24, 238, 99,
            52, 146, 59, 24, 223, 55, 50, 181, 192, 127, 222, 181, 103, 197, 195, 5, 147, 4, 4,
            112, 197, 170, 68, 29, 66, 42, 250, 122, 25, 202, 227, 136, 55, 86, 249, 160, 146, 128,
            140, 170, 97, 250, 170, 247, 5,
        ];
        let node = make_node(seed, "Bob", 9001).await;
        run_node_cli(node, "Bob").await;
    }
}