mod types;
mod bitoin_htlc;
mod config_taproot_htlc;



use std::{
    io::{self, Write},
    str::FromStr,
    time::{Duration, Instant},
};

use ldk_node::{
    bitcoin::{secp256k1::PublicKey, Network, address::Address},
    config::ChannelConfig,
    lightning::ln::msgs::SocketAddress,
    lightning_invoice::Bolt11Invoice,
    Builder, Node,
};
use ldk_node::payment::{PaymentStatus, PaymentKind};
use types::Bitcoin;
use ldk_node::bitcoin::opcodes;
use bitcoin::KnownHrp;

fn make_node(seed: [u8; 64], alias: &str, port: u16) -> ldk_node::Node {
    let mut builder = Builder::new();
    builder.set_entropy_seed_bytes(seed.to_vec()).unwrap();
    builder.set_network(Network::Signet);
    builder.set_chain_source_esplora("https://mutinynet.com/api/".to_string(), None);
    builder.set_gossip_source_rgs("https://mutinynet.ltbl.io/snapshot".to_string());
    builder.set_storage_dir_path(("./data/".to_owned() + alias).to_string());
    let _ = builder.set_listening_addresses(vec![format!("127.0.0.1:{}", port).parse().unwrap()]);
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

fn run_node_cli(node: Node, role: &str) {
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
                            println!("{} Invoice: {} //// paymenthash: {}", role, inv, payment_hash)},
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
                                                // Reveal PaymentHash
                                                println!("Payment hash: {}", hash);
            
                                                // Reveal PaymentPreimage if available
                                                if let Some(preimage) = preimage {
                                                    println!("Payment preimage: {}", preimage);
                                                } else {
                                                    println!("No preimage available");
                                                }
            
                                                // Reveal PaymentSecret if available
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
            (Some("atomicswapsend"), [amount_str, recipient_pubkey_str, sender_refund_publickey, timeout_str]) => {

                
                // Parse inputs
                let sats_value: u64 = match amount_str.parse() {
                    Ok(val) => val,
                    Err(_) => {
                        println!("Error: Invalid amount in satoshis");
                        continue;
                    }
                };

                if (sats_value >1000){
                    println!("on testnet only 1000 sats can be sent");
                    continue;
                }
           
                // Generate Lightning invoice (amount in millisatoshis)
                let msats = sats_value * 1000;

                // Instead of storing a reference, we'll store the actual hash value
                let mut payment_hash: Option<ldk_node::bitcoin::hashes::sha256::Hash> = None;

                match node.bolt11_payment().receive(msats, "test invoice", 6000) {
                    Ok(inv) => {
                        let hash = inv.payment_hash(); // Get the hash value
                        payment_hash = Some(*hash);     // Store the value, not a reference
                        println!(
                            "{} Invoice: {} //// paymenthash: {}", 
                            role, 
                            inv, 
                            hash                   // Use the hash directly
                        );
                    }
                    Err(e) => println!("Error creating invoice: {:?}", e),
                }

                if let Some(hash) = payment_hash {
                    let hash_str = hash.to_string();
                    let sender_pubkey = sender_refund_publickey.as_str();
                    let receiver_pubkey = &recipient_pubkey_str.as_str();
                    let lock_time = timeout_str.parse().expect("lock_timr has to be i64");
                    println!("Payment hash: {}", hash_str);
                    let htlc_taproot_address = bitoin_htlc::create_taproot_htlc(hash_str.as_str(), sender_pubkey, receiver_pubkey, lock_time,KnownHrp::Testnets,None).expect("Error while creating a address");

                    println!("Htlc address is {}", htlc_taproot_address);

                    match node.onchain_payment().send_to_address(&htlc_taproot_address, sats_value) {
                        Ok(txid) => println!("On-chain transfer successful. Transaction ID: {}", txid),
                        Err(e) => println!("Error sending on-chain transfer: {:?}", e),
                    }
                } else {
                    println!("No payment hash was created.");
                }
            }
            (Some("atomicswapredeem"), [amount_str, recipient_pubkey_str, sender_refund_publickey, timeout_str]) => {
                
            }
            (Some("exit"), _) => break,
            _ => println!("Unknown command or incorrect arguments: {}", input),
        }
    }

}

fn main() {
    println!("Hello, world!");
    #[cfg(feature = "alice")]
    {
        let seed: [u8; 64] = [255, 232, 2, 49, 170, 219, 110, 2, 166, 115, 242, 99, 7, 199, 80, 230, 23, 7, 167, 123, 130, 68, 101, 17, 37, 141, 176, 251, 173, 101, 120, 131, 168, 106, 244, 208, 119, 178, 74, 203, 192, 61, 244, 217, 182, 197, 137, 14, 8, 101, 228, 194, 242, 61, 208, 169, 33, 202, 132, 24, 84, 112, 234, 135];
        let node = make_node(seed, "Alice", 9000);
        run_node_cli(node, "User");
    }
    #[cfg(feature = "bob")]
    {
        let seed = [189, 147, 230, 36, 129, 64, 32, 57, 86, 203, 182, 103, 156, 178, 15, 136, 24, 238, 99, 52, 146, 59, 24, 223, 55, 50, 181, 192, 127, 222, 181, 103, 197, 195, 5, 147, 4, 4, 112, 197, 170, 68, 29, 66, 42, 250, 122, 25, 202, 227, 136, 55, 86, 249, 160, 146, 128, 140, 170, 97, 250, 170, 247, 5];
        let node = make_node(seed, "Bob", 9001);
        run_node_cli(node, "LSP");
    }
}