# AtomicLightningExchange

**AtomicLightningExchange** enables trustless swaps between Lightning Bitcoin and on-chain Bitcoin using atomic swaps, eliminating the need for a centralized authority. Built with the Lightning Development Kit (LDK), it provides a command-line interface (CLI) to interact with a Lightning Network node. Key features include generating on-chain addresses, sending transactions, managing Lightning channels, and performing atomic swaps.

> [!WARNING]  
> This project is a work in progress and requires rigorous testing before production use.

## Security Concerns

- **Private Key Storage:** Node private key handling needs enhancement; consider using LDK's built-in methods.
- **Timelock Validation:** Before the redeemer sends funds, verify the CSV timelock against the current timestamp to prevent premature refunds.
- **RPC Configuration:** Update RPC endpoints in `utils.rs` and `main.rs` to mainnet Bitcoin for production.

## Instructions

These instructions are for testing purposes only.

### Starting a Lightning Node

Configure the `make_node` and `run_node` functions in `main.rs` to start a Lightning node. Use the following commands with test private keys (never use these in production):

```sh
# Start Alice's Lightning node on localhost:9000
cargo run --features alice

# Start Bob's Lightning node on localhost:9001
cargo run --features bob
```

### Features

- **On-Chain Operations:** Generate addresses (`getaddress`), send transactions (`onchaintransfer`)
- **Channel Management:** Open (`openchannel`) and close (`closeallchannels`) Lightning channels
- **Invoices:** Create (`getinvoice`) and pay (`payinvoice`) Lightning invoices
- **Information:** View channel details (`channelinfo`) and balances (`balance`)
- **Atomic Swaps:** Swap on-chain Bitcoin and Lightning payments via HTLCs (`atomicswapsend`, `atomicswapredeem`, `atomicswaprefund`)

## Atomic Swap Features

Atomic swaps facilitate trustless exchanges between on-chain Bitcoin and Lightning Network payments using Hash-Time-Locked Contracts (HTLCs). HTLCs ensure that either both parties complete the swap or neither does. The process locks Bitcoin in an on-chain HTLC, which the recipient redeems by revealing a preimage (from paying a Lightning invoice) or the sender refunds after a lock time expires.

In an atomic swap using **Pay-to-Taproot (P2TR)**, the Taproot tree has two script leaves:

- **Redeem Leaf**: `OP_SHA256 <secret_hash> OP_EQUALVERIFY <receiver_pubkey> OP_CHECKSIG`  
  Lets the recipient claim funds with a preimage matching the secret hash and their signature.

- **Refund Leaf**: `<lock_time> OP_CSV OP_DROP <sender_pubkey> OP_CHECKSIG`  
  Lets the sender reclaim funds after a timeout (in blocks) with their signature.

These leaves form a **Merkle root**, tweaking an internal public key to create the P2TR address, ensuring the swap is atomic.

### Commands

#### `atomicswapsend <amount> <recipient_pubkey> <sender_refund_pubkey> <block_num_lock>`

- **Description:** Starts an atomic swap by generating a Lightning invoice and locking `<amount>` satoshis in an on-chain HTLC.
- **Parameters:**
  - `<amount>`: Satoshis to lock (e.g., `80000`)
  - `<recipient_pubkey>`: Recipient's public key
  - `<sender_refund_pubkey>`: Sender's refund public key
  - `<block_num_lock>`: Blocks until refund is possible (e.g., `100`)
- **Example:**
  ```sh
  atomicswapsend 80000 456db773aa5c4cc6ed3a4780243d16bd58220be318702603b219fe79eceb848f fdfbf55076737c3b8e150ab1fcf138caa7a8671d2185695944c2581ef11aa866 100
  ```

#### `atomicswapredeem <invoice> <amount> <recipient_pubkey> <sender_refund_pubkey> <block_num_lock>`

- **Description:** Redeems the on-chain HTLC by paying the `<invoice>` and using the preimage to claim funds.
- **Parameters:**
  - `<invoice>`: Lightning invoice to pay
  - `<amount>`: Locked satoshis
  - `<recipient_pubkey>`: Recipient's public key
  - `<sender_refund_pubkey>`: Sender's refund public key
  - `<block_num_lock>`: Lock time in blocks
- **Example:**
  ```sh
  atomicswapredeem lntbs800u1pn742prdq5w3jhxapqd9h8vmmfvdjsnp4q0svv2k4d2ca24r4rprcgpma7mk3t6cltwduvxj8lannxqng2en7spp5rvnvxztdf23nw3cva4c9ztp3kpcq9t3cs8jg969238we290n9u7qsp5epugyv8yyhtzfjzg69kz0vsmzd44ztd5t83jrzwg7mr97rtpyhhq9qyysgqcqpcxqr94uy9s8xaa5rlw3an2h73c32wx4tryhdtud3cyyh9a2tqcxqhztz038p28ry3h0njt4axdajyp90deqsu6tgrns2pkqspy0t3gl78fp08spy37pc8 80000 456db773aa5c4cc6ed3a4780243d16bd58220be318702603b219fe79eceb848f fdfbf55076737c3b8e150ab1fcf138caa7a8671d2185695944c2581ef11aa866 100
  ```

#### `atomicswaprefund <payment_hash> <amount> <recipient_pubkey> <sender_refund_pubkey> <block_num_lock>`

- **Description:** Refunds the on-chain HTLC after `<block_num_lock>` expires if unredeemed.
- **Parameters:**
  - `<payment_hash>`: Invoice payment hash
  - `<amount>`: Locked satoshis
  - `<recipient_pubkey>`: Recipient's public key
  - `<sender_refund_pubkey>`: Sender's refund public key
  - `<block_num_lock>`: Lock time in blocks

### Testing Private Keys

- **Recipient Private Key:** `c929c768be0902d5bb7ae6e38bdc6b3b24cefbe93650da91975756a09e408460`
- **Sender Private Key:** `8957096d6d79f8ba171bcce36eb0e6e6a6c02f17546180d849745988b2f5b0ee`

## Using Other Lightning Node Features

The CLI offers commands to manage your Lightning node beyond atomic swaps:

- **`getaddress`**: Get a new on-chain Bitcoin address.  
  _Example:_ `getaddress`

- **`onchaintransfer <address> <sats>`**: Send on-chain Bitcoin.  
  _Example:_ `onchaintransfer tb1qexampleaddress 10000`

- **`openchannel <node_id> <address> <sats>`**: Open a Lightning channel.  
  _Example:_ `openchannel 02examplepubkey 127.0.0.1:9735 100000`

- **`closeallchannels`**: Close all channels.  
  _Example:_ `closeallchannels`

- **`getinvoice <sats>`**: Create a Lightning invoice.  
  _Example:_ `getinvoice 1000`

- **`payinvoice <invoice>`**: Pay a Lightning invoice.  
  _Example:_ `payinvoice lntb1u1exampleinvoice`

- **`channelinfo`**: View channel details.  
  _Example:_ `channelinfo`

- **`balance`**: Check on-chain and Lightning balances.  
  _Example:_ `balance`

These commands let you handle on-chain transactions, channels, and invoices efficiently.

---
