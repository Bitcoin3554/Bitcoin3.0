# Crypito Bitcoin3.0 And Bitcoin

## Overview

**Bitcoin3.0** is a local implementation of the Bitcoin protocol that runs on a single machine. It includes its own block explorer, proof-of-work (PoW) mining, a Bitcoin-compatible wallet, and a P2P network restricted to **127.0.0.1** (localhost). Everything happens locally on your machine.

## Features

### 1. Block Explorer and Local HTTP API

Bitcoin3.0 includes a **block explorer** and an **HTTP API** for interacting with the blockchain. Communication is done via **127.0.0.1**, ensuring that interaction happens locally.

#### API Endpoints:
- **GET /chain**: Returns the current block chain.
- **GET /block/{hash}**: Details of a specific block.
- **GET /tx/{txid}**: Details of a specific transaction.

#### How to use:
1. Run the **Bitcoin3.0.exe** (Windows) or **./bitcoin3d** (Linux) file.
2. Open a web browser at [http://127.0.0.1](http://127.0.0.1) to access the block explorer interface.
3. Explore blocks, transactions, and addresses directly in the interface.

---

### 2. Proof-of-Work (PoW) Mining

**Bitcoin3.0** has a built-in miner that uses the **Proof-of-Work (PoW)** algorithm. You can generate new blocks on the blockchain locally.

#### Mining Flow:
1. Send a POST request to the **/mine** endpoint.
2. The node will attempt to find a valid nonce and, upon success, will add a new block to the local chain.
3. The mining reward will be credited to the specified address.

#### Mining Configuration:
In the **chainparams.cpp** file, the **nPowTargetSpacing** parameter sets the interval between blocks (usually between 1 and 10 minutes).

To change the interval, modify the value of static const int64_t nPowTargetSpacing and recompile the code.

---

### 3. Bitcoin Compatible Wallet

**Bitcoin3.0** supports standard Bitcoin (BTC) private keys and addresses, using the **WIF/P2PKH** format. This allows you to import and export private keys from BTC wallets.

#### Address Prefixes:
- **Public Address (P2PKH)**: Prefix 23 (example: starts with "M").

- **Private Key (WIF)**: Prefix 151.

---

### 4. Local P2P Network

P2P communication in Bitcoin3.0 occurs exclusively on your local machine (localhost, **127.0.0.1**). There are no external peers connected.

#### Network Configuration:
In the **bitcoin3.conf** configuration file, the network is configured to accept connections only from **127.0.0.1**.

ini
listen=1
bind=127.0.0.1
port=80

## 🚀 Overview
- **Wallet Compatibility:** Same public, private and WIF key formats as Bitcoin.
- **Own Blockchain:** Separate network that generates BTC3 instead of BTC. - **Dual Mining:** A single wallet can mine and store BTC (on the Bitcoin network) and BTC3 (on the Bitcoin3.0 network) simultaneously.

- **Fast Transactions:** Configurable blocks for faster confirmation times (1–10 minutes).

## 📄 Whitepaper
To understand in detail the design, mining algorithm, tokenomics and roadmap of Bitcoin3.0, check out the official whitepaper:

* [Bitcoin3.0 Whitepaper (PDF)](https://github.com/Bitcoin3554/Bitcoin3.0/blob/main/Bitcoin3.0_Whitepaper.pdf)
*
## 🧱 Downloads
- 📥 **Bitcoin Core:** [Downloads Here](https://github.com/Bitcoin3554/Bitcoin3.0/releases/tag/v3.0.0)

## 🔧 Tools
### Bitcoin / Bitcoin3.0 Wallet Generator
Go to this to create BTC and BTC3 compatible wallets:

http://127.0.0.1
## 🔗 API Endpoints
- **Smart Contract:** `GET http://127.0.0.1/contract/carteira/external-transactions`
- **Balance:** `GET http://127.0.0.1/balance/<address>`
- **New Transfer:** `POST http://127.0.0.1/transactions/new`
- **Blocks:** `GET http://127.0.0.1/chain`
- **Transfer:** `POST http://127.0.0.1/transfer`
- **Carteras (Wallets):** `POST http://127.0.0.1/wallet/create`
- **Mining:** `GET http://127.0.0.1/mine`

## 📷 Crypto Bitcoin!
![BTC3](https://github.com/Pipo-Pay/crypito/raw/main/Pipo-(pay).jpg)
![Wallet](https://github.com/Pipo-Pay/crypito/blob/main/Wallet.jpg)
![BTC3 BMP](https://github.com/Pipo-Pay/crypito/raw/main/pipo.bmp)
![01 BMP](https://github.com/Pipo-Pay/crypito/raw/main/01.bmp)
![02 BMP](https://github.com/Pipo-Pay/crypito/raw/main/02.bmp)

---

© 2025 Crypto Labs. All rights reserved.
