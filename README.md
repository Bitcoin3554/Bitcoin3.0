# 🚀 Bitcoin3 Btc3
🚫 **Sending Security (send.btc3.org)**
For security reasons, the sending logic (transactions) is protected and embedded in the final executable. This ensures that official endpoints cannot be spoofed or cloned by third parties. The open source client can be audited, but the sending logic is shielded from changes or attacks.

✅ The mining, wallet and balance reading code is 100% open source.
🔐 The sending routes are secured in the project's signed binary.

## Chow to use the decentralized web interface

To know more about the configuration and use of the decentralized web interface, check out the tutorial:

[BTC3 Cloudflare Tunnel Tutorial (PDF)](https://github.com/Bitcoin3554/Bitcoin3.0/blob/main/BTC3_Cloudflare_Tunnel_Tutorial.pdf)

---
🚀 Functionalities
Compatibilidade com BTC: Utilize a mesma chave privada para accessar BTC e BTC3.

Blockchain Independente: Rede propia para BTC3, eviento interferências com a blockchain do Bitcoin.

Minerador Integrado: Suporte a mineração via CPU e GPU com interface local para monitoramento.

Explorador de Blocos: Visualize transactions and mined blocks in real time.

🛠️ Tecnologias Utilizadas
Language: C++

Bibliotecas: OpenSSL, Boost, libevent

Minerador: OpenCL para suporte a GPU

Interface: Flask para server web local

📦 Installation
Requirements
Operating system: Linux or Windows

Dependencies: OpenSSL, Boost, libevent, OpenCL

GPU compatible: NVIDIA or AMD (for mineração via GPU)
## 📑 Table of Contents

- [📦 Key Features](#-key-features)
- [🖥️ System Requirements](#️-system-requirements)
- [📥 Installation](#-installation)
- [🚀 Quick Start](#-quick-start)
- [📁 Project Structure](#-project-structure)
- [📚 Documentation](#-documentation)
- [🧠 Developers](#-developers)
- [📜 License](#-license)
- [🤝 Contributions](#-contributions)

---

## 📦 Key Features

- 🧠 **BTC3 Core**: Run your own local Bitcoin3 blockchain node.
- 🛠️ **BTC3 Miner**: GPU-accelerated miner module using NVIDIA CUDA.
- 📈 **Web Dashboard**: Local dashboard to monitor network status and mined blocks.
- 🔐 **Wallet System**: Secure wallet generation and storage for BTC3.
- ⚙️ **Full Installer**: `.exe` installer with interactive wizard, custom icons, and optional CUDA Toolkit setup.

---

## 🖥️ System Requirements

- 💻 **Operating System**: Windows 10 or newer
- 🔧 **Dependency**: CUDA Toolkit 12.8 (included in the installer)
- 🧮 **CPU**: Dual Core or higher
- 🎮 **GPU**: NVIDIA with CUDA support (for mining)
- 💾 **Storage**: At least 1 GB of free space

---

## 📥 Installation

1. Download all installer files:

   [📦 Bitcore3_install.exe and additional .bin files](https://github.com/Bitcoin3554/Bitcoin3.0/releases/tag/v3.0.0)

   > ⚠️ **Important**: Make sure to download all `.bin` files alongside the `.exe`. These are parts of the complete installer.

2. Run `BitCore3_install.exe` as **administrator**.
3. Follow the installation wizard:
   - Choose the installation type: **Core**, **Miner**, or **Full**.
   - (Optional) Automatically install the CUDA Toolkit.
4. After installation, use the shortcuts created on your desktop or Start menu.

---

## 🚀 Quick Start

Once installed, you can:

- Launch **BTC3 Core** using the "Bitcoin3.0" shortcut.
- Start the **Miner** using "Bitcoin3.0-Miner".
- Access the **blockchain dashboard** in your browser: [`http://127.0.0.1`](http://127.0.0.1)

---

## 📁 Project Structure


├── core/ # BTC3 core blockchain source code
├── miner/ # Mining module source code
├── webpanel/ # Web dashboard for network monitoring
├── wallet/ # Digital wallet module
├── installer/ # Installer files and Inno Setup scripts
├── docs/ # Documentation and whitepaper
└── README.md # Project overview

## 📜 License

This project is licensed under the **MIT License**.  
Please refer to the [`LICENSE`](https://github.com/Bitcoin3554/Bitcoin3.0/blob/main/LICENSE) file for more details.

---

## 🤝 Contributions

Contributions are welcome and encouraged! To contribute:

1. **Fork** this repository.
2. Create a new branch:
   ```bash
   git checkout -b my-feature

---

## 📚 Documentation

- 📄 [Official Whitepaper (PDF)](https://github.com/Bitcoin3554/Bitcoin3.0/blob/main/Bitcoin3.0_Whitepaper.pdf)
- 🌐 [Local Website (default)](https://bitcoin.org/en/)
- 💬 [Discussions & Support](https://github.com/Bitcoin3554/Bitcoin3.0/discussions)

---

## 🧠 Developers

Want to contribute or customize?

```bash
git clone https://github.com/Bitcoin3554/Bitcoin3.0.git
cd Bitcoin3.0
