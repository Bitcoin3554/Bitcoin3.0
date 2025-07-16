# Kert-One

A simple blockchain implementation built with Python and Flask. Kert-One aims to provide a fundamental understanding of blockchain concepts, including mining, transactions, and node communication, through a straightforward and accessible interface.

---

## 🌟 Features

* **Decentralized Ledger:** A secure and immutable chain of blocks.
* **Proof-of-Work:** Implements a basic Proof-of-Work algorithm for mining new blocks.
* **Transactions:** Supports basic currency transfers between wallets.
* **Wallet Generation:** Easily create new cryptographic key pairs for managing funds.
* **RESTful API:** A Flask-based API for interacting with the blockchain.
* **Network Discovery (Optional):** Basic mechanisms for nodes to discover each other.

---

## 🚀 Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

Before you begin, ensure you have the following installed:

* **Python 3.x:** (e.g., Python 3.8 or higher recommended)
    * You can download it from [python.org](https://www.python.org/downloads/).
* **pip:** Python's package installer (usually comes with Python).

### Installation

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/YOUR_USERNAME/kert-one.git](https://github.com/YOUR_USERNAME/kert-one.git)
    cd kert-one
    ```
    *(**Remember to replace `https://github.com/YOUR_USERNAME/kert-one.git` with your actual repository URL!**)*

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    ```

3.  **Activate the virtual environment:**
    * **Windows:**
        ```bash
        .\venv\Scripts\activate
        ```
    * **macOS/Linux:**
        ```bash
        source venv/bin/activate
        ```

4.  **Install the required dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(**Important:** Make sure you have a `requirements.txt` file in your project's root directory containing `Flask`, `requests`, etc. If not, run `pip freeze > requirements.txt` after installing them manually.)*

---

## 🏃 How to Run

### 1. Start the Blockchain Node

Open your terminal or command prompt and navigate to the `kert-one` project directory.

```bash
python app.py
