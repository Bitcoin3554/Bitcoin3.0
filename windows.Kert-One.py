import hashlib
import json
import time
import threading
import sqlite3
import os
from uuid import uuid4
from flask import Flask, jsonify, request, send_file
import requests
from urllib.parse import urlparse
import socket
import ipaddress
import sys
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
import qrcode
from io import BytesIO
from datetime import datetime
import re
import os
import sys
import shutil
from flask import Flask, render_template
from google.oauth2 import service_account
from googleapiclient.discovery import build
from flask_cors import CORS
from PyQt5.QtCore import pyqtSlot

# --- Configurfrom PyQt5.QtCore import pyqtSlot
DIFFICULTY = 1
MINING_REWARD = 10
DATABASE = 'chain.db'
COIN_NAME = "Kert-One"
COIN_SYMBOL = "KERT"
PEERS_FILE = 'peers.json'

# --- NÓS SEMENTES (SEED NODES) ---
SEED_NODES = [
    "https://seend.kert-one.com", 
    "https://seend2.kert-one.com",
    "https://seend3.kert-one.com",

]

app = Flask(__name__)
node_id = str(uuid4()).replace('-', '')
CORS(app)

# --- Funções de Persistência de Peers ---
def salvar_peers(peers):
    with open(PEERS_FILE, 'w') as f:
        json.dump(list(peers), f)

def carregar_peers():
    if not os.path.exists(PEERS_FILE):
        return []
    with open(PEERS_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

known_nodes = set(carregar_peers())
miner_lock = threading.Lock()

blockchain = None
miner_address = None # Agora será definido por um endpoint ou configuração
meu_url = None
meu_ip = None
port = None

# --- Classe Blockchain ---
class Blockchain:
    ADJUST_INTERVAL = 2016
    TARGET_TIME = 600

    def __init__(self, conn, node_id):
        self.conn = conn
        self.node_id = node_id
        self._init_db()
        self.chain = self._load_chain()
    
        self.current_transactions = []  # Garante que 'current_transactions' sempre exista

        if not self.chain:
            print("[BOOT] Criando bloco Gênese...")
            self.new_block(proof=100, previous_hash='1', miner=self.node_id)

        self.difficulty = self._calculate_difficulty_for_index(len(self.chain))


    @staticmethod
    def custom_asic_resistant_hash(data_bytes, nonce):
        raw = data_bytes + str(nonce).encode()
        h1 = hashlib.sha256(raw).digest()
        h2 = hashlib.sha512(h1).digest()
        h3 = hashlib.blake2b(h2).digest()
        return hashlib.sha256(h3).hexdigest()
        
    def _init_db(self):
        print("[DEBUG] Executando _init_db() com estrutura nova...")
        c = self.conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS blocks(
                index_ INTEGER PRIMARY KEY,
                previous_hash TEXT,
                proof INTEGER,
                timestamp REAL,
                miner TEXT,
                difficulty INTEGER
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS txs(
                id TEXT PRIMARY KEY,
                sender TEXT,
                recipient TEXT,
                amount REAL,
                fee REAL,
                signature TEXT,
                block_index INTEGER,
                public_key TEXT
            )
        ''')
        self.conn.commit()

    def _load_chain(self):
        c = self.conn.cursor()
        c.execute("SELECT index_, previous_hash, proof, timestamp, miner FROM blocks ORDER BY index_")
        chain = []
        for idx, prev, proof, ts, miner in c.fetchall():
            c.execute("SELECT id, sender, recipient, amount, fee, signature, public_key FROM txs WHERE block_index=?", (idx,))
            txs = [dict(id=r[0], sender=r[1], recipient=r[2], amount=r[3], fee=r[4], signature=r[5], public_key=r[6]) for r in c.fetchall()]
            block = {
                'index': idx,
                'previous_hash': prev,
                'proof': proof,
                'timestamp': ts,
                'miner': miner,
                'transactions': txs
            }
            chain.append(block)
        return chain

    def new_block(self, proof, previous_hash, miner):
        block_index = len(self.chain) + 1
        reward = self._get_mining_reward(block_index)
        difficulty = self._calculate_difficulty_for_index(block_index)

        self.current_transactions.insert(0, {
            'id': str(uuid4()), 'sender': '0', 'recipient': miner,
            'amount': reward, 'fee': 0, 'signature': '', 'public_key': ''
        })

        block = {
            'index': block_index,
            'previous_hash': previous_hash,
            'proof': proof,
            'timestamp': time.time(),
            'miner': miner,
            'transactions': self.current_transactions,
            'difficulty': difficulty  # ADICIONADO
        }

        self.current_transactions = []
        self.chain.append(block)

        c = self.conn.cursor()
        c.execute("SELECT 1 FROM blocks WHERE index_=?", (block['index'],))
        if not c.fetchone():
            self._save_block(block)
        else:
            print(f"[AVISO] Bloco com índice {block['index']} já existe no DB. Ignorando salvamento duplicado.")
        return block


    def _save_block(self, block):
        c = self.conn.cursor()
        c.execute("INSERT INTO blocks VALUES (?, ?, ?, ?, ?, ?)",
                  (block['index'], block['previous_hash'], block['proof'],
                   block['timestamp'], block['miner'], block['difficulty']))  # <<<<< adicionado
        for t in block['transactions']:
            c.execute("INSERT INTO txs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                      (t['id'], t['sender'], t['recipient'], t['amount'],
                       t['fee'], t['signature'], block['index'], t.get('public_key', '')))
        self.conn.commit()


    def new_tx(self, sender, recipient, amount, fee, signature, public_key):
        tx = {
            'id': str(uuid4()), 'sender': sender, 'recipient': recipient,
            'amount': amount, 'fee': fee, 'signature': signature, 'public_key': public_key
        }
        self.current_transactions.append(tx)
        return self.last_block()['index'] + 1 if self.chain else 1

    def _get_mining_reward(self, block_index):
        if block_index <= 1200:
            return 50
        elif block_index <= 2200:
            return 25
        elif block_index <= 4000:
            return 12.5
        elif block_index <= 5500:
            return 6.5
        # --- A recompensa cai para um valor menor a partir daqui ---
        elif block_index <= 6200:
            return 3.25 # Recompensa anterior até 6200
        # A partir do bloco 6201, a recompensa será de 1.25 KERT
        elif block_index <= 20000:
            return 1.25
        # --- As regras de halving mais distantes se mantêm ---
        elif block_index <= 1000000:
            return 0.03
        else:
            halvings = (block_index - 1000000) // 2100000
            base_reward = 0.03
            reward = base_reward / (2 ** halvings)
            return max(reward, 0)

    def last_block(self):
        return self.chain[-1] if self.chain else None

    def proof_of_work(self, last_proof):
        difficulty_for_pow = self._calculate_difficulty_for_index(len(self.chain) + 1)
        proof = 0
        print(f"Iniciando mineração com dificuldade {difficulty_for_pow}...")
        start_time = time.time()
        while not self.valid_proof(last_proof, proof, difficulty_for_pow):
            global is_mining
            if not is_mining:
                print("[Miner] Sinal para parar recebido durante PoW. Abortando mineração.")
                return -1 # Retorna um valor especial para indicar aborto
                
            if time.time() - start_time > 10 and proof % 100000 == 0:
                print(f" Tentativa: {proof}")
            proof += 1
        print(f"Mineração concluída: proof = {proof}")
        return proof

    @staticmethod
    def valid_proof(last_proof, proof, difficulty):
        guess = f"{last_proof}{proof}".encode()
        guess_hash = Blockchain.custom_asic_resistant_hash(guess, proof)
        return guess_hash[:difficulty] == "0" * difficulty


    def valid_chain(self, chain):
        current_difficulty_check = DIFFICULTY

        for idx in range(1, len(chain)):
            prev = chain[idx - 1]
            curr = chain[idx]

            block_string = json.dumps({k: v for k, v in prev.items() if k != 'transactions'}, sort_keys=True)
            prev_hash = hashlib.sha256(block_string.encode()).hexdigest()

            if curr['previous_hash'] != prev_hash:
                print(f"[VAL_CHAIN_ERRO] Hash anterior incorreto no bloco {curr['index']}.")
                return False

            if curr['index'] >= self.ADJUST_INTERVAL:
                ref_block_in_validation_chain_idx = curr['index'] - self.ADJUST_INTERVAL

                if ref_block_in_validation_chain_idx >= 0:
                    last_adjust_block_ts = chain[ref_block_in_validation_chain_idx]['timestamp']
                    current_block_ts = curr['timestamp']

                    actual_time = current_block_ts - last_adjust_block_ts
                    expected_time = self.TARGET_TIME * self.ADJUST_INTERVAL

                    new_difficulty = current_difficulty_check
                    if actual_time < expected_time / 2:
                        new_difficulty += 1
                    elif actual_time > expected_time * 2 and new_difficulty > 1:
                        new_difficulty -= 1
                    current_difficulty_check = new_difficulty
                else:
                    current_difficulty_check = DIFFICULTY
            else:
                current_difficulty_check = DIFFICULTY

            # ←↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓↓
            difficulty = curr.get('difficulty', current_difficulty_check)
            if not self.valid_proof(prev['proof'], curr['proof'], difficulty):
                print(f"[VAL_CHAIN_ERRO] Proof of Work inválido no bloco {curr['index']} com dificuldade {difficulty}.")
                return False
            # ↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑↑

            for tx in curr.get('transactions', []):
                if tx['sender'] == '0':
                    continue
                try:
                    derived_address = hashlib.sha256(bytes.fromhex(tx['public_key'])).hexdigest()[:40]
                    if derived_address != tx['sender']:
                        print(f"[VAL_CHAIN_ERRO] Transação {tx['id']} no bloco {curr['index']}: Endereço ({tx['sender']}) não bate com o derivado da chave pública ({derived_address}).")
                        return False

                    tx_copy_for_signature = {
                        'sender': tx['sender'],
                        'recipient': tx['recipient'],
                        'amount': tx['amount'],
                        'fee': tx['fee']
                    }
                    message = json.dumps(tx_copy_for_signature, sort_keys=True).encode()

                    vk = VerifyingKey.from_string(bytes.fromhex(tx['public_key']), curve=SECP256k1)
                    vk.verify(bytes.fromhex(tx['signature']), message)

                except Exception as e:
                    print(f"[VAL_CHAIN_ERRO] Transação {tx['id']} inválida no bloco {curr['index']}: {e}")
                    return False

        return True

    def _calculate_difficulty_for_index(self, target_block_index):
        # Se não for múltiplo de ADJUST_INTERVAL, mantém a dificuldade do último bloco
        if target_block_index % self.ADJUST_INTERVAL != 0:
            if self.chain:
                return self.chain[-1].get('difficulty', DIFFICULTY)
            else:
                return DIFFICULTY

        if len(self.chain) < self.ADJUST_INTERVAL:
            return DIFFICULTY  # ainda não tem blocos suficientes para ajuste

        start_block_for_calc = self.chain[len(self.chain) - self.ADJUST_INTERVAL]
        end_block_for_calc = self.chain[len(self.chain) - 1]

        actual_window_time = end_block_for_calc['timestamp'] - start_block_for_calc['timestamp']
        expected_time = self.TARGET_TIME * self.ADJUST_INTERVAL

        current_calculated_difficulty = end_block_for_calc.get('difficulty', DIFFICULTY)

        new_difficulty = current_calculated_difficulty
        if actual_window_time < expected_time / 4:
            new_difficulty += 2
        elif actual_window_time < expected_time / 2:
            new_difficulty += 1
        elif actual_window_time > expected_time * 4 and new_difficulty > 1:
            new_difficulty -= 2
        elif actual_window_time > expected_time * 2 and new_difficulty > 1:
            new_difficulty -= 1

        return max(1, new_difficulty)

    def resolve_conflicts(self):
        neighbors = known_nodes.copy()
        new_chain = None
        max_length = len(self.chain)

        print(f"[CONSENSO] Tentando resolver conflitos com {len(neighbors)} vizinhos...")

        for node_url in neighbors:
            try:
                r = requests.get(f"{node_url}/chain", timeout=5)
                if r.status_code == 200:
                    data = r.json()
                    length = data['length']
                    chain = data['chain']
                    
                    print(f"[CONSENSO] Node {node_url}: length={length}, current_max={max_length}")
                    
                    if length > max_length:
                        if self.valid_chain(chain): # Usa a valid_chain corrigida
                            max_length = length
                            new_chain = chain
                            print(f"[CONSENSO] Encontrada cadeia mais longa e válida em {node_url}")
                        else:
                            print(f"[CONSENSO] Cadeia de {node_url} é mais longa mas INVÁLIDA.")
                    else:
                        print(f"[CONSENSO] Cadeia de {node_url} não é mais longa.")
                else:
                    print(f"[CONSENSO] Resposta inválida de {node_url}: Status {r.status_code}")
            except requests.exceptions.RequestException as e:
                print(f"[CONSENSO] Erro ao buscar cadeia em {node_url}: {e}. Removendo peer.")
                known_nodes.discard(node_url)
                salvar_peers(known_nodes)
                continue

        if new_chain:
            self.chain = new_chain
            self._rebuild_db_from_chain()
            print("[CONSENSO] Cadeia substituída pela mais longa e válida.")
            return True
        print("[CONSENSO] Cadeia atual é a mais longa ou não há cadeia válida mais longa.")
        return False

    def _rebuild_db_from_chain(self):
        c = self.conn.cursor()
        c.execute("DELETE FROM blocks")
        c.execute("DELETE FROM txs")
    
        # Corrige tentativa de deletar em sqlite_sequence que pode não existir
        try:
            c.execute("DELETE FROM sqlite_sequence WHERE name='blocks'")
        except sqlite3.OperationalError:
            print("[⚠️] Tabela sqlite_sequence não existe — ignorando reset do AUTOINCREMENT.")

        for block in self.chain:
            block_to_save = {k: v for k, v in block.items() if k != 'transactions'}
            c.execute("INSERT INTO blocks VALUES (?, ?, ?, ?, ?, ?)",
                      (block_to_save['index'], block_to_save['previous_hash'], 
                       block_to_save['proof'], block_to_save['timestamp'], block_to_save['miner'], block_to_save.get('difficulty', 4)))

            for t in block['transactions']:
                c.execute("INSERT INTO txs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                          (t['id'], t['sender'], t['recipient'], t['amount'], t['fee'], t['signature'], block['index'], t.get('public_key', '')))
    
        self.conn.commit()
        print("[DB] Banco de dados reconstruído a partir da nova cadeia.")


    def balance(self, address):
        bal = 0
        for block in self.chain:
            for t in block['transactions']:
                if t['sender'] == address:
                    bal -= (t['amount'] + t['fee'])
                if t['recipient'] == address:
                    bal += t['amount']
        
        # Considerar transações pendentes
        for t in self.current_transactions:
            if t['sender'] == address:
                bal -= (t['amount'] + t['fee'])
            if t['recipient'] == address:
                bal += t['amount']
        return bal

# --- Funções de Carteira (Node - para referência ou uso interno, mas o cliente gerará) ---
# Estas funções foram movidas para o cliente, mas mantidas no nó se houver uso de API
def create_wallet():
    private_key = SigningKey.generate(curve=SECP256k1)
    public_key = private_key.get_verifying_key()
    address = hashlib.sha256(public_key.to_string().hex().encode()).hexdigest()[:40] # Consistência na derivação
    return {
        "private_key": private_key.to_string().hex(),
        "public_key": public_key.to_string().hex(),
        "address": address
    }

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        privkey = request.form.get('privkey')
        if not privkey or len(privkey) != 64:
            flash("Erro: 'privkey' é obrigatório e deve ter 64 caracteres HEX.", 'danger')
            return render_template('blockchain.html')

        wallet = generate_wallet_data(privkey)
        return render_template('blockchain.html', wallet=wallet)

    return render_template('blockchain.html')

# Rota para a página BTC3
@app.route('/btc3')
def btc3():
    return render_template('btc3.html')

# Rota para a página BTC3
@app.route('/miner')
def miner():
    return render_template('miner.html')
    
# Rota para a página Carteira (Whitepaper)
@app.route('/whitepaper')
def Whitepaper():
    return render_template('Whitepaper.html')


@app.route('/contract/<contract_address>/transactions', methods=['GET'])
def get_contract_transactions(contract_address):
    print(f"🔍 Route called for contract: {contract_address}")
    
    # Validação simples de endereço hexadecimal (40 caracteres)
    if not re.fullmatch(r'[0-9a-fA-F]{40}', contract_address):
        return jsonify({"error": "Invalid contract address format."}), 400

    # Parâmetros de paginação
    page = int(request.args.get('page', 1))
    per_page = int(request.args.get('per_page', 20))

    transactions = []
    total_value = 0
    transaction_details = []

    if not isinstance(blockchain.chain, list):
        return jsonify({"error": "Internal error in the blockchain."}), 500

    for block in blockchain.chain:
        if not isinstance(block, dict):
            continue

        transactions_in_block = block.get("transactions", [])
        if not isinstance(transactions_in_block, list):
            continue

        for tx in transactions_in_block:
            recipient = tx.get("recipient")
            if recipient and recipient.strip().lower() == contract_address.strip().lower():
                transactions.append(tx)
                amount = tx.get("amount", 0)

                try:
                    total_value += float(amount)
                except ValueError:
                    continue

                timestamp = tx.get("timestamp", None)
                if timestamp:
                    transaction_date = datetime.utcfromtimestamp(timestamp).strftime("%d de %B, %Y")
                else:
                    transaction_date = datetime.now().strftime("%d de %B, %Y")

                transaction_details.append({
                    "date": transaction_date,
                    "amount": f"{amount:.6f}".rstrip('0').rstrip('.'),
                    "sender": tx.get("sender"),
                    "recipient": recipient,
                    "balance_after_transaction": f"{total_value:.6f}".rstrip('0').rstrip('.'),
                })

    formatted_total_value = f"{total_value:.6f}".rstrip('0').rstrip('.')
    today = datetime.now()
    formatted_date = f"{today.day} de {today.strftime('%B')}"

    # Aplicar paginação
    start = (page - 1) * per_page
    end = start + per_page
    paginated = transaction_details[start:end]

    if transactions:
        return jsonify({
            "contract_address": contract_address,
            "total_value": formatted_total_value,
            "transaction_details": paginated,
            "total_transactions": len(transaction_details),
            "page": page,
            "message": f"Total enviado: {formatted_total_value} no dia {formatted_date}"
        }), 200
    else:
        return jsonify({"error": "No transactions found for the specified contract"}), 404

def load_wallet_node(filepath='wallet.json'): # Renomeado para evitar conflito com o cliente
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return json.load(f)
    return None

def save_wallet_node(wallet_data, filepath='wallet.json'): # Renomeado
    with open(filepath, 'w') as f:
        json.dump(wallet_data, f, indent=4)

# --- Funções auxiliares (para assinatura, embora a assinatura seja do cliente) ---
def sign_transaction_node(private_key_hex, tx_data): # Renomeado
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    message = json.dumps(tx_data, sort_keys=True).encode()
    return sk.sign(message).hex()

# --- Flask Endpoints ---
miner_thread = None
is_mining = False

# Moved wallet endpoints to client-side logic to avoid confusion
# @app.route('/wallet/new', methods=['GET'])
# def wallet_new():
# ...

# @app.route('/wallet/load', methods=['GET'])
# def wallet_load():
# ...

# @app.route('/wallet/save', methods=['POST'])
# def wallet_save():
# ...

def proof_of_work(last_proof):
    global is_mining
    nonce = 0
    while is_mining:
        guess = f"{last_proof}{nonce}".encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        if guess_hash[:difficulty] == '0' * difficulty:
            return nonce
        nonce += 1
    return -1  # sinal de abortar PoW


@app.route('/miner/set_address', methods=['POST'])
def set_miner_address():
    global miner_address
    data = request.get_json()
    address = data.get('address')
    if not address:
        return jsonify({"message": "Address is required."}), 400

    if not isinstance(address, str) or len(address) != 40 or not all(c in '0123456789abcdefABCDEF' for c in address.lower()):
        return jsonify({"message": "Invalid address format. Must be 40 hex characters."}), 400

    miner_address = address
    print(f"[API] Miner address set to: {miner_address}")
    return jsonify({"message": f"Miner address set to {miner_address}"}), 200


@app.route('/miner/start', methods=['GET'])
def start_mining():
    global is_mining, miner_thread, miner_address

    if not miner_address:
        return jsonify({"message": "Miner address not set. Please set it using /miner/set_address first."}), 400

    with miner_lock:
        if is_mining:
            return jsonify({"message": "Miner already running."}), 200

        print("[API] Starting miner loop...")
        is_mining = True
        miner_thread = threading.Thread(target=miner_loop, daemon=True)
        miner_thread.start()

    return jsonify({"message": "Miner started!"}), 200


@app.route('/miner/stop', methods=['GET'])
def stop_mining():
    global is_mining
    with miner_lock:
        if not is_mining:
            return jsonify({"message": "Miner is not running."}), 200

        print("[API] Stopping miner loop...")
        is_mining = False

    return jsonify({"message": "Miner stopped!"}), 200


def miner_loop():
    global is_mining, miner_address

    is_mining = True
    print("[Miner] Iniciando minerador...")

    while is_mining:
        try:
            # Verifica conflitos ANTES de começar PoW
            if blockchain.resolve_conflicts():
                print("[Miner] Cadeia foi substituída. Abortando tentativa atual de mineração.")
                time.sleep(3)
                continue

            last = blockchain.last_block()

            if last is None:
                print("[Miner] Blockchain vazia. Aguardando inicialização...")
                time.sleep(5)
                continue

            if not blockchain.current_transactions and len(blockchain.chain) > 1:
                print("[Miner] Nenhuma transação pendente. Aguardando...")
                time.sleep(10)
                continue

            proof = blockchain.proof_of_work(last['proof'])

            if proof == -1:  # Abortado externamente
                print("[Miner] Mineração abortada.")
                break

            # Verifica se um novo bloco foi recebido durante o PoW
            new_last = blockchain.last_block()
            if new_last != last:
                print("[Miner] Novo bloco chegou durante PoW. Recomeçando...")
                continue

            previous_hash = hashlib.sha256(json.dumps(
                {k: v for k, v in last.items() if k != 'transactions'},
                sort_keys=True
            ).encode()).hexdigest()

            # Filtra e valida as transações
            valid_txs = []
            already_seen_tx_ids = set()

            for tx in blockchain.current_transactions:
                tx_id = tx.get('id')
                if not tx_id or tx_id in already_seen_tx_ids:
                    continue
                if blockchain.tx_already_mined(tx_id):
                    print(f"[Miner] Transação {tx_id} já minerada. Ignorando.")
                    continue

                if tx['sender'] == '0':
                    valid_txs.append(tx)
                    already_seen_tx_ids.add(tx_id)
                    continue

                try:
                    derived_address = hashlib.sha256(bytes.fromhex(tx['public_key'])).hexdigest()[:40]
                    if derived_address != tx['sender']:
                        print(f"[Miner] TX {tx_id} inválida: endereço não bate.")
                        continue

                    tx_data = {
                        'sender': tx['sender'],
                        'recipient': tx['recipient'],
                        'amount': tx['amount'],
                        'fee': tx['fee']
                    }
                    message = json.dumps(tx_data, sort_keys=True).encode()
                    vk = VerifyingKey.from_string(bytes.fromhex(tx['public_key']), curve=SECP256k1)
                    vk.verify(bytes.fromhex(tx['signature']), message)

                    balance = blockchain.balance(tx['sender'])
                    if balance < (tx['amount'] + tx['fee']):
                        print(f"[Miner] TX {tx_id} com saldo insuficiente. Ignorando.")
                        continue

                    valid_txs.append(tx)
                    already_seen_tx_ids.add(tx_id)

                except Exception as e:
                    print(f"[Miner] TX {tx_id} inválida: {e}. Ignorando.")
                    continue

            # Atualiza transações pendentes
            blockchain.current_transactions = valid_txs

            # Cria o novo bloco
            block = blockchain.new_block(proof, previous_hash, miner=miner_address)

            # ✅ Envia para os peers imediatamente
            for peer in known_nodes.copy():
                try:
                    r = requests.post(f"{peer}/blocks/receive", json=block, timeout=5)
                    if r.status_code != 200:
                        print(f"[Miner] Peer {peer} rejeitou o bloco: {r.text}")
                except Exception as e:
                    print(f"[Miner] Falha ao enviar bloco para {peer}: {e}")
                    known_nodes.discard(peer)
                    salvar_peers(known_nodes)

            print(f"[Miner] ✅ Bloco #{block['index']} minerado com {len(valid_txs)} transações.")

        except Exception as e:
            print(f"[Miner ERROR] Erro no loop de mineração: {e}")

        time.sleep(1)



@app.route('/mine', methods=['GET'])
def mine_once():
    global is_mining, miner_lock, miner_address

    if not miner_address:
        return jsonify({"message": "Miner address not set. Use /miner/set_address first."}), 400

    with miner_lock:
        if is_mining:
            return jsonify({"message": "Miner loop is running. Please stop it before mining once."}), 409
        is_mining = True

    try:
        blockchain.resolve_conflicts()
        last = blockchain.last_block()
        if last is None:
            return jsonify({"message": "Blockchain not initialized. Genesis block missing."}), 500

        proof = blockchain.proof_of_work(last['proof'])

        if proof == -1:
            return jsonify({"message": "Mining aborted by stop signal or new block arrived."}), 200

        new_last = blockchain.last_block()
        if new_last != last:
            print("[Mine Once] Outro bloco chegou durante PoW. Abortando.")
            return jsonify({"message": "Outro bloco chegou. Mineração abortada."}), 409

        previous_hash = hashlib.sha256(json.dumps({k: v for k, v in last.items() if k != 'transactions'}, sort_keys=True).encode()).hexdigest()

        # Validação das transações aqui...

        block = blockchain.new_block(proof, previous_hash, miner=miner_address)
        broadcast_block(block)

        return jsonify({
            'message': 'Bloco minerado',
            'index': block['index'],
            'transactions': block['transactions'],
            'coin_name': COIN_NAME,
            'coin_symbol': COIN_SYMBOL
        }), 200

    finally:
        with miner_lock:
            is_mining = False


def broadcast_block(block):
    # Função placeholder para enviar bloco aos peers da rede
    print(f"[Broadcast] Bloco {block['index']} enviado para a rede.")
    
@app.route('/chain', methods=['GET'])
def chain():
    return jsonify({
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
        'pending_transactions': len(blockchain.current_transactions)
    }), 200
    
@app.route('/nodes/register', methods=['POST'])
def register_nodes():
    data = request.get_json()
    new_node_ip = data.get('ip')
    new_node_port = data.get('port')

    if not new_node_ip or not new_node_port:
        return jsonify({"message": "Invalid IP or missing port."}), 400

    new_node_url = f"http://{new_node_ip}:{new_node_port}"

    if new_node_url != meu_url:
        if new_node_url not in known_nodes:
            known_nodes.add(new_node_url)
            salvar_peers(known_nodes)
            print(f"[INFO] Peer {new_node_url} registrado.")
        else:
            print(f"[INFO] Peer {new_node_url} já estava registrado. Atualizando, se necessário.")
    else:
        print(f"[INFO] Recebi meu próprio registro: {new_node_url}. Ignorando.")

    return jsonify({
        "message": f"Peer {new_node_url} registered or updated.",
        "known_peers": list(known_nodes)
    }), 200

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

import os
import platform

def get_user_data_dir():
    if platform.system() == 'Windows':
        appdata = os.getenv('APPDATA')
        if appdata:
            user_data_dir = os.path.join(appdata, 'BitcoinBTC3')
        else:
            # fallback se APPDATA não estiver definida
            user_data_dir = os.path.join(os.path.expanduser('~'), 'AppData', 'Roaming', 'BitcoinBTC3')
    else:
        # Linux/macOS usa pasta oculta no home
        user_data_dir = os.path.join(os.path.expanduser('~'), '.bitcoinbtc3')

    os.makedirs(user_data_dir, exist_ok=True)
    return user_data_dir


# Diretórios e caminhos dos arquivos
user_dir = get_user_data_dir()
GENERIC_CLASS_PATH = os.path.join(user_dir, 'generic-class.json')
GENERIC_OBJECT_PATH = os.path.join(user_dir, 'generic-object.json')
KERTCARD_KEY_PATH = os.path.join(user_dir, 'bitcard-key.json')


def copy_default_files_to_user_dir():
    user_dir = get_user_data_dir()

    files_to_copy = [
        'generic-class.json',
        'generic-object.json',
        'bitcard-key.json',
        # adicione mais arquivos padrão que seu app precise
    ]

    for filename in files_to_copy:
        user_file = os.path.join(user_dir, filename)
        if not os.path.exists(user_file):
            default_file = resource_path(filename)
            shutil.copyfile(default_file, user_file)
            print(f'Arquivo {filename} copiado para {user_file}')

# Na inicialização do seu app:
copy_default_files_to_user_dir()

# Agora, sempre abra e altere os arquivos da pasta fixa do usuário, exemplo:
user_dir = get_user_data_dir()
generic_class_path = os.path.join(user_dir, 'generic-class.json')
with open(generic_class_path, 'r', encoding='utf-8') as f:
    generic_class = json.load(f)

# Modifique e salve normalmente no generic_class_path

def create_generic_class():
    from google.oauth2 import service_account
    from googleapiclient.discovery import build

    with open(KERTCARD_KEY_PATH, 'r', encoding='utf-8') as f:
        service_account_info = json.load(f)

    credentials = service_account.Credentials.from_service_account_info(
        service_account_info,
        scopes=['https://www.googleapis.com/auth/wallet_object.issuer']
    )

    service = build('walletobjects', 'v1', credentials=credentials)

    with open(GENERIC_CLASS_PATH, 'r', encoding='utf-8') as f:
        generic_class = json.load(f)

    try:
        service.genericclass().insert(body=generic_class).execute()
        print("Classe genérica criada com sucesso")
    except Exception as e:
        if hasattr(e, 'status_code') and e.status_code == 409:
            print("Classe já existe, ignorando erro 409.")
        else:
            print("Erro criando classe genérica:", e)
            raise

from flask import Flask, request, render_template
import os
import json
import re
import time
from google.oauth2 import service_account
from googleapiclient.discovery import build
from google.auth import jwt, crypt


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GENERIC_CLASS_PATH = os.path.join(BASE_DIR, "generic-class.json")
GENERIC_OBJECT_PATH = os.path.join(BASE_DIR, "generic-object.json")
KEY_PATH = os.path.join(BASE_DIR, "bitcard-key.json")

# Carrega credenciais e serviço Google Wallet
with open(KEY_PATH, "r", encoding="utf-8") as f:
    service_account_info = json.load(f)

credentials = service_account.Credentials.from_service_account_info(service_account_info)
service = build('walletobjects', 'v1', credentials=credentials)


def normalize_id(id_str):
    id_str = id_str.lower()
    id_str = re.sub(r'[^a-z0-9_]', '_', id_str)
    id_str = re.sub(r'__+', '_', id_str)
    id_str = id_str.strip('_')
    return id_str


def create_or_update_generic_object(generic_object):
    try:
        service.genericobject().insert(body=generic_object).execute()
        print("Objeto genérico criado com sucesso")
    except Exception as e:
        # Se objeto já existe, atualiza
        if hasattr(e, 'status_code') and e.status_code == 409:
            service.genericobject().update(
                resourceId=generic_object['id'], body=generic_object).execute()
            print("Objeto genérico atualizado com sucesso")
        else:
            print("Erro ao criar ou atualizar objeto genérico:", e)
            raise

import os
import sys
import shutil

def resource_path(relative_path):
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def get_user_data_dir():
    system = platform.system()
    
    if system == 'Windows':
        appdata = os.getenv('APPDATA')
        if not appdata:
            raise EnvironmentError("APPDATA não está definido no sistema Windows.")
        user_data_dir = os.path.join(appdata, 'BitcoinBTC3')
    else:
        # Linux, macOS, etc
        home = os.getenv('HOME')
        if not home:
            raise EnvironmentError("HOME não está definido no sistema Unix.")
        user_data_dir = os.path.join(home, '.BitcoinBTC3')  # pasta oculta no home
    
    os.makedirs(user_data_dir, exist_ok=True)
    return user_data_dir

def copy_default_files_to_user_dir():
    user_dir = get_user_data_dir()

    files_to_copy = [
        'generic-class.json',
        'generic-object.json',
        'bitcard-key.json',
        # adicione mais arquivos padrão que seu app precise
    ]

    for filename in files_to_copy:
        user_file = os.path.join(user_dir, filename)
        if not os.path.exists(user_file):
            default_file = resource_path(filename)
            shutil.copyfile(default_file, user_file)
            print(f'Arquivo {filename} copiado para {user_file}')

# Na inicialização do seu app:
copy_default_files_to_user_dir()

# Agora, sempre abra e altere os arquivos da pasta fixa do usuário, exemplo:
user_dir = get_user_data_dir()
generic_class_path = os.path.join(user_dir, 'generic-class.json')
with open(generic_class_path, 'r', encoding='utf-8') as f:
    generic_class = json.load(f)

# Modifique e salve normalmente no generic_class_path

def create_generic_class():
    with open(GENERIC_CLASS_PATH, 'r', encoding='utf-8') as f:
        generic_class = json.load(f)

    try:
        service.genericclass().insert(body=generic_class).execute()
        print("Classe genérica criada com sucesso")
    except Exception as e:
        if hasattr(e, 'status_code') and e.status_code == 409:
            print("Classe já existe, ignorando erro 409.")
        else:
            print("Erro criando classe genérica:", e)
            raise


def generate_wallet_jwt(credentials, object_id):
    iat = int(time.time())
    claims = {
        "iss": credentials.service_account_email,
        "aud": "google",
        "typ": "savetowallet",
        "iat": iat,
        "payload": {
            "genericObjects": [{"id": object_id}]
        }
    }
    signer = crypt.RSASigner.from_service_account_info(service_account_info)
    token = jwt.encode(signer, claims)
    if isinstance(token, bytes):
        token = token.decode('utf-8')
    return token


def get_balance_from_node(wallet_address):
    local_balance_api = f"https://bitcoin.btc3-explorer.com/balance/{wallet_address}"  # ajuste se necessário
    proxies = {
        "http": None,
        "https": None
    }
    try:
        resp = requests.get(local_balance_api, proxies=proxies, timeout=5)
        if resp.ok:
            data = resp.json()
            return float(data.get("balance", 0))
    except Exception as e:
        #print("Erro ao obter saldo:", e)
        return 0.0

import re

def validar_cartao(card_number, card_expiry, card_cvv):
    # Remove espaços e converte para maiúsculo
    card_number = card_number.replace(" ", "").upper()
    
    # Verifica se só tem hexadecimais (0-9 e A-F)
    if not re.fullmatch(r'[0-9A-F]+', card_number):
        return False, "Número do cartão inválido: deve conter apenas caracteres hexadecimais (0-9, A-F)"
    
    # Verifica tamanho mínimo e máximo (exemplo: 16 caracteres)
    if len(card_number) != 16:
        return False, "Número do cartão inválido: deve ter 16 caracteres"
    
    # Aqui pode validar validade e cvv como quiser
    # Exemplo: validade no formato MM/AA
    if not re.fullmatch(r'(0[1-9]|1[0-2])\/\d{2}', card_expiry):
        return False, "Validade inválida"
    
    # CVV só números, 3 ou 4 dígitos
    if not re.fullmatch(r'\d{3,4}', card_cvv):
        return False, "CVV inválido"
    
    return True, "Cartão válido"

@app.route("/add_wallet_card", methods=["POST"])
def add_wallet_card():
    data = request.form
    wallet_address = data.get("wallet_address", "").strip()
    card_number = data.get("card_number", "").strip()
    card_expiry = data.get("card_expiry", "").strip()
    card_cvv = data.get("card_cvv", "").strip()

    if not (wallet_address and card_number and card_expiry and card_cvv):
        return {"error": "Todos os campos são obrigatórios."}, 400

    valid, msg = validar_cartao(card_number, card_expiry, card_cvv)
    if not valid:
        return {"error": msg}, 400

    account_id = normalize_id(wallet_address)
    balance = get_balance_from_node(wallet_address)

    with open(GENERIC_OBJECT_PATH, "r", encoding="utf-8") as f:
        generic_object = json.load(f)
    with open(GENERIC_CLASS_PATH, "r", encoding="utf-8") as f:
        generic_class = json.load(f)

    generic_object["classId"] = generic_class["id"]
    generic_object["id"] = f"{generic_class['id'].split('.')[0]}.genericObject_{account_id}"

    # Campos internos do objeto
    generic_object["fields"] = [
        {"name": "numero_cartao", "value": card_number},
        {"name": "validade", "value": card_expiry},
        {"name": "cvv", "value": card_cvv},
        {"name": "saldo", "value": f"{balance:.8f} BTC3"}
    ]

    # Campos que aparecem na frente do cartão (visíveis)
    generic_object["secondaryFields"] = [
        {"label": "Número do Cartão", "value": card_number},
        {"label": "Validade", "value": card_expiry},
        {"label": "Saldo", "value": f"{balance:.8f} BTC3"}
    ]

    # Detalhes no menu de mais informações (3 pontinhos)
    generic_object["textModulesData"] = [{
        "header": "Detalhes do cartão",
        "body": f"💳 Número: {card_number}\n📅 Validade: {card_expiry}\n🔐 CVV: {card_cvv}\n💰 Saldo: {balance:.8f} BTC3",
        "headerColor": "#FFD700",
        "bodyColor": "#FFFFFF"
    }]

    generic_object["barcode"] = {
        "type": "qrCode",
        "value": card_number.replace(" ", "")
    }
    nfc_url = f"https://bitcoin.btc3-explorer.com/nfc?wallet_address={wallet_address}"
    generic_object["uris"] = [
        {
            "kind": "walletobjects#uri",
            "uri": nfc_url,
            "description": "Pagar usando NFC"
        }
    ]

    generic_object["cardTitle"] = {
        "defaultValue": {
            "language": "pt-BR",
            "value": "Cartão Débito/Crédito BTC3"
        }
    }
    generic_object["header"] = {
        "defaultValue": {
            "language": "pt-BR",
            "value": "Cartão BTC3"
        }
    }

    try:
        create_or_update_generic_object(generic_object)
    except Exception as e:
        logging.error(f"Erro Google Wallet: {e}")
        return {"error": "Erro interno ao criar o cartão."}, 500

    jwt_token = generate_wallet_jwt(credentials, generic_object['id'])
    wallet_url = f"https://pay.google.com/gp/v/save/{jwt_token}"

    return {"wallet_url": wallet_url}



def load_loyalty_class():
    path = os.path.join(BASE_DIR, 'loyalty-class.json')
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def create_loyalty_class():
    loyalty_class = load_loyalty_class()
    try:
        service.loyaltyclass().insert(body=loyalty_class).execute()
        print("Classe criada com sucesso")
    except Exception as e:
        if hasattr(e, 'status_code') and e.status_code == 409:
            print("Classe já existe, ignorando erro 409.")
        else:
            print("Erro criando classe:", e)
            raise


@app.route("/card", methods=["GET", "POST"])
def card():
    # Garantir que a classe genérica exista (criar se não existir)
    create_generic_class()

    if request.method == "POST":
        data = request.form
        wallet_address = data.get("wallet_address", "").strip()
        card_number = data.get("card_number", "").strip()
        expiry = data.get("card_expiry", "").strip()
        cvv = data.get("card_cvv", "").strip()

        if not wallet_address or not card_number or not expiry or not cvv:
            return "Todos os campos são obrigatórios.", 400

        account_id = normalize_id(wallet_address)
        balance = get_balance_from_node(wallet_address) or 0.0

        with open(GENERIC_OBJECT_PATH, 'r', encoding='utf-8') as f:
            generic_object = json.load(f)

        with open(GENERIC_CLASS_PATH, 'r', encoding='utf-8') as f:
            generic_class = json.load(f)

        generic_object['classId'] = generic_class['id']
        generic_object['id'] = f"{generic_class['id'].split('.')[0]}.genericObject_{account_id}"

        # Campos internos
        generic_object['fields'] = [
            {"name": "numero_cartao", "value": card_number},
            {"name": "validade", "value": expiry},
            {"name": "cvv", "value": cvv},
            {"name": "saldo", "value": f"{balance:.8f} BTC3"}
        ]

        # Campos que aparecem na frente do cartão
        generic_object['secondaryFields'] = [
            {"label": "Número do Cartão", "value": card_number},
            {"label": "Validade", "value": expiry},
            {"label": "Saldo", "value": f"{balance:.8f} BTC3"}
        ]

        # Dados extras que aparecem no detalhe (3 pontinhos)
        generic_object['textModulesData'] = [{
            "header": "Detalhes do cartão",
            "body": f"💳 Número: {card_number}\n📅 Validade: {expiry}\n🔐 CVV: {cvv}\n💰 Saldo: {balance:.8f} BTC3",
            "headerColor": "#FFD700",
            "bodyColor": "#FFFFFF"
        }]

        generic_object['barcode'] = {
            "type": "qrCode",
            "value": card_number.replace(" ", "")
        }

        generic_object["cardTitle"] = {
            "defaultValue": {
                "language": "pt-BR",
                "value": "Cartão Débito/Crédito BTC3"
            }
        }

        generic_object["header"] = {
            "defaultValue": {
                "language": "pt-BR",
                "value": "Cartão BTC3"
            }
        }

        generic_object["uris"] = [
            {
                "kind": "walletobjects#uri",
                "uri": f"http://127.0.0.1/nfc?wallet_address={wallet_address}",
                "description": "Pagar usando NFC"
            }
        ]

        try:
            create_or_update_generic_object(generic_object)
        except Exception as e:
            return f"Erro ao criar/atualizar objeto na Google Wallet: {e}", 500

        jwt_token = generate_wallet_jwt(credentials, generic_object['id'])
        wallet_url = f"https://pay.google.com/gp/v/save/{jwt_token}"

        return render_template(
            "CartaoKert.html",
            wallet_url=wallet_url,
            wallet_address=wallet_address,
            card_number=card_number,
            card_expiry=expiry,
            card_cvv=cvv
        )

    else:
        return render_template("CartaoKert.html")


@app.route('/nodes/resolve', methods=['GET'])
def nodes_resolve():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        return jsonify({'message': 'Cadeia substituída', 'replaced': True, 'chain_length': len(blockchain.chain)}), 200
    return jsonify({'message': 'Cadeia atual já é a mais longa ou não houve alteração', 'replaced': False, 'chain_length': len(blockchain.chain)}), 200

@app.route('/balance/<addr>', methods=['GET'])
def balance(addr):
    return jsonify({
        'address': addr,
        'balance': blockchain.balance(addr),
        'coin_name': COIN_NAME,
        'coin_symbol': COIN_SYMBOL
    }), 200

@app.route('/tx/new', methods=['POST'])
def tx_new():
    data = request.get_json()
    required = ['sender', 'recipient', 'amount', 'fee', 'signature', 'public_key']
    if not all(k in data for k in required):
        return jsonify({'message': 'Dados incompletos'}), 400

    sender = data['sender']
    public_key = data['public_key']
    signature = data['signature']

    # --- CORREÇÃO DE VALIDAÇÃO DE TRANSAÇÃO RECEBIDA (TX_NEW) ---
    # 1. Recria a mensagem exata que foi assinada pelo cliente.
    # A public_key e a signature NÃO fazem parte desta mensagem.
    message_to_verify_data = {
        'sender': data['sender'],
        'recipient': data['recipient'],
        'amount': data['amount'],
        'fee': data['fee']
    }
    message_to_verify = json.dumps(message_to_verify_data, sort_keys=True).encode()

    # 2. **PRIMEIRA VALIDAÇÃO CRÍTICA**: Derivar endereço da public_key e comparar com o sender.
    derived_address_from_public_key = hashlib.sha256(bytes.fromhex(public_key)).hexdigest()[:40]
    if derived_address_from_public_key != sender:
        print(f"[TX_NEW_ERROR] Mismatch: Sender '{sender}' vs Derived from Public Key '{derived_address_from_public_key}'")
        return jsonify({'message': 'Endereço não bate com a chave pública fornecida'}), 400

    try:
        # 3. **SEGUNDA VALIDAÇÃO CRÍTICA**: Verificar a assinatura.
        vk = VerifyingKey.from_string(bytes.fromhex(public_key), curve=SECP256k1)
        vk.verify(bytes.fromhex(signature), message_to_verify)
    except (BadSignatureError, ValueError) as e:
        print(f"[TX_NEW_ERROR] Assinatura inválida ou chave pública malformada: {e}")
        return jsonify({'message': f'Assinatura inválida ou chave pública malformada: {e}'}), 400

    # 4. Verificação de saldo.
    if float(data['amount']) + float(data['fee']) > blockchain.balance(sender):
        return jsonify({'message': 'Saldo insuficiente para a transação'}), 400
    # --- FIM DA CORREÇÃO DE VALIDAÇÃO ---

    idx = blockchain.new_tx(sender, data['recipient'], float(data['amount']), float(data['fee']), signature, public_key)
    broadcast_tx(data) # Broadcast da transação para outros nós
    return jsonify({
        'message': f'Transação adicionada à fila para o bloco {idx}',
        'coin_name': COIN_NAME,
        'coin_symbol': COIN_SYMBOL
    }), 201

@app.route('/transactions/pending', methods=['GET'])
def pending_transactions():
    return jsonify(blockchain.current_transactions), 200

def is_duplicate_transaction(new_tx, current_transactions):
    for tx in current_transactions:
        if (tx['signature'] == new_tx['signature'] and
            tx['sender'] == new_tx['sender'] and
            tx['recipient'] == new_tx['recipient'] and
            tx['amount'] == new_tx['amount']):
            return True
    return False

        
def comparar_ultimos_blocos():
    for peer in known_nodes:
        try:
            r = requests.get(f"{peer}/sync/check", timeout=5)
            data = r.json()
            local_block = blockchain.last_block()
            local_hash = hashlib.sha256(json.dumps({k: v for k, v in local_block.items() if k != 'transactions'}, sort_keys=True).encode()).hexdigest()

            if data['index'] == local_block['index'] and data['hash'] == local_hash:
                print(f"[SYNC] {peer} está sincronizado.")
            else:
                print(f"[SYNC] {peer} DIFERENTE! Index local: {local_block['index']} / peer: {data['index']}")
        except Exception as e:
            print(f"[SYNC] Falha ao verificar {peer}: {e}")
            
@app.route('/sync/check', methods=['GET'])
def check_sync():
    last = blockchain.last_block()
    local_hash = hashlib.sha256(json.dumps({k: v for k, v in last.items() if k != 'transactions'}, sort_keys=True).encode()).hexdigest()
    return jsonify({
        'index': last['index'],
        'hash': local_hash,
        'timestamp': last['timestamp'],
        'miner': last['miner'],
        'num_txs': len(last['transactions'])
    })

@app.route('/blocks/receive', methods=['POST'])
def receive_block():
    block = request.get_json()

    if not blockchain.chain:
        print("[ERRO] Bloco recebido mas a cadeia local está vazia. Precisa de sincronização inicial.")
        threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
        return jsonify({'message': 'Cadeia local vazia, por favor, sincronize primeiro'}), 400

    last_block = blockchain.last_block()

    # ⚠️ Verifica se o bloco está muito à frente
    if block['index'] > last_block['index'] + 1:
        print(f"[RECEIVE_BLOCK] Bloco muito à frente (Recebido: {block['index']} / Local: {last_block['index']})")
        threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
        return jsonify({'message': 'Bloco está muito à frente. Iniciando sincronização.'}), 202

    # Checagem de repetição do mesmo bloco
    if block['index'] <= last_block['index']:
        if (block['index'] == last_block['index'] and
            block['previous_hash'] == last_block['previous_hash'] and
            block['proof'] == last_block['proof']):
            return jsonify({'message': 'Bloco já recebido e processado'}), 200

        print(f"[RECEIVE_BLOCK] Bloco ({block['index']}) inesperado. Iniciando resolução de conflitos.")
        threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
        return jsonify({'message': 'Bloco duplicado ou antigo, resolução de conflitos iniciada'}), 409

    if block['index'] != last_block['index'] + 1:
        print(f"[RECEIVE_BLOCK] Índice inválido ({block['index']}), esperado: {last_block['index'] + 1}")
        threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
        return jsonify({'message': 'Índice do bloco incorreto, resolução de conflitos iniciada'}), 400

    last_block_hash = {k: v for k, v in last_block.items() if k != 'transactions'}
    expected_hash = hashlib.sha256(json.dumps(last_block_hash, sort_keys=True).encode()).hexdigest()

    if block['previous_hash'] != expected_hash:
        print(f"[RECEIVE_BLOCK] Hash anterior incorreto. Esperado: {expected_hash}, Recebido: {block['previous_hash']}")
        threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
        return jsonify({'message': 'Hash anterior incorreto, resolução de conflitos iniciada'}), 400

    expected_difficulty = blockchain._calculate_difficulty_for_index(block['index'])
    if not Blockchain.valid_proof(last_block['proof'], block['proof'], expected_difficulty):
        print(f"[RECEIVE_BLOCK] Proof inválido para bloco {block['index']} (Dificuldade {expected_difficulty})")
        threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
        return jsonify({'message': 'Proof inválido, resolução de conflitos iniciada'}), 400

    # --- Validação de transações ---
    for tx in block.get('transactions', []):
        if tx['sender'] == '0':
            continue  # Recompensa do minerador

        if blockchain.tx_already_mined(tx['id']):
            print(f"[RECEIVE_BLOCK] Transação duplicada detectada: {tx['id']}")
            threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
            return jsonify({'message': f'Transação duplicada já minerada: {tx["id"]}, resolução de conflitos iniciada'}), 400

        try:
            derived_address = hashlib.sha256(bytes.fromhex(tx['public_key'])).hexdigest()[:40]
            if derived_address != tx['sender']:
                raise ValueError(f"Sender '{tx['sender']}' não corresponde à public_key derivada '{derived_address}'")

            tx_data = {
                'sender': tx['sender'],
                'recipient': tx['recipient'],
                'amount': tx['amount'],
                'fee': tx['fee']
            }
            message = json.dumps(tx_data, sort_keys=True).encode()

            vk = VerifyingKey.from_string(bytes.fromhex(tx['public_key']), curve=SECP256k1)
            vk.verify(bytes.fromhex(tx['signature']), message)

        except Exception as e:
            print(f"[RECEIVE_BLOCK] Transação {tx['id']} inválida no bloco {block['index']}: {e}")
            threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
            return jsonify({'message': f'Transação inválida: {e}'}), 400
    # --- Fim da validação de transações ---

    print(f"[RECEIVE_BLOCK] Bloco {block['index']} aceito.")
    blockchain.chain.append(block)
    blockchain._save_block(block)

    mined_tx_ids = {t['id'] for t in block.get('transactions', [])}
    blockchain.current_transactions = [
        tx for tx in blockchain.current_transactions if tx['id'] not in mined_tx_ids
    ]

    global is_mining, miner_thread
    if is_mining:
        print("[RECEIVE_BLOCK] Reiniciando minerador após novo bloco.")
        is_mining = False
        time.sleep(0.5)
        is_mining = True
        miner_thread = threading.Thread(target=miner_loop, daemon=True)
        miner_thread.start()

    return jsonify({'message': 'Bloco aceito e adicionado'}), 200

def tx_already_mined(self, tx_id):
    for block in self.chain:
        for tx in block.get('transactions', []):
            if tx['id'] == tx_id:
                return True
    return False

def gerar_cartao_nfc(private_key):
    hash_key = hashlib.sha256(private_key.encode()).hexdigest()
    card_num_raw = hash_key[:16]
    card_number = " ".join([card_num_raw[i:i+4] for i in range(0, 16, 4)]).upper()
    
    cvv_source = int(hash_key[16:22], 16)
    cvv = str(cvv_source % 1000).zfill(3)

    now = datetime.now()

    # Derivar "anos de validade" a partir do hash, sempre o mesmo para a mesma chave
    years_offset = (int(hash_key[22:24], 16) % 4) + 2  # valor entre 2 e 5
    
    expiry_year = now.year + years_offset
    expiry = now.replace(year=expiry_year).strftime("%m/%y")

    balance = round(random.uniform(0, 10), 4)

    return {
        "card_number": card_number,
        "cvv": cvv,
        "expiry": expiry,
        "balance": str(balance)
    }

import traceback
import random

@app.route('/card/generate', methods=['POST'])
def generate_card():
    data = request.get_json()
    if not data or 'private_key' not in data:
        return jsonify({'error': 'Campo "private_key" obrigatório'}), 400

    private_key = data['private_key']

    try:
        result = gerar_cartao_nfc(private_key)
    except Exception as e:
        return jsonify({'error': f'Erro ao gerar cartão NFC: {str(e)}'}), 500

    return jsonify(result), 200



@app.route('/payment/receive', methods=['POST'])
def pay_approx():
    values = request.get_json()
    required = ['private_key', 'password', 'recipient', 'amount', 'sender', 'expiry']
    
    if not all(k in values for k in required):
        return jsonify({'error': 'Parâmetros faltando para pagamento por aproximação.'}), 400
    
    # Verifica validade do cartão
    if not validar_expiry(values['expiry']):
        return jsonify({'error': 'Cartão expirado.'}), 400

    try:
        res = requests.post("http://127.0.0.1:80/transfer", json={
            "private_key": values['private_key'],
            "sender": values['sender'],
            "recipient": values['recipient'],
            "amount": values['amount']
        })
        return jsonify(res.json()), res.status_code
    except Exception as e:
        return jsonify({'error': f'Erro ao realizar pagamento: {str(e)}'}), 500

   
def is_valid_block(block, previous_block):
    if block['index'] != previous_block['index'] + 1:
        return False

    block_prev_hash = block['previous_hash']
    expected_hash = hashlib.sha256(json.dumps(
        {k: v for k, v in previous_block.items() if k != 'transactions'}, sort_keys=True
    ).encode()).hexdigest()

    if block_prev_hash != expected_hash:
        return False

    expected_difficulty = blockchain._calculate_difficulty_for_index(block['index'])
    if not Blockchain.valid_proof(previous_block['proof'], block['proof'], expected_difficulty):
        return False

    # Validação de transações
    for tx in block.get('transactions', []):
        if tx['sender'] == '0':
            continue  # Transação de recompensa do minerador

        try:
            derived_address = hashlib.sha256(bytes.fromhex(tx['public_key'])).hexdigest()[:40]
            if derived_address != tx['sender']:
                return False

            tx_copy = {
                'sender': tx['sender'],
                'recipient': tx['recipient'],
                'amount': tx['amount'],
                'fee': tx['fee']
            }
            message = json.dumps(tx_copy, sort_keys=True).encode()
            vk = VerifyingKey.from_string(bytes.fromhex(tx['public_key']), curve=SECP256k1)
            vk.verify(bytes.fromhex(tx['signature']), message)

        except Exception:
            return False

    return True

# --- Funções de Peer-to-Peer ---
def broadcast_tx(tx_data):
    neighbors = list(known_nodes) # Copia para evitar problemas se o set mudar durante a iteração
    for node in neighbors:
        if node == meu_url:
            continue
        try:
            requests.post(f"{node}/tx/new", json=tx_data, timeout=2)
            # print(f"[BROADCAST] Transação enviada para {node}")
        except requests.exceptions.RequestException as e:
            print(f"[BROADCAST ERROR] Falha ao enviar transação para {node}: {e}")
            known_nodes.discard(node) # Remove peer que não responde
            salvar_peers(known_nodes)


def broadcast_block(block_data):
    neighbors = list(known_nodes)
    for node in neighbors:
        if node == meu_url:
            continue
        try:
            requests.post(f"{node}/blocks/receive", json=block_data, timeout=5)
            # print(f"[BROADCAST] Bloco {block_data['index']} enviado para {node}")
        except requests.exceptions.RequestException as e:
            print(f"[BROADCAST ERROR] Falha ao enviar bloco para {node}: {e}")
            known_nodes.discard(node)
            salvar_peers(known_nodes)

def discover_peers():
    global known_nodes, meu_url
    # Adicionar seed nodes se ainda não foram adicionados
    for seed in SEED_NODES:
        if seed not in known_nodes and seed != meu_url:
            known_nodes.add(seed)
            print(f"[DISCOVERY] Adicionando seed node: {seed}")
    
    salvar_peers(known_nodes) # Salva seeds e peers carregados

    initial_peers = list(known_nodes) # Copia para iterar
    for peer in initial_peers:
        if peer == meu_url:
            continue
        try:
            # Pede a lista de peers conhecidos do vizinho
            r = requests.get(f"{peer}/nodes", timeout=3)
            if r.status_code == 200:
                new_peers = r.json().get('nodes', [])
                for np in new_peers:
                    if np not in known_nodes and np != meu_url:
                        known_nodes.add(np)
                        print(f"[DISCOVERY] Descoberto novo peer {np} via {peer}")
                        salvar_peers(known_nodes) # Salva imediatamente
                        
                        # Tenta registrar-se no novo peer descoberto
                        try:
                            # Parse a URL para obter IP e Porta
                            parsed_url = urlparse(meu_url)
                            my_ip = parsed_url.hostname
                            my_port = parsed_url.port
                            requests.post(f"{np}/nodes/register", json={'ip': my_ip, 'port': my_port}, timeout=2)
                        except Exception as e:
                            print(f"[DISCOVERY ERROR] Falha ao registrar em {np}: {e}")

            # Registra-se com o vizinho
            parsed_url = urlparse(meu_url)
            my_ip = parsed_url.hostname
            my_port = parsed_url.port
            requests.post(f"{peer}/nodes/register", json={'ip': my_ip, 'port': my_port}, timeout=2)
            
        except requests.exceptions.RequestException as e:
            print(f"[DISCOVERY ERROR] Falha ao conectar/descobrir peer {peer}: {e}. Removendo.")
            known_nodes.discard(peer)
            salvar_peers(known_nodes)

@app.route('/nodes', methods=['GET'])
def get_nodes():
    return jsonify({'nodes': list(known_nodes)}), 200


# --- Inicialização ---
def get_my_ip():
    try:
        # Tenta obter o IP externo, pode não funcionar em todas as redes
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)) # Conecta a um IP externo (DNS do Google)
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1" # Retorna localhost como fallback

def discover_peers():
    global known_nodes, meu_url
    # Adicionar seed nodes se ainda não foram adicionados
    for seed in SEED_NODES:
        if seed not in known_nodes and seed != meu_url:
            known_nodes.add(seed)
            print(f"[DISCOVERY] Adicionando seed node: {seed}")
    
    salvar_peers(known_nodes) # Salva seeds e peers carregados

    initial_peers = list(known_nodes) # Copia para iterar
    for peer in initial_peers:
        if peer == meu_url:
            continue
        try:
            # Pede a lista de peers conhecidos do vizinho
            r = requests.get(f"{peer}/nodes", timeout=3)
            if r.status_code == 200:
                # --- START OF CORRECTION ---
                # Check if the 'nodes' value is a list of dictionaries or strings
                raw_new_peers = r.json().get('nodes', [])
                new_peers = []
                for item in raw_new_peers:
                    if isinstance(item, dict) and 'url' in item:
                        new_peers.append(item['url']) # Extract the URL string
                    elif isinstance(item, str):
                        new_peers.append(item) # It's already a URL string
                    # Else, ignore malformed entries
                # --- END OF CORRECTION ---

                for np in new_peers: # Now 'np' should always be a string
                    if np not in known_nodes and np != meu_url:
                        known_nodes.add(np)
                        print(f"[DISCOVERY] Descoberto novo peer {np} via {peer}")
                        salvar_peers(known_nodes) # Salva imediatamente
                        
                        # Tenta registrar-se no novo peer descoberto
                        try:
                            # Parse a URL para obter IP e Porta
                            parsed_url = urlparse(meu_url)
                            my_ip = parsed_url.hostname
                            my_port = parsed_url.port
                            requests.post(f"{np}/nodes/register", json={'ip': my_ip, 'port': my_port}, timeout=2)
                        except Exception as e:
                            print(f"[DISCOVERY ERROR] Falha ao registrar em {np}: {e}")

            # Registra-se com o vizinho
            parsed_url = urlparse(meu_url)
            my_ip = parsed_url.hostname
            my_port = parsed_url.port
            requests.post(f"{peer}/nodes/register", json={'ip': my_ip, 'port': my_port}, timeout=2)
            
        except requests.exceptions.RequestException as e:
            print(f"[DISCOVERY ERROR] Falha ao conectar/descobrir peer {peer}: {e}. Removendo.")
            known_nodes.discard(peer)
            salvar_peers(known_nodes)

def load_or_create_node_id(filename="node_id.txt"):
    if os.path.exists(filename):
        with open(filename, "r") as f:
            return f.read().strip()
    else:
        new_id = str(uuid4()).replace("-", "")[:16]
        with open(filename, "w") as f:
            f.write(new_id)
        return new_id

import sys
import os
import json
import hashlib
import time
import requests
import threading
from urllib.parse import urlparse
from collections import OrderedDict
from datetime import datetime

# Importações PyQt5 corrigidas
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QTextEdit, 
                             QVBoxLayout, QWidget, QLabel, QLineEdit, QFormLayout, 
                             QGroupBox, QMessageBox, QHBoxLayout, QTabWidget, 
                             QStatusBar, QDialog, QDialogButtonBox, QPlainTextEdit, 
                             QInputDialog)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer, Qt, QObject, QMetaObject, Q_ARG, QMutex, QMutexLocker
from PyQt5.QtGui import QFont, QColor, QPalette, QTextCursor, QDoubleValidator, QValidator 

# Importações para a lógica de criptografia (ecdsa)
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError

# --- Configurações Globais ---
NODE_ENDPOINT = "http://127.0.0.1:5000" 
WALLET_FILE = "client_wallet.json"
COIN_NAME = "KertCoin"
COIN_SYMBOL = "KRT"

# Variáveis globais para mineração



# --- Funções de Criptografia e Carteira ---

def gerar_endereco(public_key_hex):
    """Gera um endereço de carteira a partir de uma chave pública hexadecimal."""
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        return hashlib.sha256(public_key_bytes).hexdigest()[:40]
    except ValueError:
        return None

def sign_transaction(private_key_hex, tx_data):
    """Assina digitalmente os dados de uma transação usando a chave privada fornecida."""
    try:
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    except ValueError:
        return None
    
    message_data = OrderedDict([
        ('sender', tx_data['sender']),
        ('recipient', tx_data['recipient']),
        ('amount', float(tx_data['amount'])),
        ('fee', float(tx_data['fee']))
    ])
    
    message = json.dumps(message_data, sort_keys=True).encode('utf-8')
    signature = sk.sign(message).hex()
    return signature

def create_wallet():
    """Cria e retorna dados de uma nova carteira."""
    private_key_obj = SigningKey.generate(curve=SECP256k1)
    public_key_obj = private_key_obj.get_verifying_key()
    private_key_hex = private_key_obj.to_string().hex()
    public_key_hex = public_key_obj.to_string().hex()
    address = gerar_endereco(public_key_hex)

    if address is None:
        return None

    return {
        'private_key': private_key_hex,
        'public_key': public_key_hex,
        'address': address
    }

def load_wallet_file(filepath):
    """Carrega dados da carteira de um arquivo JSON."""
    if os.path.exists(filepath):
        try:
            with open(filepath, 'r') as f:
                wallet_data = json.load(f)
                if 'public_key' in wallet_data:
                    derived_addr_check = gerar_endereco(wallet_data['public_key'])
                    if derived_addr_check and derived_addr_check != wallet_data.get('address'):
                        wallet_data['address'] = derived_addr_check
                        with open(filepath, "w") as fw:
                            json.dump(wallet_data, fw, indent=4)
                return wallet_data
        except (json.JSONDecodeError, FileNotFoundError):
            return None
    return None

def save_wallet_file(wallet_data, filepath):
    """Salva dados da carteira em um arquivo JSON."""
    with open(filepath, 'w') as f:
        json.dump(wallet_data, f, indent=4)

# --- Cliente Kert-One Core GUI (QMainWindow) ---
class KertOneCoreClient(QMainWindow):
    start_mining_timer_signal = pyqtSignal()
    log_signal = pyqtSignal(str, str)
    chain_viewer_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Kert-One Core Client ({COIN_NAME})")
        self.setGeometry(100, 100, 1000, 700)
        self.mining_active = False
        self.miner_address = None
        self.wallet_data = None
        self.mineria_activa = False

        self.apply_dark_theme()
        self.setup_ui()
        self.load_wallet()

        self.chain_viewer_signal.connect(self.chain_viewer.setPlainText)
        self.log_signal.connect(self.update_log_viewer)
        self.start_mining_timer_signal.connect(self.start_mining_timer_safe)

        self.mining_timer = QTimer(self)
        self.mining_timer.setInterval(6000)
        self.mining_timer.timeout.connect(self.mine_block_via_api)

    @pyqtSlot()
    def start_mining_timer_safe(self):
        if not self.mineria_activa:
            self.mineria_activa = True
            self.mining_timer.start()
            self.log_signal.emit("Mineração iniciada com segurança.", "success")

    @pyqtSlot()
    def _start_mining_timer_safe(self):
        if not self.mineria_activa:
            self.mining_timer.start()
            self.mineria_activa = True
            self.log_signal.emit("Mineração automática iniciada.", "success")
        else:
            self.log_signal.emit("Mineração já está ativa.", "warning")
            
    # --- Configurações de UI e Tema ---

    def apply_dark_theme(self):
        """Aplica um tema escuro (Dark Mode)."""
        dark_palette = QPalette()
        dark_palette.setColor(QPalette.ColorRole.Window, QColor(45, 45, 45))
        dark_palette.setColor(QPalette.ColorRole.WindowText, QColor(200, 200, 200))
        dark_palette.setColor(QPalette.ColorRole.Base, QColor(30, 30, 30))
        dark_palette.setColor(QPalette.ColorRole.Text, QColor(200, 200, 200))
        dark_palette.setColor(QPalette.ColorRole.Button, QColor(60, 60, 60))
        dark_palette.setColor(QPalette.ColorRole.ButtonText, QColor(200, 200, 200))
        dark_palette.setColor(QPalette.ColorRole.Highlight, QColor(42, 130, 218))
        QApplication.instance().setPalette(dark_palette)
        
        self.setStyleSheet("""
            QWidget { background-color: rgb(45, 45, 45); color: rgb(200, 200, 200); }
            QPushButton { background-color: rgb(60, 60, 60); border: 1px solid rgb(80, 80, 80); padding: 8px; border-radius: 5px; }
            QPushButton:hover { background-color: rgb(80, 80, 80); }
            QPushButton:pressed { background-color: rgb(100, 100, 100); }
            QLineEdit, QTextEdit, QPlainTextEdit { background-color: rgb(30, 30, 30); border: 1px solid rgb(60, 60, 60); padding: 5px; border-radius: 3px; }
            QGroupBox { border: 1px solid rgb(80, 80, 80); margin-top: 10px; padding-top: 15px; }
            QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top left; padding: 0 5px; color: rgb(150, 150, 255); }
            QTabWidget::pane { border: 1px solid rgb(60, 60, 60); }
            QTabBar::tab { background: rgb(55, 55, 55); border: 1px solid rgb(60, 60, 60); padding: 8px; border-bottom: none; }
            QTabBar::tab:selected { background: rgb(75, 75, 75); border-bottom: none; }
            #LogViewer { background-color: #202020; color: #f0f0f0; border: none; }
        """)

    def setup_ui(self):
        """Configura a interface principal."""
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        # Tabs
        self.tabs = QTabWidget()
        self.tab_wallet = QWidget()
        self.tab_send = QWidget()
        self.tab_mine = QWidget()
        self.tab_network = QWidget()
        
        self.tabs.addTab(self.tab_wallet, "Carteira")
        self.tabs.addTab(self.tab_send, "Enviar")
        self.tabs.addTab(self.tab_mine, "Mineração")
        self.tabs.addTab(self.tab_network, "Rede/Blockchain")
        
        self.main_layout.addWidget(self.tabs)
        
        # Painel de Log
        self.log_viewer = QTextEdit() 
        self.log_viewer.setObjectName("LogViewer")
        self.log_viewer.setReadOnly(True)
        self.main_layout.addWidget(QLabel("Log de Atividade:"))
        self.main_layout.addWidget(self.log_viewer, 3)

        # Barra de Status
        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage(f"Cliente Kert-One conectado ao nó: {NODE_ENDPOINT}", 5000)

        # Configuração das abas
        self.setup_wallet_tab()
        self.setup_send_tab()
        self.setup_mine_tab()
        self.setup_network_tab()
        
        # Informações do Nó (no topo da janela)
        node_info_group = QGroupBox("Informações do Nó")
        node_info_layout = QFormLayout(node_info_group)
        
        self.node_id_label = QLabel(f"ID do Nó: <span style='font-weight:bold;'>{node_id[:8]}...</span>")
        self.node_url_label = QLabel("URL do Nó: <span style='font-weight:bold;'>Aguardando...</span>")
        # self.chain_length_label = QLabel("Comprimento da Cadeia: <span style='font-weight:bold;'>0</span>") # Removido
        # self.pending_tx_label = QLabel("Transações Pendentes: <span style='font-weight:bold;'>0</span>") # Removido
        self.main_layout.insertWidget(0, node_info_group) # Adiciona no topo
        
    @pyqtSlot(str)
    def _on_flask_url_ready(self, url):
        global NODE_ENDPOINT, meu_url
        # Força o NODE_ENDPOINT para o cliente local a ser 127.0.0.1
        NODE_ENDPOINT = "http://127.0.0.1:5000" 
        meu_url = url # O meu_url global ainda pode ser o IP externo para outros nós
        self.api_client.set_base_url(NODE_ENDPOINT) # Atualiza o base_url no API client para o IP local

        self.update_log_viewer(f"Servidor Flask pronto em: {meu_url} (cliente conectando via {NODE_ENDPOINT})", "success")
        self.node_url_label.setText(f"URL do Nó: <span style='font-weight:bold;'>{meu_url}</span>")
        self.status_bar.showMessage(f"Cliente Kert-One conectado ao nó: {NODE_ENDPOINT}", 5000)

        # Agora que o Flask está pronto, inicializa o MinerThread - REMOVIDO
        # self.miner_thread = MinerThread(self.api_client)
        # self.miner_thread.log_signal.connect(self.update_log_viewer)

        # Força uma atualização inicial da UI
        self.update_ui_info()

    def update_log_viewer(self, message, message_type="info"):
        """Adiciona mensagens ao visualizador de log com cores."""
        color_map = {
            "info": "#a0a0ff",    
            "success": "#66ff66", 
            "error": "#ff6666",   
            "warning": "#ffff66", 
            "default": "#f0f0f0"  
        }
        color = color_map.get(message_type, color_map["default"])
        
        timestamp = datetime.now().strftime('%H:%M:%S')
        formatted_message = f"[{timestamp}] {message}"
        
        self.log_viewer.append(f'<font color="{color}">{formatted_message}</font>')

    # --- Aba Carteira (Opções 1 e 2 do CLI) ---
    
    def setup_wallet_tab(self):
        layout = QVBoxLayout(self.tab_wallet)
        
        # Saldo e Endereço Atual
        wallet_group = QGroupBox("Carteira Atual")
        wallet_layout = QFormLayout(wallet_group)
        
        self.balance_label = QLabel(f"0.0 {COIN_SYMBOL}")
        self.balance_label.setFont(QFont("Arial", 28, QFont.Weight.Bold))
        
        self.address_label = QLineEdit("N/A")
        self.address_label.setReadOnly(True)
        self.public_key_label = QTextEdit("N/A")
        self.public_key_label.setReadOnly(True)
        self.public_key_label.setFixedHeight(80)
        
        wallet_layout.addRow("Saldo Atual:", self.balance_label)
        wallet_layout.addRow("Endereço:", self.address_label)
        wallet_layout.addRow("Chave Pública:", self.public_key_label)
        
        layout.addWidget(wallet_group)

        # Botões de Ação
        button_layout = QHBoxLayout()
        new_wallet_btn = QPushButton("Criar Nova Carteira")
        new_wallet_btn.clicked.connect(self.create_new_wallet)
        load_wallet_btn = QPushButton("Carregar Carteira (client_wallet.json)")
        load_wallet_btn.clicked.connect(self.load_wallet)
        check_balance_btn = QPushButton("Atualizar Saldo")
        check_balance_btn.clicked.connect(self.check_wallet_balance)

        button_layout.addWidget(new_wallet_btn)
        button_layout.addWidget(load_wallet_btn)
        button_layout.addWidget(check_balance_btn)
        layout.addLayout(button_layout)
        
        layout.addStretch(1)

    def create_new_wallet(self):
        """Cria uma nova carteira, salva e carrega na UI."""
        wallet_data = create_wallet()
        if wallet_data:
            save_wallet_file(wallet_data, WALLET_FILE)
            self.wallet_data = wallet_data
            self.update_wallet_status()
            self.log_signal.emit(f"Nova carteira criada e salva em {WALLET_FILE}.", "success")
            QMessageBox.information(self, "Carteira Criada", f"Nova carteira salva com sucesso. Endereço: {wallet_data['address']}")
            self.check_wallet_balance()
        else:
            self.log_signal.emit("Falha ao criar nova carteira.", "error")

    def load_wallet(self):
        """Carrega a carteira do arquivo e atualiza a UI."""
        self.wallet_data = load_wallet_file(WALLET_FILE)
        if self.wallet_data:
            self.update_wallet_status()
            self.log_signal.emit(f"Carteira carregada com sucesso.", "info")
            self.check_wallet_balance()
        else:
            self.update_wallet_status()
            self.log_signal.emit("Arquivo de carteira não encontrado ou corrompido.", "warning")
            
    def update_wallet_status(self):
        """Atualiza a UI com os dados da carteira carregada."""
        if self.wallet_data:
            self.address_label.setText(self.wallet_data.get('address', 'N/A'))
            self.public_key_label.setText(self.wallet_data.get('public_key', 'N/A'))
            self.status_bar.showMessage(f"Carteira carregada: {self.wallet_data['address']}", 5000)
        else:
            self.address_label.setText("N/A")
            self.public_key_label.setText("N/A")
            self.balance_label.setText("0.0 KRT")
            self.status_bar.showMessage("Nenhuma carteira carregada.", 5000)

    def check_wallet_balance(self):
        """Consulta o saldo da carteira carregada no nó da blockchain via API."""
        if not self.wallet_data:
            self.log_signal.emit("Nenhuma carteira carregada.", "warning")
            return

        address = self.wallet_data['address']
        
        # Usar uma thread para a chamada HTTP
        threading.Thread(target=self._fetch_balance_async, args=(address,)).start()

    def _fetch_balance_async(self, address):
        """Função para buscar o saldo em segundo plano."""
        try:
            response = requests.get(f"{NODE_ENDPOINT}/balance/{address}", timeout=5)
            response.raise_for_status()
            balance_data = response.json()
            balance = balance_data.get('balance', 0)
            
            # Atualizar a UI na thread principal via sinal
            self.balance_label.setText(f"{balance} {COIN_SYMBOL}")
            self.log_signal.emit(f"Saldo atualizado: {balance} {COIN_SYMBOL}", "info")
            
        except requests.exceptions.RequestException as e:
            self.log_signal.emit(f"Erro ao conectar ao nó ({NODE_ENDPOINT}) ou buscar saldo: {e}", "error")
            self.balance_label.setText("Erro de Conexão")

    # --- Aba Enviar (Opção 3 do CLI) ---

    def setup_send_tab(self):
        layout = QVBoxLayout(self.tab_send)
        
        # Campos de transação
        transaction_group = QGroupBox("Nova Transação")
        form_layout = QFormLayout(transaction_group)
        
        self.recipient_input = QLineEdit()
        self.amount_input = QLineEdit()
        self.fee_input = QLineEdit()
        
        # Validadores para garantir números flutuantes
        validator = QDoubleValidator(0.0, 100000000.0, 8, self) 
        validator.setNotation(QDoubleValidator.StandardNotation)
        
        self.amount_input.setValidator(validator)
        self.fee_input.setValidator(validator)

        form_layout.addRow("Destinatário (Endereço):", self.recipient_input)
        form_layout.addRow(f"Valor ({COIN_SYMBOL}):", self.amount_input)
        form_layout.addRow("Taxa (Fee):", self.fee_input)

        send_btn = QPushButton("Assinar e Enviar Transação")
        send_btn.clicked.connect(self.enviar_transacao)
        
        layout.addWidget(transaction_group)
        layout.addWidget(send_btn)
        layout.addStretch(1)

    def enviar_transacao(self):
        """Prepara, assina e envia a transação para o nó da blockchain via API."""
        if not self.wallet_data:
            QMessageBox.warning(self, "Aviso", "Nenhuma carteira carregada.")
            return

        recipient_addr = self.recipient_input.text().strip()
        amount_str = self.amount_input.text().strip().replace(',', '.')
        fee_str = self.fee_input.text().strip().replace(',', '.')

        if not recipient_addr or not amount_str or not fee_str:
            QMessageBox.warning(self, "Erro", "Todos os campos são obrigatórios.")
            return

        try:
            amount = float(amount_str)
            fee = float(fee_str)

            if amount <= 0 or fee < 0:
                raise ValueError("Valor e taxa devem ser válidos.")
            
            # Preparar dados para assinatura (conforme a função sign_transaction)
            tx_data_for_signing = {
                'sender': self.wallet_data['address'],
                'recipient': recipient_addr,
                'amount': amount,
                'fee': fee
            }
            
            # Assinar a transação
            signature = sign_transaction(self.wallet_data['private_key'], tx_data_for_signing)
            
            # CORREÇÃO: Usando 'is None' para verificar a assinatura
            if signature is None: 
                raise Exception("Falha ao assinar a transação.")

            # Dados completos para enviar ao nó (API)
            tx_full_data = {
                'sender': self.wallet_data['address'],
                'recipient': recipient_addr,
                'amount': amount,
                'fee': fee,
                'signature': signature,
                'public_key': self.wallet_data['public_key']
            }

            self.log_signal.emit("Enviando transação para o nó...", "info")
            
            # Enviar para o nó externo em uma thread separada
            threading.Thread(target=self._send_transaction_async, args=(tx_full_data,)).start()

        except ValueError as e:
            QMessageBox.critical(self, "Erro de Entrada", f"Valor inválido: {e}")
        except Exception as e:
            self.log_signal.emit(f"Ocorreu um erro inesperado: {e}", "error")

    def _send_transaction_async(self, tx_full_data):
        """Função para enviar a transação via HTTP em segundo plano."""
        try:
            response = requests.post(f"{NODE_ENDPOINT}/tx/new", json=tx_full_data, timeout=10)
            response.raise_for_status()

            if response.status_code in [200, 201]:
                self.log_signal.emit(f"Transação enviada com sucesso: {response.json().get('message')}", "success")
                # Limpa os campos após o sucesso
                # A atualização da UI é segura pois ocorre via sinal no log e no check_wallet_balance
                self._clear_transaction_fields()
                self.check_wallet_balance() 
            else:
                self.log_signal.emit(f"Erro ao enviar transação: {response.json().get('error', response.text)}", "error")

        except requests.exceptions.RequestException as e:
            self.log_signal.emit(f"Erro de conexão com o nó ({NODE_ENDPOINT}) ao enviar transação: {e}", "error")

    def _clear_transaction_fields(self):
        """Limpa os campos de input de transação."""
        self.recipient_input.clear()
        self.amount_input.clear()
        self.fee_input.clear()

    # --- Aba Mineração (Opções 4, 8, 9 do CLI) ---

    def setup_mine_tab(self):
        layout = QVBoxLayout(self.tab_mine)
        
        # Endereço de mineração
        mine_addr_group = QGroupBox("Configuração de Mineração")
        mine_addr_layout = QHBoxLayout(mine_addr_group)
        
        self.miner_addr_input = QLineEdit()
        self.miner_addr_input.setPlaceholderText("Endereço para recompensa (Opcional, usa a carteira carregada)")
        
        mine_addr_layout.addWidget(self.miner_addr_input)
        layout.addWidget(mine_addr_group)

        # Controles de Mineração
        mining_control_group = QGroupBox("Controle de Mineração")
        mining_control_layout = QHBoxLayout(mining_control_group)
        
        self.mine_single_btn = QPushButton("Minerar Bloco Único")
        self.start_mining_btn = QPushButton("Iniciar Mineração Contínua")
        self.stop_mining_btn = QPushButton("Parar Mineração Contínua")
        self.stop_mining_btn.setEnabled(False)

        self.mine_single_btn.clicked.connect(self.mine_single_block)
        self.start_mining_btn.clicked.connect(self.start_continuous_mining)
        self.stop_mining_btn.clicked.connect(self.stop_continuous_mining)

        mining_control_layout.addWidget(self.mine_single_btn)
        mining_control_layout.addWidget(self.start_mining_btn)
        mining_control_layout.addWidget(self.stop_mining_btn)
        
        layout.addWidget(mining_control_group)
        layout.addStretch(1)

    def get_miner_address(self):
        addr = self.miner_addr_input.text().strip()
        if addr:
            return addr
        if self.wallet_data and 'address' in self.wallet_data:
            return self.wallet_data['address']
        QMessageBox.warning(self, "Aviso", "Nenhum endereço de mineração fornecido e nenhuma carteira carregada.")
        return None


    def mine_single_block(self):
        """Inicia uma mineração de bloco único via API em thread separada."""
        miner_addr = self.get_miner_address()
        if miner_addr:
            self.log_signal.emit("Iniciando mineração de bloco único...", "info")
            threading.Thread(target=self._mine_async, args=(miner_addr,)).start()

    def start_continuous_mining(self):
        if self.mining_active:
            self.log_signal.emit("Mineração já está ativa.", "warning")
            return
    
        addr = self.get_miner_address()
        if not addr:
            return
    
        self.miner_address = addr
        self.mining_active = True
        self.mine_single_btn.setEnabled(False)
        self.start_mining_btn.setEnabled(False)
        self.stop_mining_btn.setEnabled(True)
        self.status_bar.showMessage(f"Mineração contínua ativa para {self.miner_address}...", 0)
        self.mining_timer.start(5000)  # 5 segundos
        self.log_signal.emit("Mineração contínua iniciada.", "success")

    def _set_miner_address_on_node(self, addr):
        """Define o endereço do minerador no nó externo em thread secundária."""
        try:
            set_addr_response = requests.post(f"{NODE_ENDPOINT}/miner/set_address", json={'address': addr})
            set_addr_response.raise_for_status()
            self.log_signal.emit(f"Endereço do minerador definido no nó: {set_addr_response.json().get('message')}", "success")
        except requests.exceptions.RequestException as e:
            self.log_signal.emit(f"Erro ao definir endereço do minerador no nó: {e}", "error")
        finally:
            # Chama o método de forma segura na thread principal
            QMetaObject.invokeMethod(self, "start_mining_timer_safe", Qt.QueuedConnection)


    def _start_mining_timer_safe(self):
        """
        Inicia o QTimer na thread principal. 
        Garantimos que esta função só é executada na thread da GUI.
        """
        global mining_active
        if not self.mining_active:
            mining_active = True
            self.mine_single_btn.setEnabled(False)
            self.start_mining_btn.setEnabled(False)
            self.stop_mining_btn.setEnabled(True)
            self.status_bar.showMessage(f"Mineração contínua ativa para {miner_address}...", 0)
            
            # AQUI O QTIMER É INICIADO NA THREAD PRINCIPAL
            self.mining_timer.start(5000) 
            self.log_signal.emit("Mineração contínua iniciada. Verificando novos blocos a cada 5 segundos.", "success")
        else:
            self.log_signal.emit("Mineração contínua já está ativa.", "warning")

    def stop_continuous_mining(self):
        if not self.mining_active:
            return
        self.mining_active = False
        self.mining_timer.stop()
        self.mine_single_btn.setEnabled(True)
        self.start_mining_btn.setEnabled(True)
        self.stop_mining_btn.setEnabled(False)
        self.status_bar.showMessage("Mineração contínua parada.", 5000)
        self.log_signal.emit("Mineração contínua parada.", "info")

    def _mine_async(self, miner_address):
        """Método que define o endereço do minerador e executa a mineração em thread separada."""
        try:
            # 1. Envia o endereço para o servidor
            self.log_signal.emit(f"Definindo endereço do minerador no nó...", "info")
            set_addr_response = requests.post(f"{NODE_ENDPOINT}/miner/set_address", json={"address": miner_address}, timeout=10)
            set_addr_response.raise_for_status()

            self.log_signal.emit(f"Endereço definido: {miner_address}. Iniciando mineração...", "info")

            # 2. Inicia a mineração (sem passar parâmetros)
            response = requests.get(f"{NODE_ENDPOINT}/mine", timeout=30)
            response.raise_for_status()

            result = response.json()
            self.log_signal.emit(f"✅ Bloco minerado com sucesso: {result.get('message', '')}", "success")
            self.check_wallet_balance()

        except requests.exceptions.RequestException as e:
            self.log_signal.emit(f"Erro na mineração: {e}", "error")

    def mine_block_via_api(self):
        if not self.mining_active:
            return

        if not self.miner_address:
            self.log_signal.emit("Endereço do minerador não definido. Abortando mineração.", "error")
            return

        threading.Thread(target=self._mine_async, args=(self.miner_address,)).start()

    def mine_block_via_api(self):
        if not self.mining_active:
            return
        threading.Thread(target=self._mine_async, args=(miner_address,)).start()


    def mine_block_via_api(self):
        if not self.mining_active:
            return
    
        if not self.miner_address:
            self.log_signal.emit("Endereço do minerador não definido. Abortando mineração.", "error")
            return

        # chama a mineração em thread separada, passando o endereço válido
        threading.Thread(target=self._mine_async, args=(self.miner_address,)).start()
    
    # --- Aba Rede/Blockchain (Opções 5, 6, 7 e 10 do CLI) ---

    def setup_network_tab(self):
        layout = QVBoxLayout(self.tab_network)
        
        # Visualização da Blockchain
        chain_group = QGroupBox("Blockchain View")
        chain_layout = QVBoxLayout(chain_group)
        
        # Usando QPlainTextEdit aqui, pois o conteúdo é texto puro e formatado por json.dumps
        self.chain_viewer = QPlainTextEdit()
        self.chain_viewer.setReadOnly(True)
        self.chain_viewer.setPlaceholderText("Clique em 'Ver Blockchain Completa' para carregar os dados do nó.")
        
        self.view_chain_btn = QPushButton("Ver Blockchain Completa")
        self.sync_chain_btn = QPushButton("Sincronizar Blockchain (Consenso)")
        
        chain_layout.addWidget(self.chain_viewer)
        chain_layout.addWidget(self.view_chain_btn)
        chain_layout.addWidget(self.sync_chain_btn)
        
        self.view_chain_btn.clicked.connect(self.view_blockchain)
        self.sync_chain_btn.clicked.connect(self.sync_blockchain)
        
        layout.addWidget(chain_group)

        # Opções de Rede
        network_options_group = QGroupBox("Opções de Rede")
        network_options_layout = QHBoxLayout(network_options_group)
        
        self.register_peer_btn = QPushButton("Registrar Novo Peer")
        self.consult_contract_btn = QPushButton("Consultar Contrato Inteligente")
        
        self.register_peer_btn.clicked.connect(self.register_peer_dialog)
        self.consult_contract_btn.clicked.connect(self.consult_contract_dialog)
        
        network_options_layout.addWidget(self.register_peer_btn)
        network_options_layout.addWidget(self.consult_contract_btn)
        
        layout.addWidget(network_options_group)
        layout.addStretch(1)

    def view_blockchain(self):
        """Busca e exibe a blockchain completa do nó."""
        self.log_signal.emit("Buscando blockchain completa...", "info")
        threading.Thread(target=self._fetch_blockchain_async).start()

    def _fetch_blockchain_async(self):
        """Função para buscar a blockchain em segundo plano."""
        try:
            response = requests.get(f"{NODE_ENDPOINT}/chain", timeout=10)
            response.raise_for_status()
            chain_data = response.json()
            
            # Formatar a saída para a UI
            formatted_chain = json.dumps(chain_data, indent=2)
            
            # Atualizar a UI na thread principal usando o sinal específico para o chain_viewer
            self.chain_viewer_signal.emit(formatted_chain)
            self.log_signal.emit(f"Blockchain carregada. Comprimento: {len(chain_data['chain'])} blocos.", "success")
        
        except requests.exceptions.RequestException as e:
            self.log_signal.emit(f"Erro ao buscar blockchain: {e}", "error")
            self.chain_viewer_signal.emit("Erro ao carregar a blockchain.")

    def sync_blockchain(self):
        """Inicia a sincronização da blockchain numa thread separada."""
        threading.Thread(target=self._sync_blockchain_async, daemon=True).start()
        
    def _sync_blockchain_async(self):
        while True:
            try:
                self.log_signal.emit("Iniciando sincronização (consenso)...", "info")
                response = requests.get(f"{NODE_ENDPOINT}/nodes/resolve", timeout=30)
                response.raise_for_status()
                data = response.json()

                if data.get("message") == "Nossa cadeia foi substituída":
                    self.log_signal.emit("Blockchain sincronizada com sucesso. Cadeia atualizada para a mais longa.", "success")
                    self.view_blockchain()  # Atualiza a UI após sincronizar
                else:
                    self.log_signal.emit("Blockchain já sincronizada ou não houve alteração.", "info")

            except requests.exceptions.RequestException as e:
                self.log_signal.emit(f"Erro ao sincronizar com o nó: {e}", "error")

            time.sleep(10)  # espera 10 segundos antes da próxima sincronização


    def register_peer_dialog(self):
        """Diálogo para registrar um novo peer."""
        text, ok = QInputDialog.getText(self, 'Registrar Peer', 'Digite a URL completa do novo peer (ex: http://IP:PORTA):')
        if ok and text:
            self.log_signal.emit(f"Tentando registrar peer: {text}", "info")
            threading.Thread(target=self._register_peer_async, args=(text,)).start()
    
    def set_miner_address_on_node(self, addr):
        try:
            response = requests.post(f"{NODE_ENDPOINT}/miner/set_address", json={"address": addr})
            response.raise_for_status()
            self.log_signal.emit(f"Endereço do minerador definido no nó: {addr}", "success")
        except requests.RequestException as e:
            self.log_signal.emit(f"Erro ao definir endereço do minerador: {e}", "error")

    
    def _register_peer_async(self, node_url):
        """Função para registrar peer em segundo plano."""
        try:
            # A API espera 'ip' e 'port' separados, então precisamos parsear a URL
            parsed_url = urlparse(node_url)
            peer_ip = parsed_url.hostname
            peer_port = parsed_url.port or 5000 

            if not peer_ip:
                self.log_signal.emit(f"URL do peer inválida: {node_url}", "error")
                return

            payload = {'ip': peer_ip, 'port': peer_port}
            response = requests.post(f"{NODE_ENDPOINT}/nodes/register", json=payload, timeout=10)
            response.raise_for_status()
            
            self.log_signal.emit(f"Peer '{node_url}' registrado com sucesso! Resposta: {response.json()}", "success")
        
        except requests.exceptions.RequestException as e:
            self.log_signal.emit(f"Erro ao registrar peer: {e}", "error")

    def consult_contract_dialog(self):
        """Diálogo para consultar um contrato inteligente."""
        text, ok = QInputDialog.getText(self, 'Consultar Contrato', 'Digite o endereço do contrato inteligente:')
        if ok and text:
            self.log_signal.emit(f"Consultando contrato: {text}", "info")
            threading.Thread(target=self._consult_contract_async, args=(text,)).start()

    def _consult_contract_async(self, contract_address):
        """Função para consultar contrato em segundo plano."""
        try:
            # Rota para consultar transações do contrato (baseado no seu código CLI)
            response = requests.get(f"{NODE_ENDPOINT}/contract/{contract_address}/transactions", timeout=10)
            response.raise_for_status()
            
            contract_data = response.json()
            formatted_data = json.dumps(contract_data, indent=2)
            
            # Emitir o log na thread principal
            self.log_signal.emit(f"Detalhes do Contrato ({contract_address}):\n{formatted_data}", "info")
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                self.log_signal.emit("Contrato não encontrado na blockchain.", "warning")
            else:
                self.log_signal.emit(f"Erro HTTP ao consultar contrato: {e}", "error")
        except requests.exceptions.RequestException as e:
            self.log_signal.emit(f"Erro de conexão ao consultar contrato: {e}", "error")


# --- Execução Principal ---
def run_server():
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)  # Rodar servidor Flask

if __name__ == "__main__":
    # Configurações iniciais do blockchain e rede
    conn = sqlite3.connect(DATABASE, check_same_thread=False)
    node_id = load_or_create_node_id()  # ou crie um node_id de outra forma
    blockchain = Blockchain(conn, node_id)

    port = int(os.environ.get('PORT', 5000))
    meu_ip = get_my_ip()
    meu_url = f"http://{meu_ip}:{port}"
    print(f"[INFO] Node URL: {meu_url}")

    # Iniciar descoberta de peers em thread separada
    threading.Thread(target=discover_peers, daemon=True).start()

    # Consenso inicial (se tiver peers)
    if len(known_nodes) > 0:
        print("[BOOT] Tentando resolver conflitos na inicialização...")
        blockchain.resolve_conflicts()
    else:
        print("[BOOT] Nenhum peer conhecido. Operando de forma isolada inicialmente.")

    # Iniciar servidor Flask em thread separada (para não bloquear GUI)
    threading.Thread(target=run_server, daemon=True).start()

    # Inicializar GUI PyQt
    qt_app = QApplication(sys.argv)
    window = KertOneCoreClient()
    window.show()
    sys.exit(qt_app.exec_())