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

# --- Configurações ---
DIFFICULTY = 1
MINING_REWARD = 50
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

    def tx_already_mined(self, tx_id):
        """Verifica se uma transação (pelo ID) já foi incluída em um bloco da cadeia principal."""
        c = self.conn.cursor()
        c.execute("SELECT 1 FROM txs WHERE id=?", (tx_id,))
        return c.fetchone() is not None

    def is_duplicate_transaction(self, new_tx):
        """
        Verifica se uma transação é duplicada na lista de transações pendentes,
        comparando campos-chave para evitar reprocessamento da mesma TX.
        """
        for tx in self.current_transactions:
            # Uma transação é considerada duplicada se todos os seus campos essenciais forem iguais.
            # O 'id' da transação é gerado por UUID e deveria ser único,
            # mas outros campos (sender, recipient, amount, etc.) são importantes para segurança.
            # Se o 'id' já for um UUID, essa verificação deve ser suficiente:
            if tx.get('id') == new_tx.get('id'):
                return True
            # No entanto, se o ID não for confiável ou for gerado múltiplas vezes para a mesma intenção,
            # uma comparação mais profunda é necessária:
            if (tx.get('sender') == new_tx.get('sender') and
                tx.get('recipient') == new_tx.get('recipient') and
                tx.get('amount') == new_tx.get('amount') and
                tx.get('fee') == new_tx.get('fee') and
                tx.get('signature') == new_tx.get('signature')): # A assinatura é o mais crítico aqui
                print(f"[DUPLICIDADE] Detectada transação pendente quase idêntica (sender={new_tx.get('sender')}, amount={new_tx.get('amount')}).")
                return True
        return False
        
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
        if target_block_index < self.ADJUST_INTERVAL:
            return DIFFICULTY

        current_calculated_difficulty = DIFFICULTY # Começa com a dificuldade base
        
        # Percorre os intervalos de ajuste para calcular a dificuldade até o bloco alvo
        for i in range(self.ADJUST_INTERVAL, target_block_index + 1, self.ADJUST_INTERVAL):
            start_block_index = i - self.ADJUST_INTERVAL
            end_block_index = i - 1
            
            # Garante que os blocos de referência existam na cadeia atual
            if end_block_index >= len(self.chain):
                # Se ainda não temos blocos suficientes para o próximo ajuste completo,
                # usamos a dificuldade do último ajuste calculado.
                break 

            start_time_window = self.chain[start_block_index]['timestamp']
            end_time_window = self.chain[end_block_index]['timestamp']
            
            actual_window_time = end_time_window - start_time_window
            expected_time = self.TARGET_TIME * self.ADJUST_INTERVAL
            
            if actual_window_time < expected_time / 2:
                current_calculated_difficulty += 1
            elif actual_window_time > expected_time * 2 and current_calculated_difficulty > 1:
                current_calculated_difficulty -= 1
        
        return current_calculated_difficulty

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
            # --- PONTO CRÍTICO: RESOLUÇÃO DE CONFLITOS ANTES DE MINERAR ---
            if blockchain.resolve_conflicts():
                print("[Miner] Cadeia foi substituída por uma mais longa da rede. Abortando tentativa atual de mineração e recomeçando.")
                # Se a cadeia foi substituída, as últimas informações mudaram.
                # É crucial RECOMEÇAR o loop para buscar a nova 'last_block' e 'current_transactions'.
                time.sleep(3) # Pequena pausa para evitar loops muito rápidos
                continue # Volta para o início do loop

            last = blockchain.last_block()
            if last is None:
                print("[Miner] Blockchain vazia. Aguardando inicialização (bloco Gênese)...")
                time.sleep(5)
                continue

            if not blockchain.current_transactions and len(blockchain.chain) > 1:
                print("[Miner] Nenhuma transação pendente. Aguardando...")
                time.sleep(10)
                continue

            # Inicia o PoW
            proof = blockchain.proof_of_work(last['proof'])

            if proof == -1:  # Abortado externamente (pelo /miner/stop ou nova cadeia)
                print("[Miner] Mineração abortada (sinal externo ou nova cadeia detectada durante PoW).")
                break # Sai do loop de mineração

            # --- Outra verificação após PoW ---
            # É fundamental verificar novamente se a cadeia não mudou enquanto o PoW estava rodando.
            new_last = blockchain.last_block()
            if new_last['index'] != last['index'] or new_last['previous_hash'] != last['previous_hash']:
                print("[Miner] Novo bloco chegou durante o Proof of Work. Recomeçando a mineração.")
                continue # Volta para o início do loop para pegar o novo 'last_block'

            previous_hash = hashlib.sha256(json.dumps(
                {k: v for k, v in last.items() if k != 'transactions'},
                sort_keys=True
            ).encode()).hexdigest()

            # ... (Restante da lógica de filtragem e validação de transações) ...
            valid_txs = []
            already_seen_tx_ids = set()

            for tx in blockchain.current_transactions:
                tx_id = tx.get('id')
                if not tx_id or tx_id in already_seen_tx_ids:
                    continue
                # 🛡️ Certifique-se de que tx_already_mined consulta o banco de dados principal
                if blockchain.tx_already_mined(tx_id):
                    print(f"[Miner] Transação {tx_id} já minerada. Ignorando.")
                    continue

                if tx['sender'] == '0': # Recompensa de mineração
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

                    balance = blockchain.balance(tx['sender']) # Considera transações pendentes e mineradas
                    if balance < (tx['amount'] + tx['fee']):
                        print(f"[Miner] TX {tx_id} com saldo insuficiente para {tx['sender']}. Ignorando.")
                        continue

                    valid_txs.append(tx)
                    already_seen_tx_ids.add(tx_id)

                except Exception as e:
                    print(f"[Miner] TX {tx_id} inválida ou malformada: {e}. Ignorando.")
                    continue

            # Atualiza transações pendentes após validação para este bloco
            # Isso é importante para que as transações inválidas ou já mineradas sejam removidas
            blockchain.current_transactions = valid_txs

            # Cria o novo bloco
            block = blockchain.new_block(proof, previous_hash, miner=miner_address)

            # ✅ Envia para os peers imediatamente
            broadcast_block(block)

            print(f"[Miner] ✅ Bloco #{block['index']} minerado com {len(valid_txs)} transações.")

        except Exception as e:
            print(f"[Miner ERROR] Erro no loop de mineração: {e}")
        
        # Pequeno atraso para não consumir 100% da CPU em loops vazios
        time.sleep(1) 

    print("[Miner] Minerador parado.")


def is_duplicate_transaction(new_tx, current_transactions):
    for tx in current_transactions:
        if (tx['signature'] == new_tx['signature'] and
            tx['sender'] == new_tx['sender'] and
            tx['recipient'] == new_tx['recipient'] and
            tx['amount'] == new_tx['amount']):
            return True
    return False

@app.route('/transactions/pending', methods=['GET'])
def pending_transactions():
    return jsonify(blockchain.current_transactions), 200
    
@app.route('/mine', methods=['GET'])
def mine_once():
    global is_mining, miner_lock, miner_address

    if not miner_address:
        return jsonify({"message": "Miner address not set. Use /miner/set_address first."}), 400

    with miner_lock:
        if is_mining:
            return jsonify({"message": "Miner loop is running. Please stop it before mining once."}), 409
        # Temporariamente defina is_mining como True para que o PoW possa ser abortado
        is_mining = True # Definido aqui e restaurado no `finally`

    try:
        # --- PONTO CRÍTICO: RESOLUÇÃO DE CONFLITOS ANTES DE MINERAR ---
        if blockchain.resolve_conflicts():
            print("[Mine Once] Cadeia foi substituída. Mineração abortada para recomeço.")
            return jsonify({"message": "Cadeia foi substituída pela rede. Por favor, tente minerar novamente."}), 409

        last = blockchain.last_block()
        if last is None:
            return jsonify({"message": "Blockchain not initialized. Genesis block missing."}), 500
        
        # Inicia o PoW
        proof = blockchain.proof_of_work(last['proof'])

        if proof == -1:
            print("[Mine Once] Mineração abortada durante PoW (sinal externo ou nova cadeia).")
            return jsonify({"message": "Mineração abortada (novo bloco recebido ou sinal de parada)."}), 200

        # --- Outra verificação após PoW ---
        new_last = blockchain.last_block()
        if new_last['index'] != last['index'] or new_last['previous_hash'] != last['previous_hash']:
            print("[Mine Once] Outro bloco chegou durante PoW. Abortando mineração.")
            return jsonify({"message": "Outro bloco chegou na rede enquanto minerava. Mineração abortada."}), 409

        previous_hash = hashlib.sha256(json.dumps(
            {k: v for k, v in last.items() if k != 'transactions'},
            sort_keys=True
        ).encode()).hexdigest()

        # 🔒 Validação das transações (já parece estar bem no seu código)
        valid_txs = []
        seen_tx_ids = set()
        for tx in blockchain.current_transactions:
            tx_id = tx.get('id')
            if not tx_id or tx_id in seen_tx_ids:
                continue
            if blockchain.tx_already_mined(tx_id): # Verifica se já está na cadeia principal
                print(f"[MineOnce] Transação {tx_id} já minerada. Ignorando.")
                continue

            if tx['sender'] == '0':
                valid_txs.append(tx)
                seen_tx_ids.add(tx_id)
                continue

            try:
                derived_address = hashlib.sha256(bytes.fromhex(tx['public_key'])).hexdigest()[:40]
                if derived_address != tx['sender']:
                    print(f"[MineOnce] TX {tx_id} inválida: endereço incorreto.")
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
                    print(f"[MineOnce] TX {tx_id} com saldo insuficiente para {tx['sender']}. Ignorando.")
                    continue

                valid_txs.append(tx)
                seen_tx_ids.add(tx_id)

            except Exception as e:
                print(f"[MineOnce] TX {tx_id} inválida: {e}")
                continue

        blockchain.current_transactions = valid_txs # Atualiza as transações pendentes

        block = blockchain.new_block(proof, previous_hash, miner=miner_address)
        broadcast_block(block)

        return jsonify({
            'message': 'Bloco minerado com sucesso!',
            'index': block['index'],
            'transactions': block['transactions'],
            'coin_name': COIN_NAME,
            'coin_symbol': COIN_SYMBOL
        }), 200

    finally:
        with miner_lock:
            is_mining = False # Garante que o sinal seja resetado



def broadcast_block(block):
    # Função placeholder para enviar bloco aos peers da rede
    print(f"[Broadcast] Bloco {block['index']} enviado para a rede.")
    
@app.route('/chain', methods=['GET'])
def chain():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
        'pending_transactions': blockchain.current_transactions, # Inclua as transações pendentes
        'coin_name': COIN_NAME,
        'coin_symbol': COIN_SYMBOL,
        'node_id': node_id
    }
    return jsonify(response), 200
    
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
                "uri": f"https://seend.kert-one.com/nfc?wallet_address={wallet_address}",
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
def new_transaction_api():
    values = request.get_json()
    required = ['sender', 'recipient', 'amount', 'fee', 'public_key', 'signature']
    if not all(k in values for k in required):
        # Registre a falta de valores para depuração
        missing = [k for k in required if k not in values]
        print(f"[ERRO 400] Valores faltando na transação: {missing}")
        return jsonify({'message': f'Valores faltando na requisição: {", ".join(missing)}'}), 400

    try:
        transaction = {
            'id': str(uuid4()), # Geração de ID da transação aqui. Essencial para rastrear.
            'sender': values['sender'],
            'recipient': values['recipient'],
            'amount': float(values['amount']), # Certifique-se que é float
            'fee': float(values['fee']),       # Certifique-se que é float
            'public_key': values['public_key'],
            'signature': values['signature']
        }
    except ValueError as e:
        print(f"[ERRO 400] Erro de tipo de dado na transação: {e}")
        return jsonify({'message': f'Dados de transação inválidos (tipo de dado): {e}'}), 400
    except Exception as e:
        print(f"[ERRO 400] Erro ao construir transação: {e}")
        return jsonify({'message': f'Erro ao processar dados da transação: {e}'}), 400

    # --- VERIFICAÇÃO DE DUPLICIDADE (MUITO IMPORTANTE) ---
    if blockchain.is_duplicate_transaction(transaction):
        print(f"[AVISO] Transação duplicada detectada para {transaction['sender']} -> {transaction['recipient']}. Ignorando.")
        return jsonify({'message': 'Transação duplicada detectada. Não foi adicionada novamente.'}), 200 # HTTP 200 OK ou 409 Conflict

    message_to_verify_data = {
        'sender': transaction['sender'],
        'recipient': transaction['recipient'],
        'amount': transaction['amount'],
        'fee': transaction['fee']
    }
    message_to_verify = json.dumps(message_to_verify_data, sort_keys=True).encode()

    try:
        derived_address = hashlib.sha256(bytes.fromhex(transaction['public_key'])).hexdigest()[:40]
        if derived_address != transaction['sender']:
            print(f"[ERRO 400] Assinatura inválida: Endereço do remetente ({transaction['sender']}) não corresponde à chave pública fornecida ({derived_address}).")
            return jsonify({'message': 'Assinatura inválida: Endereço do remetente não corresponde à chave pública fornecida'}), 400

        vk = VerifyingKey.from_string(bytes.fromhex(transaction['public_key']), curve=SECP256k1)
        vk.verify(bytes.fromhex(transaction['signature']), message_to_verify)
    except (BadSignatureError, ValueError) as e:
        print(f"[ERRO 400] Assinatura inválida ou chave pública malformada: {e}. TX ID: {transaction.get('id')}")
        return jsonify({'message': f'Assinatura inválida ou chave pública malformada: {e}'}), 400
    except Exception as e:
        print(f"[ERRO 400] Erro inesperado na validação de assinatura: {e}. TX ID: {transaction.get('id')}")
        return jsonify({'message': f'Erro inesperado na validação da transação: {e}'}), 400

    # Verificação de saldo
    current_balance = blockchain.balance(transaction['sender'])
    required_amount = transaction['amount'] + transaction['fee']
    if current_balance < required_amount:
        print(f"[ERRO 400] Saldo insuficiente para {transaction['sender']}: Necessário {required_amount}, Disponível {current_balance}. TX ID: {transaction.get('id')}")
        return jsonify({'message': f'Saldo insuficiente para a transação. Saldo atual: {current_balance}, Necessário: {required_amount}'}), 400

    # Adiciona a transação à lista de transações pendentes
    # Você já está criando o dicionário 'transaction' acima, pode passá-lo diretamente
    blockchain.current_transactions.append(transaction) # Adicione o dicionário 'transaction' diretamente
    
    # Notifica os outros nós sobre a nova transação pendente
    broadcast_tx_to_peers(transaction) # Chame a função de broadcast

    response = {'message': f'Transação adicionada à fila de transações pendentes.',
                'coin_name': COIN_NAME,
                'coin_symbol': COIN_SYMBOL,
                'transaction_id': transaction['id']} # Retorne o ID da transação
    return jsonify(response), 201

# Adicione esta função para broadcast de transações se ainda não tiver
def broadcast_tx_to_peers(tx):
    print(f"[Broadcast TX] Enviando transação {tx.get('id')} para peers.")
    for peer in known_nodes.copy():
        try:
            requests.post(f"{peer}/tx/receive", json=tx, timeout=3)
        except requests.exceptions.RequestException as e:
            print(f"[Broadcast TX] Erro ao enviar TX para {peer}: {e}")
            # Considerar remover peers problemáticos, mas com cuidado
            # known_nodes.discard(peer)
            # salvar_peers(known_nodes)

# Rota para receber transações de outros nós
@app.route('/tx/receive', methods=['POST'])
def receive_transaction():
    tx_data = request.get_json()
    if not tx_data:
        return jsonify({"message": "Nenhum dado de transação recebido."}), 400

    # Recrie o objeto Transaction (ou dicionário) para validação
    # É crucial validar a transação recebida de um peer, assim como você faz em /tx/new
    # Não confie que peers enviem transações válidas sem revalidação completa.
    required = ['id', 'sender', 'recipient', 'amount', 'fee', 'public_key', 'signature']
    if not all(k in tx_data for k in required):
        return jsonify({'message': 'Dados de transação incompletos.'}), 400

    # Revalidação completa da transação recebida
    try:
        # Primeiro, verifique se a transação já está na fila de pendentes
        if blockchain.is_duplicate_transaction(tx_data):
            print(f"[RECEIVE TX] Transação {tx_data.get('id')} já existe na fila pendente. Ignorando.")
            return jsonify({'message': 'Transação já conhecida.'}), 200

        # Verificação de assinatura e saldo, igual à lógica em /tx/new
        message_to_verify_data = {
            'sender': tx_data['sender'],
            'recipient': tx_data['recipient'],
            'amount': tx_data['amount'],
            'fee': tx_data['fee']
        }
        message_to_verify = json.dumps(message_to_verify_data, sort_keys=True).encode()

        derived_address = hashlib.sha256(bytes.fromhex(tx_data['public_key'])).hexdigest()[:40]
        if derived_address != tx_data['sender']:
            print(f"[RECEIVE TX ERROR] TX {tx_data.get('id')}: Endereço ({tx_data['sender']}) não bate com chave pública.")
            return jsonify({'message': 'Transação inválida: Endereço do remetente não corresponde à chave pública.'}), 400

        vk = VerifyingKey.from_string(bytes.fromhex(tx_data['public_key']), curve=SECP256k1)
        vk.verify(bytes.fromhex(tx_data['signature']), message_to_verify)

        # Verificação de saldo - IMPORTANTE para evitar ataques de duplo gasto
        # Aqui, o balanço deve considerar a cadeia atual e as transações JÁ processadas.
        # Não considere o balanço incluindo a própria transação que você está tentando adicionar.
        # Sua função `balance` já considera `current_transactions`, então ela está OK.
        current_balance = blockchain.balance(tx_data['sender'])
        required_amount = tx_data['amount'] + tx_data['fee']
        if current_balance < required_amount:
            print(f"[RECEIVE TX ERROR] TX {tx_data.get('id')}: Saldo insuficiente para {tx_data['sender']}.")
            return jsonify({'message': 'Transação inválida: Saldo insuficiente.'}), 400

        # Se todas as validações passarem, adicione à lista de pendentes
        blockchain.current_transactions.append(tx_data)
        print(f"[RECEIVE TX] Transação {tx_data.get('id')} recebida e adicionada à fila pendente.")
        return jsonify({"message": "Transação recebida e adicionada com sucesso."}), 200

    except (BadSignatureError, ValueError) as e:
        print(f"[RECEIVE TX ERROR] Erro de validação de assinatura ou formato para TX {tx_data.get('id')}: {e}")
        return jsonify({'message': f'Transação inválida: Erro de assinatura ou formato: {e}'}), 400
    except Exception as e:
        print(f"[RECEIVE TX ERROR] Erro inesperado ao processar TX {tx_data.get('id')}: {e}")
        return jsonify({'message': f'Erro interno ao processar transação: {e}'}), 500

@app.route('/blocks/receive', methods=['POST'])
def receive_block():
    block_data = request.get_json() # Renomeado para 'block_data' para clareza
    if not block_data:
        print("[RECEIVE_BLOCK ERROR] Nenhum dado de bloco recebido.")
        return jsonify({"message": "Nenhum dado de bloco recebido."}), 400

    # 1. Verificação inicial da estrutura do bloco
    required_keys = ['index', 'previous_hash', 'proof', 'timestamp', 'miner', 'transactions', 'difficulty']
    if not all(k in block_data for k in required_keys):
        print(f"[RECEIVE_BLOCK ERROR] Bloco recebido com chaves faltando: {block_data}")
        return jsonify({"message": "Dados de bloco incompletos ou malformados."}), 400

    # 2. Lógica para cadeia vazia local
    if not blockchain.chain:
        print("[RECEIVE_BLOCK INFO] Cadeia local vazia. Iniciando resolução de conflitos para sincronização inicial.")
        # Inicia a resolução de conflitos em background. Não rejeita o bloco imediatamente,
        # pois ele pode ser o primeiro de uma cadeia válida que precisamos.
        threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
        return jsonify({'message': 'Cadeia local vazia. Tentando sincronizar com a rede.'}), 202 # Aceito, mas aguardando sincronização

    last_local_block = blockchain.last_block()

    # 3. Bloco já conhecido ou antigo (Baseado no índice)
    if block_data['index'] <= last_local_block['index']:
        # Se o índice é igual ao último local, verifica se é o mesmo bloco (duplicata)
        if block_data['index'] == last_local_block['index'] and \
           block_data['previous_hash'] == last_local_block['previous_hash'] and \
           block_data['proof'] == last_local_block['proof'] and \
           block_data['miner'] == last_local_block['miner']: # Adicione mais campos para uma verificação mais robusta
            print(f"[RECEIVE_BLOCK INFO] Bloco {block_data['index']} já recebido e processado (duplicata).")
            return jsonify({'message': 'Bloco já recebido e processado'}), 200
        else:
            # Bloco antigo ou de uma fork mais curta/inválida.
            # Não precisamos resolver conflitos aqui, pois já estamos à frente ou em uma fork mais longa.
            print(f"[RECEIVE_BLOCK INFO] Bloco {block_data['index']} é antigo ou de uma fork mais curta/inválida (Local: {last_local_block['index']}). Ignorando.")
            return jsonify({'message': 'Bloco antigo ou de uma fork não relevante.'}), 200 # OK, mas não adicionado

    # 4. Validação do Bloco como o PRÓXIMO na sequência
    if block_data['index'] == last_local_block['index'] + 1:
        # Verifica se o hash anterior do bloco recebido corresponde ao hash do último bloco local
        expected_previous_hash = blockchain.hash(last_local_block)
        if block_data['previous_hash'] != expected_previous_hash:
            print(f"[RECEIVE_BLOCK ERROR] Bloco {block_data['index']}: Hash anterior incorreto. Esperado: {expected_previous_hash}, Recebido: {block_data['previous_hash']}. Iniciando sincronização.")
            threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
            return jsonify({'message': 'Hash anterior incorreto, resolução de conflitos iniciada'}), 400

        # Verifica a prova de trabalho do bloco recebido
        expected_difficulty = blockchain._calculate_difficulty_for_index(block_data['index'])
        if not Blockchain.valid_proof(last_local_block['proof'], block_data['proof'], expected_difficulty):
            print(f"[RECEIVE_BLOCK ERROR] Bloco {block_data['index']}: Proof of Work inválido para dificuldade {expected_difficulty}. Iniciando sincronização.")
            threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
            return jsonify({'message': 'Proof inválido, resolução de conflitos iniciada'}), 400

        # Validação das transações dentro do bloco
        for tx in block_data.get('transactions', []):
            if tx['sender'] == '0': # Recompensa do minerador
                continue
            
            # 🛡️ Validação completa da transação (assinatura, chave pública, etc.)
            # Você já tem essa lógica, apenas garanta que ela esteja 100% correta e robusta.
            # Se uma transação for inválida, o bloco inteiro é inválido.
            try:
                derived_address = hashlib.sha256(bytes.fromhex(tx['public_key'])).hexdigest()[:40]
                if derived_address != tx['sender']:
                    raise ValueError(f"Sender '{tx['sender']}' não corresponde à public_key derivada '{derived_address}'")

                tx_data_for_verify = {
                    'sender': tx['sender'],
                    'recipient': tx['recipient'],
                    'amount': tx['amount'],
                    'fee': tx['fee']
                }
                message = json.dumps(tx_data_for_verify, sort_keys=True).encode()
                vk = VerifyingKey.from_string(bytes.fromhex(tx['public_key']), curve=SECP256k1)
                vk.verify(bytes.fromhex(tx['signature']), message)

                # ⚠️ Não faça verificação de saldo aqui para transações já mineradas em um bloco recebido,
                # pois o saldo pode ter mudado. A validação de saldo é feita quando a TX é criada/adicionada à fila.
                # A validação de TXs em blocos recebidos deve focar na criptografia (assinatura).

            except Exception as e:
                print(f"[RECEIVE_BLOCK ERROR] Transação {tx.get('id', 'N/A')} inválida no bloco {block_data['index']}: {e}. Iniciando sincronização.")
                threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
                return jsonify({'message': f'Transação inválida no bloco: {e}'}), 400
        
        # Se todas as validações acima passarem, o bloco é o próximo válido na sequência
        print(f"[RECEIVE_BLOCK SUCCESS] Bloco {block_data['index']} aceito e adicionado localmente.")
        blockchain.chain.append(block_data)
        blockchain._save_block(block_data) # Salva no DB

        # Remova as transações do bloco da fila de pendentes
        mined_tx_ids = {t.get('id') for t in block_data.get('transactions', []) if t.get('id')}
        blockchain.current_transactions = [
            tx for tx in blockchain.current_transactions if tx.get('id') not in mined_tx_ids
        ]
        print(f"[RECEIVE_BLOCK] Removidas {len(mined_tx_ids)} transações da fila pendente.")

        # Sinaliza o minerador local para parar e recomeçar (se estiver ativo)
        global is_mining
        with miner_lock:
            if is_mining:
                print("[RECEIVE_BLOCK] Novo bloco aceito. Sinalizando minerador para parar e recomeçar.")
                is_mining = False # Isso fará o miner_loop/PoW atual abortar
                # O miner_loop reiniciará automaticamente ou será reiniciado pela lógica externa
        
        return jsonify({'message': 'Bloco aceito e adicionado'}), 200

    # 5. Bloco está mais à frente, mas não é o próximo imediato (indica uma fork)
    elif block_data['index'] > last_local_block['index'] + 1:
        print(f"[RECEIVE_BLOCK INFO] Bloco {block_data['index']} está à frente da cadeia local ({last_local_block['index']}). Iniciando resolução de conflitos.")
        threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
        return jsonify({'message': 'Bloco está à frente. Iniciando sincronização.'}), 202 # Aceito, mas aguardando sincronização

    # 6. Caso inesperado (deveria ser pego pelas condições acima)
    print(f"[RECEIVE_BLOCK WARNING] Condição inesperada para bloco {block_data['index']}. Iniciando resolução de conflitos.")
    threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
    return jsonify({'message': 'Bloco com status inesperado, resolução de conflitos iniciada'}), 400
        
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
        res = requests.post("https://seend.kert-one.com/transfer", json={
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


def broadcast_block(block):
    """Envia um bloco recém-minerado para todos os peers conhecidos."""
    print(f"[BROADCAST] Enviando bloco #{block['index']} para {len(known_nodes)} peers...")
    peers_to_remove = set()
    for peer in known_nodes.copy(): # Itera sobre uma cópia para permitir modificação
        if peer == meu_url: continue # Não envie para si mesmo
        try:
            # Use um timeout para evitar que um peer lento pare o broadcast
            requests.post(f"{peer}/blocks/receive", json=block, timeout=5)
        except requests.exceptions.RequestException as e:
            print(f"[BROADCAST] Erro ao enviar bloco para {peer}: {e}. Removendo peer (se não for seed).")
            if peer not in SEED_NODES: # Não remove seed nodes automaticamente
                peers_to_remove.add(peer)
        except Exception as e:
            print(f"[BROADCAST] Erro inesperado ao enviar bloco para {peer}: {e}")
    
    # Remove peers problemáticos após o loop
    if peers_to_remove:
        known_nodes.difference_update(peers_to_remove)
        salvar_peers(known_nodes)
        print(f"[BROADCAST] Removidos {len(peers_to_remove)} peers problemáticos.")


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
                            parsed_url = urlparse(url)
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
        return "https://seend.kert-one.com" # Retorna localhost como fallback

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
        
if __name__ == '__main__':
    conn = sqlite3.connect(DATABASE, check_same_thread=False)
    node_id = load_or_create_node_id()  # ou crie um node_id de outra forma
    blockchain = Blockchain(conn, node_id)

    port = int(os.environ.get('PORT', 5000))
    meu_ip = get_my_ip()
    meu_url = f"http://{meu_ip}:{port}"
    print(f"[INFO] Node URL: {meu_url}")

    # Iniciar descoberta de peers em um thread separado
    threading.Thread(target=discover_peers, daemon=True).start()

    # Consenso inicial (se tiver peers)
    if len(known_nodes) > 0:
        print("[BOOT] Tentando resolver conflitos na inicialização...")
        blockchain.resolve_conflicts()
    else:
        print("[BOOT] Nenhum peer conhecido. Operando de forma isolada inicialmente.")

    app.run(host='0.0.0.0', port=port)