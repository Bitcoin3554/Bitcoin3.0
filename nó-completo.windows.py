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
import shutil
from flask import Flask, render_template, flash
from flask_cors import CORS
from PyQt5.QtCore import pyqtSlot

# Importações PyQt5
from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QTextEdit, 
                             QVBoxLayout, QWidget, QLabel, QLineEdit, QFormLayout, 
                             QGroupBox, QMessageBox, QHBoxLayout, QTabWidget, 
                             QStatusBar, QDialog, QDialogButtonBox, QPlainTextEdit, 
                             QInputDialog)
from PyQt5.QtCore import QThread, pyqtSignal, QTimer, Qt, QObject, QMetaObject, Q_ARG, QMutex, QMutexLocker
from PyQt5.QtGui import QFont, QColor, QPalette, QTextCursor, QDoubleValidator, QValidator 


# --- Configurações ---
DIFFICULTY = 1 # Dificuldade inicial para o bloco Gênese
MINING_REWARD = 50 # Recompensa padrão (será sobrescrita pela lógica de halving)
DATABASE = 'chain.db'
COIN_NAME = "Kert-One"
COIN_SYMBOL = "KERT"
PEERS_FILE = 'peers.json'
WALLET_FILE = "client_wallet.json" # Caminho para o arquivo da carteira do cliente

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
    """Salva a lista de peers conhecidos em um arquivo JSON."""
    with open(PEERS_FILE, 'w') as f:
        json.dump(list(peers), f)

def carregar_peers():
    """Carrega a lista de peers conhecidos de um arquivo JSON."""
    if not os.path.exists(PEERS_FILE):
        return []
    with open(PEERS_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            print(f"[ERRO] {PEERS_FILE} está corrompido ou vazio. Recriando.")
            return []

known_nodes = set(carregar_peers())
miner_lock = threading.Lock()

blockchain = None
miner_address = None # Agora será definido por um endpoint ou configuração
meu_url = None # Definido no main
meu_ip = None # Definido no main
port = None # Definido no main

# Global variable for mining control
is_mining = False

# --- Classe Blockchain ---
class Blockchain:
    ADJUST_INTERVAL = 2016 # Blocos para recalcular dificuldade
    TARGET_TIME = 600 # Tempo alvo entre blocos em segundos (10 minutos)

    def __init__(self, conn, node_id):
        self.conn = conn
        self.node_id = node_id
        self._init_db()
        self.chain = self._load_chain()
        self.current_transactions = []

        if not self.chain:
            print("[BOOT] Criando bloco Gênese...")
            genesis_difficulty = DIFFICULTY
            self.new_block(proof=100, previous_hash='1', miner=self.node_id, initial_difficulty=genesis_difficulty)
            
        self.difficulty = self._calculate_difficulty_for_index(len(self.chain))
        print(f"[BOOT] Dificuldade inicial da cadeia: {self.difficulty}")

    @staticmethod
    def hash(block):
        """
        Cria um hash SHA-256 de um Bloco.
        Ignora o campo 'transactions' e 'hash' (se presente) para hashing.
        """
        block_string = json.dumps({k: v for k, v in block.items() if k not in ['transactions', 'hash']}, sort_keys=True)
        return hashlib.sha256(block_string.encode()).hexdigest()

    def is_duplicate_transaction(self, new_tx):
        """Verifica se uma transação já está na fila de transações pendentes."""
        for tx in self.current_transactions:
            if tx.get('id') == new_tx.get('id'):
                return True
            # Compara com uma pequena tolerância para floats, mas idealmente amount/fee são strings agora
            if (tx.get('sender') == new_tx.get('sender') and
                tx.get('recipient') == new_tx.get('recipient') and
                tx.get('amount') == new_tx.get('amount') and # Agora compara strings
                tx.get('fee') == new_tx.get('fee') and       # Agora compara strings
                tx.get('signature') == new_tx.get('signature')):
                print(f"[DUPLICIDADE] Detectada transação pendente quase idêntica (sender={new_tx.get('sender')}, amount={new_tx.get('amount')}).")
                return True
        return False

    @staticmethod
    def custom_asic_resistant_hash(data_bytes, nonce):
        """Função de hash resistente a ASICs."""
        raw = data_bytes + str(nonce).encode()
        h1 = hashlib.sha256(raw).digest()
        h2 = hashlib.sha512(h1).digest()
        h3 = hashlib.blake2b(h2).digest()
        return hashlib.sha256(h3).hexdigest()

    def _init_db(self):
        """Inicializa o esquema do banco de dados SQLite."""
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
        # Armazenar amount e fee como TEXT para evitar problemas de float precision
        c.execute('''
            CREATE TABLE IF NOT EXISTS txs(
                id TEXT PRIMARY KEY,
                sender TEXT,
                recipient TEXT,
                amount TEXT,  -- Alterado para TEXT
                fee TEXT,     -- Alterado para TEXT
                signature TEXT,
                block_index INTEGER,
                public_key TEXT
            )
        ''')
        self.conn.commit()

    def _load_chain(self):
        """Carrega a cadeia de blocos do banco de dados."""
        c = self.conn.cursor()
        c.execute("SELECT index_, previous_hash, proof, timestamp, miner, difficulty FROM blocks ORDER BY index_")
        chain = []
        for idx, prev, proof, ts, miner, difficulty in c.fetchall():
            c.execute("SELECT id, sender, recipient, amount, fee, signature, public_key FROM txs WHERE block_index=?", (idx,))
            txs = []
            for r in c.fetchall():
                # amount e fee são armazenados como TEXT, então os usamos diretamente
                txs.append(dict(id=r[0], sender=r[1], recipient=r[2], 
                                amount=r[3], 
                                fee=r[4],     
                                signature=r[5], public_key=r[6]))
            block = {
                'index': idx,
                'previous_hash': prev,
                'proof': proof,
                'timestamp': ts,
                'miner': miner,
                'transactions': txs,
                'difficulty': difficulty
            }
            chain.append(block)
        return chain

    def new_block(self, proof, previous_hash, miner, initial_difficulty=None):
        """Cria um novo bloco e o adiciona à cadeia."""
        block_index = len(self.chain) + 1
        reward = self._get_mining_reward(block_index)
        
        difficulty = self._calculate_difficulty_for_index(block_index) if initial_difficulty is None else initial_difficulty

        # Recompensa de mineração como string formatada
        mining_reward_tx = {
            'id': str(uuid4()), 'sender': '0', 'recipient': miner,
            'amount': f"{reward:.8f}", 'fee': f"{0.0:.8f}", 'signature': '', 'public_key': ''
        }
        
        if not (proof == 100 and previous_hash == '1'):
             self.current_transactions.insert(0, mining_reward_tx)

        block = {
            'index': block_index,
            'previous_hash': previous_hash,
            'proof': proof,
            'timestamp': time.time(),
            'miner': miner,
            'transactions': self.current_transactions,
            'difficulty': difficulty
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
        """Salva um bloco e suas transações no banco de dados."""
        c = self.conn.cursor()
        c.execute("INSERT INTO blocks VALUES (?, ?, ?, ?, ?, ?)",
                  (block['index'], block['previous_hash'], block['proof'],
                   block['timestamp'], block['miner'], block['difficulty']))
        for t in block['transactions']:
            # Salvar amount e fee como TEXT
            c.execute("INSERT INTO txs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                      (t['id'], t['sender'], t['recipient'], t['amount'], # amount já é string
                       t['fee'], t['signature'], block['index'], t.get('public_key', '')))
        self.conn.commit()

    def new_tx(self, sender, recipient, amount_str, fee_str, signature, public_key):
        """Adiciona uma nova transação à lista de transações pendentes.
           amount_str e fee_str já devem ser strings formatadas."""
        tx = {
            'id': str(uuid4()), 'sender': sender, 'recipient': recipient,
            'amount': amount_str, 'fee': fee_str, 'signature': signature, 'public_key': public_key
        }
        if self.is_duplicate_transaction(tx):
            print(f"[TX] Transação {tx.get('id', '')} já pendente. Ignorando.")
            return -1
        
        self.current_transactions.append(tx)
        print(f"[TX] Nova transação adicionada: {tx['id']}")
        return self.last_block()['index'] + 1 if self.chain else 1

    def _get_mining_reward(self, block_index):
        """Calcula a recompensa de mineração com base no índice do bloco (halving)."""
        if block_index <= 1200:
            return 50.0
        elif block_index <= 2200:
            return 25.0
        elif block_index <= 4000:
            return 12.5
        elif block_index <= 5500:
            return 6.5
        elif block_index <= 6200:
            return 3.25
        elif block_index <= 20000:
            return 1.25
        elif block_index <= 1000000:
            return 0.03
        else:
            halvings = (block_index - 1000000) // 2100000
            base_reward = 0.03
            reward = base_reward / (2 ** halvings)
            return max(reward, 0.0)

    def last_block(self):
        """Retorna o último bloco da cadeia."""
        return self.chain[-1] if self.chain else None

    def proof_of_work(self, last_proof):
        """
        Encontra uma prova de trabalho que satisfaça os requisitos de dificuldade.
        Retorna a prova (nonce) ou -1 se a mineração for abortada.
        """
        difficulty_for_pow = self._calculate_difficulty_for_index(len(self.chain) + 1)
        proof = 0
        print(f"Iniciando mineração com dificuldade {difficulty_for_pow}...")
        start_time = time.time()
        
        while not self.valid_proof(last_proof, proof, difficulty_for_pow):
            global is_mining
            if not is_mining:
                print("[Miner] Sinal para parar recebido durante PoW. Abortando mineração.")
                return -1
            
            if self.last_block()['proof'] != last_proof:
                print("[Miner] Outro bloco chegou na cadeia principal durante PoW. Abortando e reiniciando.")
                return -1

            if time.time() - start_time > 10 and proof % 100000 == 0:
                print(f" Tentativa: {proof}")
            proof += 1
        print(f"Mineração concluída: proof = {proof}")
        return proof

    @staticmethod
    def valid_proof(last_proof, proof, difficulty):
        """
        Valida se um dado hash de prova satisfaz os requisitos de dificuldade.
        """
        guess = f"{last_proof}{proof}".encode()
        guess_hash = Blockchain.custom_asic_resistant_hash(guess, proof)
        return guess_hash[:difficulty] == "0" * difficulty

    def tx_already_mined(self, tx_id):
        """Verifica se uma transação com o dado ID já foi minerada em algum bloco."""
        c = self.conn.cursor()
        c.execute("SELECT 1 FROM txs WHERE id=?", (tx_id,))
        return c.fetchone() is not None

    def valid_chain(self, chain):
        """
        Determina se uma dada cadeia de blocos é válida.
        Verifica hashes, provas de trabalho, transações e dificuldade.
        """
        if not chain:
            return False

        if chain[0]['index'] != 1 or chain[0]['previous_hash'] != '1' or chain[0]['proof'] != 100:
            print("[VAL_CHAIN_ERRO] Bloco Gênese inválido.")
            return False

        for idx in range(1, len(chain)):
            prev = chain[idx - 1]
            curr = chain[idx]

            prev_hash = self.hash(prev)

            if curr['previous_hash'] != prev_hash:
                print(f"[VAL_CHAIN_ERRO] Hash anterior incorreto no bloco {curr['index']}. Esperado: {prev_hash}, Obtido: {curr['previous_hash']}.")
                return False

            block_declared_difficulty = curr.get('difficulty', DIFFICULTY)

            if not self.valid_proof(prev['proof'], curr['proof'], block_declared_difficulty):
                hash_check = self.custom_asic_resistant_hash(f"{prev['proof']}{curr['proof']}".encode(), curr['proof'])
                print(f"[VAL_CHAIN_ERRO] Proof of Work inválido no bloco {curr['index']} com dificuldade {block_declared_difficulty}. Hash: {hash_check}")
                return False

            for tx in curr.get('transactions', []):
                if tx['sender'] == '0':
                    if tx['recipient'] != curr['miner']:
                        print(f"[VAL_CHAIN_ERRO] TX de recompensa inválida no bloco {curr['index']}: Recipiente incorreto.")
                        return False
                    expected_reward = self._get_mining_reward(curr['index'])
                    # Comparar recompensas como floats, mas tx['amount'] é string
                    if abs(float(tx['amount']) - expected_reward) > 0.000001:
                        print(f"[VAL_CHAIN_ERRO] TX de recompensa inválida no bloco {curr['index']}: Valor incorreto. Esperado: {expected_reward}, Obtido: {tx['amount']}")
                        return False
                    continue

                try:
                    pk_for_address_derivation = tx['public_key']
                    if pk_for_address_derivation.startswith('04') and len(pk_for_address_derivation) == 130:
                        pk_for_address_derivation = pk_for_address_derivation[2:]
                    
                    derived_address = hashlib.sha256(bytes.fromhex(pk_for_address_derivation)).hexdigest()[:40]
                    if derived_address != tx['sender']:
                        print(f"[VAL_CHAIN_ERRO] Transação {tx['id']} no bloco {curr['index']}: Endereço ({tx['sender']}) não bate com o derivado da chave pública ({derived_address}).")
                        return False

                    # CRÍTICO: Garantir que amount e fee são strings formatadas para a verificação
                    # Sempre converte para float primeiro, depois formata para string com .8f
                    amount_to_verify = f"{float(tx['amount']):.8f}"
                    fee_to_verify = f"{float(tx['fee']):.8f}"

                    tx_copy_for_signature = {
                        'amount': amount_to_verify,
                        'fee': fee_to_verify,
                        'recipient': tx['recipient'],
                        'sender': tx['sender']
                    }
                    message = json.dumps(tx_copy_for_signature, sort_keys=True, separators=(",", ":")).encode()

                    vk = VerifyingKey.from_string(bytes.fromhex(tx['public_key']), curve=SECP256k1)
                    vk.verify_digest(bytes.fromhex(tx['signature']), hashlib.sha256(message).digest())

                except BadSignatureError:
                    print(f"[VAL_CHAIN_ERRO] Transação {tx['id']} inválida no bloco {curr['index']}: Assinatura inválida.")
                    return False
                except Exception as e:
                    print(f"[VAL_CHAIN_ERRO] Transação {tx['id']} inválida no bloco {curr['index']}: {e}")
                    return False
        return True

    def _calculate_difficulty_for_index(self, target_block_index):
        """
        Calcula a dificuldade esperada para um dado índice de bloco.
        Implementa o ajuste de dificuldade do Bitcoin.
        """
        if target_block_index <= self.ADJUST_INTERVAL:
            return DIFFICULTY

        if len(self.chain) < target_block_index - 1:
            return self.chain[-1].get('difficulty', DIFFICULTY) if self.chain else DIFFICULTY

        start_block_index_in_chain = target_block_index - self.ADJUST_INTERVAL - 1
        end_block_index_in_chain = target_block_index - 2

        if start_block_index_in_chain < 0 or end_block_index_in_chain < 0:
            return DIFFICULTY

        start_block_for_calc = self.chain[start_block_index_in_chain]
        end_block_for_calc = self.chain[end_block_index_in_chain]

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

    def get_total_difficulty(self, chain_to_check):
        """Calcula a dificuldade acumulada de uma cadeia."""
        total_difficulty = 0
        for block in chain_to_check:
            total_difficulty += block.get('difficulty', DIFFICULTY)
        return total_difficulty

    def resolve_conflicts(self):
        """
        Implementa o algoritmo de consenso para resolver conflitos na cadeia.
        Substitui a cadeia local pela mais longa e válida da rede.
        """
        neighbors = known_nodes.copy()
        new_chain = None
        current_total_difficulty = self.get_total_difficulty(self.chain)

        print(f"[CONSENSO] Tentando resolver conflitos com {len(neighbors)} vizinhos... Cadeia local dificuldade: {current_total_difficulty}")

        for node_url in neighbors:
            if node_url == meu_url:
                continue
            try:
                response = requests.get(f"{node_url}/chain", timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    peer_chain = data.get("chain")

                    if not peer_chain:
                        print(f"[CONSENSO] Resposta malformada (sem 'chain') de {node_url}. Removendo peer.")
                        known_nodes.discard(node_url)
                        salvar_peers(known_nodes)
                        continue

                    peer_total_difficulty = self.get_total_difficulty(peer_chain)
                    
                    print(f"[CONSENSO] Node {node_url}: Dificuldade Total={peer_total_difficulty}, Comprimento={len(peer_chain)}. Local Comprimento={len(self.chain)}")

                    if peer_total_difficulty > current_total_difficulty and self.valid_chain(peer_chain):
                        current_total_difficulty = peer_total_difficulty
                        new_chain = peer_chain
                        print(f"[CONSENSO] ✔ Cadeia mais difícil e válida encontrada em {node_url} (Dificuldade: {peer_total_difficulty})")
                    else:
                        print(f"[CONSENSO] ✘ Cadeia de {node_url} (Dificuldade: {peer_total_difficulty}) não é mais difícil ou não é válida.")
                else:
                    print(f"[CONSENSO] Resposta inválida de {node_url}: Status {response.status_code}. Removendo peer.")
                    known_nodes.discard(node_url)
                    salvar_peers(known_nodes)
            except requests.exceptions.RequestException as e:
                print(f"[CONSENSO] Erro ao buscar cadeia de {node_url}: {e}. Removendo peer.")
                known_nodes.discard(node_url)
                salvar_peers(known_nodes)

        if new_chain:
            old_chain_tx_ids = set()
            for block in self.chain:
                for tx in block.get('transactions', []):
                    old_chain_tx_ids.add(tx['id'])

            new_chain_tx_ids = set()
            for block in new_chain:
                for tx in block.get('transactions', []):
                    new_chain_tx_ids.add(tx['id'])
            
            re_add_txs = []
            for block in self.chain:
                for tx in block.get('transactions', []):
                    if tx['id'] not in new_chain_tx_ids and tx['sender'] != '0':
                        re_add_txs.append(tx)
            
            for tx in self.current_transactions:
                if tx['id'] not in new_chain_tx_ids:
                    re_add_txs.append(tx)

            self.current_transactions = []
            for tx in re_add_txs:
                temp_tx_for_duplicate_check = {
                    'sender': tx['sender'],
                    'recipient': tx['recipient'],
                    'amount': tx['amount'], # Já é string
                    'fee': tx['fee'],       # Já é string
                    'id': tx.get('id')
                }
                if not self.is_duplicate_transaction(temp_tx_for_duplicate_check):
                    self.current_transactions.append(tx)
            
            self.chain = new_chain
            self._rebuild_db_from_chain()
            print(f"[CONSENSO] ✅ Cadeia substituída com sucesso pela mais difícil e válida (Dificuldade: {current_total_difficulty}). {len(re_add_txs)} transações re-adicionadas.")
            return True

        print("[CONSENSO] 🔒 Cadeia local continua sendo a mais difícil ou nenhuma cadeia mais difícil/válida foi encontrada.")
        return False

    def _rebuild_db_from_chain(self):
        """Reconstrói o banco de dados local a partir da cadeia atual (usado após consenso)."""
        print("[REBUILD] Reconstruindo dados locais a partir da nova cadeia...")
        try:
            c = self.conn.cursor()
            c.execute("DELETE FROM blocks")
            c.execute("DELETE FROM txs")

            for block in self.chain:
                difficulty_to_save = block.get('difficulty', DIFFICULTY)
                c.execute("INSERT INTO blocks VALUES (?, ?, ?, ?, ?, ?)",
                          (block['index'], block['previous_hash'], block['proof'],
                           block['timestamp'], block['miner'], difficulty_to_save))
                for tx in block['transactions']:
                    c.execute("INSERT INTO txs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                              (tx['id'], tx['sender'], tx['recipient'], tx['amount'], # amount já é string
                               tx['fee'], tx['signature'], block['index'], tx.get('public_key', '')))
            self.conn.commit()
            print("[REBUILD] Banco reconstruído com sucesso.")
        except Exception as e:
            print(f"[REBUILD] Erro ao reconstruir banco: {e}")
            sys.exit(1)

    def balance(self, address):
        """Calcula o saldo de um endereço, incluindo transações pendentes."""
        bal = 0.0
        for block in self.chain:
            for t in block['transactions']:
                if t['sender'] == address:
                    bal -= (float(t['amount']) + float(t['fee'])) # Converter para float para cálculo
                if t['recipient'] == address:
                    bal += float(t['amount']) # Converter para float para cálculo
        
        for t in self.current_transactions:
            if t['sender'] == address:
                bal -= (float(t['amount']) + float(t['fee'])) # Converter para float para cálculo
            if t['recipient'] == address:
                bal += float(t['amount']) # Converter para float para cálculo
        return bal

# --- Funções de Criptografia e Carteira ---
def gerar_endereco(public_key_hex):
    """Gera um endereço de carteira a partir de uma chave pública hexadecimal."""
    try:
        # A chave pública pode vir com prefixo '04'
        if public_key_hex.startswith("04"):
            public_key_hex = public_key_hex[2:]
        public_key_bytes = bytes.fromhex(public_key_hex)
        return hashlib.sha256(public_key_bytes).hexdigest()[:40]
    except ValueError:
        return None

def sign_transaction(private_key_hex, tx_data):
    """
    Assina uma transação com a chave privada ECDSA (SECP256k1).
    tx_data deve ter: 'sender', 'recipient', 'amount' (string), 'fee' (string).
    Retorna a assinatura em hex.
    """
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)

    # Recria o dicionário na ordem que o servidor espera.
    # amount e fee já devem ser strings formatadas aqui.
    message_data = {
        'amount':    tx_data['amount'],
        'fee':       tx_data['fee'],
        'recipient': tx_data['recipient'],
        'sender':    tx_data['sender']
    }

    # Serialização determinística sem espaços
    message_json = json.dumps(
        message_data,
        sort_keys=True,
        separators=(',',':')
    ).encode('utf-8')

    print(f"DEBUG_SIGN: JSON da mensagem para assinatura (decodificado): {message_json.decode('utf-8')}")
    print(f"DEBUG_SIGN: Bytes da mensagem para assinatura (raw): {message_json}")
    print(f"DEBUG_SIGN: Hash da mensagem para assinatura (SHA256, HEX): {hashlib.sha256(message_json).hexdigest()}")

    # SHA256 + sign_digest
    message_hash = hashlib.sha256(message_json).digest()
    return sk.sign_digest(message_hash).hex()

def create_wallet():
    """Cria e retorna dados de uma nova carteira."""
    private_key_obj = SigningKey.generate(curve=SECP256k1)
    public_key_obj = private_key_obj.get_verifying_key()
    private_key_hex = private_key_obj.to_string().hex()
    public_key_hex = "04" + public_key_obj.to_string().hex() # Adicionar prefixo '04'
    address = gerar_endereco(public_key_hex)

    if address is None: # Corrigido de '===' para 'is'
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
                        # Opcional: Salvar a carteira atualizada se o endereço foi corrigido
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

# --- Flask Endpoints (do nó) ---
@app.route('/', methods=['GET'])
def index_web():
    return "Kert-One Blockchain Node is running!"

@app.route('/miner')
def miner_web():
    return render_template('miner.html')

@app.route('/chain', methods=['GET'])
def chain_api():
    response = {
        'chain': blockchain.chain,
        'length': len(blockchain.chain),
        'pending_transactions': blockchain.current_transactions,
        'coin_name': COIN_NAME,
        'coin_symbol': COIN_SYMBOL,
        'node_id': node_id
    }
    return jsonify(response), 200

@app.route('/nodes/register', methods=['POST'])
def register_nodes_api():
    data = request.get_json()
    new_node_ip = data.get('ip')
    new_node_port = data.get('port')

    if not new_node_ip or not new_node_port:
        return jsonify({"message": "IP ou porta inválidos/ausentes."}), 400

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
        "message": f"Peer {new_node_url} registrado ou atualizado.",
        "known_peers": list(known_nodes)
    }), 200

@app.route('/nodes', methods=['GET'])
def get_nodes_api():
    return jsonify({'nodes': list(known_nodes)}), 200

@app.route('/nodes/resolve', methods=['GET'])
def resolve_api():
    replaced = blockchain.resolve_conflicts()
    if replaced:
        response = {'message': 'Nossa cadeia foi substituída.'}
    else:
        response = {'message': 'Nossa cadeia é a mais longa.'}
    return jsonify(response), 200

@app.route('/balance/<addr>', methods=['GET'])
def balance_api(addr):
    return jsonify({
        'address': addr,
        'balance': blockchain.balance(addr),
        'coin_name': COIN_NAME,
        'coin_symbol': COIN_SYMBOL
    }), 200

@app.route('/tx/new', methods=['POST'])
def new_transaction_api():
    """Recebe uma nova transação do cliente e a adiciona à fila pendente."""
    print(f"DEBUG_SERVER: Requisição recebida para /tx/new")
    print(f"DEBUG_SERVER: Headers da requisição: {request.headers}")
    print(f"DEBUG_SERVER: Mimetype da requisição: {request.mimetype}")
    print(f"DEBUG_SERVER: Content-Type da requisição: {request.content_type}")
    print(f"DEBUG_SERVER: Dados da requisição (raw): {request.data}")

    raw_values = None
    try:
        raw_values = request.get_json(silent=True)
        print(f"DEBUG_SERVER: Payload JSON parseado (request.get_json()): {raw_values}")
    except Exception as e:
        print(f"DEBUG_SERVER: ERRO - Exceção durante o parsing JSON: {e}")
    
    if raw_values is None:
        print(f"DEBUG_SERVER: ERRO - request.get_json() retornou None. Verifique o Content-Type ou a validade do JSON.")
        return jsonify({'message': 'Erro: Não foi possível parsear o JSON da requisição. Verifique o Content-Type ou a validade do JSON.'}), 400
    
    values = raw_values

    required = ['id', 'sender', 'recipient', 'amount', 'fee', 'public_key', 'signature']
    if not all(k in values for k in required):
        missing = [k for k in required if k not in values]
        print(f"[ERRO 400] Valores ausentes na transação: {missing}")
        return jsonify({'message': f'Valores ausentes na requisição: {", ".join(missing)}'}), 400

    try:
        # amount e fee vêm como strings do cliente, mas podem precisar de formatação
        amount_float = float(values['amount'])
        fee_float = float(values['fee'])
        amount_str_formatted = f"{amount_float:.8f}"
        fee_str_formatted = f"{fee_float:.8f}"

        transaction = {
            'id': values['id'],
            'sender': values['sender'],
            'recipient': values['recipient'],
            'amount': amount_str_formatted, # Armazenar como string formatada
            'fee': fee_str_formatted,       # Armazenar como string formatada
            'public_key': values['public_key'],
            'signature': values['signature'],
            'timestamp': values.get('timestamp', time.time())
        }
    except Exception as e:
        print(f"[ERRO 400] Erro ao construir transação: {e}")
        return jsonify({'message': f'Erro ao processar dados da transação: {e}'}), 400

    temp_tx_for_duplicate_check = {
        'sender': transaction['sender'],
        'recipient': transaction['recipient'],
        'amount': transaction['amount'], # Já é string
        'fee': transaction['fee'],       # Já é string
        'id': transaction.get('id')
    }
    if blockchain.is_duplicate_transaction(temp_tx_for_duplicate_check):
        print(f"[AVISO] Transação duplicada detectada para {transaction['sender']} -> {transaction['recipient']}. Ignorando.")
        return jsonify({'message': 'Transação duplicada detectada. Não adicionada novamente.'}), 200

    try:
        pk_for_address_derivation = transaction['public_key']
        if pk_for_address_derivation.startswith('04') and len(pk_for_address_derivation) == 130:
            pk_for_address_derivation = pk_for_address_derivation[2:]
        
        derived_address = hashlib.sha256(bytes.fromhex(pk_for_address_derivation)).hexdigest()[:40] 
        if derived_address != transaction['sender']:
            print(f"[ERRO 400] Assinatura inválida: Endereço do remetente ({transaction['sender']}) não corresponde à chave pública fornecida ({derived_address}).")
            return jsonify({'message': 'Assinatura inválida: Endereço do remetente não corresponde à chave pública fornecida'}), 400

        if not verify_signature(transaction['public_key'], transaction['signature'], transaction):
            print(f"[ERRO 400] Assinatura inválida ou chave pública malformada para TX ID: {transaction.get('id')}")
            return jsonify({'message': 'Assinatura inválida ou chave pública malformada: Falha na verificação da assinatura'}), 400
            
    except Exception as e:
        print(f"[ERRO 400] Erro inesperado na validação da assinatura: {e}. TX ID: {transaction.get('id')}")
        return jsonify({'message': f'Erro inesperado na validação da transação: {e}'}), 400

    # Usar float() para cálculo de saldo, pois balance() espera floats para isso
    current_balance = blockchain.balance(transaction['sender'])
    required_amount = float(transaction['amount']) + float(transaction['fee'])
    if current_balance < required_amount:
        print(f"[ERRO 400] Saldo insuficiente para {transaction['sender']}: Necessário {required_amount}, Disponível {current_balance}. TX ID: {transaction.get('id')}")
        return jsonify({'message': f'Saldo insuficiente para a transação. Saldo atual: {current_balance}, Necessário: {required_amount}'}), 400

    # Adicionar à fila de transações pendentes (amount e fee já são strings formatadas)
    blockchain.current_transactions.append(transaction)
    
    broadcast_tx_to_peers(transaction)

    response = {'message': f'Transação adicionada à fila de transações pendentes.',
                'coin_name': COIN_NAME,
                'coin_symbol': COIN_SYMBOL,
                'transaction_id': transaction['id']}
    return jsonify(response), 201

def broadcast_tx_to_peers(tx):
    """Envia uma transação para todos os peers conhecidos."""
    print(f"[Broadcast TX] Enviando transação {tx.get('id')} para peers.")
    peers_to_remove = set()
    for peer in known_nodes.copy():
        if peer == meu_url: continue
        try:
            requests.post(f"{peer}/tx/receive", json=tx, timeout=3)
        except requests.exceptions.RequestException as e:
            print(f"[Broadcast TX] Erro ao enviar TX para {peer}: {e}. Removendo peer (se não for seed).")
            if peer not in SEED_NODES:
                peers_to_remove.add(peer)
    
    if peers_to_remove:
        known_nodes.difference_update(peers_to_remove)
        salvar_peers(known_nodes)
        print(f"[Broadcast TX] Removidos {len(peers_to_remove)} peers problemáticos.")

@app.route('/tx/receive', methods=['POST'])
def receive_transaction_api():
    """Recebe uma transação de outro nó e a adiciona à fila pendente após validação."""
    tx_data = request.get_json()
    if not tx_data:
        return jsonify({"message": "Nenhum dado de transação recebido."}), 400

    required = ['id', 'sender', 'recipient', 'amount', 'fee', 'public_key', 'signature']
    if not all(k in tx_data for k in required):
        return jsonify({'message': 'Dados de transação incompletos.'}), 400

    try:
        # amount e fee vêm como strings (esperado), garantir formatação
        amount_float = float(tx_data['amount'])
        fee_float = float(tx_data['fee'])
        amount_str_formatted = f"{amount_float:.8f}"
        fee_str_formatted = f"{fee_float:.8f}"

        temp_tx_for_duplicate_check = {
            'sender': tx_data['sender'],
            'recipient': tx_data['recipient'],
            'amount': amount_str_formatted, # Usar string formatada
            'fee': fee_str_formatted,       # Usar string formatada
            'id': tx_data.get('id')
        }
        if blockchain.is_duplicate_transaction(temp_tx_for_duplicate_check):
            print(f"[RECEIVE TX] Transação {tx_data.get('id')} já existe na fila pendente. Ignorando.")
            return jsonify({'message': 'Transação já conhecida.'}), 200

        # Passar a transação com amount/fee como strings formatadas para verify_signature
        tx_for_verification = {
            'id': tx_data['id'],
            'sender': tx_data['sender'],
            'recipient': tx_data['recipient'],
            'amount': amount_str_formatted,
            'fee': fee_str_formatted,
            'public_key': tx_data['public_key'],
            'signature': tx_data['signature'],
            'timestamp': tx_data.get('timestamp', time.time())
        }

        if not verify_signature(tx_for_verification['public_key'], tx_for_verification['signature'], tx_for_verification):
            print(f"[RECEIVE TX ERROR] TX {tx_data.get('id')}: Assinatura inválida ou chave pública malformada.")
            return jsonify({'message': 'Transação inválida: Assinatura inválida ou chave pública malformada.'}), 400

        # Usar float() para cálculo de saldo, pois balance() espera floats para isso
        current_balance = blockchain.balance(tx_data['sender'])
        required_amount = float(tx_data['amount']) + float(tx_data['fee'])
        if current_balance < required_amount:
            print(f"[RECEIVE TX ERROR] TX {tx_data.get('id')}: Saldo insuficiente para {tx_data['sender']}.")
            return jsonify({'message': 'Transação inválida: Saldo insuficiente.'}), 400

        # Adicionar à fila de transações pendentes (amount e fee já são strings formatadas)
        blockchain.current_transactions.append(tx_for_verification)
        print(f"[RECEIVE TX] Transação {tx_data.get('id')} recebida e adicionada à fila pendente.")
        return jsonify({"message": "Transação recebida e adicionada com sucesso."}), 200

    except Exception as e:
        print(f"[RECEIVE TX ERROR] Erro inesperado ao processar TX {tx_data.get('id')}: {e}")
        return jsonify({'message': f'Erro interno ao processar transação: {e}'}), 500
        
def verify_signature(public_key_hex, signature_hex, tx_data):
    """
    Verifica a assinatura de uma transação.
    tx_data deve conter 'sender', 'recipient', 'amount', 'fee'.
    'amount' e 'fee' podem ser strings ou floats ao entrar nesta função,
    mas serão convertidos para string formatada para a verificação.
    """
    try:
        vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)

        # CRÍTICO: Garantir que amount e fee são strings formatadas para a verificação
        # Sempre converte para float primeiro, depois formata para string com .8f
        amount_to_verify = f"{float(tx_data['amount']):.8f}"
        fee_to_verify = f"{float(tx_data['fee']):.8f}"

        prepared_message_data = {
            'amount': amount_to_verify,
            'fee': fee_to_verify,
            'recipient': tx_data['recipient'],
            'sender': tx_data['sender']
        }
        
        message = json.dumps(prepared_message_data, sort_keys=True, separators=(',', ':')).encode('utf-8')

        message_hash_bytes = hashlib.sha256(message).digest()
        signature_bytes = bytes.fromhex(signature_hex)

        print(f"DEBUG_VERIFY: Chave Pública recebida (hex): {public_key_hex}")
        print(f"DEBUG_VERIFY: Assinatura recebida (hex): {signature_hex}")
        print(f"DEBUG_VERIFY: Dados da mensagem para verificação (antes de json.dumps): {prepared_message_data}")
        print(f"DEBUG_VERIFY: JSON da mensagem para verificação (decodificado): {message.decode('utf-8')}")
        print(f"DEBUG_VERIFY: Bytes da mensagem para verificação (raw): {message}")
        print(f"DEBUG_VERIFY: Hash da mensagem para verificação (SHA256, HEX): {hashlib.sha256(message).hexdigest()}")

        vk.verify_digest(signature_bytes, message_hash_bytes)
        return True
    except BadSignatureError:
        print("Falha na verificação da assinatura: BadSignatureError!")
        return False
    except ValueError as ve:
        print(f"Falha na verificação da assinatura: ValueError (e.g., bad hex string or malformed key): {ve}")
        return False
    except Exception as e:
        print(f"Erro durante a verificação da assinatura: {e}")
        return False
        
@app.route('/blocks/receive', methods=['POST'])
def receive_block_api():
    """Recebe um bloco de outro nó e tenta adicioná-lo à cadeia local."""
    block_data = request.get_json()
    if not block_data:
        print("[RECEIVE_BLOCK ERROR] Nenhum dado de bloco recebido.")
        return jsonify({"message": "Nenhum dado de bloco recebido."}), 400

    required_keys = ['index', 'previous_hash', 'proof', 'timestamp', 'miner', 'transactions', 'difficulty']
    if not all(k in block_data for k in required_keys):
        print(f"[RECEIVE_BLOCK ERROR] Bloco recebido com chaves ausentes: {block_data}")
        return jsonify({"message": "Dados de bloco incompletos ou malformados."}), 400

    if not blockchain.chain:
        print("[RECEIVE_BLOCK INFO] Cadeia local vazia. Iniciando resolução de conflitos para sincronização inicial.")
        threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
        return jsonify({'message': 'Cadeia local vazia. Tentando sincronizar com a rede.'}), 202

    last_local_block = blockchain.last_block()

    if block_data['index'] <= last_local_block['index']:
        if block_data['index'] == last_local_block['index'] and \
           block_data['previous_hash'] == last_local_block['previous_hash'] and \
           block_data['proof'] == last_local_block['proof'] and \
           block_data['miner'] == last_local_block['miner'] and \
           block_data['difficulty'] == last_local_block['difficulty']:
            print(f"[RECEIVE_BLOCK INFO] Bloco {block_data['index']} já recebido e processado (duplicado).")
            return jsonify({'message': 'Bloco já recebido e processado'}), 200
        else:
            print(f"[RECEIVE_BLOCK INFO] Bloco {block_data['index']} é antigo ou de um fork mais curto/inválido (Local: {last_local_block['index']}). Ignorando.")
            return jsonify({'message': 'Bloco antigo ou de um fork irrelevante.'}), 200

    if block_data['index'] == last_local_block['index'] + 1:
        expected_previous_hash = blockchain.hash(last_local_block)
        if block_data['previous_hash'] != expected_previous_hash:
            print(f"[RECEIVE_BLOCK ERROR] Bloco {block_data['index']}: Hash anterior incorreto. Esperado: {expected_previous_hash}, Recebido: {block_data['previous_hash']}. Iniciando sincronização.")
            threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
            return jsonify({'message': 'Hash anterior incorreto, resolução de conflitos iniciada'}), 400

        if not blockchain.valid_proof(last_local_block['proof'], block_data['proof'], block_data['difficulty']):
            print(f"[RECEIVE_BLOCK ERROR] Bloco {block_data['index']}: Prova de Trabalho inválida. Iniciando sincronização.")
            threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
            return jsonify({'message': 'Prova inválida, resolução de conflitos iniciada'}), 400

        for tx in block_data.get('transactions', []):
            if tx['sender'] == '0':
                continue
            
            try:
                # Certificar que amount e fee são strings formatadas para verificação
                tx_for_verification = {
                    'id': tx['id'],
                    'sender': tx['sender'],
                    'recipient': tx['recipient'],
                    'amount': f"{float(tx['amount']):.8f}", # Garante formato string .8f
                    'fee': f"{float(tx['fee']):.8f}",       # Garante formato string .8f
                    'public_key': tx['public_key'],
                    'signature': tx['signature'],
                    'timestamp': tx.get('timestamp', time.time())
                }
                if not verify_signature(tx_for_verification['public_key'], tx_for_verification['signature'], tx_for_verification):
                    raise ValueError(f"Assinatura inválida para transação {tx.get('id', 'N/A')}")

            except Exception as e:
                print(f"[RECEIVE_BLOCK ERROR] Transação inválida {tx.get('id', 'N/A')} no bloco {block_data['index']}: {e}. Iniciando sincronização.")
                threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
                return jsonify({'message': f'Transação inválida no bloco: {e}'}), 400
        
        print(f"[RECEIVE_BLOCK SUCCESS] Bloco {block_data['index']} aceito e adicionado localmente.")
        blockchain.chain.append(block_data)
        blockchain._save_block(block_data)

        mined_tx_ids = {t.get('id') for t in block_data.get('transactions', []) if t.get('id')}
        blockchain.current_transactions = [
            tx for tx in blockchain.current_transactions if tx.get('id') not in mined_tx_ids
        ]
        print(f"[RECEIVE_BLOCK] Removidas {len(mined_tx_ids)} transações da fila pendente.")
                
        return jsonify({'message': 'Bloco aceito e adicionado'}), 200

    elif block_data['index'] > last_local_block['index'] + 1:
        print(f"[RECEIVE_BLOCK INFO] Bloco {block_data['index']} está à frente da cadeia local ({last_local_block['index']}). Iniciando resolução de conflitos.")
        threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
        return jsonify({'message': 'Bloco está à frente. Iniciando sincronização.'}), 202

    print(f"[RECEIVE_BLOCK WARNING] Condição inesperada para o bloco {block_data['index']}. Iniciando resolução de conflitos.")
    threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
    return jsonify({'message': 'Bloco com status inesperado, resolução de conflitos iniciada'}), 400

@app.route('/sync/check', methods=['GET'])
def check_sync_api():
    last = blockchain.last_block()
    local_hash = blockchain.hash(last)
    return jsonify({
        'index': last['index'],
        'hash': local_hash,
        'timestamp': last['timestamp'],
        'miner': last['miner'],
        'num_txs': len(last['transactions'])
    })

@app.route('/miner/set_address', methods=['POST'])
def set_miner_address_api():
    """Define o endereço de mineração para o nó."""
    global miner_address
    data = request.get_json()
    address = data.get('address')
    if not address:
        return jsonify({"message": "Endereço do minerador ausente."}), 400
    miner_address = address
    return jsonify({"message": f"Endereço do minerador definido para {miner_address}"}), 200

@app.route('/mine', methods=['GET'])
def mine_api():
    """Inicia o processo de mineração de um novo bloco."""
    global is_mining, miner_address
    if not miner_address:
        return jsonify({"message": "Endereço do minerador não definido. Por favor, defina um endereço primeiro."}), 400

    with miner_lock: # Garante que apenas um processo de mineração seja executado por vez
        if is_mining:
            return jsonify({"message": "Mineração já está em andamento."}), 409
        is_mining = True

    last_block = blockchain.last_block()
    if not last_block:
        return jsonify({"message": "Blockchain não inicializada. Não é possível minerar."}), 500

    last_proof = last_block['proof']
    
    # Executa a Prova de Trabalho de forma que possa ser interrompida
    proof = blockchain.proof_of_work(last_proof)

    with miner_lock:
        is_mining = False # Redefine o flag de mineração após a tentativa de PoW

    if proof == -1: # Mineração foi abortada
        return jsonify({"message": "Mineração abortada ou interrompida."}), 200

    previous_hash = blockchain.hash(last_block)
    new_block = blockchain.new_block(proof, previous_hash, miner_address)

    # Transmite o bloco recém-minerado para a rede
    broadcast_block(new_block)

    response = {
        'message': "Novo bloco forjado!",
        'index': new_block['index'],
        'transactions': new_block['transactions'],
        'proof': new_block['proof'],
        'previous_hash': new_block['previous_hash'],
        'difficulty': new_block['difficulty']
    }
    return jsonify(response), 200


# --- Funções de Peer-to-Peer (do nó) ---
def broadcast_block(block):
    """Envia um bloco recém-minerado para todos os peers conhecidos."""
    print(f"[BROADCAST] Enviando bloco #{block['index']} para {len(known_nodes)} peers...")
    peers_to_remove = set()
    for peer in known_nodes.copy():
        if peer == meu_url: continue
        try:
            requests.post(f"{peer}/blocks/receive", json=block, timeout=5)
        except requests.exceptions.RequestException as e:
            print(f"[BROADCAST] Erro ao enviar bloco para {peer}: {e}. Removendo peer (se não for seed).")
            if peer not in SEED_NODES:
                peers_to_remove.add(peer)
        except Exception as e:
            print(f"[BROADCAST] Erro inesperado ao enviar bloco para {peer}: {e}")
    
    if peers_to_remove:
        known_nodes.difference_update(peers_to_remove)
        salvar_peers(known_nodes)
        print(f"[BROADCAST] Removidos {len(peers_to_remove)} peers problemáticos.")

def discover_peers():
    """
    Descobre e registra peers na rede.
    Prioriza a conexão com os nós semente (SEED_NODES) para iniciar a descoberta.
    """
    global known_nodes, meu_url
    
    # 1. Adiciona os nós semente à lista de peers conhecidos.
    for seed in SEED_NODES:
        if seed not in known_nodes and seed != meu_url:
            known_nodes.add(seed)
            print(f"[DISCOVERY] Adicionando nó semente: {seed}")
    
    salvar_peers(known_nodes) # Salva a lista atualizada de peers

    # 2. Itera sobre a lista de peers conhecidos (incluindo os nós semente)
    # para descobrir novos peers e registrar o nó local.
    initial_peers = list(known_nodes) # Cria uma cópia para iterar
    for peer in initial_peers:
        if peer == meu_url:
            continue # Não tentar conectar a si mesmo
        try:
            # Tenta obter a lista de nós conhecidos pelo peer
            r = requests.get(f"{peer}/nodes", timeout=3)
            if r.status_code == 200:
                raw_new_peers = r.json().get('nodes', [])
                new_peers = []
                for item in raw_new_peers:
                    if isinstance(item, dict) and 'url' in item:
                        new_peers.append(item['url'])
                    elif isinstance(item, str):
                        new_peers.append(item)

                for np in new_peers:
                    if np not in known_nodes and np != meu_url:
                        known_nodes.add(np)
                        print(f"[DISCOVERY] Descoberto novo peer {np} via {peer}")
                        salvar_peers(known_nodes) # Salva a lista após cada nova descoberta
                        
                        # Tenta registrar o nó local com o novo peer descoberto
                        try:
                            parsed_url = urlparse(meu_url)
                            my_ip = parsed_url.hostname
                            my_port = parsed_url.port
                            requests.post(f"{np}/nodes/register", json={'ip': my_ip, 'port': my_port}, timeout=2)
                        except Exception as e:
                            print(f"[DISCOVERY ERROR] Falha ao registrar em {np}: {e}")

            # Tenta registrar o nó local com o peer atual (seja ele semente ou descoberto)
            parsed_url = urlparse(meu_url)
            my_ip = parsed_url.hostname
            my_port = parsed_url.port
            requests.post(f"{peer}/nodes/register", json={'ip': my_ip, 'port': my_port}, timeout=2)
            
        except requests.exceptions.RequestException as e:
            print(f"[DISCOVERY ERROR] Falha ao conectar/descobrir peer {peer}: {e}. Removendo.")
            # Remove o peer se não for um nó semente e falhar na conexão
            if peer not in SEED_NODES:
                known_nodes.discard(peer)
                salvar_peers(known_nodes)

def get_my_ip():
    """Tenta obter o IP local do nó e avisa se for privado."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80)) # Conecta a um IP externo para obter o IP local de saída
        ip = s.getsockname()[0]
        s.close()
        try:
            # Verifica se o IP é privado
            if ipaddress.ip_address(ip).is_private:
                print(f"[AVISO IP] Seu IP ({ip}) é privado. Para comunicação completa com peers públicos, configure o redirecionamento de portas (port forwarding) para a porta {port} no seu roteador.")
        except ValueError:
            # Não é um endereço IP válido, apenas continua
            pass
        return ip
    except Exception:
        print("[AVISO IP] Não foi possível determinar o IP local. Usando 127.0.0.1 como fallback. A comunicação com peers externos pode ser limitada.")
        return "127.0.0.1" # Retorna localhost como fallback

def load_or_create_node_id(filename="node_id.txt"):
    """Carrega ou cria um ID de nó único."""
    if os.path.exists(filename):
        with open(filename, "r") as f:
            return f.read().strip()
    else:
        new_id = str(uuid4()).replace("-", "")[:16]
        with open(filename, "w") as f:
            f.write(new_id)
        return new_id

# Funções auxiliares para auto_sync_checker (movidas para antes do main)
def auto_sync_checker(blockchain_instance):
    while True:
        comparar_ultimos_blocos(blockchain_instance)
        time.sleep(60)

def comparar_ultimos_blocos(blockchain_instance):
    if blockchain_instance is None or blockchain_instance.last_block() is None:
        print("[SYNC] Blockchain ainda não inicializada. Aguardando...")
        return

    print("\n🔍 Verificando sincronização com os peers...")
    local_block = blockchain_instance.last_block()
    local_hash = blockchain_instance.hash(local_block)

    for peer in known_nodes.copy():
        try:
            r = requests.get(f"{peer}/sync/check", timeout=5)
            data = r.json()
            peer_index = data['index']
            peer_hash = data['hash']

            if peer_index == local_block['index'] and peer_hash == local_hash:
                print(f"[SYNC ✅] {peer} está sincronizado com índice {peer_index}.")
            else:
                print(f"[SYNC ⚠️] {peer} DIFERENTE! Local: {local_block['index']} | Peer: {peer_index}")
                threading.Thread(target=blockchain_instance.resolve_conflicts, daemon=True).start()
        except Exception as e:
            print(f"[SYNC ❌] Falha ao verificar {peer}: {e}")
            if peer not in SEED_NODES:
                known_nodes.discard(peer)
                salvar_peers(known_nodes)

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
        self.apply_dark_theme()
        self.api_client = APIClient(f"http://{meu_ip}:{port}") # Usar meu_ip e port globais
        self.setup_ui()
        self.load_wallet()

        self.chain_viewer_signal.connect(self.chain_viewer.setPlainText)
        self.log_signal.connect(self.update_log_viewer)
        self.start_mining_timer_signal.connect(self.start_mining_timer_safe)

        self.mining_timer = QTimer(self)
        self.mining_timer.setInterval(6000)
        self.mining_timer.timeout.connect(self.mine_block_via_api)

        self._on_flask_url_ready("https://seend.kert-one.com")

    def update_ui_info(self):
        self.update_log_viewer("Interface atualizada.", "info")

    @pyqtSlot()
    def start_mining_timer_safe(self):
        if not self.mining_active:
            self.mining_active = True
            self.mining_timer.start()
            self.log_signal.emit("Mineração iniciada com segurança.", "success")

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
    
        self.log_viewer = QTextEdit() 
        self.log_viewer.setObjectName("LogViewer")
        self.log_viewer.setReadOnly(True)
        self.main_layout.addWidget(QLabel("Log de Atividade:"))
        self.main_layout.addWidget(self.log_viewer, 3)

        self.status_bar = QStatusBar(self)
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage(f"Cliente Kert-One conectado ao nó: {meu_url}", 5000)

        self.setup_wallet_tab()
        self.setup_send_tab()
        self.setup_mine_tab()
        self.setup_network_tab()
    
        node_info_group = QGroupBox("Informações do Nó")
        node_info_layout = QFormLayout(node_info_group)
    
        self.node_id_label = QLabel(f"<span style='font-weight:bold;'>{node_id[:8]}...</span>")
        self.node_url_label = QLabel("<span style='font-weight:bold;'>Aguardando...</span>")
    
        node_info_layout.addRow("ID do Nó:", self.node_id_label)
        node_info_layout.addRow("URL do Nó:", self.node_url_label)
    
        self.main_layout.insertWidget(0, node_info_group)

        
    @pyqtSlot(str)
    def _on_flask_url_ready(self, url):
        global meu_url
        meu_url = url
        self.api_client.set_base_url(meu_url) # Atualiza a URL base do cliente API

        self.update_log_viewer(f"Servidor Flask pronto em: {meu_url}", "success")
        self.node_url_label.setText(f"<span style='font-weight:bold;'>{meu_url}</span>")
        self.status_bar.showMessage(f"Cliente Kert-One conectado ao nó: {meu_url}", 5000)

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
        
        threading.Thread(target=self._fetch_balance_async, args=(address,)).start()

    def _fetch_balance_async(self, address):
        """Função para buscar o saldo em segundo plano."""
        try:
            response = requests.get(f"{meu_url}/balance/{address}", timeout=5) # Usar meu_url
            response.raise_for_status()
            balance_data = response.json()
            balance = balance_data.get('balance', 0)
            
            self.balance_label.setText(f"{balance} {COIN_SYMBOL}")
            self.log_signal.emit(f"Saldo atualizado: {balance} {COIN_SYMBOL}", "info")
            
        except requests.exceptions.RequestException as e:
            self.log_signal.emit(f"Erro ao conectar ao nó ({meu_url}) ou buscar saldo: {e}", "error")
            self.balance_label.setText("Erro de Conexão")

    # --- Aba Enviar (Opção 3 do CLI) ---

    def setup_send_tab(self):
        layout = QVBoxLayout(self.tab_send)
        
        transaction_group = QGroupBox("Nova Transação")
        form_layout = QFormLayout(transaction_group)
        
        self.recipient_input = QLineEdit()
        self.amount_input = QLineEdit()
        self.fee_input = QLineEdit()
        
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
        """
        Cria, assina e envia uma nova transação para o nó via interface gráfica.
        """
        if not self.wallet_data:
            QMessageBox.warning(self, "Aviso", "Nenhuma carteira carregada.")
            return
    
        recipient_addr = self.recipient_input.text().strip()
        amount_str     = self.amount_input.text().strip().replace(',', '.')
        fee_str        = self.fee_input.text().strip().replace(',', '.')

        if not recipient_addr or not amount_str or not fee_str:
            QMessageBox.warning(self, "Erro", "Todos os campos são obrigatórios.")
            return

        try:
            amount = float(amount_str)
            fee    = float(fee_str)
            if amount <= 0 or fee < 0:
                raise ValueError("Valor ou taxa inválidos.")

            transaction_id = str(uuid4())

            amount_fmt = f"{amount:.8f}"
            fee_fmt     = f"{fee:.8f}"

            # Passar amount e fee como strings formatadas para sign_transaction
            tx_data_for_signing = {
                'sender':    self.wallet_data['address'],
                'recipient': recipient_addr,
                'amount':    amount_fmt,
                'fee':       fee_fmt
            }
            signature = sign_transaction(self.wallet_data['private_key'], tx_data_for_signing)
            if signature is None:
                raise Exception("Falha ao assinar a transação.")

            tx_full_data = {
                'id':         transaction_id,
                'sender':     self.wallet_data['address'],
                'recipient':  recipient_addr,
                'amount':     amount_fmt,      # Armazenar como string formatada
                'fee':        fee_fmt,         # Armazenar como string formatada
                'signature':  signature,
                'public_key': self.wallet_data['public_key'],
                'timestamp':  time.time()
            }

            self.log_signal.emit("Enviando transação para o nó...", "info")
            threading.Thread(
                target=self._send_transaction_async,
                args=(tx_full_data,),
                daemon=True
            ).start()

        except ValueError as e:
            QMessageBox.critical(self, "Erro de Entrada", f"Valor inválido: {e}")
        except Exception as e:
            self.log_signal.emit(f"Ocorreu um erro inesperado: {e}", "error")

    def _send_transaction_async(self, tx_full_data):
        """Função para enviar a transação via HTTP em segundo plano."""
        try:
            response = requests.post(f"{meu_url}/tx/new", json=tx_full_data, timeout=10) # Usar meu_url
            response.raise_for_status()

            if response.status_code in [200, 201]:
                self.log_signal.emit(f"Transação enviada com sucesso: {response.json().get('message')}", "success")
                self._clear_transaction_fields()
                self.check_wallet_balance() 
            else:
                self.log_signal.emit(f"Erro ao enviar transação: {response.json().get('error', response.text)}", "error")

        except requests.exceptions.RequestException as e:
            self.log_signal.emit(f"Taxa é obrigatória ou erro de conexão com o nó ({meu_url}) ao enviar transação: {e}", "error")


    def _clear_transaction_fields(self):
        """Limpa os campos de input de transação."""
        self.recipient_input.clear()
        self.amount_input.clear()
        self.fee_input.clear()

    # --- Aba Mineração (Opções 4, 8, 9 do CLI) ---

    def setup_mine_tab(self):
        layout = QVBoxLayout(self.tab_mine)
        
        mine_addr_group = QGroupBox("Configuração de Mineração")
        mine_addr_layout = QHBoxLayout(mine_addr_group)
        
        self.miner_addr_input = QLineEdit()
        self.miner_addr_input.setPlaceholderText("Endereço para recompensa (Opcional, usa a carteira carregada)")
        
        mine_addr_layout.addWidget(self.miner_addr_input)
        layout.addWidget(mine_addr_group)

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
            self.log_signal.emit(f"Definindo endereço do minerador no nó...", "info")
            set_addr_response = requests.post(f"{meu_url}/miner/set_address", json={"address": miner_address}, timeout=10)
            set_addr_response.raise_for_status()

            self.log_signal.emit(f"Endereço definido: {miner_address}. Iniciando mineração...", "info")

            response = requests.get(f"{meu_url}/mine", timeout=30)
            response.raise_for_status()

            result = response.json()
            self.log_signal.emit(f"✅ Bloco minerado com sucesso: {result.get('message', '')}", "success")
            self.check_wallet_balance()

        except requests.exceptions.RequestException as e:
            self.log_signal.emit(f"Dificuldade alta: {e}. Minerando o próximo bloco...", "error")


    def mine_block_via_api(self):
        if not self.mining_active:
            return
    
        if not self.miner_address:
            self.log_signal.emit("Endereço do minerador não definido. Abortando mineração.", "error")
            return

        threading.Thread(target=self._mine_async, args=(self.miner_address,)).start()
    
    # --- Aba Rede/Blockchain (Opções 5, 6, 7 e 10 do CLI) ---

    def setup_network_tab(self):
        layout = QVBoxLayout(self.tab_network)

        chain_group = QGroupBox("Blockchain View")
        chain_layout = QVBoxLayout(chain_group)

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

        network_options_group = QGroupBox("Opções de Rede")
        network_options_layout = QHBoxLayout(network_options_group)

        self.register_peer_btn = QPushButton("Registrar Novo Peer")
        self.consult_contract_btn = QPushButton("Consultar Contrato Inteligente")

        self.register_peer_btn.clicked.connect(self.register_peer_dialog)
        self.consult_contract_btn.clicked.connect(self.consult_contract_dialog)

        network_options_layout.addWidget(self.register_peer_btn)
        network_options_layout.addWidget(self.consult_contract_btn)

        layout.addWidget(network_options_group)

        self.open_urls_button = QPushButton("Abrir Portais")
        self.open_urls_button.clicked.connect(self.abrir_portais)
        layout.addWidget(self.open_urls_button)

        layout.addStretch(1)


    def abrir_portais(self):
        import webbrowser # Importar aqui para evitar problemas de dependência
        webbrowser.open(f"http://{meu_ip}:{port}/") # Usar meu_ip e port
        webbrowser.open(f"http://{meu_ip}:{port}/miner") # Usar meu_ip e port
        webbrowser.open("https://kert-one.com/")
        self.log_signal.emit("Abrindo portais do Kert-One...", "info")


    def view_blockchain(self):
        """Busca e exibe a blockchain completa do nó."""
        self.log_signal.emit("Buscando blockchain completa...", "info")
        threading.Thread(target=self._fetch_blockchain_async).start()

    def _fetch_blockchain_async(self):
        """Função para buscar a blockchain em segundo plano."""
        try:
            response = requests.get(f"{meu_url}/chain", timeout=10) # Usar meu_url
            response.raise_for_status()
            chain_data = response.json()
            
            formatted_chain = json.dumps(chain_data, indent=2)
            
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
                response = requests.get(f"{meu_url}/nodes/resolve", timeout=30) # Usar meu_url
                response.raise_for_status()
                data = response.json()

                if data.get("message") == "Nossa cadeia foi substituída.":
                    self.log_signal.emit("Blockchain sincronizada com sucesso. Cadeia atualizada para a mais longa.", "success")
                    self.view_blockchain()
                else:
                    self.log_signal.emit("Blockchain já sincronizada ou não houve alteração.", "info")

            except requests.exceptions.RequestException as e:
                self.log_signal.emit(f"Erro ao sincronizar com o nó: {e}", "error")

            time.sleep(10)

    def register_peer_dialog(self):
        """Diálogo para registrar um novo peer."""
        text, ok = QInputDialog.getText(self, 'Registrar Peer', 'Digite a URL completa do novo peer (ex: http://IP:PORTA):')
        if ok and text:
            self.log_signal.emit(f"Tentando registrar peer: {text}", "info")
            threading.Thread(target=self._register_peer_async, args=(text,)).start()
    
    def _register_peer_async(self, node_url):
        """Função para registrar peer em segundo plano."""
        try:
            parsed_url = urlparse(node_url)
            peer_ip = parsed_url.hostname
            peer_port = parsed_url.port or 5000 

            if not peer_ip:
                self.log_signal.emit(f"URL do peer inválida: {node_url}", "error")
                return

            payload = {'ip': peer_ip, 'port': peer_port}
            response = requests.post(f"{meu_url}/nodes/register", json=payload, timeout=10) # Usar meu_url
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
            response = requests.get(f"{meu_url}/contract/{contract_address}/transactions", timeout=10) # Usar meu_url
            response.raise_for_status()
            
            contract_data = response.json()
            formatted_data = json.dumps(contract_data, indent=2)
            
            self.log_signal.emit(f"Detalhes do Contrato ({contract_address}):\n{formatted_data}", "info")
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                self.log_signal.emit("Contrato não encontrado na blockchain.", "warning")
            else:
                self.log_signal.emit(f"Erro HTTP ao consultar contrato: {e}", "error")
        except requests.exceptions.RequestException as e:
            self.log_signal.emit(f"Erro de conexão ao consultar contrato: {e}", "error")

# --- APIClient para a GUI ---
class APIClient:
    def __init__(self, base_url):
        self.base_url = base_url

    def set_base_url(self, new_url):
        self.base_url = new_url

    def get_node_info(self):
        try:
            response = requests.get(f"{self.base_url}/chain", timeout=5)
            response.raise_for_status()
            data = response.json()
            return {
                "node_id": data.get("node_id", "N/A"),
                "url": self.base_url,
                "chain_length": data.get("length", 0),
                "pending_transactions": len(data.get("pending_transactions", []))
            }
        except requests.exceptions.RequestException as e:
            print(f"Erro ao buscar informações do nó: {e}")
            return {
                "node_id": "Erro",
                "url": self.base_url,
                "chain_length": "Erro",
                "pending_transactions": "Erro"
            }

# --- Execução Principal ---
def run_server():
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)

if __name__ == "__main__":
    conn = sqlite3.connect(DATABASE, check_same_thread=False)
    node_id = load_or_create_node_id()
    blockchain = Blockchain(conn, node_id)

    port = int(os.environ.get('PORT', 5000))
    meu_ip = get_my_ip()
    meu_url = f"http://{meu_ip}:{port}"
    print(f"[INFO] Node URL: {meu_url}")

    threading.Thread(target=discover_peers, daemon=True).start()

    if len(known_nodes) > 0:
        print("[BOOT] Tentando resolver conflitos na inicialização...")
        blockchain.resolve_conflicts()
    else:
        print("[BOOT] Nenhum peer conhecido. Operando de forma isolada inicialmente.")

    # Iniciar servidor Flask em thread separada
    server_thread = threading.Thread(target=run_server, daemon=True)
    server_thread.start()
    time.sleep(1) # Pequeno atraso para garantir que o Flask esteja totalmente pronto

    # Iniciar verificação de sincronização automática
    threading.Thread(target=auto_sync_checker, args=(blockchain,), daemon=True).start()

    qt_app = QApplication(sys.argv)
    window = KertOneCoreClient()
    window.show()
    sys.exit(qt_app.exec_())
