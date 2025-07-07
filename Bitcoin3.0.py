import requests
import json
import concurrent.futures
from pathlib import Path
import ipaddress
import time
import hashlib
import threading
from urllib.parse import urlencode
import warnings
from flask import Flask, request, jsonify
import os
import string
import random
import ecdsa
import base58
import secrets
import sqlite3
from collections import Counter
import datetime
import jwt
import logging
from datetime import datetime, timedelta

# --- Configuration ---
PORTAS = [5000]
CAMINHO = "/p2p-btc3"
HEADERS = {"User-Agent": "p2p-btc3-AutoScanner/1.0"}
ARQUIVO_PEERS = "peers.json"
SECRET_KEY = "25s5ash5556s54d45593ksaa55s25a45545s5d4a5s55440-0"
LIBERAR_PORTAS = True
mysql_pool = None # Placeholder for MySQL connection pool, not used in this version.

# --- Logging Setup ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --- Global Variables ---
app = Flask(__name__)
mining_lock = threading.Lock()
parar_event = threading.Event()
encontrados_lock = threading.Lock()
cache_ultimo_bloco = {}
nodes = {}  # ip: dados for actively registered nodes (memory)
known_nodes = [] # List of peers from peers.json and discovered
falhas = {} # To track consecutive failures for heartbeat

# --- Helper Functions ---
def registrar_em_peers(ip, peers_list):
    """Registers this node's IP with a list of other peers."""
    for peer in peers_list:
        try:
            url = f"http://{peer}:5000/register_node"
            requests.post(url, json={"ip": ip}, timeout=5)
            logger.info(f"Registered with {url}")
        except Exception as e:
            logger.warning(f"Failed to register with {peer}: {e}")

def ip_range(start_ip, end_ip):
    """Generates a list of IPs within a given range."""
    start = ipaddress.ip_address(start_ip)
    end = ipaddress.ip_address(end_ip)
    if start.version != end.version:
        raise ValueError("Start IP and End IP must be of the same version (IPv4 or IPv6)")
    ips = []
    current = start
    while current <= end:
        ips.append(str(current))
        current += 1
    return ips
    
def montar_url(ip, porta, protocolo):
    """Constroi uma URL com protocolo, IP (IPv4/IPv6), porta e caminho."""
    if ':' in ip and not ip.startswith('['):  # IPv6 precisa de colchetes
        ip_formatado = f"[{ip.strip('[]')}]"
    else:
        ip_formatado = ip
    return f"{protocolo}://{ip_formatado}:{porta}{CAMINHO}"



def peer_tem_endpoint_mine(ip):
    """Checks if a peer has a reachable /mine endpoint."""
    params = {"miner": "teste"}
    portas_testar = [5000]
    for porta in portas_testar:
        protocolos = ["https"] if porta == 443 else ["http"]
        for protocolo in protocolos:
            url_base = montar_url(ip, porta, protocolo)
            url_mine = url_base.rsplit('/', 1)[0] + "/mine"  # replaces path
            try:
                logger.debug(f"🔍 Testing /mine at: {url_mine}")
                resp = requests.get(url_mine, params=params, timeout=5, verify=False)
                if resp.status_code == 200:
                    return True
            except Exception as e:
                logger.debug(f" Error testing /mine at {url_mine}: {e}")
    return False

def salvar_peers_sem_mine(ip):
    """Saves IPs of peers without a /mine endpoint to a separate file."""
    arquivo = Path("peers_sem_mine.json")
    try:
        lista = json.loads(arquivo.read_text()) if arquivo.exists() else []
    except json.JSONDecodeError:
        lista = []
    if ip not in lista:
        lista.append(ip)
        arquivo.write_text(json.dumps(sorted(lista), indent=4))

def thread_busca_continua_peers(intervalo=60):
    """Continuously searches for new peers from existing ones."""
    while True:
        atualizar_peers_de_peers_existentes()
        logger.info("🔄 Peer list automatically updated.")
        time.sleep(intervalo)

def atualizar_peers_de_peers_existentes():
    """Updates known peers by querying existing known peers."""
    peers_conhecidos = carregar_peers()
    todos_peers_novos = set()
    for ip in peers_conhecidos:
        for porta in PORTAS:
            protocolos = ["https"] if porta == 443 else ["http"]
            for protocolo in protocolos:
                url_base = f"{protocolo}://{ip}:{porta}"
                novos_peers = puxar_nodes_de_peer(url_base)
                if novos_peers:
                    todos_peers_novos.update(novos_peers)
    if todos_peers_novos:
        salvar_peers(todos_peers_novos)

def puxar_nodes_de_peer(url_base):
    """Fetches nodes from a given peer's API endpoints."""
    endpoints = ["/nodes", "/register_node"]
    todos_peers = []
    for endpoint in endpoints:
        url = url_base.rstrip('/') + "/" + endpoint.lstrip('/')
        try:
            resp = requests.get(url, timeout=8, headers=HEADERS, verify=False)
            if resp.status_code == 200:
                dados = resp.json()
                if isinstance(dados, list):
                    todos_peers.extend([ip for ip in dados if isinstance(ip, str)])
                elif isinstance(dados, dict):
                    if "nodes" in dados and isinstance(dados["nodes"], list):
                        for node_data in dados["nodes"]:
                            if isinstance(node_data, dict) and "ip" in node_data:
                                todos_peers.append(node_data["ip"])
                            elif isinstance(node_data, str):
                                todos_peers.append(node_data)
                break
        except Exception:
            logger.debug(f"Searching P2p nodes at {url}")
    ips_formatados = []
    for ip in set(todos_peers):
        if ':' in ip and not ip.startswith('['):
            ip = f"[{ip}]"
        ips_formatados.append(ip)
    if ips_formatados:
        salvar_peers(ips_formatados)
    return ips_formatados

def sincronizar_peers_de_arquivo():
    """Synchronizes known peers by querying the /nodes or /register_node endpoints of existing peers."""
    peers_existentes = carregar_peers()
    logger.info(f"\nSyncing /register_node from {len(peers_existentes)} known peers...")
    novos_peers = set()
    for ip in peers_existentes:
        for porta in PORTAS:
            protocolos = ["https"] if porta == 443 else ["http"]
            for protocolo in protocolos:
                url_base = f"{protocolo}://{ip}:{porta}"
                novos = puxar_nodes_de_peer(url_base)
                if novos:
                    logger.info(f"{len(novos)} new peers received from {url_base}")
                    novos_peers.update(novos)
    if novos_peers:
        salvar_peers(novos_peers)

def verificar_ip(ip, contador, total, encontrados_list):
    """Verifies if an IP hosts a valid BTC3 node."""
    tokens_validos = gerar_tokens_validos()
    for porta in PORTAS:
        protocolos = ["https"] if porta == 443 else ["http"]
        for protocolo in protocolos:
            url = montar_url(ip, porta, protocolo)
            try:
                resp = requests.get(url, headers=HEADERS, timeout=3, verify=False)
                if resp.status_code == 200 and "BTC3" in resp.text:
                    if any(token in resp.text for token in tokens_validos):
                        with encontrados_lock:
                            if ip not in encontrados_list:
                                encontrados_list.append(ip)
                        if peer_tem_endpoint_mine(ip):
                            logger.info(f"\n[{contador}/{total}] Valid BTC3 node with /mine found at {url}")
                        else:
                            logger.warning(f"\n [{contador}/{total}] Peer {ip} valid but without /mine (added anyway)")
                        return
            except (requests.exceptions.SSLError,
                    requests.exceptions.ConnectTimeout,
                    requests.exceptions.ConnectionError):
                continue
            except Exception as e:
                logger.warning(f"Unexpected error verifying IP {ip}: {e}")
    logger.debug(f"\r🔎 [{contador}/{total}] Scanned: {ip}", end='', flush=True)

from urllib.parse import urlparse

def carregar_peers():
    with open('peers.json', 'r') as f:
        raw_peers = json.load(f)

    normalized_peers = []
    for peer in raw_peers:
        # Extrai apenas o hostname (IP)
        parsed = urlparse(peer if "://" in peer else f"http://{peer}")
        hostname = parsed.hostname
        normalized_peers.append(hostname)

    return sorted(set(normalized_peers))  # Retorna só IPs limpos

def salvar_peers(new_peers_list):
    """Saves a list of peers to the peers.json file."""
    arquivo = Path(ARQUIVO_PEERS)
    peers_atuais = set(carregar_peers())
    new_peers_set = set(new_peers_list)
    todos_peers = peers_atuais.union(new_peers_set)
    if todos_peers != peers_atuais:
        arquivo.write_text(json.dumps(sorted(list(todos_peers)), indent=4))
        logger.info(f"🟢 peers.json updated with {len(todos_peers - peers_atuais)} new peers.")
    else:
        logger.info(" peers.json had no changes.")

def iniciar_scanner(faixa_inicio, faixa_fim, ips_alvo=None):
    """Starts the BTC3 node scanner within a specified IP range or for target IPs."""
    logger.info(" Starting BTC3 scan...\n")
    if ips_alvo is None:
        ips = ip_range(faixa_inicio, faixa_fim)
    else:
        ips = ips_alvo
    total = len(ips)
    encontrados_list = []
    peers_atuais = set(carregar_peers())
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = []
        for i, ip in enumerate(ips, 1):
            if parar_event.is_set():
                break
            futures.append(executor.submit(verificar_ip, ip, i, total, encontrados_list))
        concurrent.futures.wait(futures)
    novos = list(set(encontrados_list) - peers_atuais)
    if novos:
        salvar_peers(novos)
    else:
        logger.info("\nNo new distinct nodes found.")
    return encontrados_list

def scanner_continuo(start_ip, end_ip, bloco_tamanho=10000, delay_seg=1):
    """Performs a continuous scan of IP ranges in blocks."""
    peers_atuais = set(carregar_peers())
    if peers_atuais:
        logger.info(f"Scanning IPs from peers.json ({len(peers_atuais)})...")
        encontrados = iniciar_scanner(None, None, ips_alvo=list(peers_atuais))
        if encontrados:
            logger.info(f" Valid nodes found in peer list: {encontrados}")
            return encontrados
    start = ipaddress.ip_address(start_ip)
    end = ipaddress.ip_address(end_ip)
    atual = start
    while atual <= end:
        fim_bloco_int = int(atual) + bloco_tamanho
        if fim_bloco_int > int(end):
            fim_bloco_int = int(end)
        fim_bloco = ipaddress.ip_address(fim_bloco_int)
        logger.info(f"\nStarting scan from {atual} to {fim_bloco}")
        encontrados = iniciar_scanner(str(atual), str(fim_bloco))
        if encontrados:
            logger.info(f" Valid nodes found in block: {encontrados}")
            return encontrados
        atual = ipaddress.ip_address(fim_bloco_int + 1)
        logger.info(f"⏳ Finished block, waiting {delay_seg} seconds...")
        time.sleep(delay_seg)
    return []

def backoff_exp(attempt, base=5, max_delay=60):
    """Calculates exponential backoff delay."""
    delay = base * (2 ** attempt)
    return min(delay, max_delay)

def minerar_com_peer_continuo(peer, miner_address="btc3-local-miner", usar_gpu=False,
                             tentativas=5, delay_tentativa=0, limite_blocos=None, max_503_consecutivos=3):
    """Continuously mines with a given peer."""
    params = {"miner": miner_address, "gpu": str(usar_gpu).lower()}
    logger.info(f" Starting continuous mining on peer: {peer}")
    blocos_minerados = 0
    erros_503_consecutivos = 0
    global cache_ultimo_bloco
    while limite_blocos is None or blocos_minerados < limite_blocos:
        sucesso = False
        for porta in PORTAS:
            protocolos = ["https"] if porta == 443 else ["http"]
            for protocolo in protocolos:
                url = montar_url(peer, porta, protocolo).rsplit('/', 1)[0] + "/mine"
                full_url = f"{url}?{urlencode(params)}"
                for tentativa in range(tentativas):
                    logger.info(f" Mining via: {full_url} (Attempt {tentativa+1}/{tentativas})")
                    try:
                        resp = requests.get(full_url, headers=HEADERS, timeout=25, verify=False)
                        if resp.status_code == 200:
                            dados = resp.json()
                            bloco_id = dados.get("block") or dados.get("block_id")
                            if bloco_id:
                                ultimo = cache_ultimo_bloco.get(peer)
                                if ultimo == bloco_id:
                                    logger.info(f"🕒 Block {bloco_id} already mined on peer {peer}, waiting before new attempt...")
                                    if delay_tentativa > 0:
                                        time.sleep(delay_tentativa)
                                    continue
                                else:
                                    cache_ultimo_bloco[peer] = bloco_id
                            logger.info(f"Block mined via peer {peer}: {json.dumps(dados, indent=2)}")
                            blocos_minerados += 1
                            sucesso = True
                            erros_503_consecutivos = 0
                            break
                        elif resp.status_code == 409:
                            logger.warning(f" Conflict (409): Another miner already created the block. Waiting 10s...")
                            time.sleep(10)
                        elif resp.status_code == 503:
                            erros_503_consecutivos += 1
                            delay = backoff_exp(erros_503_consecutivos - 1)
                            logger.warning(f" Service unavailable (503) on peer {peer}. Retrying in {delay}s...")
                            time.sleep(delay)
                            if erros_503_consecutivos >= max_503_consecutivos:
                                logger.warning(f" Block Not Found, Difficulty Heavy... {peer}.")
                                return False
                        else:
                            logger.error(f"Unexpected error from peer {peer}: {resp.status_code}")
                    except (requests.exceptions.SSLError,
                            requests.exceptions.ConnectTimeout,
                            requests.exceptions.ConnectionError) as e:
                        logger.warning(f" Connection/SSL error mining on peer {peer}: {e}")
                    except Exception as e:
                        logger.error(f" Unexpected error mining via {peer}: {e}")
                    if delay_tentativa > 0 and tentativa < tentativas - 1:
                        logger.info(f"⏳ Retrying in {delay_tentativa}s...")
                        time.sleep(delay_tentativa)
                if sucesso:
                    break
            if sucesso:
                break
        if not sucesso:
            logger.error(f"Mining failed with peer {peer}. Trying next peer...")
            return False
        time.sleep(1)
    logger.info(f" Limit of {limite_blocos} blocks mined reached on peer {peer}. Stopping continuous mining.")
    return True

def garantir_arquivo_peers():
    """Ensures the peers.json file exists."""
    arquivo = Path(ARQUIVO_PEERS)
    if not arquivo.exists():
        arquivo.write_text("[]")
        logger.info(f"File {ARQUIVO_PEERS} created as it did not exist.")

def obter_ip_publico():
    """Fetches the public IP address of the node."""
    try:
        resp = requests.get("https://api.ipify.org", timeout=5)
        if resp.status_code == 200:
            return resp.text.strip()
    except Exception:
        logger.error("Failed to get public IP.")
        pass
    return None

def adicionar_peer_manual(ip):
    """Adds an IP address to the known peers list manually."""
    arquivo = Path(ARQUIVO_PEERS)
    try:
        peers_list = json.loads(arquivo.read_text()) if arquivo.exists() else []
    except json.JSONDecodeError:
        peers_list = []
    if ip not in peers_list:
        peers_list.append(ip)
        arquivo.write_text(json.dumps(sorted(peers_list), indent=4))
        logger.info(f"📝 Client public IP added directly to peers.json: {ip}")
    else:
        logger.info(f"Public IP already in peers.json: {ip}")

def gerar_tokens_validos(intervalo_segundos=60, tolerancia_janelas=1):
    """Generates valid tokens for a given time window."""
    now = int(time.time() // intervalo_segundos)
    tokens = []
    for offset in range(-tolerancia_janelas, tolerancia_janelas + 1):
        time_window = now + offset
        texto = f"{SECRET_KEY}{time_window}"
        token = hashlib.sha256(texto.encode()).hexdigest()
        tokens.append(token)
    return tokens

def garantir_protocolo(url):
    """Ensures the URL has http:// or https://."""
    if not url.startswith('http://') and not url.startswith('https://'):
        return 'http://' + url
    return url

def url_sem_protocolo_porta(url):
    """Removes protocol and port from a URL to extract just the IP."""
    parsed = urlparse(url)
    if parsed.port:
        return parsed.hostname
    return parsed.netloc

def salvar_nos():
    """Saves the current list of known nodes to peers.json."""
    peers_to_save = [node['ip'] for node in nodes.values()]
    salvar_peers(peers_to_save)

def sync_all():
    """Synchronizes blockchain and known nodes from all peers."""
    sincronizar_blockchain()
    for node_ip in known_nodes:
        atualizar_peers_de_no(node_ip)

def create_mysql_connection():
    """Returns a MySQL connection from the pool. (Currently a placeholder)."""
    return mysql_pool.get_connection() if 'mysql_pool' in globals() else None

def update_balance(conn, address, amount):
    """Updates a wallet balance in the database (placeholder for actual DB logic)."""
    # This function needs actual database interaction logic if you're using a real DB.
    # For now, it's just a placeholder as the Blockchain class handles wallet balances.
    pass

def get_balance_db(conn, address):
    """Retrieves a wallet balance from the database (placeholder for actual DB logic)."""
    # This function needs actual database interaction logic if you're using a real DB.
    # For now, it's just a placeholder as the Blockchain class handles wallet balances.
    return blockchain.get_balance(address)

def rodar_servidor_flask(porta=5000):
    """Starts the Flask server."""
    app.run(host='0.0.0.0', port=porta, threaded=True)

class Wallet:
    """Represents a cryptocurrency wallet."""
    def __init__(self):
        self.private_key = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.public_key = self.private_key.get_verifying_key()
        self.address = self.generate_address(self.public_key.to_string())

    def generate_address(self, public_key_bytes):
        sha256_1 = hashlib.sha256(public_key_bytes).digest()
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_1)
        hashed_public_key = ripemd160.digest()

        # Add network byte (0x00 for mainnet, 0x6f for testnet)
        network_byte = b'\x00'
        checksum_content = network_byte + hashed_public_key
        checksum_1 = hashlib.sha256(checksum_content).digest()
        checksum_2 = hashlib.sha256(checksum_1).digest()
        checksum = checksum_2[:4]

        return base58.b58encode(checksum_content + checksum).decode('utf-8')

class Blockchain:
    """Represents the blockchain."""
    INTERVALO_AJUSTE = 2016
    BLOCO_ALVO_SEGUNDOS = 600
    TEMPO_ALVO_TOTAL = INTERVALO_AJUSTE * BLOCO_ALVO_SEGUNDOS

    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.wallets = {}
        self.difficulty = 1
        self.lock = threading.Lock()
        self.peers = set() # To store IPs of other nodes

        self.init_db()
        self.load_chain_from_db()
        self.load_wallets_from_db()
        
        # Create genesis block if chain is empty
        if not self.chain:
            self.create_genesis_block()

    def init_db(self):
        conn = sqlite3.connect('blockchain.db')
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS blockchain (
                idx INTEGER PRIMARY KEY,
                block TEXT NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS wallets (
                address TEXT PRIMARY KEY,
                data TEXT NOT NULL
            )
        ''')
        conn.commit()
        conn.close()

    def load_chain_from_db(self):
        conn = sqlite3.connect('blockchain.db')
        c = conn.cursor()
        c.execute('SELECT block FROM blockchain ORDER BY idx')
        rows = c.fetchall()
        self.chain = [json.loads(row[0]) for row in rows]
        if self.chain:
            self.difficulty = self.chain[-1].get('difficulty', 1)
        conn.close()

    def save_chain_to_db(self):
        conn = sqlite3.connect('blockchain.db')
        c = conn.cursor()
        c.execute('DELETE FROM blockchain')
        for i, block in enumerate(self.chain):
            c.execute('INSERT INTO blockchain (idx, block) VALUES (?, ?)', (i, json.dumps(block)))
        conn.commit()
        conn.close()

    def load_wallets_from_db(self):
        conn = sqlite3.connect('blockchain.db')
        c = conn.cursor()
        c.execute("SELECT address, data FROM wallets")
        results = c.fetchall()
        self.wallets = {addr: json.loads(data) for addr, data in results}
        conn.close()

    def save_wallets_to_db(self):
        conn = sqlite3.connect('blockchain.db')
        c = conn.cursor()
        c.execute("DELETE FROM wallets")
        for address, data in self.wallets.items():
            c.execute("INSERT INTO wallets (address, data) VALUES (?, ?)", (address, json.dumps(data)))
        conn.commit()
        conn.close()

    def create_genesis_block(self):
        if self.chain:
            return

        genesis_block = {
            "index": 1,
            "timestamp": 1720000000.0,
            "transactions": [],
            "proof": 100,
            "previous_hash": "0",
            "difficulty": 1,
            "miners": {"1HrqaZRbaqru4rtKdLZkBg7exu2QoGPxhA": 1},
            "hash": self.hash_block({
                "index": 1,
                "timestamp": 1720000000.0,
                "transactions": [],
                "proof": 100,
                "previous_hash": "0",
                "difficulty": 1,
                "miners": {"1HrqaZRbaqru4rtKdLZkBg7exu2QoGPxhA": 1}
            })
        }
        self.chain.append(genesis_block)
        self.save_chain_to_db()
        logger.info("Genesis block created.")

    def reset_local_data(self):
        for fname in ['blockchain.db', 'blockchain.json', 'wallets.json']:
            try:
                os.remove(fname)
                logger.info(f"Removed {fname}")
            except FileNotFoundError:
                continue

    def create_new_block(self, previous_hash, proof, timestamp, miner, transactions=None):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': timestamp,
            'transactions': transactions or self.current_transactions.copy(),
            'proof': proof,
            'previous_hash': previous_hash,
            'difficulty': self.difficulty,
            'miner': miner,
        }
        block['hash'] = Blockchain.hash_block(block)
        return block

    @staticmethod
    def hash_block(block):
        block_copy = block.copy()
        block_copy.pop('hash', None)
        block_str = json.dumps(block_copy, sort_keys=True).encode()
        return hashlib.sha256(block_str).hexdigest()
 
    @property
    def last_block(self):
        return self.chain[-1] if self.chain else None

    def new_transaction(self, sender, recipient, amount):
        if sender != "0" and self.get_balance(sender) < amount:
            return False
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount
        })
        self.update_balance(sender, -amount if sender != "0" else 0)
        self.update_balance(recipient, amount)
        self.save_wallets_to_db() # Save wallet changes to DB
        return self.last_block['index'] + 1 if self.last_block else 1

    def update_balance(self, address, amount):
        if address not in self.wallets:
            self.wallets[address] = {'balance': 0.0}
        self.wallets[address]['balance'] += amount

    def get_balance(self, address):
        return self.wallets.get(address, {'balance': 0.0})['balance']

    def create_wallet(self):
        wallet = Wallet()
        self.wallets[wallet.address] = {
            'private_key': wallet.private_key.to_string().hex(),
            'balance': 0.0
        }
        self.save_wallets_to_db()
        return wallet.address, wallet.private_key.to_string().hex()

    def proof_of_work(self, last_proof, usar_gpu=False):
        # This is a simplified PoW. For a real blockchain, you'd need a more robust algorithm.
        proof = 0
        while True:
            guess = f'{last_proof}{proof}'.encode()
            guess_hash = hashlib.sha256(guess).hexdigest()
            if guess_hash[:self.difficulty] == "0" * self.difficulty:
                return proof
            proof += 1

    def new_block(self, proof, miner_address, previous_hash=None):
        with self.lock:
            if previous_hash is None:
                previous_hash = self.hash_block(self.last_block) if self.last_block else '0'

            # Clear transactions that were added to the block
            transactions_to_add = self.current_transactions.copy()
            self.current_transactions = []

            block = self.create_new_block(previous_hash, proof, time.time(), miner_address, transactions_to_add)
            self.chain.append(block)
            self.save_chain_to_db()
            self.adjust_difficulty() # Adjust difficulty after a new block
            return block

    def current_reward(self):
        initial_reward = 0.50
        halving_interval = 210000
        blocks_mined = len(self.chain)
        halvings = blocks_mined // halving_interval
        return max(initial_reward / (2 ** halvings), 0.00000001)

    def replace_chain(self, new_chain):
        if len(new_chain) > len(self.chain) and self.is_chain_valid(new_chain):
            self.chain = new_chain
            self.save_chain_to_db()
            logger.info("Blockchain replaced with a longer, valid chain.")
            return True
        return False

    def is_chain_valid(self, chain):
        for i in range(1, len(chain)):
            current_block = chain[i]
            prev_block = chain[i - 1]

            if current_block['previous_hash'] != Blockchain.hash_block(prev_block):
                logger.warning(f"Chain invalid: Previous hash mismatch at block {current_block['index']}")
                return False

            if not self.valid_proof(prev_block['proof'], current_block['proof'], current_block.get('difficulty', 1)):
                logger.warning(f"Chain invalid: Invalid proof of work at block {current_block['index']}")
                return False
        return True



    def valid_proof(self, last_proof, proof, difficulty):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:difficulty] == "0" * difficulty

    def adjust_difficulty(self):
        if len(self.chain) % self.INTERVALO_AJUSTE == 0:
            first_block_in_interval = self.chain[-self.INTERVALO_AJUSTE]
            time_taken = self.last_block['timestamp'] - first_block_in_interval['timestamp']

            if time_taken < self.TEMPO_ALVO_TOTAL / 2:
                self.difficulty += 1
                logger.info(f"Difficulty increased to {self.difficulty}")
            elif time_taken > self.TEMPO_ALVO_TOTAL * 2:
                if self.difficulty > 1: # Ensure difficulty doesn't go below 1
                    self.difficulty -= 1
                    logger.info(f"Difficulty decreased to {self.difficulty}")
            else:
                logger.info("Difficulty remains unchanged.")
        else:
            logger.debug("Not time to adjust difficulty.")

    def load_state(self):
        """Reloads the blockchain and wallet states from the database."""
        self.load_chain_from_db()
        self.load_wallets_from_db()


# Instantiate the blockchain
blockchain = Blockchain()

# --- Flask Routes ---
@app.route('/known_nodes')
def get_known_nodes():
    """Returns a list of all known nodes."""
    conhecidos = set(carregar_peers())
    all_nodes = []

    for node_data in nodes.values():
        all_nodes.append(node_data)

    for ip in conhecidos:
        if ip not in nodes: # Add peers from file that are not in active memory
            all_nodes.append({'ip': ip, 'name': f"Node {ip}"})

    return jsonify({'known_nodes': all_nodes})

@app.route('/last_block', methods=['GET'])
def last_block():
    """Returns the last block in the blockchain."""
    if blockchain.last_block:
        return jsonify(blockchain.last_block)
    return jsonify({"message": "Blockchain is empty"}), 404

@app.route('/submit_block', methods=['POST'])
def submit_block():
    """Endpoint for submitting a newly mined block."""
    data = request.get_json()

    required = ['index', 'proof', 'previous_hash', 'miner']
    if not all(k in data for k in required):
        return jsonify({'error': 'Missing required fields in block data'}), 400

    try:
        blockchain.load_state() # Ensure up-to-date state

        last_block = blockchain.last_block
        if not last_block:
            return jsonify({'error': 'Blockchain is empty. Cannot submit a block.'}), 400

        # Validate if the block makes sense with the local blockchain
        if data['index'] != last_block['index'] + 1:
            return jsonify({'error': 'Invalid block index'}), 400

        if data['previous_hash'] != blockchain.hash_block(last_block):
            return jsonify({'error': 'Previous hash does not match'}), 400

        # Check proof of work using the current difficulty
        current_difficulty = last_block.get('difficulty', 1)
        if not blockchain.valid_proof(last_block['proof'], data['proof'], current_difficulty):
            return jsonify({'error': 'Invalid proof of work'}), 400

        # Reward the miner and add the block
        blockchain.new_transaction("0", data['miner'], blockchain.current_reward())
        novo_bloco = blockchain.new_block(data['proof'], data['miner'], data['previous_hash'])

        logger.info(f" Block #{novo_bloco['index']} accepted from miner {data['miner']}")

        return jsonify({
            "message": "Block accepted and added to the blockchain.",
            "block": novo_bloco
        }), 201

    except Exception as e:
        logger.error(f"Error validating block: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/balance/<address>', methods=['GET'])
def get_balance_endpoint(address):
    """Retrieves the balance for a given wallet address by querying peers."""
    peers = carregar_peers()
    portas = [5000]
    saldos_confirmados = []

    for peer in peers:
        for porta in portas:
            base_url = garantir_protocolo(peer)
            if ':' not in peer.split('//')[-1]:
                url = f"{base_url}:{porta}/balance/{address}"
            else:
                url = f"{base_url}/balance/{address}"
            try:
                r = requests.get(url, timeout=5)
                if r.status_code == 200:
                    saldo = float(r.json().get('balance', 0))
                    saldos_confirmados.append(saldo)
                    logger.info(f" Peer {peer} returned balance: {saldo}")
                    break
                else:
                    logger.warning(f"Peer {peer} returned invalid status: {r.status_code}")
            except Exception as e:
                logger.warning(f"Failure on peer {peer}: {e}")
                continue

    total_ativos = len(saldos_confirmados)
    logger.info(f"Total active peers: {total_ativos}")

    if total_ativos == 0:
        return jsonify({'error': 'No active peers responded with a valid balance'}), 500

    contagem = Counter(saldos_confirmados)
    logger.info(f"Count of confirmed balances: {contagem}")

    mais_comum, ocorrencias = contagem.most_common(1)[0]
    saldo_mais_alto = max(saldos_confirmados)
    logger.info(f"Most common balance: {mais_comum} with {ocorrencias} occurrences")
    logger.info(f"Highest balance received: {saldo_mais_alto}")

    min_confirmacoes = 2
    min_confirmacoes = min(min_confirmacoes, total_ativos)
    if total_ativos < 3:
        min_confirmacoes = 1

    logger.info(f"Minimum confirmations required: {min_confirmacoes}")

    if ocorrencias >= min_confirmacoes:
        blockchain.wallets[address] = {'balance': mais_comum}
        blockchain.save_wallets_to_db()
        return jsonify({
            'address': address,
            'balance': f"{mais_comum:.8f}",
            'confirmacoes': ocorrencias,
            'peers_ativos': total_ativos
        }), 200
    else:
        blockchain.wallets[address] = {'balance': saldo_mais_alto}
        blockchain.save_wallets_to_db()
        return jsonify({
            'address': address,
            'balance': f"{saldo_mais_alto:.8f}",
            'confirmacoes': ocorrencias,
            'peers_ativos': total_ativos,
            'warning': 'No consensus among peers, but returning the highest available balance'
        }), 200

def propagar_para_peers(transacao):
    """Propagates a transaction to known peers."""
    peers = carregar_peers()
    for peer in peers:
        try:
            if not peer.endswith("/"):
                peer += "/"
            url = peer + "transactions/new"
            requests.post(url, json=transacao, timeout=2)
        except Exception as e:
            logger.warning(f"Failed to propagate transaction to {peer}: {e}")
            continue

def tentar_peers(path, method='GET', json_data=None, timeout=5):
    """Attempts to send a request to known peers."""
    peers = carregar_peers()
    portas = [5000]

    for peer in peers:
        for porta in portas:
            try:
                url_base = garantir_protocolo(peer)
                endereco = peer.split('//')[-1]
                if ':' not in endereco:
                    url = f"{url_base}:{porta}/{path.lstrip('/')}"
                else:
                    url = f"{url_base}/{path.lstrip('/')}"
                
                if method.upper() == 'GET':
                    r = requests.get(url, timeout=timeout)
                elif method.upper() == 'POST':
                    r = requests.post(url, json=json_data, timeout=timeout)
                else:
                    return None
                
                if r.status_code in (200, 201):
                    return r
            except requests.RequestException as e:
                logger.warning(f"Error accessing {url}: {e}")
                continue
    return None

@app.route('/wallet/create', methods=['POST'])
def create_wallet_endpoint():
    """Creates a new wallet and registers it with peers."""
    peers = carregar_peers()
    portas = [5000]
    timeout_segundos = 10

    # First, try to create it locally
    try:
        address, private_key = blockchain.create_wallet()
        logger.info(f"🆕 Local wallet created: Address={address}")
        return jsonify({
            'address': address,
            'private_key': private_key
        }), 201
    except Exception as e:
        logger.error(f"Error creating local wallet: {e}")
        # If local creation fails, try to create it via peers

    for peer in peers:
        base_url = garantir_protocolo(peer).rstrip('/')
        endereco = peer.split('//')[-1]
        for porta in portas:
            if ':' not in endereco:
                url = f"{base_url}:{porta}/wallet/create"
            else:
                url = f"{base_url}/wallet/create"
            try:
                logger.info(f"Attempting to create wallet on peer: {url}")
                response = requests.get(url, timeout=timeout_segundos, verify=False)
                response.raise_for_status()
                data = response.json()
                logger.info(f"Response from peer {peer}: {data}")

                if 'address' in data and 'private_key' in data:
                    address = data['address']
                    private_key = data['private_key']

                    blockchain.wallets[address] = {
                        'private_key': private_key,
                        'balance': 0.0
                    }
                    blockchain.save_wallets_to_db()

                    return jsonify({
                        'address': address,
                        'private_key': private_key
                    }), 201
                else:
                    logger.warning(f" Peer {peer} did not return expected data for wallet creation.")

            except requests.RequestException as e:
                logger.error(f"Error accessing {url}: {e}")
                continue

    return jsonify({'error': 'Failed to create wallet. All nodes failed or no local creation possible.'}), 503
    
@app.route('/chain', methods=['GET'])
def full_chain():
    """Returns the full blockchain and attempts to synchronize with peers."""
    peers = carregar_peers()
    portas = [5000]
    timeout_segundos = 10

    blockchain.load_state() # Ensure local chain is up-to-date

    for peer in peers:
        base_url = garantir_protocolo(peer).rstrip('/')
        endereco = peer.split('//')[-1]
        for porta in portas:
            if ':' not in endereco:
                url = f"{base_url}:{porta}/chain"
            else:
                url = f"{base_url}/chain"

            try:
                logger.info(f"Attempting to get blockchain from peer: {url}")
                response = requests.get(url, timeout=timeout_segundos, verify=False)
                response.raise_for_status()
                data = response.json()
                logger.debug(f"Response from peer {peer}: {data}")

                if 'chain' in data:
                    remote_blockchain_data = data['chain']

                    if blockchain.replace_chain(remote_blockchain_data):
                        return jsonify({'message': 'Blockchain replaced by longer and valid version!', 'new_chain': blockchain.chain}), 200
                    else:
                        logger.warning(f" Blockchain from peer {peer} invalid or shorter. Continuing to check other peers...")

            except requests.RequestException as e:
                logger.error(f"Error accessing {url}: {e}")
                continue

    return jsonify({
        'message': 'No longer valid blockchain found among peers, or local is already the longest.',
        'local_length': len(blockchain.chain),
        'local_chain': blockchain.chain
    }), 200 # Return 200 even if no replacement, as it's a valid query

@app.route('/transactions/new', methods=['POST'])
def new_transaction_endpoint():
    """Endpoint for creating a new transaction."""
    peers = carregar_peers()
    portas = [5000]
    timeout_segundos = 10

    values = request.get_json()
    required = ['sender', 'recipient', 'amount']

    if not values or not all(k in values for k in required):
        return jsonify({'error': 'Missing values.'}), 400

    # Validate amount
    try:
        amount = float(values['amount'])
        if amount <= 0:
            return jsonify({'error': 'Amount must be greater than zero.'}), 400
        values['amount'] = amount
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount.'}), 400

    # Try to process locally first
    try:
        blockchain.load_state() # Ensure up-to-date wallet balances
        index = blockchain.new_transaction(values['sender'], values['recipient'], values['amount'])
        if index is False:
            return jsonify({'error': 'Insufficient balance.'}), 400
        logger.info(f"Transaction registered locally for block {index}")
        # Propagate to peers in a non-blocking way
        threading.Thread(target=propagar_para_peers, args=(values,)).start()
        return jsonify({
            'message': f'Transaction registered locally and propagated to peers. Will be added to block {index}',
            'transaction': values
        }), 201
    except Exception as e:
        logger.error(f"Error registering transaction locally: {e}")

    # If local fails or not preferred, try to propagate to peers
    if not peers:
        return jsonify({'error': 'No peers available and local processing failed.'}), 500

    for peer in peers:
        base_url = garantir_protocolo(peer).rstrip('/')
        endereco = peer.split('//')[-1]

        for porta in portas:
            if ':' not in endereco:
                url = f"{base_url}:{porta}/transactions/new"
            else:
                url = f"{base_url}/transactions/new"

            try:
                r = requests.post(url, json=values, timeout=timeout_segundos, verify=False)
                if r.status_code == 201:
                    logger.info(f"Transaction registered on peer {peer}: {r.json()}")
                    return jsonify(r.json()), 201
            except requests.RequestException as e:
                logger.warning(f"Error accessing {url}: {e}")
                continue

    return jsonify({'error': 'Could not register transaction on any peer.'}), 500

# Mock for NFC card generation (for demonstration purposes only)
def gerar_cartao_nfc(private_key_hex):
    # This is a very simplified mock. In a real scenario, this would involve
    # cryptographic operations related to the private key to generate a card.
    # DO NOT use this for any real financial transactions.
    random.seed(private_key_hex) # Use private key to pseudo-randomly generate details
    card_number = ''.join([str(random.randint(0, 9)) for _ in range(16)])
    cvv = ''.join([str(random.randint(0, 9)) for _ in range(3)])
    expiry_month = str(random.randint(1, 12)).zfill(2)
    expiry_year = str(random.randint(25, 30)) # Example years

    return {
        "card_number": ' '.join([card_number[i:i+4] for i in range(0, 16, 4)]),
        "cvv": cvv,
        "expiry": f"{expiry_month}/{expiry_year}"
    }

@app.route("/transfer", methods=["POST"])
def transfer_endpoint():
    """Handles cryptocurrency transfers, including mock NFC card payments."""
    peers = carregar_peers()
    portas = [5000]
    timeout_segundos = 1

    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request. Missing or malformed JSON."}), 400

    data_for_log = data.copy()
    for key in ['private_key', 'cvv', 'expiry']:
        if key in data_for_log:
            data_for_log[key] = '*** hidden ***'
    logger.info(f"Received data: {data_for_log}")

    card_required = ['private_key', 'card_number', 'cvv', 'expiry', 'recipient', 'amount']
    normal_required = ['private_key', 'sender', 'recipient', 'amount']

    def validar_numero_cartao_mock(private_key, card_number_input):
        expected_card = gerar_cartao_nfc(private_key)["card_number"].replace(" ", "").upper()
        received_card = card_number_input.replace(" ", "").upper()
        return expected_card == received_card

    is_card_payment = all(k in data for k in card_required)

    if is_card_payment:
        for field in card_required:
            if not data.get(field):
                return jsonify({"error": f"Required field '{field}' missing."}), 400

        if not validar_numero_cartao_mock(data['private_key'], data['card_number']):
            return jsonify({'error': 'Invalid card number for this private key.'}), 400

        cartao_gerado = gerar_cartao_nfc(data['private_key'])

        if data['cvv'] != cartao_gerado['cvv']:
            return jsonify({'error': 'Invalid CVV for this private key.'}), 400

        try:
            expiry_input = datetime.strptime(data['expiry'], "%m/%y")
            expiry_esperada = datetime.strptime(cartao_gerado['expiry'], "%m/%y")
        except ValueError:
            return jsonify({'error': 'Invalid expiry format. Use MM/YY.'}), 400

        if expiry_input != expiry_esperada:
            return jsonify({'error': 'Expiry date does not match the private key.'}), 400

        if expiry_input < datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0):
            return jsonify({'error': 'Card expired.'}), 400

        data['sender'] = 'card_payment_sender' # Special sender for card payments
    else:
        if not all(k in data for k in normal_required):
            return jsonify({'error': 'Missing required fields for normal transfer.'}), 400

    try:
        amount = float(data['amount'])
        if amount <= 0:
            return jsonify({'error': 'Amount must be greater than zero.'}), 400
        data['amount'] = amount
    except (ValueError, TypeError):
        return jsonify({'error': 'Invalid amount.'}), 400

    sender = data.get('sender')
    recipient = data.get('recipient')
    if not isinstance(sender, str) or not sender.strip():
        return jsonify({'error': 'Invalid sender.'}), 400
    if not isinstance(recipient, str) or not recipient.strip():
        return jsonify({'error': 'Invalid recipient.'}), 400

    # Try to propagate to peers first
    for peer in peers:
        base_url = garantir_protocolo(peer).rstrip('/')
        endereco_sem_protocolo = peer.split('//')[-1]

        for porta in portas:
            if ':' not in endereco_sem_protocolo:
                url = f"{base_url}:{porta}/transfer"
            else:
                url = f"{base_url}/transfer"
            
            logger.info(f"Attempting peer: {url}")

            try:
                response = requests.post(url, json=data, timeout=timeout_segundos, verify=False)
                response.raise_for_status()
                response_data = response.json()
                logger.info(f"Peer {url} responded: {response_data}")

                if not response_data.get("error"):
                    return jsonify(response_data), 200
            except Exception as e:
                logger.warning(f" Error with peer {url}: {e}")
                continue

    # Fallback to local processing if all peers fail
    try:
        if not is_card_payment:
            index = blockchain.new_transaction(
                sender=data['sender'],
                recipient=data['recipient'],
                amount=data['amount']
            )
        else:
            index = blockchain.new_transaction(
                sender="card_payment_sender",
                recipient=data['recipient'],
                amount=data['amount']
            )
        
        if index is False: # Check for insufficient balance
            return jsonify({'error': 'Insufficient balance for local transfer.'}), 400

        return jsonify({
            'message': f'Transaction registered locally in block {index} (not yet mined)',
            'transaction': {
                'sender': data.get('sender'),
                'recipient': data.get('recipient'),
                'amount': data.get('amount')
            }
        }), 200
    except Exception as e:
        import traceback
        logger.error(f"Error in local processing: {traceback.format_exc()}")
        return jsonify({'error': f'Local error: {str(e)}'}), 500

@app.route('/mine', methods=['GET'])
def mine():
    """Endpoint for mining a new block."""
    valido, user_or_msg = validar_token()
    if not valido:
        return jsonify({'error': user_or_msg}), 401

    miner_address = request.args.get('miner')
    usar_gpu = request.args.get('gpu', 'false').lower() == 'true'

    if not miner_address:
        return jsonify({'error': 'Miner address not provided'}), 400

    # No direct MySQL connection here in this refactored version
    # The Blockchain class now handles its own SQLite database interactions.

    with mining_lock:
        try:
            blockchain.load_state()

            last_block = blockchain.last_block
            if not last_block:
                return jsonify({'error': 'Blockchain is empty. Cannot mine.'}), 503

            last_proof = last_block['proof']
            last_index = last_block['index']

            logger.info(f"Performing proof of work... (GPU={usar_gpu})")
            proof = blockchain.proof_of_work(last_proof, usar_gpu=usar_gpu)

            blockchain.load_state() # Re-load state to check for new blocks
            if blockchain.last_block['index'] != last_index:
                return jsonify({'message': 'Another node has already mined the next block. Conflict detected.'}), 409

            logger.info("💰 Generating reward...")
            # The new_transaction method now updates the balance in the blockchain's wallets.
            blockchain.new_transaction("0", miner_address, blockchain.current_reward())

            previous_hash = blockchain.hash_block(blockchain.last_block)
            novo_bloco = blockchain.new_block(proof, miner_address, previous_hash)

            # Get the updated balance after mining
            saldo = blockchain.get_balance(miner_address)

            logger.info(f" Block #{novo_bloco['index']} mined successfully by {miner_address}")

            return jsonify({
                "message": "Block mined successfully",
                "block": novo_bloco["index"],
                "transactions": novo_bloco["transactions"],
                "proof": novo_bloco["proof"],
                "previous_hash": novo_bloco["previous_hash"],
                "hash": novo_bloco["hash"],
                "miner": miner_address,
                "reward": blockchain.current_reward(),
                "balance": f"{saldo:.8f}"
            }), 200

        except Exception as e:
            logger.error(f"Error during mining: {str(e)}")
            return jsonify({'error': str(e)}), 503

def sincronizar_blockchain():
    """Synchronizes the local blockchain with longer, valid chains from known nodes."""
    global known_nodes # Use the global known_nodes
    peers_to_check = list(known_nodes) # Iterate over a copy

    for node_url in peers_to_check:
        try:
            response = requests.get(f"{node_url}/chain", timeout=5)
            if response.status_code == 200:
                remote_chain = response.json().get('chain', [])
                if blockchain.replace_chain(remote_chain):
                    logger.info(f"[SYNC] Blockchain updated by node {node_url}")
                    return # Chain replaced, no need to check further
        except Exception as e:
            logger.warning(f"[SYNC] Failed to synchronize with {node_url}: {e}")

@app.route('/nodes', methods=['GET'])
def listar_nodes():
    """Returns a list of all known nodes (from file and memory)."""
    conhecidos = set(carregar_peers())
    todos = []

    for peer_data in nodes.values():
        todos.append(peer_data)

    for ip in conhecidos:
        if ip not in nodes:
            todos.append({'ip': ip, 'name': f"Node {ip}"})

    return jsonify(todos)

@app.route('/card/generate', methods=['POST'])
def generate_card():
    """Generates mock NFC card details based on a private key."""
    data = request.get_json()
    if not data or 'private_key' not in data:
        return jsonify({'error': 'Field "private_key" is required'}), 400

    private_key = data['private_key']

    try:
        result = gerar_cartao_nfc(private_key)
    except Exception as e:
        return jsonify({'error': f'Error generating NFC card: {str(e)}'}), 500

    return jsonify(result), 200

@app.route('/peers', methods=['GET'])
def get_peers_endpoint():
    """Returns the list of known peers."""
    return jsonify({'known_nodes': carregar_peers()})

def atualizar_peers_de_no(peer_url):
    """Updates known peers by querying another peer's /peers endpoint."""
    global known_nodes
    try:
        resp = requests.get(f"{peer_url}/peers", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            novos_peers = data.get('known_nodes', [])
            updated = False
            ips_existentes = {url_sem_protocolo_porta(u) for u in known_nodes}

            for peer in novos_peers:
                ip_peer = url_sem_protocolo_porta(peer)
                if ip_peer not in ips_existentes:
                    known_nodes.append(peer)
                    updated = True
                    logger.info(f"[INFO] New peer added via synchronization: {peer}")

            if updated:
                salvar_peers(known_nodes) # Pass the list to save
    except Exception as e:
        logger.error(f"[ERROR] Failed to synchronize peers from node {peer_url}: {e}")

def manter_rede_viva():
    """Heartbeat function to keep the network alive by syncing and cleaning inactive nodes."""
    while True:
        logger.info("[HEARTBEAT] Syncing and cleaning inactive nodes...")
        peers_to_check = list(known_nodes) # Work on a copy to allow modification
        for node in peers_to_check:
            try:
                resp = requests.get(f"{node}/ping", timeout=3)
                if resp.status_code != 200:
                    raise Exception("Status not 200")
                falhas[node] = 0 # Reset failure count
                atualizar_peers_de_no(node) # Sync peers from active nodes
            except Exception as e:
                falhas[node] = falhas.get(node, 0) + 1
                logger.info(f"[INFO] Ping failed for {node} ({falhas[node]} failures)")
                if falhas[node] >= 3:
                    logger.info(f"[INFO] Node {node} removed after {falhas[node]} consecutive failures.")
                    if node in known_nodes: # Ensure it's still in the list before removing
                        known_nodes.remove(node)
                    falhas.pop(node)
        sync_all()
        salvar_peers(known_nodes) # Save the modified known_nodes list
        logger.info(f"[HEARTBEAT] Current known_nodes: {known_nodes}")
        time.sleep(60)

@app.route('/register_node', methods=['POST'])
def register_node_endpoint():
    """Registers a new node (peer) with this node."""
    data = request.get_json()
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()

    if not data or 'ip' not in data:
        return jsonify({"message": "Invalid IP or missing data."}), 400

    ip_novo = data['ip']
    if ':' in ip_novo and not ip_novo.startswith('['):
        ip_novo = f"[{ip_novo}]"

    # Add to in-memory nodes if not present
    if ip_novo not in nodes:
        nodes[ip_novo] = {
            'ip': ip_novo,
            'name': data.get('name', f"Node {ip_novo}"),
            'last_active': time.time()
        }
        # Also add to the persistent known_nodes list and save
        global known_nodes
        if ip_novo not in known_nodes:
            known_nodes.append(ip_novo)
            salvar_peers(known_nodes)
        logger.info(f"Peer {ip_novo} registered.")
        return jsonify({"message": f"Peer {ip_novo} registered."}), 200
    
    # If already registered, just update last_active time
    nodes[ip_novo]['last_active'] = time.time()
    return jsonify({"message": "IP already registered, updated last active time."}), 200

@app.route('/ping', methods=['GET'])
def ping():
    """A simple endpoint for checking node health."""
    return jsonify({"status": "ok", "message": "BTC3 node is alive"}), 200

def gerar_token_unico_auth(intervalo_segundos=60):
    """Generates a unique token for authentication based on time window."""
    time_window = int(time.time() // intervalo_segundos)
    texto = f"{SECRET_KEY}{time_window}"
    return hashlib.sha256(texto.encode()).hexdigest()

def gerar_token(usuario):
    """Generates a JWT token for a given user."""
    payload = {
        "user": usuario,
        "exp": datetime.utcnow() + timedelta(hours=2)  # Token valid for 2 hours
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token

def validar_token():
    """Validates the JWT token from the request header."""
    token = request.headers.get("Authorization")
    if not token:
        return False, "Token not provided"
    
    # Remove "Bearer " prefix if present
    if token.startswith("Bearer "):
        token = token[len("Bearer "):]

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return True, payload["user"]
    except jwt.ExpiredSignatureError:
        return False, "Token expired"
    except jwt.InvalidTokenError:
        return False, "Invalid token"
        
@app.route("/p2p-btc3")
def p2p_btc3():
    """Main endpoint for the BTC3 node, returning a unique token."""
    token = gerar_token_unico_auth()
    return f"""
    <html>
        <head><title>BTC3 Node</title></head>
        <body>
            <h1> BTC3 Online</h1>
            <p>Bitcoin 3.0: Decentralization and Innovation</p>
            <p>Token: {token}</p>
        </body>
    </html>
    """, 200

def escanear_varias_faixas(faixas):
    """Scans multiple IP ranges for BTC3 nodes."""
    todos_encontrados = []
    for faixa_inicio, faixa_fim in faixas:
        encontrados = scanner_continuo(faixa_inicio, faixa_fim)
        todos_encontrados.extend(encontrados)
    return todos_encontrados

def minerar_localmente_e_enviar(miner_address):
    """Mines a block locally and attempts to submit it to peers."""
    blockchain.load_state() # Ensure local chain is up-to-date
    last_block = blockchain.last_block
    if not last_block:
        logger.error("Cannot mine locally: Blockchain is empty.")
        return False

    last_proof = last_block['proof']
    last_index = last_block['index']
    previous_hash = blockchain.hash_block(last_block)

    logger.info("Mining locally...")
    proof = blockchain.proof_of_work(last_proof)

    bloco_data = {
        "index": last_index + 1,
        "proof": proof,
        "previous_hash": previous_hash,
        "miner": miner_address
    }

    peers = carregar_peers()
    if not peers:
        logger.warning("No peers available to submit the mined block.")
        return False

    for peer in peers:
        try:
            url = f"{garantir_protocolo(peer)}:5000/submit_block"
            logger.info(f"Sending block to server: {url}")
            response = requests.post(url, json=bloco_data, timeout=10, verify=False)
            logger.info(f"Server response: {response.status_code}")
            logger.info(response.json())
            if response.status_code == 201:
                logger.info(f"Block successfully submitted to {peer}.")
                return True
        except Exception as e:
            logger.error(f"Error submitting block to {peer}: {e}")
            continue

    logger.warning(" No server accepted the block.")
    return False

# --- Main Execution Block ---
if __name__ == "__main__":
    # Ignore SSL warnings (for development/testing only, not recommended for production)
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    garantir_arquivo_peers()
    known_nodes = carregar_peers() # Initialize global known_nodes

    # Start the Flask server
    if LIBERAR_PORTAS:
        servidor_thread = threading.Thread(target=rodar_servidor_flask, args=(5000,), daemon=True)
        servidor_thread.start()
        logger.info(" Flask server started to open port 5000 and act as an active peer.")
    
    # Start the heartbeat thread
    heartbeat_thread = threading.Thread(target=manter_rede_viva, daemon=True)
    heartbeat_thread.start()
    logger.info("Heartbeat thread started.")

    # Get public IP and register with other peers
    ip_cliente = obter_ip_publico()
    if ip_cliente:
        adicionar_peer_manual(ip_cliente)
        registrar_em_peers(ip_cliente, carregar_peers())

    # Synchronize known peers locally from the file
    sincronizar_peers_de_arquivo()

    miner_address = "12Fsf93erqAzdLZ3PLYRD2A5yEmQswtadP" # Example miner address

    faixas_de_ip = [
        ("45.228.238.0", "45.228.252.255"),
        ("45.221.222.0", "45.221.222.255"),
        ("15.204.1.0", "15.204.8.255"),
        ("141.95.82.0", "141.95.82.255"),
        ("13.95.82.0", "13.95.82.255"),
        #("2804:14c:82::", "2804:14c:82:ffff:ffff:ffff:ffff:ffff"),  # IPv6 disabled for now
    ]

    while True:
        logger.info("\n Starting scan of defined IP ranges...")
        peers_validos = escanear_varias_faixas(faixas_de_ip)

        if not peers_validos:
            logger.warning(" No valid peers found. Waiting before trying again...")
            time.sleep(10)
            continue

        # Try to mine with discovered valid peers
        mined_successfully_with_peer = False
        for peer_to_mine in peers_validos:
            result = minerar_com_peer_continuo(peer_to_mine, miner_address)
            if result: # If mining was successful (or reached limit)
                mined_successfully_with_peer = True
                logger.info(" Mined successfully with the current peer. Rescanning peers...\n")
                break
            else:
                logger.info(f" Failed to mine on peer {peer_to_mine}. Trying next peer...\n")
        
        # If no peer was successfully mined with (or all attempts failed), try local mining
        if not mined_successfully_with_peer:
            logger.info("Attempting local mining as no peers accepted or all failed...")
            local_mine_success = minerar_localmente_e_enviar(miner_address)
            if local_mine_success:
                logger.info(" Block mined locally and successfully submitted to a peer!")
            else:
                logger.warning("Local mining attempt failed to be submitted to any peer.")
                logger.warning(" No peer available for mining at the moment. Waiting...")
                time.sleep(35)