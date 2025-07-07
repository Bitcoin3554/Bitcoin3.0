
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
# servidor.py
from flask import Flask, jsonify, request
import time
import threading
import os
import string
import random
# outras importações que o script usa...
import ecdsa
import base58
from flask import Flask
import secrets
import json
import time
import hashlib
from pathlib import Path
import sqlite3
from collections import Counter

def registrar_em_peers(ip, peers):
    for peer in peers:
        try:
            url = f"http://{peer}:5000/register_node"
            requests.post(url, json={"ip": ip}, timeout=5)
            print(f"✅ Registrado em {url}")
        except Exception as e:
            print(f"❌ Falha ao registrar em {peer}: {e}")

def register_peer(peer):
    if not peer.startswith("http"):
        peer = "http://" + peer
    url = f"{peer}/register_node"
    try:
        response = requests.post(url, json={"node": my_ip})
        # tratar resposta...
    except Exception as e:
        print(f"❌ Falha ao registrar em {peer}: {e}")

def mine_bitcoin(miner_address):
    try:
        # Selecione a rede Bitcoin (pode ser 'mainnet' ou 'testnet')
        SelectParams('mainnet')

        # Gere uma chave privada e endereço válidos para o minerador (exemplo)
        secret = CBitcoinSecret('5J...')  # Substitua com uma chave privada válida (WIF)
        address = P2PKHBitcoinAddress.from_pubkey(secret.pub)

        # Exemplo de transação simples (em uma rede real, você precisaria de UTXOs válidos)
        txin = CTxIn(lx('4f3c89...'))  # Referência para um UTXO
        txout = CTxOut(50 * COIN, address.to_scriptPubKey())  # 50 BTC para o minerador

        # Cria a transação
        tx = CTransaction([txin], [txout])

        # Simulando a prova de trabalho
        attempts = 0
        while not valid_proof_of_work(tx):
            tx = CTransaction([txin], [txout])  # Recria a transação
            attempts += 1

            if attempts > 10000:  # Limite para evitar loop infinito
                return {'error': 'Prova de trabalho não foi encontrada dentro do número máximo de tentativas.'}

            time.sleep(0.1)  # Pausa para evitar sobrecarga de CPU

        # Sucesso, retorna uma mensagem de sucesso
        return {'message': f'Minerador {miner_address} successfully mined 50 BTC!'}

    except Exception as e:
        return {'error': str(e)}

def process_transfer(conn, sender, recipient, amount):
    cursor = conn.cursor()
    # Debitar do remetente:
    cursor.execute("UPDATE wallets SET balance = balance - %s WHERE address = %s", (amount, sender))
    # Creditar no destinatário:
    cursor.execute("UPDATE wallets SET balance = balance + %s WHERE address = %s", (amount, recipient))
    conn.commit()

# Ignorar warnings SSL (apenas para dev)
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

# Configurações básicas
PORTAS = [5000]
CAMINHO = "/p2p-btc3"
HEADERS = {"User-Agent": "p2p-btc3-AutoScanner/1.0"}
ARQUIVO_PEERS = "peers.json"
SECRET_KEY = "25s5ash5556s54d45593ksaa55s25a45545s5d4a5s55440-0"


def ip_range(start_ip, end_ip):
    start = ipaddress.ip_address(start_ip)
    end = ipaddress.ip_address(end_ip)
    if start.version != end.version:
        raise ValueError("Start IP e End IP devem ser da mesma versão (IPv4 ou IPv6)")
    ips = []
    current = start
    while current <= end:
        ips.append(str(current))
        current += 1
    return ips

def montar_url(ip, porta, protocolo):
    if ':' in ip:  # IPv6
        ip_formatado = f"[{ip.strip('[]')}]"  # remove colchetes duplicados
    else:
        ip_formatado = ip
    return f"{protocolo}://{ip_formatado}:{porta}{CAMINHO}"

def peer_tem_endpoint_mine(ip):
    params = {"miner": "teste"}
    portas_testar = [5000]
    for porta in portas_testar:
        protocolos = ["https"] if porta == 443 else ["http"]
        for protocolo in protocolos:
            url_base = montar_url(ip, porta, protocolo)
            url_mine = url_base.rsplit('/', 1)[0] + "/mine"  # substitui caminho
            try:
                print(f"🔍 Testando /mine em: {url_mine}")
                resp = requests.get(url_mine, params=params, timeout=5, verify=False)
                if resp.status_code == 200:
                    return True
            except Exception as e:
                print(f"⚠️ Erro ao testar /mine em {url_mine}: {e}")
    return False

def salvar_peers_sem_mine(ip):
    arquivo = Path("peers_sem_mine.json")
    try:
        lista = json.loads(arquivo.read_text()) if arquivo.exists() else []
    except:
        lista = []
    if ip not in lista:
        lista.append(ip)
        arquivo.write_text(json.dumps(sorted(lista), indent=4))
        
def thread_busca_continua_peers(intervalo=60):
    while True:
        atualizar_peers_de_peers_existentes()
        print("🔄 Lista de peers atualizada automaticamente.")
        time.sleep(intervalo)

def atualizar_peers_de_peers_existentes():
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
                        for node in dados["nodes"]:
                            if isinstance(node, dict) and "ip" in node:
                                todos_peers.append(node["ip"])
                            elif isinstance(node, str):
                                todos_peers.append(node)
                break
        except Exception:
            print("Buscando nodes P2p")
    ips_formatados = []
    for ip in set(todos_peers):
        if ':' in ip and not ip.startswith('['):
            ip = f"[{ip}]"
        ips_formatados.append(ip)
    if ips_formatados:
        salvar_peers(ips_formatados)
    return ips_formatados

def sincronizar_peers_de_arquivo():
    peers_existentes = carregar_peers()
    print(f"\n🔁 Sincronizando /register_node de {len(peers_existentes)} peers conhecidos...")
    novos_peers = set()
    for ip in peers_existentes:
        for porta in PORTAS:
            protocolos = ["https"] if porta == 443 else ["http"]
            for protocolo in protocolos:
                url_base = f"{protocolo}://{ip}:{porta}"
                novos = puxar_nodes_de_peer(url_base)
                if novos:
                    print(f"✅ {len(novos)} novos peers recebidos de {url_base}")
                    novos_peers.update(novos)
    if novos_peers:
        salvar_peers(novos_peers)

def verificar_ip(ip, contador, total, encontrados):
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
                            if ip not in encontrados:
                                encontrados.append(ip)
                        if peer_tem_endpoint_mine(ip):
                            print(f"\n✅ [{contador}/{total}] Nó BTC3 válido com /mine encontrado em {url}")
                        else:
                            print(f"\n⚠️ [{contador}/{total}] Peer {ip} válido mas sem /mine (mas adicionado mesmo assim)")
                        return
            except (requests.exceptions.SSLError,
                    requests.exceptions.ConnectTimeout,
                    requests.exceptions.ConnectionError):
                continue
            except Exception as e:
                print(f"⚠️ Erro inesperado ao verificar IP {ip}: {e}")
    print(f"\r🔎 [{contador}/{total}] Escaneado: {ip}", end='', flush=True)

def carregar_peers():
    try:
        return json.loads(Path(ARQUIVO_PEERS).read_text())
    except Exception:
        return []

def registrar_em_mim(peers):
    for ip in peers:
        try:
            resp = requests.post(MEU_NODE_URL, json={"ip": ip}, timeout=3)
            if resp.status_code == 200:
                print(f"✅ Registrado: {ip}")
            else:
                print(f"⚠️ Falha ao registrar {ip} - Status {resp.status_code}")
        except Exception as e:
            print(f"❌ Erro ao registrar {ip}: {e}")
            
def salvar_peers(novos_peers):
    arquivo = Path(ARQUIVO_PEERS)
    peers_atuais = set(carregar_peers())
    novos_peers = set(novos_peers)
    todos_peers = peers_atuais.union(novos_peers)
    if todos_peers != peers_atuais:
        arquivo.write_text(json.dumps(sorted(todos_peers), indent=4))
        print(f"🟢 peers.json atualizado com {len(todos_peers - peers_atuais)} novos peers.")
    else:
        print("ℹ️ peers.json não teve alterações.")

def iniciar_scanner(faixa_inicio, faixa_fim, ips_alvo=None):
    print("🛰️ Iniciando escaneamento BTC3...\n")
    if ips_alvo is None:
        ips = ip_range(faixa_inicio, faixa_fim)
    else:
        ips = ips_alvo
    total = len(ips)
    encontrados = []
    peers_atuais = set(carregar_peers())
    with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
        futures = []
        for i, ip in enumerate(ips, 1):
            if parar_event.is_set():
                break
            futures.append(executor.submit(verificar_ip, ip, i, total, encontrados))
        concurrent.futures.wait(futures)
    novos = list(set(encontrados) - peers_atuais)
    if novos:
        salvar_peers(novos)
    else:
        print("\nℹ️ Nenhum nó novo diferente foi encontrado.")
    return encontrados

def scanner_continuo(start_ip, end_ip, bloco_tamanho=10000, delay_seg=1):
    peers_atuais = set(carregar_peers())
    # Primeiro tenta os IPs do peers.json
    if peers_atuais:
        print(f"♻️ Escaneando IPs do peers.json ({len(peers_atuais)})...")
        encontrados = iniciar_scanner(None, None, ips_alvo=list(peers_atuais))
        if encontrados:
            print(f"🚀 Nós válidos encontrados na lista de peers: {encontrados}")
            return encontrados
    # Depois escaneia a faixa IP completa em blocos
    start = ipaddress.ip_address(start_ip)
    end = ipaddress.ip_address(end_ip)
    atual = start
    while atual <= end:
        fim_bloco_int = int(atual) + bloco_tamanho
        if fim_bloco_int > int(end):
            fim_bloco_int = int(end)
        fim_bloco = ipaddress.ip_address(fim_bloco_int)
        print(f"\nIniciando varredura de {atual} até {fim_bloco}")
        encontrados = iniciar_scanner(str(atual), str(fim_bloco))
        if encontrados:
            print(f"🚀 Nós válidos encontrados no bloco: {encontrados}")
            return encontrados
        atual = ipaddress.ip_address(fim_bloco_int + 1)
        print(f"⏳ Finalizou bloco, aguardando {delay_seg} segundos...")
        time.sleep(delay_seg)
    return []

def backoff_exp(attempt, base=5, max_delay=60):
    delay = base * (2 ** attempt)
    return min(delay, max_delay)

def minerar_com_peer_continuo(peer, miner_address="btc3-local-miner", usar_gpu=False,
                             tentativas=5, delay_tentativa=0, limite_blocos=None, max_503_consecutivos=3):
    params = {"miner": miner_address, "gpu": str(usar_gpu).lower()}
    print(f"🚀 Iniciando mineração contínua no peer: {peer}")
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
                    print(f"⛏️ Minerando via: {full_url} (Tentativa {tentativa+1}/{tentativas})")
                    try:
                        resp = requests.get(full_url, headers=HEADERS, timeout=25, verify=False)
                        if resp.status_code == 200:
                            dados = resp.json()
                            bloco_id = dados.get("block") or dados.get("block_id")
                            if bloco_id:
                                ultimo = cache_ultimo_bloco.get(peer)
                                if ultimo == bloco_id:
                                    print(f"🕒 Bloco {bloco_id} já minerado anteriormente no peer {peer}, aguardando antes de nova tentativa...")
                                    if delay_tentativa > 0:
                                        time.sleep(delay_tentativa)
                                    continue
                                else:
                                    cache_ultimo_bloco[peer] = bloco_id
                            print(f"✅ Bloco minerado via peer {peer}: {json.dumps(dados, indent=2)}")
                            blocos_minerados += 1
                            sucesso = True
                            erros_503_consecutivos = 0
                            break
                        elif resp.status_code == 409:
                            print(f"⚠️ Conflito (409): Outro minerador já criou o bloco. Aguardando 10s...")
                            time.sleep(10)
                        elif resp.status_code == 503:
                            erros_503_consecutivos += 1
                            delay = backoff_exp(erros_503_consecutivos - 1)
                            print(f"⚠️ Serviço indisponível (503) no peer {peer}. Tentando novamente em {delay}s...")
                            time.sleep(delay)
                            if erros_503_consecutivos >= max_503_consecutivos:
                                print(f"⚠️ Bloco Não Encontrado, Dificuldade Pesando... {peer}.")
                                return False
                        else:
                            print(f"❌ Erro inesperado do peer {peer}: {resp.status_code}")
                    except (requests.exceptions.SSLError,
                            requests.exceptions.ConnectTimeout,
                            requests.exceptions.ConnectionError) as e:
                        print(f"⚠️ Erro de conexão/SSL ao minerar no peer {peer}: {e}")
                    except Exception as e:
                        print(f"⚠️ Erro inesperado ao minerar via {peer}: {e}")
                    if delay_tentativa > 0 and tentativa < tentativas - 1:
                        print(f"⏳ Retentando em {delay_tentativa}s...")
                        time.sleep(delay_tentativa)
                if sucesso:
                    break
            if sucesso:
                break
        if not sucesso:
            print(f"❌ Falha na mineração com o peer {peer}. Tentando próximo peer...")
            return False
        time.sleep(1)
    print(f"⚠️ Limite de {limite_blocos} blocos minerados atingido no peer {peer}. Parando mineração contínua.")
    return True


def garantir_arquivo_peers():
    arquivo = Path(ARQUIVO_PEERS)
    if not arquivo.exists():
        arquivo.write_text("[]")
        print(f"ℹ️ Arquivo {ARQUIVO_PEERS} criado pois não existia.")
        
def obter_ip_publico():
    try:
        resp = requests.get("https://api.ipify.org", timeout=5)
        if resp.status_code == 200:
            return resp.text.strip()
    except:
        pass
    return None

def adicionar_peer_manual(ip):
    arquivo = Path(ARQUIVO_PEERS)
    try:
        peers = json.loads(arquivo.read_text()) if arquivo.exists() else []
    except json.JSONDecodeError:
        peers = []
    if ip not in peers:
        peers.append(ip)
        arquivo.write_text(json.dumps(sorted(peers), indent=4))
        print(f"📝 IP público do cliente adicionado diretamente no peers.json: {ip}")
    else:
        print(f"ℹ️ IP público já está no peers.json: {ip}")


peers = []
nodes = {}  # ip: dados
    

from flask import Flask, request, jsonify
app = Flask(__name__)

blockchain = [{'index': 0, 'data': 'Genesis block'}]

known_nodes = carregar_peers()  # ou carregado de peers.json

@app.route('/known_nodes')
def get_known_nodes():
    global known_nodes
    return jsonify({'known_nodes': known_nodes})

def register_self_to_others(name='Cliente BTC3', port1=5000, port2=80):
    try:
        my_ip = requests.get('https://api.ipify.org').text.strip()
        print(f"[DEBUG CLIENTE] Meu IP público: {my_ip}")
    except Exception as e:
        print(f"[ERRO] Não conseguiu pegar IP externo: {e}")
        return

    for node_url in known_nodes:
        for port in [port1, port2]:
            full_url = f'{node_url}/register_node'
            try:
                print(f"[DEBUG CLIENTE] Registrando em {full_url}")
                resp = requests.post(full_url,
                    json={'ip': my_ip, 'port': port, 'name': name}, timeout=5)
                print(f"[SUCESSO] Registrado em {full_url}: {resp.status_code} - {resp.text}")
            except Exception as e:
                print(f"[ERRO] Falha ao registrar em {full_url}: {e}")

@app.route('/known_nodes', methods=['GET'])
def get_known_nodes_v2():
    # Retorna peers conhecidos do arquivo + registrados em memória
    conhecidos = set(carregar_peers())
    todos = []

    for node in nodes.values():
        todos.append(node)

    for ip in conhecidos:
        if ip not in nodes:
            todos.append({'ip': ip, 'name': f"Nó {ip}"})

    return jsonify({'known_nodes': todos})

@app.route('/last_block', methods=['GET'])
def last_block():
    return jsonify(blockchain.last_block())

def init_db():
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
    
class Blockchain:
    INTERVALO_AJUSTE = 2016
    BLOCO_ALVO_SEGUNDOS = 600
    TEMPO_ALVO_TOTAL = INTERVALO_AJUSTE * BLOCO_ALVO_SEGUNDOS

    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.wallets = {}
        self.difficulty = 1
        self.lock = threading.Lock()

        init_db()  # garante que o banco está inicializado
        self.load_chain_from_db()
        self.load_wallets_from_db()

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
    
    def load_chain_from_db(self):
        conn = sqlite3.connect('blockchain.db')
        c = conn.cursor()
        c.execute("SELECT block FROM blockchain ORDER BY idx")
        blocks = c.fetchall()
        self.chain = [json.loads(b[0]) for b in blocks]
        if self.chain:
            self.difficulty = self.chain[-1]['difficulty']
        conn.close()
    
    def save_chain_to_db(self):
        conn = sqlite3.connect('blockchain.db')
        c = conn.cursor()
        c.execute("DELETE FROM blockchain")
        for i, block in enumerate(self.chain):
            c.execute("INSERT INTO blockchain (idx, block) VALUES (?, ?)", (i, json.dumps(block)))
        conn.commit()
        conn.close()
    

    def save_chain_to_file(self, filename='blockchain.json'):
        with open(filename, 'w') as f:
            json.dump(self.chain, f, indent=4)

    def load_wallets_from_file(self, filename='wallets.json'):
        try:
            with open(filename, 'r') as f:
                self.wallets = json.load(f)
        except FileNotFoundError:
            self.wallets = {}
        
    def save_wallets_to_file(self, filename='wallets.json'):
        with open(filename, 'w') as f:
            json.dump(self.wallets, f, indent=4)
            
    def create_genesis_block(self):
        if self.chain:
            return

        genesis_block = {
            "index": 1,
            "timestamp": 1720000000.0,  # use o timestamp padrão da rede
            "transactions": [],
            "proof": 100,
            "previous_hash": "0",
            "difficulty": 1,
            "miners": {"1HrqaZRbaqru4rtKdLZkBg7exu2QoGPxhA": 1},
            "hash": "7737eb7493a6fa8ca564e3ee1703275ef6a9682ad398129226d862e1478b10d6"
        }

        self.chain.append(genesis_block)
        self.save_chain_to_file()
        self.save_chain_to_db()



    def reset_local_data():
        import os
        for fname in ['blockchain.db', 'blockchain.json', 'wallets.json']:
            try:
                os.remove(fname)
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
            'miner': miner,  # <-- Adicionado
        }
        block['hash'] = self.hash_block(block)
        return block

    def hash_block(block):
        block_copy = block.copy()
        block_copy.pop('hash', None)  # Remove o campo hash antes de gerar um novo
        block_str = json.dumps(block_copy, sort_keys=True).encode()
        return hashlib.sha256(block_str).hexdigest()


    def save_chain_to_file(self, filename='blockchain.json'):
        with open(filename, 'w') as f:
            json.dump(self.chain, f, indent=4)

    def load_chain_from_file(self, filename='blockchain.json'):
        try:
            with open(filename, 'r') as f:
                self.chain = json.load(f)
            if self.chain:
                self.difficulty = self.chain[-1]['difficulty']
        except FileNotFoundError:
            self.chain = []

    @property
    def last_block(self):
        return self.chain[-1] if self.chain else None

    def new_transaction(self, sender, recipient, amount):
        if self.get_balance(sender) < amount:
            return False
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount
        })
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
            'private_key': wallet.private_key,
            'balance': 0.0
        }
        self.save_wallets_to_file()
        return wallet.address

    def proof_of_work(self, last_proof):
        proof = 0
        while True:
            guess = f'{last_proof}{proof}'.encode()
            guess_hash = hashlib.sha256(guess).hexdigest()
            if guess_hash[:self.difficulty] == "0" * self.difficulty:
                return proof
            proof += 1

    def new_block(self, proof, miner_address):
        with self.lock:
            previous_hash = self.last_block['hash'] if self.last_block else '0'
            block = self.create_new_block(previous_hash, proof, time.time(), miner_address)
            self.chain.append(block)
            self.save_chain_to_file()
            self.save_chain_to_db()
            return block


    def current_reward(self):
        initial_reward = 0.50
        halving_interval = 210000
        blocks_mined = len(self.chain)
        halvings = blocks_mined // halving_interval
        return max(initial_reward / (2 ** halvings), 0.00000001)

    def replace_chain(self, new_chain):
        if len(new_chain) > len(self.chain):
            self.chain = new_chain
            self.save_chain_to_file()
            self.save_chain_to_db()  # <-- Salva no banco SQLite também


blockchain = Blockchain()  # criando a instância

parar_event = threading.Event()
encontrados_lock = threading.Lock()
cache_ultimo_bloco = {}

def gerar_tokens_validos(intervalo_segundos=60, tolerancia_janelas=1):
    agora = int(time.time() // intervalo_segundos)
    tokens = []
    for offset in range(-tolerancia_janelas, tolerancia_janelas + 1):
        time_window = agora + offset
        texto = f"{SECRET_KEY}{time_window}"
        token = hashlib.sha256(texto.encode()).hexdigest()
        tokens.append(token)
    return tokens

@app.route('/submit_block', methods=['POST'])
def submit_block():
    data = request.get_json()

    required = ['index', 'proof', 'previous_hash', 'miner']
    if not all(k in data for k in required):
        return jsonify({'error': 'Campos obrigatórios ausentes no bloco'}), 400

    try:
        # Validar se o bloco faz sentido com a blockchain local
        last_block = blockchain.last_block

        if data['index'] != last_block['index'] + 1:
            return jsonify({'error': 'Índice do bloco inválido'}), 400

        if data['previous_hash'] != blockchain.hash(last_block):
            return jsonify({'error': 'Hash anterior não confere'}), 400

        if not blockchain.valid_proof(last_block['proof'], data['proof']):
            return jsonify({'error': 'Prova de trabalho inválida'}), 400

        # Recompensa o minerador e adiciona o bloco
        blockchain.new_transaction("0", data['miner'], blockchain.current_reward())
        novo_bloco = blockchain.new_block(data['proof'], data['miner'], data['previous_hash'])

        print(f"✅ Bloco #{novo_bloco['index']} aceito do minerador {data['miner']}")

        return jsonify({
            "message": "Bloco aceito e adicionado à blockchain.",
            "block": novo_bloco
        }), 201

    except Exception as e:
        print(f"Erro ao validar bloco: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/balance/<address>', methods=['GET'])
def get_balance_endpoint(address):
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
                    print(f"✅ Peer {peer} retornou saldo: {saldo}")
                    break
                else:
                    print(f"❌ Peer {peer} retornou status inválido: {r.status_code}")
            except Exception as e:
                print(f"❌ Falha no peer {peer}: {e}")
                continue

    total_ativos = len(saldos_confirmados)
    print(f"Total de peers ativos: {total_ativos}")

    if total_ativos == 0:
        return jsonify({'error': 'Nenhum peer ativo respondeu com saldo válido'}), 500

    contagem = Counter(saldos_confirmados)
    print(f"Contagem dos saldos confirmados: {contagem}")

    mais_comum, ocorrencias = contagem.most_common(1)[0]
    saldo_mais_alto = max(saldos_confirmados)
    print(f"Saldo mais comum: {mais_comum} com {ocorrencias} ocorrências")
    print(f"Saldo mais alto recebido: {saldo_mais_alto}")

    min_confirmacoes = 2
    min_confirmacoes = min(min_confirmacoes, total_ativos)
    if total_ativos < 3:
        min_confirmacoes = 1

    print(f"Mínimo de confirmações necessárias: {min_confirmacoes}")

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
        # Retorna saldo mais alto mesmo sem consenso
        blockchain.wallets[address] = {'balance': saldo_mais_alto}
        blockchain.save_wallets_to_db()
        return jsonify({
            'address': address,
            'balance': f"{saldo_mais_alto:.8f}",
            'confirmacoes': ocorrencias,
            'peers_ativos': total_ativos,
            'warning': 'Não houve consenso entre os peers, mas retornando o saldo mais alto disponível'
        }), 200


def propagar_para_peers(transacao):
    peers = carregar_peers()
    for peer in peers:
        try:
            if not peer.endswith("/"):
                peer += "/"
            url = peer + "transactions/new"
            requests.post(url, json=transacao, timeout=2)
        except:
            continue
        
def tentar_peers(path, method='GET', json_data=None, timeout=5):
    peers = carregar_peers()
    portas = [5000]

    for peer in peers:
        for porta in portas:
            try:
                url_base = garantir_protocolo(peer)
                # Verifica se já tem porta na URL (após o protocolo)
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
                    return None  # pode implementar outros métodos se quiser
                
                if r.status_code in (200, 201):
                    return r
            except requests.RequestException as e:
                print(f"Erro ao acessar {url}: {e}")
                continue
    return None
    
def garantir_protocolo(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        return "http://" + url
    return url

def criar_carteira():
    r = requests.post(f"{BASE_URL}/wallet/create")
    if r.status_code == 201:
        dados = r.json()
        print(f"🆕 Nova carteira criada:")
        print(f"🔑 Endereço: {dados.get('address')}")
        print(f"🔐 Chave privada: {dados.get('private_key')}")
    else:
        print("❌ Erro ao criar carteira")


def garantir_protocolo(url):
    """Garante que a URL tenha http:// ou https://"""
    if not url.startswith('http://') and not url.startswith('https://'):
        return 'http://' + url
    return url

def carregar_peers_ativos():
    peers = carregar_peers()
    peers_ativos = []
    portas = [5000]
    proxies = {"http": None, "https": None}

    for peer in peers:
        base_url = garantir_protocolo(peer)
        ativo = False
        for porta in portas:
            if ':' not in peer.split('//')[-1]:
                url = f"{base_url}:{porta}/health"  # ou /status, ou qualquer rota simples que o peer tenha
            else:
                url = f"{base_url}/health"

            try:
                r = requests.get(url, proxies=proxies, timeout=3, verify=False)
                if r.ok:
                    ativo = True
                    break
            except:
                continue
        if ativo:
            peers_ativos.append(peer)
    return peers_ativos

@app.route('/wallet/create', methods=['POST'])
def create_wallet():
    proxies = {"http": None, "https": None}
    peers = carregar_peers()
    portas = [5000]
    timeout_segundos = 10

    for peer in peers:
        base_url = garantir_protocolo(peer).rstrip('/')
        endereco = peer.split('//')[-1]
        for porta in portas:
            if ':' not in endereco:
                url = f"{base_url}:{porta}/wallet/create"
            else:
                url = f"{base_url}/wallet/create"
            try:
                print(f"Tentando criar carteira no peer: {url}")
                response = requests.get(url, proxies=proxies, timeout=timeout_segundos, verify=False)
                response.raise_for_status()
                data = response.json()
                print(f"Resposta do peer {peer}: {data}")

                # ⚠️ Verifica se tem endereço e chave privada
                if 'address' in data and 'private_key' in data:
                    address = data['address']
                    private_key = data['private_key']

                    # 💾 Salva no dicionário de carteiras
                    blockchain.wallets[address] = {
                        'private_key': private_key,
                        'balance': 0.0
                    }

                    # 🗂️ Salva no banco de dados
                    blockchain.save_wallets_to_db()

                    return jsonify({
                        'address': address,
                        'private_key': private_key
                    }), 201
                else:
                    print(f"⚠️ Peer {peer} não retornou os dados esperados.")

            except requests.RequestException as e:
                print(f"Erro ao acessar {url}: {e}")
                continue

    return jsonify({'error': 'Falharam ao criar carteira. Todos os nós falharam.'}), 503


    
def sanitize_chain(chain):
    # Valida e retorna a chain. Por enquanto, apenas retorna.
    return chain
    
@app.route('/chain', methods=['GET'])
def full_chain():
    proxies = {"http": None, "https": None}
    peers = carregar_peers()
    portas = [5000]
    timeout_segundos = 10

    global local_blockchain

    for peer in peers:
        base_url = garantir_protocolo(peer).rstrip('/')
        endereco = peer.split('//')[-1]
        for porta in portas:
            if ':' not in endereco:
                url = f"{base_url}:{porta}/chain"
            else:
                url = f"{base_url}/chain"

            try:
                print(f"Tentando obter blockchain do peer: {url}")
                response = requests.get(url, proxies=proxies, timeout=timeout_segundos, verify=False)
                response.raise_for_status()
                data = response.json()
                print(f"Resposta do peer {peer}: {data}")

                if 'chain' in data:
                    blockchain_data = data['chain']

                    if validar_chain(blockchain_data) and len(blockchain_data) > len(blockchain.chain):
                        blockchain.replace_chain(blockchain_data)
                        print("✅ Blockchain substituída com sucesso.")
                        return jsonify({'message': 'Blockchain substituída por versão mais longa e válida!', 'new_chain': blockchain_data}), 200
                    else:
                        print(f"⚠️ Blockchain do peer {peer} inválida ou menor. Continuando a verificar outros peers...")
                        # Aqui não retorna, só continua o loop

            except requests.RequestException as e:
                print(f"Erro ao acessar {url}: {e}")
                continue

    # Se chegou aqui, nenhuma blockchain válida maior foi encontrada
    return jsonify({
        'message': 'Nenhuma blockchain válida maior foi encontrada entre os peers.',
        'local_length': len(blockchain.chain)
    }), 400


def sanitize_chain(chain):
    # Valida e retorna a chain. Por enquanto, apenas retorna.
    return chain

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    proxies = {"http": None, "https": None}
    peers = carregar_peers()
    portas = [5000]
    timeout_segundos = 10

    values = request.get_json()
    required = ['sender', 'recipient', 'amount']

    if not values or not all(k in values for k in required):
        return jsonify({'error': 'Faltando valores.'}), 400

    if not peers:
        return jsonify({'error': 'Nenhum peer disponível'}), 500

    for peer in peers:
        base_url = garantir_protocolo(peer).rstrip('/')
        endereco = peer.split('//')[-1]

        for porta in portas:
            if ':' not in endereco:
                url = f"{base_url}:{porta}/transactions/new"
            else:
                url = f"{base_url}/transactions/new"

            try:
                r = requests.post(url, json=values, timeout=timeout_segundos, proxies=proxies, verify=False)
                if r.status_code == 201:
                    return jsonify(r.json()), 201
            except requests.RequestException as e:
                print(f"Erro ao acessar {url}: {e}")
                continue

    return jsonify({'error': 'Não foi possível registrar transação em nenhum peer'}), 500


@app.route("/transfer", methods=["POST"])
def transfer():
    proxies = {"http": None, "https": None}
    peers = carregar_peers()
    portas = [5000]
    timeout_segundos = 1

    data = request.get_json()
    if not data:
        return jsonify({"error": "Requisição inválida. JSON ausente ou malformado."}), 400

    # Oculta dados sensíveis para log
    data_for_log = data.copy()
    for key in ['private_key', 'cvv', 'expiry']:
        if key in data_for_log:
            data_for_log[key] = '*** ocultado ***'
    print("Dados recebidos:", data_for_log, flush=True)  # flush=True força saída imediata

    card_required = ['private_key', 'card_number', 'cvv', 'expiry', 'recipient', 'amount']
    normal_required = ['private_key', 'sender', 'recipient', 'amount']

    def validar_numero_cartao(private_key, card_number):
        esperado = gerar_cartao_nfc(private_key)["card_number"].replace(" ", "").upper()
        recebido = card_number.replace(" ", "").upper()
        return esperado == recebido

    is_card_payment = all(k in data for k in card_required)

    if is_card_payment:
        for field in card_required:
            if not data.get(field):
                return jsonify({"error": f"Campo obrigatório '{field}' ausente."}), 400

        if not validar_numero_cartao(data['private_key'], data['card_number']):
            return jsonify({'error': 'Número do cartão inválido para essa chave privada.'}), 400

        cartao_gerado = gerar_cartao_nfc(data['private_key'])

        if data['cvv'] != cartao_gerado['cvv']:
            return jsonify({'error': 'CVV inválido para essa chave privada.'}), 400

        try:
            expiry_input = datetime.strptime(data['expiry'], "%m/%y")
            expiry_esperada = datetime.strptime(cartao_gerado['expiry'], "%m/%y")
        except ValueError:
            return jsonify({'error': 'Formato de validade inválido. Use MM/AA.'}), 400

        if expiry_input != expiry_esperada:
            return jsonify({'error': 'Data de validade não confere com a chave privada.'}), 400

        if expiry_input < datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0):
            return jsonify({'error': 'Cartão expirado.'}), 400

        data['sender'] = 'card_payment_sender'
    else:
        if not all(k in data for k in normal_required):
            return jsonify({'error': 'Campos obrigatórios faltando para transferência normal.'}), 400

    try:
        amount = float(data['amount'])
        if amount <= 0:
            return jsonify({'error': 'Amount deve ser maior que zero.'}), 400
        data['amount'] = amount
    except (ValueError, TypeError):
        return jsonify({'error': 'Amount inválido.'}), 400

    sender = data.get('sender')
    recipient = data.get('recipient')
    if not isinstance(sender, str) or not sender.strip():
        return jsonify({'error': 'Sender inválido.'}), 400
    if not isinstance(recipient, str) or not recipient.strip():
        return jsonify({'error': 'Recipient inválido.'}), 400

    for peer in peers:
        base_url = garantir_protocolo(peer).rstrip('/')
        endereco_sem_protocolo = peer.split('//')[-1]

        for porta in portas:
            if ':' not in endereco_sem_protocolo:
                url = f"{base_url}:{porta}/transfer"
            else:
                url = f"{base_url}/transfer"

            # Garantir que sempre imprima a tentativa ANTES do try
            print(f"🔁 Tentando peer: {url}", flush=True)

            try:
                response = requests.post(url, json=data, proxies=proxies, timeout=timeout_segundos, verify=False)
                response.raise_for_status()
                response_data = response.json()
                print(f"✅ Peer {url} respondeu: {response_data}", flush=True)

                if not response_data.get("error"):
                    return jsonify(response_data), 200
            except Exception as e:
                print(f"⚠️ Erro com peer {url}: {e}", flush=True)
                continue

    # Fallback local se todos peers falharem
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

        return jsonify({
            'message': f'Transação registrada localmente no bloco {index} (ainda não minerado)',
            'transaction': {
                'sender': data.get('sender'),
                'recipient': data.get('recipient'),
                'amount': data.get('amount')
            }
        }), 200
    except Exception as e:
        import traceback
        print("Erro no processamento local:", traceback.format_exc(), flush=True)
        return jsonify({'error': f'Erro local: {str(e)}'}), 500

# --- Endpoints corrigidos --- #
import logging

def format_peer_url(peer_ip):
    if not peer_ip.startswith('http'):
        return f"http://{peer_ip}:5000/register_node"
    return f"{peer_ip}/register_node"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger()

mining_lock = threading.Lock()
logger = logging.getLogger(__name__)

@app.route('/mine', methods=['GET'])
def mine():
    valido, user_or_msg = validar_token()
    if not valido:
        return jsonify({'error': user_or_msg}), 401

    miner_address = request.args.get('miner')
    usar_gpu = request.args.get('gpu', 'false').lower() == 'true'

    if not miner_address:
        return jsonify({'error': 'Endereço do minerador não fornecido'}), 400

    conn = create_mysql_connection()
    if not conn:
        return jsonify({'error': 'Banco de dados indisponível'}), 503

    with mining_lock:
        try:
            logger.info("🔄 Recarregando estado da blockchain...")
            blockchain.load_state()

            last_block = blockchain.last_block
            last_proof = last_block['proof']
            last_index = last_block['index']

            logger.info(f"⛏️ Realizando prova de trabalho... (GPU={usar_gpu})")
            proof = blockchain.proof_of_work(last_proof, usar_gpu=usar_gpu)

            # Validar se outro nó já minerou
            blockchain.load_state()
            if blockchain.last_block['index'] != last_index:
                return jsonify({'message': 'Outro nó já minerou o próximo bloco.'}), 409

            logger.info("💰 Gerando recompensa...")
            blockchain.new_transaction("0", miner_address, blockchain.current_reward())

            previous_hash = blockchain.hash(blockchain.last_block)
            novo_bloco = blockchain.new_block(proof, miner_address, previous_hash)

            # Atualizar saldo do minerador no banco com transação
            try:
                cursor = conn.cursor()
                cursor.execute('START TRANSACTION')
                update_balance(conn, miner_address, blockchain.current_reward())
                conn.commit()
            except Exception as e:
                conn.rollback()
                logger.error(f"Erro ao atualizar saldo no banco: {e}")
                return jsonify({'error': 'Erro ao atualizar saldo no banco'}), 500

            saldo = get_balance(conn, miner_address)

            logger.info(f"✅ Bloco #{novo_bloco['index']} minerado com sucesso por {miner_address}")

            return jsonify({
                "message": "Bloco minerado com sucesso",
                "block": novo_bloco["index"],
                "transactions": novo_bloco["transactions"],
                "proof": novo_bloco["proof"],
                "previous_hash": novo_bloco["previous_hash"],
                "hash": novo_bloco["hash"],
                "miner": miner_address,
                "reward": blockchain.current_reward(),
                "balance": saldo
            }), 200

        except Exception as e:
            logger.error(f"❌ Erro durante mineração: {str(e)}")
            return jsonify({'error': str(e)}), 503

def sincronizar_blockchain():
    global blockchain
    for node in known_nodes:
        try:
            response = requests.get(f"{node}/chain", timeout=5)
            if response.status_code == 200:
                remote_chain = response.json().get('chain', [])
                if is_chain_valid(remote_chain) and len(remote_chain) > len(blockchain.chain):
                    blockchain.replace_chain(remote_chain)
                    print(f"[SYNC] Blockchain atualizada pelo nó {node}")
        except Exception as e:
            print(f"[SYNC] Falha ao sincronizar com {node}: {e}")

def validar_chain(chain):
    for i in range(1, len(chain)):
        bloco_atual = chain[i]
        bloco_anterior = chain[i - 1]

        # Verifica se o hash do bloco anterior bate
        if bloco_atual['previous_hash'] != hashlib.sha256(json.dumps(bloco_anterior, sort_keys=True).encode()).hexdigest():
            print(f"❌ Hash inválido no bloco {i}")
            return False

        # Verifica prova de trabalho
        proof = bloco_atual['proof']
        last_proof = bloco_anterior['proof']
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        if guess_hash[:bloco_atual.get('difficulty', 1)] != "0" * bloco_atual.get('difficulty', 1):
            print(f"❌ Prova de trabalho inválida no bloco {i}")
            return False

    return True


# carregar também os peers conhecidos do peers.json no endpoint /nodes
@app.route('/nodes', methods=['GET'])
def listar_nodes():
    conhecidos = set(carregar_peers())
    todos = []

    # Adiciona os da memória
    for peer in nodes.values():
        todos.append(peer)

    # Adiciona os do arquivo
    for ip in conhecidos:
        if ip not in nodes:
            todos.append({'ip': ip, 'name': f"Nó {ip}"})

    return jsonify(todos)

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

@app.route('/peers', methods=['GET'])
def get_peers():
    return jsonify({'known_nodes': known_nodes})

def atualizar_peers_de_no(peer_url):
    try:
        resp = requests.get(f"{peer_url}/peers", timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            novos_peers = data.get('known_nodes', [])
            updated = False
            ips_existentes = [url_sem_protocolo_porta(u) for u in known_nodes]

            for peer in novos_peers:
                ip_peer = url_sem_protocolo_porta(peer)
                if ip_peer not in ips_existentes:
                    known_nodes.append(peer)
                    updated = True
                    print(f"[INFO] Novo peer adicionado via sincronização: {peer}")

            if updated:
                salvar_nos()

    except Exception as e:
        print(f"[ERRO] Falha ao sincronizar peers do nó {peer_url}: {e}")

def manter_rede_viva():
    while True:
        print("[HEARTBEAT] Sincronizando e limpando nós inativos...")
        for node in known_nodes[:]:
            try:
                resp = requests.get(f"{node}/ping", timeout=3)
                if resp.status_code != 200:
                    raise Exception("Status diferente de 200")
                # Se conseguiu pingar, reseta contagem de falhas
                falhas[node] = 0

                # Sincroniza peers de nós ativos
                atualizar_peers_de_no(node)

            except Exception as e:
                falhas[node] = falhas.get(node, 0) + 1
                print(f"[INFO] Ping falhou para {node} ({falhas[node]} falhas)")
                if falhas[node] >= 3:  # 3 falhas consecutivas pra remover
                    print(f"[INFO] Nó {node} removido após {falhas[node]} falhas consecutivas.")
                    known_nodes.remove(node)
                    falhas.pop(node)
        sync_all()
        salvar_nos()
        print(f"[HEARTBEAT] known_nodes atuais: {known_nodes}")
        time.sleep(60)

@app.route('/register_node', methods=['POST'])
def register_node():
    data = request.get_json()
    ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if ip and ',' in ip:
        ip = ip.split(',')[0].strip()

    if not data or 'ip' not in data:
        return jsonify({"message": "IP inválido ou dados ausentes."}), 400

    ip_novo = data['ip']
    if ':' in ip_novo and not ip_novo.startswith('['):
        ip_novo = f"[{ip_novo}]"

    if ip_novo not in nodes:
        nodes[ip_novo] = {
            'ip': ip_novo,
            'name': data.get('name', f"Nó {ip_novo}"),
            'last_active': time.time()
        }
        return jsonify({"message": f"Peer {ip_novo} registrado."}), 200
    return jsonify({"message": "IP já registrado."}), 400


def calcular_recompensa_dinamica():
    # Exemplo simples: retorna um valor fixo
    return

def rodar_servidor_flask(porta=5000):
    app.run(host='0.0.0.0', port=porta, threaded=True)

LIBERAR_PORTAS = True


SECRET_KEY = "25s5ash5556s54d45593ksaa55s25a45545s5d4a5s55440-0"

def gerar_token_unico(intervalo_segundos=60):
    time_window = int(time.time() // intervalo_segundos)
    texto = f"{SECRET_KEY}{time_window}"
    return hashlib.sha256(texto.encode()).hexdigest()

def gerar_token(usuario):
    payload = {
        "user": usuario,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=2)  # token válido 2h
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm="HS256")
    return token

def validar_token():
    token = request.headers.get("Authorization")
    if not token:
        return False, "Token não fornecido"
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return True, payload["user"]
    except jwt.ExpiredSignatureError:
        return False, "Token expirado"
    except jwt.InvalidTokenError:
        return False, "Token inválido"
        
@app.route("/p2p-btc3")
def p2p_btc3():
    token = gerar_token_unico()
    return f"""
    <html>
        <head><title>BTC3 Node</title></head>
        <body>
            <h1>✅ BTC3 Online</h1>
            <p>Bitcoin 3.0: Decentralization and Innovation</p>
            <p>Token: {token}</p>
        </body>
    </html>
    """, 200

def escanear_varias_faixas(faixas):
    todos_encontrados = []
    for faixa_inicio, faixa_fim in faixas:
        encontrados = scanner_continuo(faixa_inicio, faixa_fim)
        todos_encontrados.extend(encontrados)
    return todos_encontrados

def get_balance(address):
    for peer in peers:
        try:
            r = requests.get(f"{peer}/balance/{address}", timeout=5)
            if r.status_code == 200:
                return r.json()
        except:
            print(f"⚠️ Peer {peer} falhou")
    raise Exception("Todos os peers estão offline")

def create_mysql_connection():
    """Retorna uma conexão do pool MySQL."""
    return mysql_pool.get_connection() if 'mysql_pool' in globals() else None

def minerar_localmente_e_enviar(miner_address):
    last_block = blockchain.last_block
    last_proof = last_block['proof']
    last_index = last_block['index']
    previous_hash = blockchain.hash(last_block)

    print("⛏️ Minerando localmente...")
    proof = blockchain.proof_of_work(last_proof)

    bloco = {
        "index": last_index + 1,
        "proof": proof,
        "previous_hash": previous_hash,
        "miner": miner_address
    }

    peers = carregar_peers()
    for peer in peers:
        try:
            url = f"{garantir_protocolo(peer)}:5000/submit_block"
            print(f"📡 Enviando bloco ao servidor: {url}")
            response = requests.post(url, json=bloco, timeout=10)
            print(f"📥 Resposta do servidor: {response.status_code}")
            print(response.json())
            if response.status_code == 201:
                return True
        except Exception as e:
            print(f"❌ Erro ao enviar bloco: {e}")
            continue

    print("⚠️ Nenhum servidor aceitou o bloco.")
    return False

def minerar_localmente(blockchain, miner_address):
    last_block = blockchain.last_block
    last_proof = last_block['proof']
    last_index = last_block['index']
    previous_hash = blockchain.hash(last_block)

    print("⛏️ Minerando localmente...")
    proof = blockchain.proof_of_work(last_proof)

    bloco = {
        "index": last_index + 1,
        "proof": proof,
        "previous_hash": previous_hash,
        "miner": miner_address
    }

    peers = carregar_peers()
    for peer in peers:
        try:
            url = f"{garantir_protocolo(peer)}:5000/submit_block"
            print(f"📡 Enviando bloco ao peer: {url}")
            response = requests.post(url, json=bloco, timeout=10)
            print(f"📥 Resposta do servidor: {response.status_code}")
            print(response.json())
            if response.status_code == 201:
                return True
        except Exception as e:
            print(f"❌ Erro ao enviar bloco: {e}")
            continue

    return False

def valid_proof(self, last_proof, proof):
    guess = f'{last_proof}{proof}'.encode()
    guess_hash = hashlib.sha256(guess).hexdigest()
    return guess_hash[:self.difficulty] == "0" * self.difficulty

if __name__ == "__main__":
    garantir_arquivo_peers()

    # Iniciar o servidor Flask
    if LIBERAR_PORTAS:
        servidor_thread = threading.Thread(target=rodar_servidor_flask, args=(5000,), daemon=True)
        servidor_thread.start()
        print("⚙️ Servidor Flask iniciado para liberar porta 5000 e atuar como peer ativo.")

    # Obter IP público e registrar em outros peers
    ip_cliente = obter_ip_publico()
    if ip_cliente:
        adicionar_peer_manual(ip_cliente)
        registrar_em_peers(ip_cliente, carregar_peers())

    # Registrar peers conhecidos localmente
    sincronizar_peers_de_arquivo()

    miner_address = "sua cartera aqui"

    faixas_de_ip = [
        ("45.228.238.0", "45.228.252.255"),
        ("45.221.222.0", "45.221.222.255"),
        ("15.204.1.0", "15.204.8.255"),
        ("141.95.82.0", "141.95.82.255"),
        ("13.95.82.0", "13.95.82.255"),
        #("2804:14c:82::", "2804:14c:82:ffff:ffff:ffff:ffff:ffff"),  # IPv6 desabilitado por enquanto
    ]

    while True:
        print("\n🚀 Iniciando escaneamento das faixas definidas...")
        peers_validos = escanear_varias_faixas(faixas_de_ip)

        if not peers_validos:
            print("⚠️ Nenhum peer válido encontrado. Aguardando antes de tentar novamente...")
            time.sleep(10)
            continue

        for peer_para_minar in peers_validos:
            resultado = minerar_com_peer_continuo(peer_para_minar, miner_address)
            if resultado:
                print("♻️ Minerou o limite no peer atual. Escaneando peers novamente...\n")
                break
            else:
                print(f"♻️ Falha ao minerar no peer {peer_para_minar}. Tentando próximo peer...\n")
        else:
            print("⚠️ Nenhum peer disponível para minerar no momento. Aguardando...")
            time.sleep(35)
