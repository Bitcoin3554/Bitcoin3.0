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

# ----------------- Minerador -----------------
class Miner:
    def __init__(self, address):
        self.address = address
        self.attempt_points = 0
        self.running = True

    def mine(self, blockchain):
        last_block = blockchain.last_block
        proof = 0

        while self.running:
            # Sempre usar o proof_of_work para validar
            if blockchain.valid_proof(last_block['proof'], proof):
                # Encontrou proof válido, para mineração
                print(f"🔑 Proof encontrado: {proof}")
                break

            proof += 1
            self.attempt_points += 1

            if self.attempt_points % 1000 == 0:
                time.sleep(0.1)

            if self.attempt_points % 5000 == 0:
                print(f"📉 Pausando para reduzir CPU")
                time.sleep(1)

            if self.attempt_points % 10000 == 0:
                print(f"💤 Pausa maior para economia de CPU")
                time.sleep(2)

            # Se outra thread atualizou a blockchain (ex: bloco criado por outro), interrompa mineração
            blockchain.load_state()
            if blockchain.last_block['index'] != last_block['index']:
                print("⚠️ Outro bloco foi criado. Parando mineração atual.")
                self.running = False
                break

        return proof

    def stop_mining(self):
        self.running = False
        print("🔴 Mineração parada.")


# ----------------- Classes: Wallet e Blockchain -----------------
class Wallet:
    def __init__(self):
        self.private_key = self.create_private_key()
        self.public_key = self.create_public_key()
        self.address = self.create_address()

    def create_private_key(self):
        """Gera uma chave privada de 32 bytes para ECDSA secp256k1"""
        return os.urandom(32).hex()

    def create_public_key(self):
        """Gera uma chave pública a partir da chave privada usando ECDSA secp256k1"""
        private_key_bytes = bytes.fromhex(self.private_key)
        sk = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
        vk = sk.verifying_key
        public_key_bytes = b'\x04' + vk.to_string()
        return public_key_bytes.hex()

    def create_address(self):
        """Gera um endereço usando SHA-256, RIPEMD-160 e Base58Check"""
        public_key_bytes = bytes.fromhex(self.public_key)
        
        # SHA-256 da chave pública
        sha256_hash = hashlib.sha256(public_key_bytes).digest()
        
        # RIPEMD-160 do SHA-256
        ripemd160 = hashlib.new('ripemd160')
        ripemd160.update(sha256_hash)
        public_key_hash = ripemd160.digest()
        
        # Adiciona o prefixo de rede (0x00 para Bitcoin)
        prefixed_hash = b'\x00' + public_key_hash
        
        # Calcula o checksum (SHA-256 duas vezes e pega os primeiros 4 bytes)
        checksum = hashlib.sha256(hashlib.sha256(prefixed_hash).digest()).digest()[:4]
        
        # Concatena o hash com o checksum e converte para Base58Check
        address_bytes = prefixed_hash + checksum
        return base58.b58encode(address_bytes).decode()

    def show_wallet_info(self):
        """Exibe a chave privada, chave pública e endereço"""
        print(f"Chave Privada: {self.private_key}")
        print(f"Chave Pública: {self.public_key}")
        print(f"Endereço: {self.address}")

# Instanciando a carteira e mostrando as informações
wallet = Wallet()
wallet.show_wallet_info()


def verificar_integridade(self):
    for i in range(1, len(self.chain)):
        atual = self.chain[i]
        anterior = self.chain[i - 1]

        # Verifica índice sequencial
        if atual['index'] != anterior['index'] + 1:
            print(f"❌ Índice inválido no bloco {atual['index']}")
            return False

        # Verifica hash do bloco anterior
        if atual['previous_hash'] != self.hash(anterior):
            print(f"❌ Hash anterior inválido no bloco {atual['index']}")
            return False

        # Verifica hash do bloco atual
        if atual.get('hash') and atual['hash'] != self.hash_block(atual):
            print(f"❌ Hash incorreto no bloco {atual['index']}")
            return False

    print("✅ Blockchain íntegra.")
    return True

def update_miners_in_db(self, block):
    cursor = self.conn.cursor()
    cursor.execute("""
        UPDATE blockchain SET miners = %s WHERE `index` = %s
    """, (json.dumps(block['miners']), block['index']))
    self.conn.commit()

class Blockchain:
    INTERVALO_AJUSTE = 2016  # Número de blocos por ajuste (igual ao Bitcoin)
    BLOCO_ALVO_SEGUNDOS = 600  # 10 minutos por bloco
    TEMPO_ALVO_TOTAL = INTERVALO_AJUSTE * BLOCO_ALVO_SEGUNDOS  # Tempo total ideal

    def __init__(self, conn, miner_addresses=None):
        self.conn = conn
        self.current_transactions = []
        self.adjustment_interval = 2016
        self.miner_addresses = miner_addresses or []
        self.lock = threading.Lock()  # ← Adicionado aqui

        # Carrega do banco
        self.chain = []
        try:
            cursor = self.conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM blockchain ORDER BY `index` ASC")
            rows = cursor.fetchall()

            for row in rows:
                block = {
                    'index': row['index'],
                    'timestamp': row['timestamp'],
                    'transactions': json.loads(row['transactions']),
                    'proof': row['proof'],
                    'previous_hash': row['previous_hash'],
                    'difficulty': row['difficulty'],
                    'hash': row.get('hash'),
                    'miners': json.loads(row['miners']) if row.get('miners') else []  # ← AQUI
                }
                self.chain.append(block)

            self.difficulty = self.chain[-1]['difficulty'] if self.chain else 1
            print(f"✅ Blockchain carregada do banco com {len(self.chain)} blocos.")

        except Exception as e:
            print(f"❌ Erro ao carregar blockchain do banco: {e}")
            self.chain = []
            self.difficulty = 1

    def create_genesis_block(self):
        if self.chain:
            print("⚠️ Bloco gênese já existe.")
            return

        genesis_block = self.create_new_block(previous_hash="0", proof=100, timestamp=time.time())
        self.chain.append(genesis_block)
        self.save_state()
        print("✅ Bloco gênese criado.")

    def limpar_blocos_duplicados(self):
        print("🧹 Limpando blocos duplicados...")
        seen = set()
        new_chain = []
        for block in sorted(self.chain, key=lambda b: b['index']):
            if block['index'] not in seen:
                new_chain.append(block)
                seen.add(block['index'])
            else:
                print(f"⚠️ Removendo bloco duplicado index={block['index']}")

        self.chain = new_chain
        self.save_state()


    def create_new_block(self, previous_hash, proof, timestamp, transactions=None):
        block = {
            'index': self.last_block['index'] + 1 if self.chain else 1,
            'timestamp': timestamp,
            'proof': proof,
            'previous_hash': previous_hash,
            'transactions': transactions or self.current_transactions.copy(),
            'difficulty': self.difficulty  # ← ESSA LINHA É NECESSÁRIA
        }
        block['hash'] = self.hash_block(block)
        return block



    def hash_block(self, block):
        """Cria o hash SHA-256 de um bloco"""
        block_string = f"{block['index']}{block['timestamp']}{block['proof']}{block['previous_hash']}"
        return hashlib.sha256(block_string.encode('utf-8')).hexdigest()

    def save_state(self):
        self.ensure_connection()
        cursor = self.conn.cursor()
        for block in self.chain:
            cursor.execute("SELECT 1 FROM blockchain WHERE `index` = %s", (block['index'],))
            if cursor.fetchone():
                continue  # pula os blocos que já existem
            # só insere novos blocos
            cursor.execute("""
                INSERT INTO blockchain (`index`, `timestamp`, `transactions`, `proof`, `previous_hash`, `difficulty`, `hash`)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
            """, (
                block['index'],
                block['timestamp'],
                json.dumps(block['transactions']),
                block['proof'],
                block['previous_hash'],
                block['difficulty'],
                block['hash']
            ))
        self.conn.commit()



    def load_state(self):
        self.chain.clear()
        try:
            cursor = self.conn.cursor(dictionary=True)
            cursor.execute("SELECT * FROM blockchain ORDER BY `index` ASC")
            rows = cursor.fetchall()

            for row in rows:
                block = {
                    'index': row['index'],
                    'timestamp': row['timestamp'],
                    'transactions': json.loads(row['transactions']),
                    'proof': row['proof'],
                    'previous_hash': row['previous_hash'],
                    'difficulty': row['difficulty'],
                    'hash': row.get('hash'),
                    'miners': json.loads(row['miners']) if row.get('miners') else []  # ← AQUI
                }
                self.chain.append(block)

            self.difficulty = self.chain[-1]['difficulty'] if self.chain else 1
            print(f"✅ Blockchain recarregada do banco com {len(self.chain)} blocos.")

        except Exception as e:
            print(f"❌ Erro ao recarregar blockchain: {e}")
            self.chain = []
            self.difficulty = 1


    @property
    def last_block(self):
        if not self.chain:
            raise Exception("Blockchain vazia! Nenhum bloco foi encontrado.")
        return self.chain[-1]


    def row_to_block(self, row):
        return {
            'index': row['index'],
            'timestamp': row['timestamp'],
            'transactions': json.loads(row['transactions']),  # <-- aqui!
            'proof': row['proof'],
            'previous_hash': row['previous_hash'],
            'difficulty': row['difficulty'],
        }
        

    def save_block(self, block):
        cursor = self.conn.cursor()

        miners_json = json.dumps(block.get('miners', []))

        cursor.execute("SELECT 1 FROM blockchain WHERE `index` = %s", (block['index'],))
        if cursor.fetchone():
            # Atualiza só os mineradores
            cursor.execute("""
                UPDATE blockchain SET miners = %s WHERE `index` = %s
            """, (miners_json, block['index']))
        else:
            # Insere novo bloco incluindo miners
            cursor.execute("""
                INSERT INTO blockchain (`index`, `timestamp`, `transactions`, `proof`, `previous_hash`, `difficulty`, `hash`, `miners`)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                block['index'],
                block['timestamp'],
                json.dumps(block['transactions']),
                block['proof'],
                block['previous_hash'],
                block['difficulty'],
                block['hash'],
                miners_json
            ))
        self.conn.commit()
        print(f"✅ Bloco #{block['index']} salvo no banco.")


    def get_difficulty(self):
        """Obtém a dificuldade atual do banco de dados."""        
        cursor = self.conn.cursor()
        cursor.execute("SELECT value FROM blockchain_settings WHERE key = 'difficulty'")
        row = cursor.fetchone()
        return int(row[0]) if row else 4  # Valor padrão se não encontrar no banco de dados

    def set_difficulty(self, difficulty):
        """Atualiza a dificuldade no banco de dados."""        
        with self.conn:
            cursor = self.conn.cursor()
            cursor.execute("UPDATE blockchain_settings SET value = %s WHERE `key` = 'difficulty'", (difficulty,))


    def ajustar_dificuldade(self):
        if len(self.chain) < self.INTERVALO_AJUSTE + 1:
            return self.difficulty

        ultimo_bloco = self.chain[-1]
        bloco_de_referencia = self.chain[-self.INTERVALO_AJUSTE - 1]

        tempo_real = ultimo_bloco['timestamp'] - bloco_de_referencia['timestamp']
        tempo_alvo = self.BLOCO_ALVO_SEGUNDOS * self.INTERVALO_AJUSTE
        dificuldade_atual = self.difficulty

        fator_ajuste = tempo_real / tempo_alvo
        fator_ajuste = max(0.5, min(2.0, fator_ajuste))  # limita fator entre 0.5 e 2

        nova_dificuldade = max(1, int(dificuldade_atual * (1 / fator_ajuste)))

        print(f"[AJUSTE] Tempo real: {tempo_real:.2f}s | Tempo ideal: {tempo_alvo:.2f}s")
        print(f"[AJUSTE] Dificuldade ajustada de {dificuldade_atual} para {nova_dificuldade}")
        return nova_dificuldade


            
    def new_block(self, proof, minerador_address, previous_hash=None):
        with self.lock:
            last_index = self.chain[-1]['index'] if self.chain else 0
            new_index = last_index + 1

            # Ajusta dificuldade se necessário
            if new_index % self.INTERVALO_AJUSTE == 0:
                self.difficulty = self.ajustar_dificuldade()

            # Verifica se bloco já existe na chain
            for block in self.chain:
                if block['index'] == new_index:
                    # Atualiza mineradores do bloco existente
                    miners_effort = block.get('miners', {})
                    miners_effort[minerador_address] = miners_effort.get(minerador_address, 0) + 1
                    block['miners'] = miners_effort
                    self.save_block(block)
                    print(f"🤝 Minerador {minerador_address} colaborou no bloco {new_index}, esforço total: {miners_effort[minerador_address]}")
                    return block

            # Cria novo bloco
            block = {
                'index': new_index,
                'timestamp': time.time(),
                'transactions': self.current_transactions.copy(),
                'proof': proof,
                'previous_hash': previous_hash or self.hash(self.last_block),
               'difficulty': self.difficulty,
                'miners': {minerador_address: 1}
            }
            block['hash'] = self.hash_block(block)

            # Reseta lista de transações pendentes
            self.current_transactions = []

            # Adiciona à cadeia e salva no banco
            self.chain.append(block)
            self.save_block(block)

            print(f"✅ Novo bloco #{new_index} adicionado com minerador inicial {minerador_address}")
            return block


    def distribuir_recompensa(self, block):
        # Soma total do esforço (total de proofs) dos mineradores que ajudaram no bloco
        total_effort = sum(block['miners'].values())
        if total_effort == 0:
            print("⚠️ Nenhum esforço registrado para o bloco.")
            return {}

        reward_total = self.current_reward()
        recompensas = {}

        print(f"🏆 Distribuindo recompensa total de {reward_total:.8f} entre mineradores...")
    
        for miner, effort in block['miners'].items():
            # Proporção do minerador = esforço dele / total de esforços
            recompensa = reward_total * (effort / total_effort)
            recompensas[miner] = recompensa

            # Atualiza saldo do minerador
            self.update_balance(miner, recompensa)

            print(f"Minerador {miner} recebeu {recompensa:.8f} pipo.")

        return recompensas


    def new_transaction(self, sender, recipient, amount):
        if self.get_balance(sender) < amount:
            return False
        self.current_transactions.append({
            'sender': sender,
            'recipient': recipient,
            'amount': amount,
        })
        return self.last_block['index'] + 1



    @staticmethod
    def hash(block):
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_proof):
        proof = 0
        inicio = time.time()
        LIMITE_SEGUNDOS = 60

        while True:
            guess = f'{last_proof}{proof}'.encode()
            guess_hash = hashlib.sha256(guess).hexdigest()

            if guess_hash[:self.difficulty] == "0" * self.difficulty:
                print(f"[✔️] Hash encontrado: {guess_hash} com proof {proof} em {int(time.time() - inicio)}s")
                return proof

            proof += 1

            if time.time() - inicio > LIMITE_SEGUNDOS:
                raise Exception("⏱️ Mineração levou tempo demais. Abortando.")



    def valid_proof(self, last_proof, proof):
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:self.difficulty] == "0" * self.difficulty

    def create_wallet(self):
        wallet = Wallet()
        add_wallet(self.conn, wallet.address, wallet.private_key)
        self.wallets[wallet.address] = {'private_key': wallet.private_key}
        return wallet.address

    def update_balance(self, address, amount):
        update_balance(self.conn, address, amount)
        return self.get_balance(address)

    def get_balance(self, address):
        cursor = conn.cursor()
        row = cursor.fetchone()
        cursor.close()
        conn.close()
        return float(row[0]) if row else 0.0


    # Método que calcula a recompensa atual baseado na altura da cadeia (modelo Bitcoin)
    def current_reward(self):
        initial_reward = 50  # Recompensa inicial (ex: 50 pipo)
        halving_interval = 210000  # Intervalo para halving
        blocks_mined = len(self.chain) - 1  # Considera que o bloco gênese não conta para o halving
        halvings = blocks_mined // halving_interval
        reward = initial_reward / (2 ** halvings)
        return reward


def mine_block(miner_address):
    try:
        last_block = blockchain.last_block
        last_proof = last_block['proof']
        proof = blockchain.proof_of_work(last_proof)

        blockchain.load_state()

        if blockchain.last_block['index'] != last_block['index']:
            print("⚠️ Outro bloco já foi minerado.")
            return

        previous_hash = blockchain.hash(last_block)
        block = blockchain.new_block(proof, miner_address, previous_hash)

        update_balance(conn, miner_address, blockchain.current_reward())
        print(f"[✅] Bloco #{block['index']} minerado por {miner_address}")

    except Exception as e:
        print(f"[❌] Erro na mineração: {e}")

def get_network_usage():
    """ Obtém o tráfego de rede do servidor. """
    net_io = psutil.net_io_counters()
    bytes_sent = net_io.bytes_sent
    bytes_received = net_io.bytes_recv
    return bytes_sent, bytes_received

def select_node_for_request():
    if not nodes:
        return None
    return min(nodes, key=lambda node: (node["cpu"], node["memory"], node.get("network_load", 0)))


# Função para obter a carga do servidor (simples exemplo)
def get_server_load():
    cpu_percent = psutil.cpu_percent(interval=1)
    memory_percent = psutil.virtual_memory().percent
    return cpu_percent, memory_percent

# Carregar nós do arquivo JSON
def load_nodes():
    global nodes
    if os.path.exists('nodes.json'):
        with open('nodes.json') as f:
            try:
                nodes = json.load(f)
            except json.JSONDecodeError:
                nodes = {}

def save_nodes():
    with open('nodes.json', 'w') as f:
        json.dump(nodes, f, indent=2)

# Lista global de nós
nodes = load_nodes() if isinstance(load_nodes(), dict) else {}

# Monitoramento contínuo dos nós para manter os ativos conectados
def monitor_nodes():
    while True:
        current_time = time.time()
        for ip, info in list(nodes.items()):
            last_active = info.get("last_active", 0)
            if current_time - last_active > 300:  # Remove nós inativos há mais de 5 minutos
                del nodes[ip]
                logging.warning(f"Nó {ip} removido por inatividade.")
        save_nodes()
        time.sleep(10)
        
# Função para enviar "ping" para garantir que os nós fiquem conectados
def keep_alive_ping():
    while True:
        for ip in list(nodes.keys()):
            try:
                socketio.emit('ping', room=ip)
                logging.info(f"Ping enviado para o nó {ip}")
            except Exception as e:
                logging.warning(f"Erro ao enviar ping para {ip}: {e}")
        time.sleep(2)

def reconnect_nodes():
    max_backoff = 60
    while True:
        for ip in list(nodes.keys()):
            backoff = 1
            while True:
                try:
                    socketio.emit('ping', room=ip)
                    logging.info(f"Reconectado: {ip}")
                    break
                except Exception as e:
                    logging.warning(f"Erro ao reconectar {ip}: {e}")
                    time.sleep(backoff)
                    backoff = min(backoff * 2, max_backoff)
        time.sleep(2)


def get_client_ip():
    forwarded_for = request.headers.get('X-Forwarded-For', None)
    if forwarded_for:
        # Pega o primeiro IP se houver vários
        ip = forwarded_for.split(',')[0].strip()
    else:
        ip = request.remote_addr
    return ip

def broadcast_block(block):
    for node in peer_nodes:
        try:
            url = f"{node}/receive_block"
            response = requests.post(url, json=block, timeout=3)
            if response.status_code == 201:
                print(f"✅ Bloco #{block['index']} enviado com sucesso para {node}")
            else:
                print(f"[⚠️] Resposta inesperada de {node}: {response.status_code} {response.text}")
        except Exception as e:
            print(f"[❌] Erro ao enviar bloco para {node}: {e}")

def synchronize_chain():
    global peer_nodes
    longest_chain = None
    max_length = len(blockchain.chain)

    for node in peer_nodes:
        try:
            url = f"{node}/chain"
            response = requests.get(url, timeout=3)
            if response.status_code == 200:
                data = response.json()
                length = data['length']
                chain = data['chain']
                if length > max_length and blockchain.is_valid_chain(chain):
                    max_length = length
                    longest_chain = chain
        except Exception as e:
            print(f"[❌] Falha ao sincronizar com {node}: {e}")

    if longest_chain:
        with blockchain.lock:
            blockchain.chain = longest_chain
            blockchain.save_state()
        print("✅ Cadeia sincronizada com a mais longa da rede")
        return True
    return False



def valid_proof_of_work(tx):
    tx_hash = tx.hash()
    return tx_hash.startswith("0000")  # verificar os 4 primeiros caracteres hex

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
                                print(f"⚠️ Muitos erros 503 consecutivos. Abortando mineração no peer {peer}.")
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

def testar_mine(peer):
    try:
        resp = requests.get(f"http://{peer}:5000/mine", timeout=5)
        if resp.status_code == 200:
            return True
        else:
            print(f"⚠️ /mine no peer {peer} retornou {resp.status_code}")
            return False
    except Exception as e:
        print(f"⚠️ Erro ao conectar no /mine do peer {peer}: {e}")
        return False

    
def checar_mine_disponivel(peer):
    try:
        res = requests.get(f"http://{peer}:5000/mine?miner=TESTE", timeout=5)
        return res.status_code == 200
    except:
        return False

def escanear_varias_faixas(faixas):
    todos_peers = []
    for start_ip, end_ip in faixas:
        encontrados = scanner_continuo(start_ip, end_ip, bloco_tamanho=1000, delay_seg=5)
        todos_peers.extend(encontrados)
    return list(set(todos_peers))

def registrar_em_peers(ip_local, peers):
    for peer_ip in peers:
        url = f"http://{peer_ip}:5000/register_node"
        try:
            resp = requests.post(url, json={"ip": ip_local, "name": "Scanner BTC3"}, timeout=5)

            if resp.status_code == 200:
                print(f"Registrado no peer {peer_ip}")
        except Exception as e:
            print(f"Erro ao registrar no peer {peer_ip}: {e}")


app = Flask(__name__)

nodes = {}  # ip: dados
    

from flask import Flask, request, jsonify
app = Flask(__name__)

@app.route('/mine', methods=['GET'])
def mine():
    miner = request.args.get('miner')
    if not miner:
        return jsonify({'error': 'Endereço do minerador é obrigatório'}), 400

    # Aqui a variável blockchain já existe e pode ser usada
    last_block = blockchain.last_block
    last_proof = last_block['proof']
    proof = blockchain.proof_of_work(last_proof)

    block = blockchain.new_block(proof, miner)

    return jsonify({
        'message': 'Novo bloco minerado!',
        'index': block['index'],
        'transactions': block['transactions'],
        'proof': block['proof'],
        'previous_hash': block['previous_hash'],
        'hash': block['hash'],
        'miner': block['miner'],
    })


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

    miner_address = "1LjRQdTC2CgUHXWricXjmPsu23rB2Tnitg"

    faixas_de_ip = [
        ("45.228.242.170", "45.228.242.255"),
        ("2804:14c:82::", "2804:14c:82:ffff:ffff:ffff:ffff:ffff"),  # IPv6 desabilitado por enquanto
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
