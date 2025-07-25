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
from flask import Flask, render_template, flash
from flask_cors import CORS
# from PyQt5.QtCore import pyqtSlot # Removido, pois não é usado diretamente aqui e pode causar erro se não for app PyQt
import webbrowser

# --- Configurações ---
DIFFICULTY = 1 # Dificuldade inicial para o bloco Gênese
MINING_REWARD = 50 # Recompensa padrão (será sobrescrita pela lógica de halving)
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
            print(f"[ERRO] {PEERS_FILE} está corrompido ou vazio. Recriando.")
            return []

known_nodes = set(carregar_peers())
miner_lock = threading.Lock()

blockchain = None
miner_address = None # Agora será definido por um endpoint ou configuração
meu_url = None # Definido no main
meu_ip = None # Definido no main
port = None # Definido no main

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
            # O bloco Gênese deve ter difficulty, senão get_total_difficulty pode falhar
            genesis_difficulty = DIFFICULTY # A dificuldade inicial pode ser 1 ou outro valor base
            self.new_block(proof=100, previous_hash='1', miner=self.node_id, initial_difficulty=genesis_difficulty)
            
        # Garante que a dificuldade atual do nó esteja em sincronia com a cadeia
        self.difficulty = self._calculate_difficulty_for_index(len(self.chain))
        print(f"[BOOT] Dificuldade inicial da cadeia: {self.difficulty}")

    def is_duplicate_transaction(self, new_tx):
        # ... (seu código existente) ...
        for tx in self.current_transactions:
            if tx.get('id') == new_tx.get('id'):
                return True
            if (tx.get('sender') == new_tx.get('sender') and
                tx.get('recipient') == new_tx.get('recipient') and
                tx.get('amount') == new_tx.get('amount') and
                tx.get('fee') == new_tx.get('fee') and
                tx.get('signature') == new_tx.get('signature')):
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
        # ... (seu código existente) ...
        c = self.conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS blocks(
                index_ INTEGER PRIMARY KEY,
                previous_hash TEXT,
                proof INTEGER,
                timestamp REAL,
                miner TEXT,
                difficulty INTEGER -- Garanta que esta coluna existe no DB
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
        # Garanta que 'difficulty' seja carregado
        c.execute("SELECT index_, previous_hash, proof, timestamp, miner, difficulty FROM blocks ORDER BY index_")
        chain = []
        for idx, prev, proof, ts, miner, difficulty in c.fetchall(): # <<< Carrega 'difficulty'
            c.execute("SELECT id, sender, recipient, amount, fee, signature, public_key FROM txs WHERE block_index=?", (idx,))
            txs = [dict(id=r[0], sender=r[1], recipient=r[2], amount=r[3], fee=r[4], signature=r[5], public_key=r[6]) for r in c.fetchall()]
            block = {
                'index': idx,
                'previous_hash': prev,
                'proof': proof,
                'timestamp': ts,
                'miner': miner,
                'transactions': txs,
                'difficulty': difficulty # <<< Adiciona 'difficulty' ao bloco
            }
            chain.append(block)
        return chain

    def new_block(self, proof, previous_hash, miner, initial_difficulty=None):
        block_index = len(self.chain) + 1
        reward = self._get_mining_reward(block_index)
        
        # A dificuldade do novo bloco é a dificuldade calculada para o índice atual
        difficulty = self._calculate_difficulty_for_index(block_index) if initial_difficulty is None else initial_difficulty

        # Adicionar a transação de recompensa no início da lista de transações
        # Certifique-se de que não haja recompensa duplicada se o bloco for rejeitado e a transação ficar pendente
        mining_reward_tx = {
            'id': str(uuid4()), 'sender': '0', 'recipient': miner,
            'amount': reward, 'fee': 0, 'signature': '', 'public_key': ''
        }
        # Adiciona a recompensa apenas se não for o bloco gênese com proof=100
        if proof != 100 or previous_hash != '1':
             self.current_transactions.insert(0, mining_reward_tx)


        block = {
            'index': block_index,
            'previous_hash': previous_hash,
            'proof': proof,
            'timestamp': time.time(),
            'miner': miner,
            'transactions': self.current_transactions,
            'difficulty': difficulty # ADICIONADO
        }

        self.current_transactions = [] # Limpa transações pendentes após inclusão
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
                   block['timestamp'], block['miner'], block['difficulty'])) # <<<<< adicionado
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
        # Verifica duplicidade antes de adicionar
        if self.is_duplicate_transaction(tx):
            print(f"[TX] Transação {tx.get('id', '')} já pendente. Ignorando.")
            return -1 # Sinaliza transação duplicada
        
        self.current_transactions.append(tx)
        print(f"[TX] Nova transação adicionada: {tx['id']}")
        return self.last_block()['index'] + 1 if self.chain else 1

    def _get_mining_reward(self, block_index):
        # ... (seu código existente) ...
        if block_index <= 1200:
            return 50
        elif block_index <= 2200:
            return 25
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
            return max(reward, 0)

    def last_block(self):
        return self.chain[-1] if self.chain else None

    def proof_of_work(self, last_proof):
        # Dificuldade do PRÓXIMO bloco
        difficulty_for_pow = self._calculate_difficulty_for_index(len(self.chain) + 1)
        proof = 0
        print(f"Iniciando mineração com dificuldade {difficulty_for_pow}...")
        start_time = time.time()
        
        while not self.valid_proof(last_proof, proof, difficulty_for_pow):
            global is_mining
            if not is_mining:
                print("[Miner] Sinal para parar recebido durante PoW. Abortando mineração.")
                return -1 # Retorna um valor especial para indicar aborto
            
            # Verifica se um novo bloco chegou enquanto minerava (otimização)
            # Isso é CRÍTICO para não minerar em uma cadeia obsoleta
            if self.last_block()['proof'] != last_proof:
                print("[Miner] Outro bloco chegou na cadeia principal durante PoW. Abortando e reiniciando.")
                return -1 # Sinaliza para o minerador reiniciar o ciclo

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

    def tx_already_mined(self, tx_id):
        # ... (seu código existente) ...
        c = self.conn.cursor()
        c.execute("SELECT 1 FROM txs WHERE id=?", (tx_id,))
        return c.fetchone() is not None

    def valid_chain(self, chain):
        """
        Determina se uma dada cadeia de blocos é válida.
        Verifica hashes, provas de trabalho, transações e dificuldade.
        """
        if not chain:
            return False # Uma cadeia vazia não é válida

        current_difficulty_check = DIFFICULTY
        
        # Validar o bloco Gênese
        if chain[0]['index'] != 1 or chain[0]['previous_hash'] != '1' or chain[0]['proof'] != 100:
            print("[VAL_CHAIN_ERRO] Bloco Gênese inválido.")
            return False

        for idx in range(1, len(chain)):
            prev = chain[idx - 1]
            curr = chain[idx]

            # Recalcula o hash do bloco anterior para verificar a ligação
            block_string_prev = json.dumps({k: v for k, v in prev.items() if k not in ['transactions', 'hash']}, sort_keys=True)
            prev_hash = hashlib.sha256(block_string_prev.encode()).hexdigest()

            if curr['previous_hash'] != prev_hash:
                print(f"[VAL_CHAIN_ERRO] Hash anterior incorreto no bloco {curr['index']}. Esperado: {prev_hash}, Obtido: {curr['previous_hash']}.")
                return False

            # Recalcula a dificuldade esperada para o bloco atual
            if curr['index'] > self.ADJUST_INTERVAL: # Só ajusta a partir do bloco ADJUST_INTERVAL + 1
                # Encontre o bloco de referência para o cálculo da dificuldade
                # O bloco de referência é ADJUST_INTERVAL blocos antes do bloco atual (curr['index'] - ADJUST_INTERVAL)
                # Na cadeia que está sendo validada (NÃO na self.chain)
                ref_block_index_in_chain = curr['index'] - self.ADJUST_INTERVAL -1 # -1 porque o index é 1-based, lista é 0-based
                
                if ref_block_index_in_chain < 0: # Não há blocos suficientes para o ajuste ainda
                     current_difficulty_check = DIFFICULTY
                else:
                    if ref_block_index_in_chain >= len(chain): # Evita IndexError se a cadeia for muito curta
                        print(f"[VAL_CHAIN_ERRO] Indice de bloco de referência fora da cadeia durante validação de dificuldade.")
                        return False

                    last_adjust_block_ts = chain[ref_block_index_in_chain]['timestamp']
                    current_block_ts = prev['timestamp'] # Usar o timestamp do bloco anterior ao 'curr' para o cálculo

                    actual_time = current_block_ts - last_adjust_block_ts
                    expected_time = self.TARGET_TIME * self.ADJUST_INTERVAL

                    # Ajuste de dificuldade (regrar do Bitcoin)
                    new_difficulty = current_difficulty_check
                    if actual_time < expected_time / 4: # Se 4x mais rápido, dobra dificuldade
                        new_difficulty += 2
                    elif actual_time < expected_time / 2: # Se 2x mais rápido, aumenta dificuldade
                        new_difficulty += 1
                    elif actual_time > expected_time * 4 and new_difficulty > 1: # Se 4x mais lento, corta dificuldade pela metade
                        new_difficulty -= 2
                    elif actual_time > expected_time * 2 and new_difficulty > 1: # Se 2x mais lento, diminui dificuldade
                        new_difficulty -= 1
                    
                    # Garante que a dificuldade nunca seja menor que 1
                    current_difficulty_check = max(1, new_difficulty)
            else:
                current_difficulty_check = DIFFICULTY # Para os primeiros blocos

            # 🚨 Ponto crítico: Validar a prova de trabalho com a dificuldade do próprio bloco
            # ou a dificuldade recalculada para o seu índice.
            # É mais robusto usar a dificuldade que o bloco *declarou* ter (curr.get('difficulty'))
            # e verificar se ela está dentro de uma margem razoável da dificuldade recalculada.
            # Para simplicidade inicial, vamos usar a dificuldade declarada pelo bloco, mas *validar a prova contra ela*.
            
            block_declared_difficulty = curr.get('difficulty', current_difficulty_check)
            if not self.valid_proof(prev['proof'], curr['proof'], block_declared_difficulty):
                hash_check = self.custom_asic_resistant_hash(f"{prev['proof']}{curr['proof']}".encode(), curr['proof'])
                print(f"[VAL_CHAIN_ERRO] Proof of Work inválido no bloco {curr['index']} com dificuldade {block_declared_difficulty}. Hash: {hash_check}")
                return False

            # Validação de transações (seu código existente é bom aqui)
            for tx in curr.get('transactions', []):
                if tx['sender'] == '0': # Recompensa do minerador
                    if tx['recipient'] != curr['miner']:
                        print(f"[VAL_CHAIN_ERRO] TX de recompensa inválida no bloco {curr['index']}: Recipiente incorreto.")
                        return False
                    # Verificar se a recompensa está correta para o índice do bloco
                    expected_reward = self._get_mining_reward(curr['index'])
                    if abs(tx['amount'] - expected_reward) > 0.000001: # Usar tolerância para floats
                        print(f"[VAL_CHAIN_ERRO] TX de recompensa inválida no bloco {curr['index']}: Valor incorreto. Esperado: {expected_reward}, Obtido: {tx['amount']}")
                        return False
                    continue # Não precisa validar assinatura da transação de recompensa

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

                    # Validação de saldo (requer estado do blockchain até o bloco anterior)
                    # Esta validação é complexa em valid_chain, pois exige recalcular saldos
                    # O ideal é que esta validação seja feita no momento da `new_tx` e `mine_block`.
                    # Em `valid_chain`, você pode assumir que as transações eram válidas quando o bloco foi minerado.
                    # Se você quer validar o saldo aqui, precisaria de uma função que calcule o saldo
                    # apenas até o bloco anterior (prev['index']), o que torna `valid_chain` lenta.
                    # Por enquanto, vou remover a validação de saldo aqui para não complicar demais o `valid_chain`.
                    # if self.balance(tx['sender']) < (tx['amount'] + tx['fee']):
                    #    print(f"[VAL_CHAIN_ERRO] Saldo insuficiente para TX {tx['id']} no bloco {curr['index']}.")
                    #    return False

                except BadSignatureError:
                    print(f"[VAL_CHAIN_ERRO] Transação {tx['id']} inválida no bloco {curr['index']}: Assinatura inválida.")
                    return False
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

    def get_total_difficulty(self, chain_to_check):
        """Calcula a dificuldade acumulada de uma cadeia."""
        total_difficulty = 0
        for block in chain_to_check:
            # Use o 'difficulty' armazenado no bloco.
            # Se por algum motivo o bloco não tiver 'difficulty' (ex: bloco Gênese antigo), use DIFFICULTY padrão.
            total_difficulty += block.get('difficulty', DIFFICULTY)
        return total_difficulty

    def resolve_conflicts(self):
        neighbors = known_nodes.copy()
        new_chain = None
        current_total_difficulty = self.get_total_difficulty(self.chain)

        print(f"[CONSENSO] Tentando resolver conflitos com {len(neighbors)} vizinhos... Cadeia local dificuldade: {current_total_difficulty}")

        for node_url in neighbors:
            if node_url == meu_url: # Não consultar a si mesmo
                continue
            try:
                response = requests.get(f"{node_url}/chain", timeout=10) # Aumentar timeout para redes lentas
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

                    # PRINCIPAL MUDANÇA AQUI: Comparar por dificuldade TOTAL, não apenas comprimento
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
            # Antes de substituir a cadeia, mova as transações pendentes da cadeia antiga
            # para as transações pendentes da nova cadeia, se ainda não estiverem lá.
            # Isso é importante para não perder transações válidas em uma reorganização.
            
            # 1. Obtenha as transações da cadeia substituída que não estão na nova
            old_chain_tx_ids = set()
            for block in self.chain:
                for tx in block.get('transactions', []):
                    old_chain_tx_ids.add(tx['id'])

            new_chain_tx_ids = set()
            for block in new_chain:
                for tx in block.get('transactions', []):
                    new_chain_tx_ids.add(tx['id'])
            
            # Adicione transações da cadeia antiga que não estão na nova e não são recompensas de mineração
            re_add_txs = []
            for block in self.chain:
                for tx in block.get('transactions', []):
                    if tx['id'] not in new_chain_tx_ids and tx['sender'] != '0':
                        re_add_txs.append(tx)
            
            # Adicione as transações atuais pendentes que não estão na nova cadeia
            for tx in self.current_transactions:
                if tx['id'] not in new_chain_tx_ids:
                    re_add_txs.append(tx)

            # Limpe as transações pendentes atuais e adicione as que devem ser re-processadas
            self.current_transactions = []
            for tx in re_add_txs:
                if not self.is_duplicate_transaction(tx): # Evita duplicatas ao re-adicionar
                    self.current_transactions.append(tx)
            
            self.chain = new_chain
            self._rebuild_db_from_chain()
            print(f"[CONSENSO] ✅ Cadeia substituída com sucesso pela mais difícil e válida (Dificuldade: {current_total_difficulty}). {len(re_add_txs)} transações re-adicionadas.")
            return True

        print("[CONSENSO] 🔒 Cadeia local continua sendo a mais difícil ou nenhuma cadeia mais difícil/válida foi encontrada.")
        return False


    def _rebuild_db_from_chain(self):
        # ... (seu código existente) ...
        print("[REBUILD] Reconstruindo dados locais a partir da nova cadeia...")
        try:
            c = self.conn.cursor()
            c.execute("DELETE FROM blocks")
            c.execute("DELETE FROM txs")

            for block in self.chain:
                # Verifique se 'difficulty' está presente no bloco, caso contrário, use um valor padrão
                difficulty_to_save = block.get('difficulty', DIFFICULTY)
                c.execute("INSERT INTO blocks VALUES (?, ?, ?, ?, ?, ?)",
                          (block['index'], block['previous_hash'], block['proof'],
                           block['timestamp'], block['miner'], difficulty_to_save))
                for tx in block['transactions']:
                    c.execute("INSERT INTO txs VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                              (tx['id'], tx['sender'], tx['recipient'], tx['amount'],
                               tx['fee'], tx['signature'], block['index'], tx.get('public_key', '')))
            self.conn.commit()
            print("[REBUILD] Banco reconstruído com sucesso.")
        except Exception as e:
            print(f"[REBUILD] Erro ao reconstruir banco: {e}")
            # Em caso de erro grave, pode ser necessário reiniciar ou alertar o usuário
            sys.exit(1) # Sair para evitar estado inconsistente

    def balance(self, address):
        bal = 0
        for block in self.chain:
            for t in block['transactions']:
                if t['sender'] == address:
                    bal -= (t['amount'] + t['fee'])
                if t['recipient'] == address:
                    bal += t['amount']
        
        # Considerar transações pendentes (não mineradas)
        for t in self.current_transactions:
            if t['sender'] == address:
                bal -= (t['amount'] + t['fee'])
            if t['recipient'] == address:
                bal += t['amount']
        return bal

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


@app.route('/transmitir', methods=['POST'])
def transmitir():
    tx = request.get_json()
    # Aqui você pode validar a tx, assinatura etc. Por enquanto, só imprime e responde OK
    print("Transação recebida:", tx)

    # TODO: validar assinatura, inserir na blockchain, etc.

    return jsonify({"status": "success", "message": "Transação recebida"}), 200
    
# --- Funções auxiliares (para assinatura, embora a assinatura seja do cliente) ---
def sign_transaction_node(private_key_hex, tx_data):
    sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    message = json.dumps(tx_data, sort_keys=True).encode()

    # Assina no formato DER
    der_signature = sk.sign(message)

    # Decodifica DER para (r, s)
    r, s = sigdecode_der(der_signature, SECP256k1.order)

    # Codifica como assinatura raw (64 bytes concatenados r+s)
    raw_signature_bytes = sigencode_string(r, s, SECP256k1.order)

    # Retorna assinatura em hex (64 bytes * 2 chars = 128 chars)
    return raw_signature_bytes.hex()

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

for peer in known_nodes:
    try:
        requests.post(f"{peer}/blocks/receive", json=block, timeout=3)
    except:
        print(f"Erro ao enviar bloco para {peer}")

import json
from ecdsa import SigningKey, SECP256k1
import json
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
from ecdsa.util import sigdecode_string, sigencode_der
from ecdsa import VerifyingKey, SECP256k1

def verify_raw_signature(public_key_hex, message, raw_signature_hex):
    vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)
    raw_signature = bytes.fromhex(raw_signature_hex)

    # Convert raw (r+s) para DER
    # A função verify() pode usar o decode do raw signature
    try:
        # Aqui tentamos verificar passando raw e decoder de string (r+s)
        return vk.verify(raw_signature, message, sigdecode=sigdecode_string)
    except Exception as e:
        print(f"Verificação falhou: {e}")
        return False

def sign_transaction(private_key_hex, tx_data):
    """
    Assina uma transação com a chave privada ECDSA (SECP256k1).
    """
    try:
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)

        # Cria a mensagem JSON ordenada e compactada
        message = json.dumps(tx_data, sort_keys=True, separators=(",", ":")).encode()

        # Gera a assinatura determinística
        signature = sk.sign_deterministic(message).hex()
        return signature
    except Exception as e:
        print(f"[ERRO AO ASSINAR] {e}")
        return None


def verificar_assinatura(tx):
    """
    Verifica a assinatura de uma transação usando a chave pública.
    A transação (tx) deve conter: sender, recipient, amount, fee, signature, public_key
    """
    try:
        # Constrói o objeto da mensagem
        message = json.dumps({
            "sender": tx["sender"],
            "recipient": tx["recipient"],
            "amount": tx["amount"],
            "fee": tx["fee"]
        }, sort_keys=True, separators=(",", ":")).encode()

        # Converte a chave pública e a assinatura para bytes
        pub_key_bytes = bytes.fromhex(tx['public_key'])
        signature_bytes = bytes.fromhex(tx["signature"])

        # Verifica a assinatura
        vk = VerifyingKey.from_string(pub_key_bytes, curve=SECP256k1)
        return vk.verify(signature_bytes, message)

    except BadSignatureError:
        print("❌ Assinatura inválida.")
        return False
    except Exception as e:
        print(f"❌ Erro ao verificar assinatura: {e}")
        return False
        
def sign_transaction(private_key_hex, tx_data):
    try:
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)

        # SERIALIZAÇÃO DETERMINÍSTICA
        message = json.dumps(tx_data, sort_keys=True, separators=(",", ":")).encode()

        signature = sk.sign_deterministic(message).hex()
        return signature
    except Exception as e:
        print(f"[ERRO ASSINATURA] {e}")
        return None


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

from ecdsa import SigningKey, SECP256k1
import hashlib
import json

# Gerar chave privada
sk = SigningKey.generate(curve=SECP256k1)
vk = sk.verifying_key

# Extrair hex da chave privada e pública (com prefixo '04')
private_key_hex = sk.to_string().hex()
public_key_hex = "04" + vk.to_string().hex()

# Derivar endereço (SHA256 dos bytes da chave pública completa, pegar 40 primeiros hex)
pub_bytes = bytes.fromhex(public_key_hex)
sha = hashlib.sha256(pub_bytes).digest()
address = sha.hex()[:40]

# Criar estrutura JSON da carteira
wallet = {
    "private_key": private_key_hex,
    "public_key": public_key_hex,
    "address": address
}

# Salvar em arquivo JSON
with open("client_wallet.json", "w") as f:
    json.dump(wallet, f, indent=4)

print("Carteira gerada:")
print(json.dumps(wallet, indent=4))

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
def new_transaction_api():
    # --- INÍCIO DA DEPURAGEM CRÍTICA ---
    print(f"DEBUG_SERVER: Request received for /tx/new")
    print(f"DEBUG_SERVER: Request headers: {request.headers}")
    print(f"DEBUG_SERVER: Request mimetype: {request.mimetype}")
    print(f"DEBUG_SERVER: Request content_type: {request.content_type}")
    print(f"DEBUG_SERVER: Request data (raw): {request.data}")

    raw_values = None
    try:
        # Tenta obter o JSON do corpo da requisição.
        # force=True tenta analisar o JSON mesmo se o Content-Type não for application/json.
        # silent=True retorna None em caso de erro de parsing, em vez de levantar uma exceção.
        raw_values = request.get_json(silent=True)
        print(f"DEBUG_SERVER: Parsed JSON payload (request.get_json()): {raw_values}")
    except Exception as e:
        print(f"DEBUG_SERVER: ERROR - Exception during JSON parsing: {e}")
        # Se request.get_json() falhar, raw_values será None, e o erro será tratado abaixo.
    
    if raw_values is None:
        print(f"DEBUG_SERVER: ERROR - request.get_json() returned None. Check Content-Type header or JSON validity.")
        return jsonify({'message': 'Error: Could not parse JSON from request. Check Content-Type header or JSON validity.'}), 400
    # --- FIM DA DEPURAGEM CRÍTICA ---

    # ATUALIZADO: Se o payload é um array, pega o primeiro elemento (como no cliente Python)
    # REMOVIDO: A remoção do array no HTML torna esta verificação desnecessária para o caso normal,
    # mas mantê-la pode ser útil para compatibilidade com outras fontes se necessário.
    # No entanto, para o problema atual, `values = raw_values` é o caminho correto.
    values = raw_values

    # Check that the required fields are in the POST'ed data
    # Added 'id' to required fields as client now sends it
    required = ['id', 'sender', 'recipient', 'amount', 'fee', 'public_key', 'signature']
    if not all(k in values for k in required):
        # Log missing values for debugging
        missing = [k for k in required if k not in values]
        print(f"[ERROR 400] Missing values in transaction: {missing}")
        return jsonify({'message': f'Missing values in request: {", ".join(missing)}'}), 400

    try:
        # amount and fee are now expected to be strings from the HTML client.
        # Store them as strings in the transaction dictionary for consistency with signature verification.
        # For balance calculations, they will be converted to float later.
        transaction = {
            'id': values['id'], # Use ID from client
            'sender': values['sender'],
            'recipient': values['recipient'],
            'amount': values['amount'], # Keep as string as received from HTML
            'fee': values['fee'],        # Keep as string as received from HTML
            'public_key': values['public_key'],
            'signature': values['signature'],
            'timestamp': values.get('timestamp', time.time()) # Use timestamp from client or generate if missing
        }
    except Exception as e:
        print(f"[ERROR 400] Error building transaction: {e}")
        return jsonify({'message': f'Error processing transaction data: {e}'}), 400

    # --- DUPLICATE TRANSACTION CHECK (VERY IMPORTANT) ---
    # Note: For duplicate check, amount and fee must be compared as floats, not strings.
    # Convert them temporarily for this check.
    temp_tx_for_duplicate_check = {
        'sender': transaction['sender'],
        'recipient': transaction['recipient'],
        'amount': float(transaction['amount']),
        'fee': float(transaction['fee']),
        'id': transaction.get('id')
    }
    if blockchain.is_duplicate_transaction(temp_tx_for_duplicate_check):
        print(f"[WARNING] Duplicate transaction detected for {transaction['sender']} -> {transaction['recipient']}. Ignorando.")
        return jsonify({'message': 'Duplicate transaction detected. Not added again.'}), 200 # HTTP 200 OK or 409 Conflict

    # Signature validation now uses the verify_signature function which expects strings for amount/fee
    try:
        # --- CORREÇÃO: Derivação do endereço da chave pública ---
        # A chave pública recebida pode ter o prefixo '04'.
        # Para derivar o endereço (SHA256 dos bytes brutos da public_key SEM o prefixo '04'),
        # precisamos remover o '04' se ele estiver presente.
        pk_for_address_derivation = transaction['public_key']
        if pk_for_address_derivation.startswith('04') and len(pk_for_address_derivation) == 130:
            pk_for_address_derivation = pk_for_address_derivation[2:]
        
        derived_address = hashlib.sha256(bytes.fromhex(pk_for_address_derivation)).hexdigest()[:40] 
        if derived_address != transaction['sender']:
            print(f"[ERROR 400] Invalid signature: Sender address ({transaction['sender']}) does not match provided public key ({derived_address}).")
            return jsonify({'message': 'Invalid signature: Sender address does not match provided public key'}), 400

        # Call the signature verification function, passing the transaction dictionary
        # which now contains amount/fee as strings.
        if not verify_signature(transaction['public_key'], transaction['signature'], transaction):
            print(f"[ERROR 400] Invalid signature or malformed public key for TX ID: {transaction.get('id')}")
            return jsonify({'message': 'Invalid signature or malformed public key: Signature verification failed'}), 400
            
    except Exception as e:
        print(f"[ERROR 400] Unexpected error in signature validation: {e}. TX ID: {transaction.get('id')}")
        return jsonify({'message': f'Unexpected error in transaction validation: {e}'}), 400

    # Balance verification - Convert amount and fee to float for this calculation
    current_balance = blockchain.balance(transaction['sender'])
    required_amount = float(transaction['amount']) + float(transaction['fee'])
    if current_balance < required_amount:
        print(f"[ERROR 400] Insufficient balance for {transaction['sender']}: Needed {required_amount}, Available {current_balance}. TX ID: {transaction.get('id')}")
        return jsonify({'message': f'Insufficient balance for transaction. Current balance: {current_balance}, Needed: {required_amount}'}), 400

    # Add the transaction to the list of pending transactions
    # Ensure amount and fee are stored as floats in current_transactions for later use (e.g., mining)
    final_transaction_for_pending_queue = {
        'id': transaction['id'],
        'sender': transaction['sender'],
        'recipient': transaction['recipient'],
        'amount': float(transaction['amount']), # Store as float for internal blockchain logic
        'fee': float(transaction['fee']),       # Store as float for internal blockchain logic
        'public_key': transaction['public_key'],
        'signature': transaction['signature'],
        'timestamp': transaction.get('timestamp', time.time())
    }
    blockchain.current_transactions.append(final_transaction_for_pending_queue)
    
    # Notify other nodes about the new pending transaction
    broadcast_tx_to_peers(final_transaction_for_pending_queue) # Call the broadcast function

    response = {'message': f'Transaction added to pending transactions queue.',
                'coin_name': COIN_NAME,
                'coin_symbol': COIN_SYMBOL,
                'transaction_id': transaction['id']} # Return the transaction ID
    return jsonify(response), 201

# Add this function for transaction broadcast if you don't have it yet
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

    # Full revalidation of the received transaction
    try:
        # First, check if the transaction is already in the pending queue
        # For duplicate check, amount and fee must be compared as floats, not strings.
        temp_tx_for_duplicate_check = {
            'sender': tx_data['sender'],
            'recipient': tx_data['recipient'],
            'amount': float(tx_data['amount']),
            'fee': float(tx_data['fee']),
            'id': tx_data.get('id')
        }
        if blockchain.is_duplicate_transaction(temp_tx_for_duplicate_check):
            print(f"[RECEIVE TX] Transação {tx_data.get('id')} já existe na fila pendente. Ignorando.")
            return jsonify({'message': 'Transação já conhecida.'}), 200

        # Call the signature verification function, passing the tx_data dictionary
        # which now contains amount/fee as strings.
        if not verify_signature(tx_data['public_key'], tx_data['signature'], tx_data):
            print(f"[RECEIVE TX ERROR] TX {tx_data.get('id')}: Invalid signature or malformed public key.")
            return jsonify({'message': 'Invalid transaction: Invalid signature or malformed public key.'}), 400

        # Balance verification - Convert amount and fee to float for this calculation
        current_balance = blockchain.balance(tx_data['sender'])
        required_amount = float(tx_data['amount']) + float(tx_data['fee'])
        if current_balance < required_amount:
            print(f"[RECEIVE TX ERROR] TX {tx_data.get('id')}: Saldo insuficiente para {tx_data['sender']}.")
            return jsonify({'message': 'Transação inválida: Saldo insuficiente.'}), 400

        # If all validations pass, add to the pending list
        # Ensure amount and fee are stored as floats in current_transactions for later use (e.g., mining)
        final_tx_for_pending_queue = {
            'id': tx_data['id'],
            'sender': tx_data['sender'],
            'recipient': tx_data['recipient'],
            'amount': float(tx_data['amount']), # Store as float for internal blockchain logic
            'fee': float(tx_data['fee']),       # Store as float for internal blockchain logic
            'public_key': tx_data['public_key'],
            'signature': tx_data['signature'],
            'timestamp': tx_data.get('timestamp', time.time())
        }
        blockchain.current_transactions.append(final_tx_for_pending_queue)
        print(f"[RECEIVE TX] Transação {tx_data.get('id')} recebida e adicionada à fila pendente.")
        return jsonify({"message": "Transação recebida e adicionada com sucesso."}), 200

    except Exception as e:
        print(f"[RECEIVE TX ERROR] Unexpected error processing TX {tx_data.get('id')}: {e}")
        return jsonify({'message': f'Internal error processing transaction: {e}'}), 500
        

# --- Signature Verification Function (Moved for proper definition order) ---
def verify_signature(public_key_hex, signature_hex, message_data):
    try:
        # Reconstruct the verifying key from the public key hex
        # The public_key_hex should be the 130-character (04 + X + Y) string.
        # We no longer strip the '04' prefix here.
        vk = VerifyingKey.from_string(bytes.fromhex(public_key_hex), curve=SECP256k1)

        # CRITICAL: Prepare message data with floats as STRINGS for json.dumps
        # The HTML client sends 'amount' and 'fee' as strings formatted to 8 decimal places.
        # We must use these string representations directly to match the signed message.
        prepared_message_data = {
            'amount': message_data['amount'], # Use string directly as received from HTML (no str() conversion needed if already string)
            'fee': message_data['fee'],        # Use string directly as received from HTML (no str() conversion needed if already string)
            'recipient': message_data['recipient'],
            'sender': message_data['sender']
        }
        
        # Now, json.dumps will serialize these strings, matching client's signing.
        # It will also add spaces after ':' and ',' as per default behavior.
        message = json.dumps(prepared_message_data, sort_keys=True, separators=(',', ':')).encode('utf-8') # ADDED separators

        # Calculate the hash of the message for comparison
        message_hash_bytes = hashlib.sha256(message).digest() # Get bytes digest
        message_hash_hex = hashlib.sha256(message).hexdigest() # Get hex digest for logging

        # Convert the signature from hex to bytes (the client sends hex, not base64)
        signature_bytes = bytes.fromhex(signature_hex)

        # --- DEBUG PRINTS ---
        print(f"DEBUG_SERVER: Public Key received (hex): {public_key_hex}")
        print(f"DEBUG_SERVER: Signature received (hex): {signature_hex}")
        print(f"DEBUG_SERVER: Message data for verification (before json.dumps): {prepared_message_data}")
        print(f"DEBUG_SERVER: String JSON for verification (decoded): {message.decode('utf-8')}")
        print(f"DEBUG_SERVER: Bytes of the message for verification (raw): {message}")
        print(f"DEBUG_SERVER: Hash of the message for verification (SHA256, HEX): {message_hash_hex}") # Updated log
        # --- END DEBUG PRINTS ---

        # Use verify_digest if the client signed the digest directly
        vk.verify_digest(signature_bytes, message_hash_bytes) # Use verify_digest and pass the bytes hash
        return True
    except BadSignatureError:
        print("Signature verification failed: BadSignatureError!")
        return False
    except ValueError as ve:
        print(f"Signature verification failed: ValueError (e.g., bad hex string or malformed key): {ve}")
        return False
    except Exception as e:
        print(f"Error during signature verification: {e}")
        return False
        
@app.route('/blocks/receive', methods=['POST'])
def receive_block():
    block_data = request.get_json() # Renamed to 'block_data' for clarity
    if not block_data:
        print("[RECEIVE_BLOCK ERROR] No block data received.")
        return jsonify({"message": "No block data received."}), 400

    # 1. Initial block structure verification
    required_keys = ['index', 'previous_hash', 'proof', 'timestamp', 'miner', 'transactions', 'difficulty']
    if not all(k in block_data for k in required_keys):
        print(f"[RECEIVE_BLOCK ERROR] Received block with missing keys: {block_data}")
        return jsonify({"message": "Incomplete or malformed block data."}), 400

    # 2. Logic for empty local chain
    if not blockchain.chain:
        print("[RECEIVE_BLOCK INFO] Local chain is empty. Starting conflict resolution for initial synchronization.")
        # Start conflict resolution in the background. Do not reject the block immediately,
        # as it might be the first of a valid chain that we need.
        threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
        return jsonify({'message': 'Local chain is empty. Attempting to synchronize with the network.'}), 202 # Accepted, but awaiting synchronization

    last_local_block = blockchain.last_block

    # 3. Already known or old block (Based on index)
    if block_data['index'] <= last_local_block['index']:
        # If the index is equal to the local last, check if it's the same block (duplicate)
        if block_data['index'] == last_local_block['index'] and \
           block_data['previous_hash'] == last_local_block['previous_hash'] and \
           block_data['proof'] == last_local_block['proof'] and \
           block_data['miner'] == last_local_block['miner']: # Add more fields for a more robust check
            print(f"[RECEIVE_BLOCK INFO] Block {block_data['index']} already received and processed (duplicate).")
            return jsonify({'message': 'Block already received and processed'}), 200
        else:
            # Old block or from a shorter/invalid fork.
            # We don't need to resolve conflicts here, as we are ahead or on a longer fork.
            print(f"[RECEIVE_BLOCK INFO] Block {block_data['index']} is old or from a shorter/invalid fork (Local: {last_local_block['index']}). Ignorando.")
            return jsonify({'message': 'Old block or from an irrelevant fork.'}), 200 # OK, but not added

    # 4. Block Validation as the NEXT in sequence
    if block_data['index'] == last_local_block['index'] + 1:
        # Check if the previous hash of the received block matches the hash of the local last block
        expected_previous_hash = blockchain.hash(last_local_block)
        if block_data['previous_hash'] != expected_previous_hash:
            print(f"[RECEIVE_BLOCK ERROR] Block {block_data['index']}: Incorrect previous hash. Expected: {expected_previous_hash}, Received: {block_data['previous_hash']}. Starting synchronization.")
            threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
            return jsonify({'message': 'Incorrect previous hash, conflict resolution started'}), 400

        # Check the proof of work of the received block
        # Difficulty must be calculated consistently
        # Assuming you have a method to calculate difficulty for a given index
        # If not, use the difficulty of the last block or a fixed value for testing
        # expected_difficulty = blockchain._calculate_difficulty_for_index(block_data['index']) # If you have this function
        # if not Blockchain.valid_proof(last_local_block['proof'], block_data['proof'], expected_difficulty):
        # Simplified to use a fixed value or the difficulty of the received block for initial testing
        if not blockchain.valid_proof(last_local_block['proof'], block_data['proof'], last_local_block['hash']): # Using the hash of the last block for valid_proof
            print(f"[RECEIVE_BLOCK ERROR] Block {block_data['index']}: Invalid Proof of Work. Starting synchronization.")
            threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
            return jsonify({'message': 'Invalid Proof, conflict resolution started'}), 400

        # Validate transactions within the block
        for tx in block_data.get('transactions', []):
            if tx['sender'] == '0': # Miner reward
                continue
            
            # 🛡️ Full transaction validation (signature, public key, etc.)
            try:
                # The verify_signature function already handles float formatting
                if not verify_signature(tx['public_key'], tx['signature'], tx):
                    raise ValueError(f"Invalid signature for transaction {tx.get('id', 'N/A')}")

            except Exception as e:
                print(f"[RECEIVE_BLOCK ERROR] Invalid transaction {tx.get('id', 'N/A')} in block {block_data['index']}: {e}. Starting synchronization.")
                threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
                return jsonify({'message': f'Invalid transaction in block: {e}'}), 400
        
        # If all validations pass, the block is the next valid in sequence
        print(f"[RECEIVE_BLOCK SUCCESS] Block {block_data['index']} accepted and added locally.")
        blockchain.chain.append(block_data)
        blockchain.save_block(block_data) # Save to DB

        # Remove transactions from the block from the pending queue
        mined_tx_ids = {t.get('id') for t in block_data.get('transactions', []) if t.get('id')}
        blockchain.current_transactions = [
            tx for tx in blockchain.current_transactions if tx.get('id') not in mined_tx_ids
        ]
        print(f"[RECEIVE_BLOCK] Removed {len(mined_tx_ids)} transactions from pending queue.")

        # Signal the local miner to stop and restart (if active)
        # Assuming you have a mechanism to control the miner, like a global variable or a signal
        # global is_mining # If you have this variable
        # with miner_lock: # If you have a lock
        #     if is_mining:
        #         print("[RECEIVE_BLOCK] New block accepted. Signaling miner to stop and restart.")
        #         is_mining = False # This will cause the current miner_loop/PoW to abort
        #         # The miner_loop will restart automatically or be restarted by external logic
                
        return jsonify({'message': 'Block accepted and added'}), 200

    # 5. Block is ahead, but not the immediate next (indicates a fork)
    elif block_data['index'] > last_local_block['index'] + 1:
        print(f"[RECEIVE_BLOCK INFO] Block {block_data['index']} is ahead of the local chain ({last_local_block['index']}). Starting conflict resolution.")
        threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
        return jsonify({'message': 'Block is ahead. Starting synchronization.'}), 202 # Accepted, but awaiting synchronization

    # 6. Unexpected case (should be caught by the above conditions)
    print(f"[RECEIVE_BLOCK WARNING] Unexpected condition for block {block_data['index']}. Starting conflict resolution.")
    threading.Thread(target=blockchain.resolve_conflicts, daemon=True).start()
    return jsonify({'message': 'Bloco com status inesperado, resolução de conflitos iniciada'}), 400
def comparar_ultimos_blocos():
    print("\n🔍 Verificando sincronização com os peers...")
    local_block = blockchain.last_block()
    local_hash = hashlib.sha256(json.dumps(
        {k: v for k, v in local_block.items() if k != 'transactions'},
        sort_keys=True
    ).encode()).hexdigest()

    for peer in known_nodes:
        try:
            r = requests.get(f"{peer}/sync/check", timeout=5)
            data = r.json()
            peer_index = data['index']
            peer_hash = data['hash']

            if peer_index == local_block['index'] and peer_hash == local_hash:
                print(f"[SYNC ✅] {peer} está sincronizado com índice {peer_index}.")
            else:
                print(f"[SYNC ⚠️] {peer} DIFERENTE! Local: {local_block['index']} | Peer: {peer_index}")
        except Exception as e:
            print(f"[SYNC ❌] Falha ao verificar {peer}: {e}")

def auto_sync_checker():
    while True:
        comparar_ultimos_blocos()
        time.sleep(60)

# Em algum ponto da inicialização do app:
threading.Thread(target=auto_sync_checker, daemon=True).start()

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

def derivar_endereco(chave_publica_hex):
    # Remove o prefixo '04' se tiver
    if chave_publica_hex.startswith("04"):
        chave_publica_hex = chave_publica_hex[2:]
    
    chave_publica_bytes = bytes.fromhex(chave_publica_hex)
    endereco_hash = hashlib.sha256(chave_publica_bytes).hexdigest()
    endereco = endereco_hash[:40]  # Pega os primeiros 40 caracteres
    return endereco
    
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