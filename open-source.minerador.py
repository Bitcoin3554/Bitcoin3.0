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


def garantir_protocolo(url):
    if not url.startswith("http://") and not url.startswith("https://"):
        return "http://" + url
    return url

@app.route('/balance/<address>', methods=['GET'])
def get_balance_endpoint(address):
    peers = carregar_peers()  # Lista só com IPs ou domínios, sem porta
    portas = [80, 5000]
    saldos = []

    for peer in peers:
        for porta in portas:
            base_url = garantir_protocolo(peer)
            # Adiciona a porta (só se não tiver na URL)
            if ':' not in peer.split('//')[-1]:  # se não tem porta já
                url = f"{base_url}:{porta}/balance/{address}"
            else:
                url = f"{base_url}/balance/{address}"
            try:
                r = requests.get(url, timeout=2)
                if r.status_code == 200:
                    saldo = float(r.json().get('balance', 0))
                    saldos.append(saldo)
                    # Se já encontrou um saldo válido, pode pular para o próximo peer (opcional)
                    break
            except Exception as e:
                print(f"Erro ao consultar {url}: {e}")
                continue

    if not saldos:
        return jsonify({'error': 'Não foi possível obter o saldo dos peers'}), 500

    saldo_max = max(saldos)
    saldo_formatado = f"{saldo_max:.8f}"

    return jsonify({'address': address, 'balance': saldo_formatado}), 200



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
        
def propagar_para_peers(transacao):
    peers = carregar_peers()
    for peer in peers:
        try:
            if not peer.endswith("/"):
                peer += "/"
            url = peer + "transactions/new"
            requests.post(url, json=transacao, timeout=3)
        except requests.RequestException as e:
            print(f"Erro ao propagar para {peer}: {e}")

def tentar_peers(path, method='GET', json_data=None, timeout=5):
    peers = carregar_peers()
    portas = [80, 5000]

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

@app.route('/wallet/create', methods=['POST'])
def create_wallet():
    proxies = {"http": None, "https": None}
    peers = carregar_peers()
    portas = [80, 5000]
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
                if 'address' in data:
                    resultado = {'address': data['address']}
                    if 'private_key' in data:
                        resultado['private_key'] = data['private_key']
                    else:
                        print(f"⚠️ Peer {peer} não retornou chave privada.")
                    return jsonify(resultado), 201
            except requests.RequestException as e:
                print(f"Erro ao acessar {url}: {e}")
                continue

    return jsonify({'error': 'Falharam ao criar carteira. Todos os nós falharam.'}), 503

def carregar_peers_ativos():
    peers = carregar_peers()
    peers_ativos = []
    portas = [80, 5000]
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
    
@app.route("/transfer", methods=["POST"])
def transfer():
    proxies = {"http": None, "https": None}
    peers = carregar_peers()
    portas = [80, 5000]
    timeout_segundos = 10

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


def sanitize_chain(chain):
    # Valida e retorna a chain. Por enquanto, apenas retorna.
    return chain


# --- Endpoints corrigidos --- #

@app.route('/transactions/new', methods=['POST'])
def new_transaction():
    proxies = {"http": None, "https": None}
    peers = carregar_peers()
    portas = [80, 5000]
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


@app.route('/transfer', methods=['POST'])
def transfer_balance():
    proxies = {"http": None, "https": None}
    peers = carregar_peers()
    portas = [80, 5000]
    timeout_segundos = 10

    values = request.get_json()
    required = ['private_key', 'recipient', 'amount']

    if not values or not all(k in values for k in required):
        return jsonify({'error': 'Missing values'}), 400

    conn = create_mysql_connection()
    if not conn:
        return jsonify({'error': 'DB connection failed'}), 500

    sender_address = None
    wallets = load_wallets(conn)

    for address, wallet in wallets.items():
        if wallet['private_key'] == values['private_key']:
            sender_address = address
            break

    if sender_address is None:
        return jsonify({'error': 'Invalid private key'}), 400

    try:
        amount = float(values['amount'])
    except ValueError:
        return jsonify({'error': 'Invalid amount format'}), 400

    sender_balance = get_balance(conn, sender_address)
    if sender_balance < amount:
        return jsonify({'error': 'Insufficient balance'}), 400

    if values['recipient'] not in wallets:
        return jsonify({'error': 'Recipient wallet does not exist'}), 404

    # Registra a transação localmente
    tx_index = blockchain.new_transaction(sender_address, values['recipient'], amount)

    transacao = {
        'sender': sender_address,
        'recipient': values['recipient'],
        'amount': amount
    }

    # Propaga para os peers em thread separada
    threading.Thread(target=propagar_para_peers, args=(transacao,), daemon=True).start()

    # Atualiza os saldos no banco local
    if not update_balance(conn, sender_address, -amount):
        return jsonify({'error': 'Error updating sender balance'}), 500

    if not update_balance(conn, values['recipient'], amount):
        return jsonify({'error': 'Error updating recipient balance'}), 500

    try:
        conn.close()
    except Exception:
        pass

    # Inicia mineração em thread separada
    threading.Thread(target=mine_block, daemon=True).start()

    return jsonify({'message': 'Transfer registered successfully.', 'transaction_index': tx_index}), 200
    
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

    miner_address = "sua cartera minig"

    faixas_de_ip = [
        ("45.228.238.0", "45.228.252.255"),
        ("45.221.222.0", "45.221.222.255"),
        ("15.204.1.0", "15.204.8.255"),
        ("141.95.82.0 ", "141.95.82.255"),
        ("13.95.82.0 ", "13.95.82.255"),
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
