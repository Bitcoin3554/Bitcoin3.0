import requests
import json
import concurrent.futures
from pathlib import Path
import ipaddress
import time
import hashlib
import threading
from urllib.parse import urlencode

PORTAS = [5000]
CAMINHO = "/p2p-btc3"
HEADERS = {"User-Agent": "p2p-btc3-AutoScanner/1.0"}
ARQUIVO_PEERS = "peers.json"
SECRET_KEY = "25s5ash5556s54d45593ksaa55s25a45545s5d4a5s55440-0"

parar_event = threading.Event()
encontrados_lock = threading.Lock()


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
        ip_formatado = f"[{ip}]"
    else:
        ip_formatado = ip
    return f"{protocolo}://{ip_formatado}:{porta}{CAMINHO}"

# --- Nova função para testar se o peer tem endpoint /mine válido ---
def peer_tem_endpoint_mine(ip):
    params = {"miner": "teste"}
    portas_testar = [5000]  # Pode ampliar se quiser testar outras portas

    for porta in portas_testar:
        protocolos = ["https"] if porta == 443 else ["http"]
        for protocolo in protocolos:
            url_mine = montar_url(ip, porta, protocolo).replace(CAMINHO, "/mine")
            try:
                print(f"🔍 BTC3 /mine em: {url_mine}")
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

def puxar_nodes_de_peer(url_base):
    endpoints = ["/nodes", "/register_node"]
    todos_peers = []

    for endpoint in endpoints:
        url = url_base.rstrip('/') + endpoint
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
        except Exception as e:
            print(f"Buscando nodes P2p")

    ips_formatados = []
    for ip in set(todos_peers):
        if ':' in ip and not ip.startswith('['):
            ip = f"[{ip}]"
        ips_formatados.append(ip)

    if ips_formatados:
        salvar_peers(ips_formatados)

    return ips_formatados
def sincronizar_peers_de_arquivo():
    """
    Lê todos os peers do arquivo peers.json e tenta puxar a lista de /nodes de cada um,
    adicionando novos IPs ao arquivo peers.json.
    """
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

# ---------------------------------------
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
                # Silenciar erros comuns
                continue
            except Exception as e:
                print(f"⚠️ Erro inesperado ao verificar IP {ip}: {e}")
    print(f"\r🔎 [{contador}/{total}] Escaneado: {ip}", end='', flush=True)
def carregar_peers():
    arquivo = Path(ARQUIVO_PEERS)
    if arquivo.exists():
        try:
            return json.loads(arquivo.read_text())
        except json.JSONDecodeError:
            print("⚠️ peers.json inválido. Criando novo.")
    return []
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

    return encontrados  # retorna lista dos peers válidos com /mine

def scanner_continuo(start_ip, end_ip, bloco_tamanho=10000, delay_seg=1):
    peers_atuais = set(carregar_peers())

    # 1. Primeiro tenta os IPs do peers.json
    if peers_atuais:
        print(f"♻️ Escaneando IPs do peers.json ({len(peers_atuais)})...")
        encontrados = iniciar_scanner(None, None, ips_alvo=list(peers_atuais))
        if encontrados:
            print(f"🚀 Nós válidos encontrados na lista de peers: {encontrados}")
            return encontrados

    # 2. Depois escaneia a faixa IP completa em blocos
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

# No método minerar_com_peer_continuo, ajuste para garantir que o cache não pule blocos indevidamente
def minerar_com_peer_continuo(peer, miner_address="btc3-local-miner", usar_gpu=False,
                             tentativas=5, delay_tentativa=5, limite_blocos=10, max_503_consecutivos=3):
    params = {"miner": miner_address, "gpu": str(usar_gpu).lower()}
    print(f"🚀 Iniciando mineração contínua no peer: {peer}")

    blocos_minerados = 0
    erros_503_consecutivos = 0

    global cache_ultimo_bloco

    while blocos_minerados < limite_blocos:
        sucesso = False
        for porta in PORTAS:
            protocolos = ["https"] if porta == 443 else ["http"]
            for protocolo in protocolos:
                url = montar_url(peer, porta, protocolo).replace(CAMINHO, "/mine")
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

                    if tentativa < tentativas - 1:
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
        arquivo.write_text("[]")  # cria um arquivo JSON vazio (lista vazia)
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

def escanear_varias_faixas(faixas):
    todos_peers = []
    for start_ip, end_ip in faixas:
        encontrados = scanner_continuo(start_ip, end_ip, bloco_tamanho=1000, delay_seg=5)
        todos_peers.extend(encontrados)
    return list(set(todos_peers))  # remove duplicados

from flask import Flask, request, jsonify

app = Flask(__name__)
nodes = {}
    
@app.route('/')
def index():
    return "Nó BTC3 ativo e pronto."

@app.route('/mine')
def mine():
    miner = request.args.get("miner", "desconhecido")
    # Aqui você pode implementar a lógica real de mineração, agora só um exemplo:
    return jsonify({
        "message": "Requisição de mineração recebida",
        "miner": miner,
        "status": "ok",
        "block": "exemplo_de_bloco_mine"
    })

@app.route("/nodes")
def listar_nodes():
    return jsonify(list(nodes.keys()))
    
def rodar_servidor_flask(porta=5000):
    # Inicia servidor Flask para liberar porta e ser peer ativo
    app.run(host='0.0.0.0', port=porta, threaded=True)

LIBERAR_PORTAS = True  # Defina False para não abrir o servidor

if __name__ == "__main__":
    garantir_arquivo_peers()

    if LIBERAR_PORTAS:
        servidor_thread = threading.Thread(target=rodar_servidor_flask, args=(5000,), daemon=True)
        servidor_thread.start()
        print("⚙️ Servidor Flask iniciado para liberar porta 5000 e atuar como peer ativo.")

    ip_cliente = obter_ip_publico()
    if ip_cliente:
        adicionar_peer_manual(ip_cliente)

    # ✅ Antes de tudo, sincroniza os peers conhecidos
    sincronizar_peers_de_arquivo()

    miner_address = "139BBaC9tXvnracPHhVQbKBBqVSpgHRmrw"

    faixas_de_ip = [
        ("45.228.240.0", "45.228.245.255"),
        ("186.202.0.0",   "186.202.255.255"),
        ("191.252.0.0",   "191.252.255.255"),
        ("200.195.0.0",   "200.195.255.255"),
        ("2804:14c:82::", "2804:14c:82:ffff:ffff:ffff:ffff:ffff"),
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
            time.sleep(10)
