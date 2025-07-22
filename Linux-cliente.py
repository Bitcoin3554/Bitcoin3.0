import threading
import time
import requests
import json
import hashlib
from ecdsa import SigningKey, VerifyingKey, SECP256k1
from pyzbar.pyzbar import decode
from PIL import Image
from colorama import init, Fore, Style
import os # Importa o módulo os para verificar arquivos
from collections import OrderedDict # Para garantir ordem consistente na assinatura

# Inicializa colorama para cores no terminal
init(autoreset=True)

# --- Configurações Globais ---
# URL base do seu nó minerador (onde o Flask app está rodando)
# Se o minerador estiver em outra máquina, mude o IP aqui.
BASE = "http://127.0.0.1:5000" # Mantenha seu IP local se for o caso
# Nome do arquivo onde a carteira será salva/carregada
WALLET_FILE = "client_wallet.json"
# Nome e símbolo da sua moeda (personalize conforme necessário)
COIN_NAME = "KertCoin"
COIN_SYMBOL = "KRT"

# Variáveis de estado para controle da mineração contínua
miner_address = None
mining_active = False
miner_thread = None

# --- Funções Auxiliares de Impressão ---
def print_info(text):
    """Imprime mensagens informativas em azul ciano."""
    print(Fore.CYAN + text + Style.RESET_ALL)

def print_success(text):
    """Imprime mensagens de sucesso em verde."""
    print(Fore.GREEN + text + Style.RESET_ALL)

def print_error(text):
    """Imprime mensagens de erro em vermelho."""
    print(Fore.RED + text + Style.RESET_ALL)

def print_warning(text):
    """Imprime mensagens de aviso em amarelo."""
    print(Fore.YELLOW + text + Style.RESET_ALL)

# --- Funções de Criptografia e Endereço ---
def gerar_endereco(public_key_hex):
    """
    Gera um endereço de carteira a partir de uma chave pública hexadecimal.
    O endereço é um hash SHA256 da chave pública, truncado para os primeiros 40 caracteres.
    """
    # CORREÇÃO CRÍTICA: Converte a string hexadecimal da public key de volta para bytes
    # antes de fazer o hash SHA256. Esta é a mesma lógica usada no nó para validação.
    try:
        public_key_bytes = bytes.fromhex(public_key_hex)
        return hashlib.sha256(public_key_bytes).hexdigest()[:40]
    except ValueError:
        print_error("Erro: Chave pública hexadecimal inválida para gerar endereço.")
        return None

def sign_transaction(private_key_hex, tx_data):
    """
    Assina digitalmente os dados de uma transação usando a chave privada fornecida.
    A assinatura garante a autenticidade e a integridade da transação.
    """
    try:
        # CORREÇÃO: Usar bytes.fromhex() para converter a chave privada hexadecimal para bytes
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    except ValueError:
        print_error("Erro: Chave privada hexadecimal inválida para assinatura.")
        return None
    
    # IMPORTANTE: A ordem dos campos DEVE ser consistente com o nó para a assinatura ser válida.
    # Usar OrderedDict ou json.dumps(..., sort_keys=True) garante isso.
    # A 'public_key' e 'signature' NÃO fazem parte dos dados que são assinados.
    message_data = OrderedDict([
        ('sender', tx_data['sender']),
        ('recipient', tx_data['recipient']),
        ('amount', float(tx_data['amount'])), # CORREÇÃO: Garante que são floats
        ('fee', float(tx_data['fee']))        # CORREÇÃO: Garante que são floats
    ])
    
    # Serializa a mensagem para bytes. `sort_keys=True` é CRÍTICO para consistência.
    message = json.dumps(message_data, sort_keys=True).encode('utf-8')
    
    signature = sk.sign(message).hex() # A assinatura é gerada em bytes e convertida para hex
    return signature

# --- Funções de QR Code (requer Pillow e pyzbar) ---
def read_qr_code(file_path):
    """
    Lê dados JSON de um QR Code em um arquivo de imagem.
    Útil para importar dados como endereços de carteira.
    """
    try:
        if not os.path.exists(file_path):
            print_error(f"Arquivo QR code não encontrado: {file_path}")
            return None
        img = Image.open(file_path)
        decoded = decode(img)
        if not decoded:
            raise ValueError('Nenhum QR code válido encontrado na imagem.')
        data = decoded[0].data.decode('utf-8')
        return json.loads(data)
    except Exception as e:
        print_error(f"Erro ao ler QR code: {e}")
        return None

# --- Funções de Gerenciamento de Carteira ---
def nova_carteira():
    """
    Cria uma nova carteira (par de chaves pública/privada e endereço)
    e a salva no arquivo WALLET_FILE.
    """
    try:
        # CORREÇÃO CRÍTICA: O cliente AGORA GERA AS CHAVES LOCALMENTE.
        # A chamada ao nó para /wallet/new foi removida do nó.
        private_key_obj = SigningKey.generate(curve=SECP256k1)
        public_key_obj = private_key_obj.get_verifying_key()

        # Obter a representação hexadecimal das chaves.
        private_key_hex = private_key_obj.to_string().hex()
        public_key_hex = public_key_obj.to_string().hex() 

        # Derivar o endereço usando a função `gerar_endereco`, que usa a mesma lógica do nó.
        address = gerar_endereco(public_key_hex)
        if address is None: # Se a geração do endereço falhar
            return None

        wallet_data = {
            'private_key': private_key_hex,
            'public_key': public_key_hex,
            'address': address
        }

        print_success("=== Nova Carteira Criada ===")
        print_success(f"Chave privada: {wallet_data['private_key']}")
        print_success(f"Chave pública: {wallet_data['public_key']}")
        print_success(f"Endereço: {wallet_data['address']}")

        # Salva a carteira em um arquivo JSON
        with open(WALLET_FILE, "w") as f:
            json.dump(wallet_data, f, indent=4)
        print_info(f"Carteira salva em {WALLET_FILE}")
        return wallet_data
    except Exception as e:
        print_error(f"Erro inesperado ao criar carteira: {e}")
        return None

def carregar_carteira():
    """
    Carrega uma carteira existente do arquivo WALLET_FILE.
    Se o arquivo não existir, retorna None.
    """
    try:
        if not os.path.exists(WALLET_FILE):
            print_warning("Arquivo de carteira não encontrado. Gere uma nova carteira (opção 1).")
            return None
        with open(WALLET_FILE, "r") as f:
            wallet_data = json.load(f)
        
        # CORREÇÃO: Garante que o endereço esteja presente e seja válido, mesmo se o arquivo antigo não o tiver
        if 'public_key' in wallet_data:
            derived_addr_check = gerar_endereco(wallet_data['public_key'])
            if derived_addr_check and derived_addr_check != wallet_data.get('address'):
                print_warning("Atenção: Endereço na carteira salva não corresponde à chave pública atual. Atualizando...")
                wallet_data['address'] = derived_addr_check
                # Salva de volta com o endereço corrigido
                with open(WALLET_FILE, "w") as f:
                    json.dump(wallet_data, f, indent=4)
            elif 'address' not in wallet_data: # Caso raro onde public_key existe mas address não
                wallet_data['address'] = derived_addr_check
                with open(WALLET_FILE, "w") as f:
                    json.dump(wallet_data, f, indent=4)
        else:
            print_error("Carteira carregada não possui chave pública. Arquivo pode estar corrompido.")
            return None

        return wallet_data
    except FileNotFoundError:
        print_warning("Carteira não encontrada. Gere uma nova carteira (opção 1).")
        return None
    except json.JSONDecodeError:
        print_error("Arquivo de carteira corrompido ou mal formatado. Por favor, verifique.")
        return None
    except Exception as e:
        print_error(f"Erro inesperado ao carregar carteira: {e}")
        return None

def mostrar_carteira():
    """Exibe as informações da carteira atualmente carregada."""
    wallet = carregar_carteira()
    if wallet:
        print_info("\n=== Carteira Atual ===")
        print_info(f"Endereço: {wallet['address']}")
        print_info(f"Chave pública: {wallet['public_key']}")
        # print_info(f"Chave privada: {wallet['private_key']}") # Evitar exibir chave privada abertamente
    else:
        print_warning("Nenhuma carteira carregada.")

# --- Funções de Interação com a Blockchain ---
def saldo(addr):
    """
    Consulta o saldo de um endereço específico no nó da blockchain.
    """
    try:
        r = requests.get(f"{BASE}/balance/{addr}")
        r.raise_for_status()
        balance = r.json().get('balance', 0)
        print_success(f"Saldo do endereço {addr}: {balance} {COIN_SYMBOL}")
    except requests.exceptions.RequestException as e:
        print_error(f"Erro ao buscar saldo: {e}")
    except Exception as e:
        print_error(f"Erro inesperado ao consultar saldo: {e}")

def enviar(sender_address, recipient_address, amount):
    """
    Cria, assina e envia uma nova transação para a rede.
    """
    wallet = carregar_carteira()
    if wallet is None:
        print_error("Nenhuma carteira carregada. Crie uma nova (opção 1) ou carregue uma existente.")
        return
    if wallet['address'] != sender_address:
        print_error("O endereço do remetente não corresponde à carteira carregada.")
        return

    try:
        amount = float(amount)
        if amount <= 0:
            print_error("O valor de envio deve ser um número positivo.")
            return

        # CORREÇÃO: Pedir a taxa ao usuário
        fee_str = input(Fore.YELLOW + "Digite a taxa (fee) da transação: " + Style.RESET_ALL).strip()
        fee = float(fee_str)
        if fee < 0:
            print_error("A taxa não pode ser negativa.")
            return

        tx_data = {
            'sender': sender_address,
            'recipient': recipient_address,
            'amount': amount,
            'fee': fee
        }

        # Assina a transação
        signature = sign_transaction(wallet['private_key'], tx_data)
        if signature is None: # Se a assinatura falhar
            print_error("Falha ao assinar a transação.")
            return

        # Adiciona a assinatura e a chave pública aos dados da transação para envio
        tx_full_data = {
            'sender': sender_address,
            'recipient': recipient_address,
            'amount': amount,
            'fee': fee,
            'signature': signature,
            'public_key': wallet['public_key'] # Chave pública para o nó verificar
        }

        # Envia a transação para o nó
        r = requests.post(f"{BASE}/tx/new", json=tx_full_data)
        r.raise_for_status() # Levanta erro para status 4xx/5xx

        if r.status_code in [200, 201]:
            print_success(f"Transação enviada com sucesso! Resposta do nó: {r.json().get('message')}")
        else:
            print_error(f"Erro ao enviar transação: Status {r.status_code} - {r.text}")

    except ValueError:
        print_error("Valor de envio ou taxa inválido. Por favor, insira um número.")
    except requests.exceptions.RequestException as e:
        print_error(f"Erro de conexão ou resposta do nó ao enviar transação: {e}")
    except Exception as e:
        print_error(f"Erro inesperado ao enviar transação: {e}")

def minerar(miner_addr=None):
    """
    Inicia uma única operação de mineração.
    A recompensa do bloco é enviada para o miner_addr especificado.
    """
    try:
        # CORREÇÃO: Define o endereço do minerador no nó via POST antes de minerar
        if miner_addr:
            current_miner_addr = miner_addr
        else:
            wallet = carregar_carteira()
            if wallet and 'address' in wallet:
                current_miner_addr = wallet['address']
            else:
                print_warning("Nenhum endereço de minerador fornecido e nenhuma carteira carregada. Não é possível minerar.")
                return

        print_info(f"Definindo endereço do minerador no nó para: {current_miner_addr}")
        set_addr_response = requests.post(f"{BASE}/miner/set_address", json={'address': current_miner_addr})
        set_addr_response.raise_for_status()
        print_success(f"Endereço do minerador definido no nó: {set_addr_response.json().get('message')}")

        # CORREÇÃO: A requisição /mine agora é um GET simples, sem parâmetros
        print_info(f"Iniciando mineração de um bloco com {COIN_NAME} ({COIN_SYMBOL})...")
        r = requests.get(f"{BASE}/mine", timeout=120) # Aumenta o timeout para mineração
        r.raise_for_status()
        print_success(f"Bloco minerado com sucesso! Detalhes: {r.json()}")
    except requests.exceptions.Timeout:
        print_error("A requisição de mineração excedeu o tempo limite. O bloco pode ter sido minerado, mas a resposta não foi recebida.")
    except requests.exceptions.RequestException as e:
        self.log_signal.emit("Dificuldade alta detectada, minerando próximo bloco. Por favor, aguarde...", "warning")
    except Exception as e:
        print_error(f"Erro inesperado durante a mineração: {e}")

def ver_chain():
    """
    Busca e exibe a cópia atual da blockchain do nó.
    """
    try:
        r = requests.get(f"{BASE}/chain")
        r.raise_for_status()
        data = r.json()
        print_info(f"\n=== Blockchain Atual (Comprimento: {len(data['chain'])}) ===")
        for block in data['chain']:
            print(json.dumps(block, indent=2))
        print_info(f"Transações Pendentes no Nó: {data.get('pending_transactions', 'N/A')}")
    except requests.exceptions.RequestException as e:
        print_error(f"Erro ao obter a cadeia: {e}")
    except Exception as e:
        print_error(f"Erro inesperado ao exibir a cadeia: {e}")

        
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

def registrar_peer(node_url):
    """
    Registra um novo nó (peer) com o seu nó minerador.
    Isso ajuda a rede a descobrir outros participantes.
    """
    try:
        # CORREÇÃO: O nó espera 'ip' e 'port', não uma lista de 'nodes'
        parsed_url = urlparse(node_url)
        peer_ip = parsed_url.hostname
        peer_port = parsed_url.port

        if not peer_ip or not peer_port:
            print_error(f"URL do peer inválida: {node_url}. Formato esperado: http://IP:PORTA")
            return

        r = requests.post(f"{BASE}/nodes/register", json={'ip': peer_ip, 'port': peer_port})
        r.raise_for_status()
        print_success(f"Peer '{node_url}' registrado com sucesso! Resposta: {r.json()}")
    except requests.exceptions.RequestException as e:
        print_error(f"Erro ao registrar peer '{node_url}': {e}")
    except Exception as e:
        print_error(f"Erro inesperado ao registrar peer: {e}")

def sincronizar_blockchain():
    """
    Inicia o mecanismo de consenso do nó para resolver conflitos de cadeia
    e garantir que a cadeia local seja a mais longa e válida.
    """
    print_info("Iniciando sincronização da blockchain com peers...")
    try:
        # CORREÇÃO: O nó minerador tem uma rota GET para resolver conflitos
        r = requests.get(f"{BASE}/nodes/resolve") # CORREÇÃO: Mudei para GET
        r.raise_for_status()
        response = r.json()
        if response.get('replaced'): # Verifica o campo 'replaced'
            print_success(f"Blockchain sincronizada com sucesso! A cadeia foi atualizada para a mais longa: {response.get('chain_length')} blocos.")
        else:
            print_info(f"Blockchain já está sincronizada. Sua cadeia é a mais longa ou não houve alteração. Comprimento: {response.get('chain_length')} blocos.")
        ver_chain() # Opcional: mostrar a cadeia após a sincronização
    except requests.exceptions.RequestException as e:
        print_error(f"Erro ao sincronizar blockchain: {e}. Verifique se o nó tem uma rota /nodes/resolve.")
    except Exception as e:
        print_error(f"Erro inesperado durante a sincronização: {e}")

# --- Funções de Mineração Contínua ---
def minerar_continuo_thread():
    global mining_active
    # CORREÇÃO: Mensagem correta sobre como parar
    print_success(f"Mineração contínua iniciada para {COIN_NAME} ({COIN_SYMBOL}). Pressione '9' para parar.") 
    while mining_active:
        try:
            # CORREÇÃO: A requisição /mine agora é um GET simples, sem parâmetros
            r = requests.get(f"{BASE}/mine", timeout=60) 
            r.raise_for_status()
            print_success(f"Bloco minerado (contínuo)! Detalhes: {r.json()}") 
        except requests.exceptions.Timeout:
            print_warning("Requisição de mineração contínua excedeu o tempo limite. Tentando novamente...")
        except requests.exceptions.RequestException as e:
            print_error(f"Erro na mineração contínua: {e}") 
        time.sleep(10) # Espera 10 segundos antes de tentar minerar NOVAMENTE.
        
def iniciar_mineracao_continua(addr):
    global miner_address, mining_active, miner_thread
    if mining_active: 
        print_warning("Mineração contínua já está rodando!")
        return
    
    # CORREÇÃO: Define o endereço do minerador no nó via POST antes de iniciar a thread
    if addr:
        current_miner_addr = addr
    else:
        wallet = carregar_carteira()
        if wallet and 'address' in wallet:
            current_miner_addr = wallet['address']
        else:
            print_error("Nenhum endereço de minerador fornecido e nenhuma carteira carregada para mineração contínua.")
            return

    try:
        print_info(f"Definindo endereço do minerador no nó para: {current_miner_addr}")
        set_addr_response = requests.post(f"{BASE}/miner/set_address", json={'address': current_miner_addr})
        set_addr_response.raise_for_status()
        print_success(f"Endereço do minerador definido no nó: {set_addr_response.json().get('message')}")
    except requests.exceptions.RequestException as e:
        print_error(f"Erro ao definir endereço do minerador para mineração contínua: {e}")
        return

    miner_address = current_miner_addr # Atualiza a variável global
    mining_active = True
    miner_thread = threading.Thread(target=minerar_continuo_thread, daemon=True)
    miner_thread.start()
    print_success("Mineração contínua iniciada em segundo plano.")

def parar_mineracao_continua():
    """
    Para a thread de mineração contínua.
    """
    global mining_active
    if mining_active:
        mining_active = False
        print_info("Sinal para parar a mineração contínua enviado. Pode levar alguns segundos para a thread encerrar.")
    else:
        print_warning("A mineração contínua não está rodando.")

# --- Menu Interativo Principal ---
def menu():
    """
    Exibe o menu principal e gerencia as interações do usuário.
    """
    print_info(f"\nBem-vindo ao Cliente Kert-One Blockchain ({COIN_NAME} - {COIN_SYMBOL})!")
    while True:
        print(Fore.BLUE + "\n--- Menu Principal ---" + Style.RESET_ALL)
        print(Fore.BLUE + "1. Gerenciar Carteira")
        print(Fore.BLUE + "2. Ver Saldo de Endereço")
        print(Fore.BLUE + "3. Enviar Moedas")
        print(Fore.BLUE + "4. Minerar Bloco Único")
        print(Fore.BLUE + "5. Ver Blockchain Completa")
        print(Fore.BLUE + "6. Registrar Novo Peer (Nó)")
        print(Fore.BLUE + "7. Sincronizar Blockchain (Consenso)")
        print(Fore.BLUE + "8. Iniciar Mineração Contínua")
        print(Fore.BLUE + "9. Parar Mineração Contínua")
        print(Fore.BLUE + "0. Sair")
        op = input(Fore.YELLOW + "Escolha uma opção: " + Style.RESET_ALL).strip()

        if op == "1":
            menu_carteira()
        elif op == "2":
            addr = input(Fore.YELLOW + "Digite o endereço para consultar o saldo: " + Style.RESET_ALL).strip()
            if addr:
                saldo(addr)
            else:
                print_error("Endereço não pode ser vazio.")
        elif op == "3":
            wallet = carregar_carteira()
            if wallet is None:
                continue
            sender_addr = wallet['address']
            print_info(f"Seu endereço remetente: {sender_addr}")
            recipient_addr = input(Fore.YELLOW + "Digite o endereço do destinatário: " + Style.RESET_ALL).strip()
            amount_str = input(Fore.YELLOW + "Digite o valor a enviar: " + Style.RESET_ALL).strip()
            if not recipient_addr:
                print_error("Endereço do destinatário não pode ser vazio.")
                continue
            enviar(sender_addr, recipient_addr, amount_str) # A função enviar agora pede a taxa
        elif op == "4":
            miner_addr_input = input(Fore.YELLOW + "Endereço para recompensa da mineração (deixe vazio para usar a carteira carregada): " + Style.RESET_ALL).strip()
            minerar(miner_addr_input if miner_addr_input else None)
        elif op == "5":
            ver_chain()
        elif op == "6":
            node_url = input(Fore.YELLOW + "Digite a URL completa do novo peer (ex: http://192.168.0.5:5000): " + Style.RESET_ALL).strip()
            if node_url:
                registrar_peer(node_url)
            else:
                print_error("URL do peer não pode ser vazia.")
        elif op == "7":
            sincronizar_blockchain()
        elif op == "8":
            miner_addr_input = input(Fore.YELLOW + "Endereço para recompensa da mineração contínua (deixe vazio para usar a carteira carregada): " + Style.RESET_ALL).strip()
            iniciar_mineracao_continua(miner_addr_input if miner_addr_input else None)
        elif op == "9":
            parar_mineracao_continua()
        elif op == "0":
            if mining_active:
                parar_mineracao_continua()
            print_info("Saindo do cliente Kert-One. Até mais!")
            break
        else:
            print_warning("Opção inválida. Por favor, escolha uma opção do menu.")

def menu_carteira():
    """Sub-menu para operações de carteira."""
    while True:
        print(Fore.MAGENTA + "\n--- Gerenciar Carteira ---" + Style.RESET_ALL)
        print(Fore.MAGENTA + "1. Criar Nova Carteira")
        print(Fore.MAGENTA + "2. Mostrar Carteira Atual")
        print(Fore.MAGENTA + "3. Ler QR Code para endereço (Ainda não implementado completamente para uso prático)")
        print(Fore.MAGENTA + "0. Voltar ao Menu Principal")
        op = input(Fore.YELLOW + "Escolha uma opção de carteira: " + Style.RESET_ALL).strip()

        if op == "1":
            nova_carteira()
        elif op == "2":
            mostrar_carteira()
        elif op == "3":
            qr_file = input(Fore.YELLOW + "Digite o caminho do arquivo de imagem do QR Code: " + Style.RESET_ALL).strip()
            data = read_qr_code(qr_file)
            if data:
                print_info(f"Dados lidos do QR Code: {json.dumps(data, indent=2)}")
                # Aqui você pode adicionar lógica para usar esses dados, e.g., preencher endereço de destinatário
            else:
                print_warning("Não foi possível ler dados do QR Code ou o arquivo está inválido.")
        elif op == "0":
            break
        else:
            print_warning("Opção inválida. Por favor, escolha uma opção do menu de carteira.")


# --- Execução Principal ---
if __name__ == "__main__":
    menu()