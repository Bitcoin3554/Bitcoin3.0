import threading
import time
import requests
import json
import hashlib
from ecdsa import SigningKey, VerifyingKey, SECP256k1, BadSignatureError
from pyzbar.pyzbar import decode
from PIL import Image
from colorama import init, Fore, Style
import os # Importa o módulo os para verificar arquivos
from collections import OrderedDict # Para garantir ordem consistente na assinatura
import uuid # Importar o módulo uuid para gerar IDs únicos
import webbrowser # Para abrir URLs no navegador

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
    try:
        # Se a chave pública vier com o prefixo '04' (130 caracteres), remove-o para o hash
        if public_key_hex.startswith('04') and len(public_key_hex) == 130:
            public_key_hex_for_hash = public_key_hex[2:]
        else:
            public_key_hex_for_hash = public_key_hex

        public_key_bytes = bytes.fromhex(public_key_hex_for_hash)
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
        sk = SigningKey.from_string(bytes.fromhex(private_key_hex), curve=SECP256k1)
    except ValueError:
        print_error("Erro: Chave privada hexadecimal inválida para assinatura.")
        return None
    
    # CRÍTICO: amount e fee devem ser STRINGS formatadas para corresponder à assinatura do servidor
    # O servidor espera a representação de string exata para a verificação.
    message_data = OrderedDict([
        ('amount', f"{tx_data['amount']:.8f}"), # Formata como string com 8 casas decimais
        ('fee', f"{tx_data['fee']:.8f}"),        # Formata como string com 8 casas decimais
        ('recipient', tx_data['recipient']),
        ('sender', tx_data['sender'])
    ])
    
    # Serializa a mensagem para bytes. `sort_keys=True` e `separators=(',', ':')` são CRÍTICOS
    # para garantir que a string JSON seja idêntica à gerada no lado do servidor/HTML.
    message = json.dumps(message_data, sort_keys=True, separators=(',', ':')).encode('utf-8')
    
    # CRÍTICO: Assinar o DIGEST (hash) da mensagem, não a mensagem diretamente.
    # Isso corresponde ao `vk.verify_digest` no servidor.
    message_hash_bytes = hashlib.sha256(message).digest()
    signature = sk.sign_digest(message_hash_bytes).hex() 
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
        private_key_obj = SigningKey.generate(curve=SECP256k1)
        public_key_obj = private_key_obj.get_verifying_key()

        private_key_hex = private_key_obj.to_string().hex()
        # CRÍTICO: Adiciona o prefixo '04' à chave pública para consistência com o servidor
        public_key_hex = '04' + public_key_obj.to_string().hex() 

        address = gerar_endereco(public_key_hex)
        if address is None: # Se a geração do endereço falhar
            return None

        wallet_data = {
            'private_key': private_key_hex,
            'public_key': public_key_hex, # Agora com prefixo '04'
            'address': address
        }

        print_success("=== Nova Carteira Criada ===")
        print_success(f"Chave privada: {wallet_data['private_key']}")
        print_success(f"Chave pública: {wallet_data['public_key']}")
        print_success(f"Endereço: {wallet_data['address']}")

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
        
        # Garante que a chave pública tenha o prefixo '04' se for uma chave não comprimida e não tiver
        if 'public_key' in wallet_data:
            current_public_key = wallet_data['public_key']
            # Check if it's an uncompressed key (128 chars) and missing '04' prefix
            if len(current_public_key) == 128 and not current_public_key.startswith('04'):
                print_warning("Atenção: Chave pública no arquivo da carteira está em formato antigo (sem prefixo '04'). Atualizando...")
                wallet_data['public_key'] = '04' + current_public_key
                # Save the updated wallet data back to the file
                with open(WALLET_FILE, "w") as fw:
                    json.dump(wallet_data, fw, indent=4)
            
            # Re-derive address to ensure it's consistent with current logic
            derived_addr_check = gerar_endereco(wallet_data['public_key'])
            if derived_addr_check and derived_addr_check != wallet_data.get('address'):
                print_warning("Atenção: Endereço na carteira salva não corresponde à chave pública atual. Atualizando...")
                wallet_data['address'] = derived_addr_check
                # Save back with the corrected address
                with open(WALLET_FILE, "w") as fw:
                    json.dump(wallet_data, fw, indent=4)
            elif 'address' not in wallet_data: 
                wallet_data['address'] = derived_addr_check
                with open(WALLET_FILE, "w") as fw:
                    json.dump(wallet_data, fw, indent=4)
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

        fee_str = input(Fore.YELLOW + "Digite a taxa (fee) da transação: " + Style.RESET_ALL).strip()
        fee = float(fee_str)
        if fee < 0:
            print_error("A taxa não pode ser negativa.")
            return

        tx_data_for_signing = {
            'sender': sender_address,
            'recipient': recipient_address,
            'amount': amount, # Passa como float para a função de assinatura que vai formatar
            'fee': fee        # Passa como float para a função de assinatura que vai formatar
        }

        signature = sign_transaction(wallet['private_key'], tx_data_for_signing)
        if signature is None: 
            print_error("Falha ao assinar a transação.")
            return

        # CRÍTICO: Adiciona o ID da transação (UUID)
        transaction_id = str(uuid.uuid4())

        # CRÍTICO: O payload completo para o nó. amount e fee devem ser STRINGS formatadas.
        tx_full_data = {
            'id': transaction_id, # ID da transação
            'sender': sender_address,
            'recipient': recipient_address,
            'amount': f"{amount:.8f}", # Envia como string formatada
            'fee': f"{fee:.8f}",       # Envia como string formatada
            'signature': signature,
            'public_key': wallet['public_key'], # Chave pública COM prefixo '04'
            'timestamp': time.time() # Adiciona timestamp
        }

        print_info(f"Enviando transação para o nó: {json.dumps(tx_full_data, indent=2)}") # Debug
        r = requests.post(f"{BASE}/tx/new", json=tx_full_data)
        r.raise_for_status() 

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

        print_info(f"Iniciando mineração de um bloco com {COIN_NAME} ({COIN_SYMBOL})...")
        r = requests.get(f"{BASE}/mine", timeout=120) # Aumenta o timeout para mineração
        r.raise_for_status()
        print_success(f"Bloco minerado com sucesso! Detalhes: {r.json()}")
    except requests.exceptions.Timeout:
        print_error("A requisição de mineração excedeu o tempo limite. O bloco pode ter sido minerado, mas a resposta não foi recebida.")
    except requests.exceptions.RequestException as e:
        print_error(f"Erro na mineração: {e}")
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
    # Esta função parece ser um placeholder ou de um contexto diferente,
    # pois usa 'blockchain' que não está definido neste script cliente.
    # Se for para comparar com peers, precisa de uma lista de peers.
    print_warning("A função comparar_ultimos_blocos não está totalmente implementada neste cliente.")
    # for peer in known_nodes:
    #     try:
    #         r = requests.get(f"{peer}/sync/check", timeout=5)
    #         data = r.json()
    #         local_block = blockchain.last_block()
    #         local_hash = hashlib.sha256(json.dumps({k: v for k, v in local_block.items() if k != 'transactions'}, sort_keys=True).encode()).hexdigest()

    #         if data['index'] == local_block['index'] and data['hash'] == local_hash:
    #             print(f"[SYNC] {peer} está sincronizado.")
    #         else:
    #             print(f"[SYNC] {peer} DIFERENTE! Index local: {local_block['index']} / peer: {data['index']}")
    #     except Exception as e:
    #         print(f"[SYNC] Falha ao verificar {peer}: {e}")

# A rota @app.route('/sync/check', methods=['GET']) é do lado do servidor (Flask), não do cliente.
# def check_sync():
#     pass

def registrar_peer(node_url):
    """
    Registra um novo nó (peer) com o seu nó minerador.
    Isso ajuda a rede a descobrir outros participantes.
    """
    try:
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
        r = requests.get(f"{BASE}/nodes/resolve") 
        r.raise_for_status()
        response = r.json()
        if response.get('replaced'): 
            print_success(f"Blockchain sincronizada com sucesso! A cadeia foi atualizada para a mais longa: {response.get('chain_length')} blocos.")
        else:
            print_info(f"Blockchain já está sincronizada. Sua cadeia é a mais longa ou não houve alteração. Comprimento: {response.get('chain_length')} blocos.")
        ver_chain() 
    except requests.exceptions.RequestException as e:
        print_error(f"Erro ao sincronizar blockchain: {e}. Verifique se o nó tem uma rota /nodes/resolve.")
    except Exception as e:
        print_error(f"Erro inesperado durante a sincronização: {e}")

# --- Funções de Mineração Contínua ---
def minerar_continuo_thread():
    global mining_active
    print_success(f"Mineração contínua iniciada para {COIN_NAME} ({COIN_SYMBOL}). Pressione '9' para parar.") 
    while mining_active:
        try:
            r = requests.get(f"{BASE}/mine", timeout=60) 
            r.raise_for_status()
            print_success(f"Bloco minerado (contínuo)! Detalhes: {r.json()}") 
        except requests.exceptions.Timeout:
            print_warning("Requisição de mineração contínua excedeu o tempo limite. Tentando novamente...")
        except requests.exceptions.RequestException as e:
            print_error(f"Erro na mineração contínua: {e}") 
        time.sleep(10) 
        
def iniciar_mineracao_continua(addr):
    global miner_address, mining_active, miner_thread
    if mining_active: 
        print_warning("Mineração contínua já está rodando!")
        return
    
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

    miner_address = current_miner_addr 
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
        print(Fore.BLUE + "10. Abrir Portais Web") # Nova opção
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
            enviar(sender_addr, recipient_addr, amount_str) 
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
        elif op == "10": # Nova opção para abrir portais web
            webbrowser.open(f"{BASE}/")
            webbrowser.open(f"{BASE}/miner")
            print_info("Abrindo portais web do nó minerador...")
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
            else:
                print_warning("Não foi possível ler dados do QR Code ou o arquivo está inválido.")
        elif op == "0":
            break
        else:
            print_warning("Opção inválida. Por favor, escolha uma opção do menu de carteira.")


# --- Execução Principal ---
if __name__ == "__main__":
    menu()
