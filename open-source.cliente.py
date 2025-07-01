import requests

BASE_URL = "http://localhost:5000"  # Ajuste conforme necessário

def ver_saldo():
    endereco = input("Digite o endereço da carteira para ver saldo: ")
    r = requests.get(f"{BASE_URL}/balance/{endereco}")
    if r.ok:
        data = r.json()
        print(f"💰 Saldo da carteira {data['address']}: {data['balance']}")
    else:
        print("❌ Erro ao consultar saldo.")
        
def transferir():
    remetente = input("Digite o endereço do remetente: ").strip()
    destinatario = input("Digite o endereço do destinatário: ").strip()
    valor = input("Digite o valor para transferir: ").strip()
    chave_privada = input("Digite a chave privada do remetente: ").strip()

    try:
        valor_float = float(valor)
        if valor_float <= 0:
            print("❌ O valor deve ser maior que zero.")
            return
    except ValueError:
        print("❌ Valor inválido! Use um número, ex: 0.001")
        return

    payload = {
        "sender": remetente,
        "recipient": destinatario,
        "amount": valor_float,
        "private_key": chave_privada
    }

    peers = []

    sucesso = False
    ultima_resposta = None

    for peer_url in peers:
        try:
            r = requests.post(f"{peer_url}/transfer", json=payload, timeout=10)
            r.raise_for_status()
            resposta = r.json()
            if "error" in resposta:
                print(f"❌ Erro no peer {peer_url}: {resposta['error']}")
            else:
                print(f"✅ Transferência confirmada pelo peer {peer_url}")
                print("Detalhes:", resposta)
                sucesso = True
                ultima_resposta = resposta
                break  # Para no primeiro sucesso
        except requests.exceptions.Timeout:
            print(f"❌ Timeout ao conectar com {peer_url}")
        except requests.exceptions.ConnectionError:
            print(f"❌ Falha de conexão com {peer_url}")
        except Exception as e:
            print(f"❌ Erro inesperado com {peer_url}: {e}")

    if not sucesso:
        print("❌ Transferência falhou em todos os peers.")
        return

    # Opcional: Minerar para confirmar a transação
    miner = remetente
    r = requests.get(f"{peer_url}/mine", params={"miner": miner})
    if r.ok:
        print("⛏️ Bloco minerado após transferência:")
        print(r.json())
    else:
        print("❌ Erro ao minerar bloco após transferência.")

    # Mostrar saldo atualizado
    saldo_response = requests.get(f"{peer_url}/balance/{remetente}")
    if saldo_response.ok:
        saldo_data = saldo_response.json()
        print(f"💰 Saldo atualizado da carteira {remetente}: {saldo_data.get('balance', 'N/A')}")
    else:
        print("❌ Não foi possível obter o saldo atualizado.")


def minerar():
    miner = input("Endereço da carteira mineradora: ")
    r = requests.get(f"{BASE_URL}/mine", params={"miner": miner})
    if r.ok:
        print("✅ Bloco minerado!")
        print(r.json())
    else:
        print("❌ Erro ao minerar:", r.json().get("error", "Erro desconhecido"))

def criar_carteira():
    r = requests.post(f"{BASE_URL}/wallet/create")
    if r.status_code == 201:
        dados = r.json()
        print(f"🆕 Nova carteira criada: {dados.get('address', '[sem endereço]')}")
        if 'private_key' in dados:
            print(f"🔑 Chave privada: {dados['private_key']}")
        else:
            print("⚠️ Chave privada não foi retornada pelo servidor.")
    else:
        print("❌ Erro ao criar carteira")

def ver_chain():
    r = requests.get(f"{BASE_URL}/chain")
    if r.ok:
        data = r.json()
        print("Resposta completa:", data)  # DEBUG para ver o JSON exato
        
        chain = data.get('chain')
        if not chain:
            print("❌ Resposta inválida: blockchain não encontrada.")
            return
        
        print(f"📦 Blockchain (total de blocos: {len(chain)})")
        for bloco in chain:
            print(f"\n🔗 Bloco #{bloco.get('index', '?')}")
            print(f"Transações: {bloco.get('transactions', [])}")
    else:
        print("❌ Erro ao buscar blockchain")




def ver_peers():
    r = requests.get(f"{BASE_URL}/nodes")
    if r.ok:
        print("🌐 Peers conectados:")
        for peer in r.json():
            print(f"- {peer.get('ip', 'desconhecido')} ({peer.get('name', '')})")
    else:
        print("❌ Erro ao listar peers")

def menu():
    while True:
        print("\n=== BTC3 MENU ===")
        print("1 - Ver saldo da carteira")
        print("2 - Transferir entre carteiras")
        print("3 - Minerar bloco")
        print("4 - Criar nova carteira")
        print("5 - Ver blockchain completa")
        print("6 - Ver peers conectados")
        print("0 - Sair")
        escolha = input("Opção: ")

        if escolha == "1":
            ver_saldo()
        elif escolha == "2":
            transferir()
        elif escolha == "3":
            minerar()
        elif escolha == "4":
            criar_carteira()
        elif escolha == "5":
            ver_chain()
        elif escolha == "6":
            ver_peers()
        elif escolha == "0":
            break
        else:
            print("❌ Opção inválida!")

if __name__ == "__main__":
    menu()
