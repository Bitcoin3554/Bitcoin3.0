import requests

BASE_URL = "http://127.0.0.1:5000"  # Ajuste conforme necessário

def carregar_peers():
    try:
        with open("peers.json", "r") as f:
            peers = json.load(f)
        return peers
    except Exception as e:
        print(f"❌ Erro ao carregar peers: {e}")
        return []
        
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

    try:
        r = requests.post(f"{BASE_URL}/transfer", json=payload, timeout=10)
        r.raise_for_status()
        data = r.json()

        if "error" in data:
            print(f"❌ Erro: {data['error']}")
            return

        print("✅ Transferência realizada com sucesso!")
        for k, v in data.items():
            print(f"{k}: {v}")

        # Minerar bloco após a transferência
        minerar_resp = requests.get(f"{BASE_URL}/mine", params={"miner": remetente})
        if minerar_resp.ok:
            print("⛏️ Bloco minerado com sucesso:")
            print(minerar_resp.json())
        else:
            print("✅ Sucesso ao enviar bloco.")

        # Mostrar saldo atualizado
        saldo = requests.get(f"{BASE_URL}/balance/{remetente}")
        if saldo.ok:
            saldo_data = saldo.json()
            print(f"💰 Saldo atualizado da carteira {remetente}: {saldo_data.get('balance', 'N/A')}")
        else:
            print("❌ Não foi possível consultar o saldo atualizado.")

    except requests.exceptions.Timeout:
        print("❌ Tempo de conexão esgotado.")
    except requests.exceptions.ConnectionError:
        print("❌ Erro de conexão com o servidor.")
    except Exception as e:
        print(f"❌ Erro inesperado: {e}")


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