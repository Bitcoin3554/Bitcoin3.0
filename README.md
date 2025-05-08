# Crypito Bitcoin3.0 And Bitcoin

## Visão Geral

O **Bitcoin3.0** é uma implementação local do protocolo Bitcoin, que roda em uma única máquina. Ele inclui um explorador de blocos próprio, mineração utilizando prova de trabalho (PoW), uma carteira compatível com o Bitcoin, e uma rede P2P restrita a **127.0.0.1** (localhost). Tudo ocorre localmente em sua máquina.

## Funcionalidades

### 1. Block Explorer e API HTTP Local

O Bitcoin3.0 inclui um **explorador de blocos** e uma **API HTTP** para interação com a blockchain. A comunicação é feita via **127.0.0.1**, garantindo que a interação ocorra localmente. 

#### Endpoints da API:
- **GET /chain**: Retorna a cadeia de blocos atual.
- **GET /block/{hash}**: Detalhes de um bloco específico.
- **GET /tx/{txid}**: Detalhes de uma transação específica.

#### Como usar:
1. Execute o arquivo **Bitcoin3.0.exe** (Windows) ou **./bitcoin3d** (Linux).
2. Abra o navegador em [http://127.0.0.1](http://127.0.0.1) para acessar a interface do explorador de blocos.
3. Explore os blocos, transações e endereços diretamente na interface.

---

### 2. Mineração com Prova de Trabalho (PoW)

O **Bitcoin3.0** tem um minerador embutido que utiliza o algoritmo de **Prova de Trabalho (PoW)**. Você pode gerar novos blocos na blockchain localmente.

#### Fluxo de Mineração:
1. Envie uma requisição POST para o endpoint **/mine**.
2. O nó tentará encontrar um nonce válido e, ao sucesso, adicionará um novo bloco à cadeia local.
3. A recompensa pela mineração será creditada ao endereço especificado.

#### Configuração de Mineração:
No arquivo **chainparams.cpp**, o parâmetro **nPowTargetSpacing** define o intervalo entre blocos (geralmente entre 1 e 10 minutos).

Para alterar o intervalo, modifique o valor de `static const int64_t nPowTargetSpacing` e recompile o código.

---

### 3. Carteira Compatível com Bitcoin

O **Bitcoin3.0** é compatível com as chaves privadas e endereços padrão do Bitcoin (BTC), utilizando o formato **WIF/P2PKH**. Isso permite importar e exportar chaves privadas de carteiras BTC.

#### Prefixos de Endereços:
- **Endereço Público (P2PKH)**: Prefixo `23` (exemplo: começa com "M").
- **Chave Privada (WIF)**: Prefixo `151`.

---

### 4. Rede P2P Local

A comunicação P2P no Bitcoin3.0 ocorre exclusivamente na sua máquina local (localhost, **127.0.0.1**). Não há peers externos conectados.

#### Configuração de Rede:
No arquivo de configuração **bitcoin3.conf**, a rede é configurada para aceitar conexões apenas de **127.0.0.1**.

```ini
listen=1
bind=127.0.0.1
port=80

## 🚀 Visão Geral
- **Compatibilidade de Carteiras:** Mesmos formatos de chaves públicas, privadas e WIF do Bitcoin.
- **Blockchain Própria:** Rede separada que gera BTC3 em vez de BTC.
- **Mineração Dual:** Uma carteira única pode minerar e armazenar BTC (na rede Bitcoin) e BTC3 (na rede Bitcoin3.0) simultaneamente.
- **Transações Rápidas:** Blocos configuráveis para tempos de confirmação mais baixos (1–10 minutos).

## 📄 Whitepaper
Para entender em detalhes o design, algoritmo de mineração, tokenomics e roadmap do Bitcoin3.0, consulte o whitepaper oficial:

* [Whitepaper Bitcoin3.0 (PDF)](https://github.com/Bitcoin3554/Bitcoin3.0/blob/main/Bitcoin3.0_Whitepaper.pdf)
* 
## 🧱 Downloads
- 📥 **Bitcoin Core:** [Downloads Aqui](https://github.com/Bitcoin3554/Bitcoin3.0/releases/tag/v3.0.0)

## 🔧 Ferramentas
### Bitcoin / Bitcoin3.0 Wallet Generator
Acesse para criar carteiras compatíveis com BTC e BTC3:

http://127.0.0.1
## 🔗 Endpoints da API
- **Smart Contract:** `GET http://127.0.0.1/contract/carteira/external-transactions`
- **Balance:** `GET http://127.0.0.1/balance/<address>`
- **New Transfer:** `POST http://127.0.0.1/transactions/new`
- **Blocks:** `GET http://127.0.0.1/chain`
- **Transfer:** `POST http://127.0.0.1/transfer`
- **Carteras (Carteiras):** `POST http://127.0.0.1/wallet/create`
- **Mining (Mineração):** `GET http://127.0.0.1/mine`

## 📷 Crypto Bitcoin!
![BTC3](https://github.com/Pipo-Pay/crypito/raw/main/Pipo-(pay).jpg)
![Wallet](https://github.com/Pipo-Pay/crypito/blob/main/Wallet.jpg)
![BTC3 BMP](https://github.com/Pipo-Pay/crypito/raw/main/pipo.bmp)
![01 BMP](https://github.com/Pipo-Pay/crypito/raw/main/01.bmp)
![02 BMP](https://github.com/Pipo-Pay/crypito/raw/main/02.bmp)

---

© 2025 Crypito Labs. Todos os direitos reservados.
