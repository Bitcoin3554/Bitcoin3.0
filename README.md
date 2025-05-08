# Crypito Bitcoin3.0 And Bitcoin

Visão Geral do Funcionamento “Local” do Bitcoin3.0
O Bitcoin3.0, conforme distribuído no repositório de Bitcoin3554, é na prática uma implementação local (única máquina) que engloba:

Block explorer próprio rodando como um servidor HTTP local.

Minerador embutido que cria blocos “normais” usando prova de trabalho.

Carteira compatível com Bitcoin (BTC) — mesmas chaves privadas/WIF e formatos de endereço.

Rede P2P restrita a 127.0.0.1 — não há peers externos; tudo acontece na sua máquina.

A seguir, explico como cada componente se integra e como você pode “ligar o .exe” e testar essas funcionalidades.

1. Block Explorer e API HTTP Local
O whitepaper e o repositório incluem exemplos de endpoints REST para exploração de blocos e transações, todos apontando para 127.0.0.1 :

GET /chain — retorna a cadeia de blocos atual.

GET /block/{hash} — detalhes de um bloco específico.

GET /tx/{txid} — detalhes de uma transação.

Como usar:

Execute o Bitcoin3.0.exe.

Abra o navegador em http://127.0.0.1 (porta default; confira o README ou configs do .exe).

Você terá acesso a uma interface web simples para navegar blocos, txs e endereços .

2. Mineração “Normal” em Prova de Trabalho
O módulo de mineração está embutido no executável e expõe o endpoint POST /mine .

Fluxo:

Envie uma requisição POST (ou use o botão “Mine” na UI) para /mine.

O nó tentará encontrar o nonce válido e adicionará um novo bloco à cadeia local.

A recompensa é creditada ao endereço definido nos parâmetros de gênese.

Configuração:

O arquivo chainparams.cpp no fork do Bitcoin Core define o nPowTargetSpacing (intervalo de blocos configurável entre 1–10 min).

Para alterar, recompile alterando static const int64_t nPowTargetSpacing 
bitaps.com
.

3. Carteira e Chaves Privadas Compatíveis com BTC
Bitcoin3.0 reutiliza o formato WIF/P2PKH do Bitcoin original, o que permite usar a mesma carteira e chaves privadas .

Prefixos:

cpp
Copiar
Editar
base58Prefixes[PUBKEY_ADDRESS] = {23};    // endereços começam com ‘M’ (exemplo)
base58Prefixes[SECRET_KEY]     = {151};   // WIF privado padrão
``` :contentReference[oaicite:5]{index=5}  
Importação/Exportação:

No cliente GUI local, há opção “Import WIF” para carregar sua chave BTC existente.

Endereços gerados serão reconhecidos por qualquer wallet compatível com aquele prefixo (e.g., Bitcoin Core).

4. Rede P2P em 127.0.0.1
Não existem DNS seeds nem peers públicos — toda a comunicação P2P é feita localmente .

Configuração de peers:

O arquivo de configuração (bitcoin3.conf) inclui linhas como:

ini
Copiar
Editar
listen=1
bind=127.0.0.1
port=8333
Para conectar manualmente outro nó local, use addnode=127.0.0.1 em múltiplas instâncias .

Implica que cada instância do .exe (ou do daemon) fala apenas com si mesma, a menos que você rode várias instâncias na mesma máquina.

5. Passo a Passo para Testar Tudo na Sua Máquina
Baixe e extraia o release v3.0.0 do GitHub.

Abra um terminal na pasta e execute Bitcoin3.0.exe (Windows) ou ./bitcoin3d (Linux).

Visite http://127.0.0.1 para o explorer e http://127.0.0.1 para a RPC mineradora.

Importe sua chave WIF via UI, ou coloque importprivkey <WIF> na RPC console.

Mine enviando curl -X POST http://127.0.0.1/mine (ou clicando no botão).

Confira no explorer o novo bloco e o saldo sendo creditado no seu endereço.

Conclusão
Tudo que o Bitcoin3.0 oferece é uma instância local do protocolo Bitcoin customizado para gerar “BTC3”, rodando exclusivamente em 127.0.0.1. Ele reutiliza as mesmas chaves e formatos de endereço do Bitcoin real e agrupa em um único executável:

Explorer próprio via HTTP local

Mineração PoW com bloco configurável

Carteira BTC compatível e importação de chaves WIF

Rede P2P isolada à sua máquina

**Bitcoin3.0 (BTC3)** é uma evolução do conceito original do Bitcoin (BTC), combinando a segurança comprovada do sistema de carteiras Bitcoin com uma blockchain independente e um mecanismo de mineração próprio.

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
```
http://127.0.0.1
```

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
