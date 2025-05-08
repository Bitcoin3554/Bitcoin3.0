Crypito Bitcoin3.0 And Bitcoin

🚀 Visão Geral do Funcionamento “Local” do Bitcoin3.0

O Bitcoin3.0, conforme distribuído no repositório de Bitcoin3554, é uma implementação local (única máquina) que engloba:

Block explorer próprio rodando como um servidor HTTP local.

Minerador embutido que cria blocos “normais” usando prova de trabalho.

Carteira compatível com Bitcoin (BTC) — mesmas chaves privadas/WIF e formatos de endereço.

Rede P2P restrita a 127.0.0.1 — não há peers externos; tudo acontece na sua máquina.

A seguir, explicamos como cada componente se integra e como você pode ligar o executável e testar todas as funcionalidades.

1. Block Explorer e API HTTP Local

O whitepaper e o repositório incluem exemplos de endpoints REST para exploração de blocos e transações, todos apontando para 127.0.0.1:

GET /chain        — retorna a cadeia de blocos atual.
GET /block/{hash} — detalhes de um bloco específico.
GET /tx/{txid}    — detalhes de uma transação.

Como usar:

Execute o Bitcoin3.0.exe (Windows) ou ./bitcoin3d (Linux).

Abra o navegador em http://127.0.0.1:3001 (porta default; verifique o README interno ou configs do executável).

Acesse a interface web para navegar por blocos, transações e endereços.

2. Mineração “Normal” em Prova de Trabalho

O módulo de mineração está embutido no executável e expõe o endpoint POST /mine:

Fluxo de mineração:

Envie uma requisição POST para /mine (ou use o botão "Mine" na UI).

O nó procura o nonce válido e adiciona um novo bloco à cadeia local.

A recompensa é creditada ao endereço definido nos parâmetros de gênese.

Configuração de intervalos de bloco:

No arquivo chainparams.cpp, ajuste o parâmetro nPowTargetSpacing para configurar o intervalo de bloco (entre 1 e 10 minutos):

static const int64_t nPowTargetSpacing = 2 * 60; // Exemplo: 2 minutos

Recompile o projeto após alterações.

3. Carteira e Chaves Privadas Compatíveis com BTC

O Bitcoin3.0 reutiliza o formato WIF/P2PKH do Bitcoin original, permitindo usar a mesma carteira e chaves privadas.

Prefixos de endereços:

base58Prefixes[PUBKEY_ADDRESS] = {23};  // endereços começam com ‘M’ (exemplo)
base58Prefixes[SECRET_KEY]     = {151}; // WIF privado padrão

Importação/Exportação:

Use a opção "Import WIF" na interface local para carregar sua chave BTC existente.

Endereços gerados serão reconhecidos por qualquer wallet compatível com aquele prefixo (e.g., Bitcoin Core).

4. Rede P2P em 127.0.0.1

Não existem DNS seeds nem peers públicos — toda a comunicação P2P é feita localmente.

Configuração de peers:
No arquivo bitcoin3.conf:

listen=1
bind=127.0.0.1
port=8333
addnode=127.0.0.1:8333

Para conectar múltiplas instâncias, rode várias cópias do executável na mesma máquina.

5. Passo a Passo para Testar Tudo na Sua Máquina

Baixe e extraia o release v3.0.0 do GitHub.

Execute Bitcoin3.0.exe (Windows) ou ./bitcoin3d (Linux) no diretório extraído.

Explorer: acesse http://127.0.0.1:3001 para navegar blocos e txs.

RPC Mineradora: acesse http://127.0.0.1:8332 (Console RPC).

Importe sua chave WIF: via UI ou importprivkey <WIF> na console RPC.

Inicie a mineração: curl -X POST http://127.0.0.1:8332/mine ou clicando no botão "Mine".

Verifique no explorer o novo bloco e o saldo creditado.

🔧 Recursos Adicionais

Whitepaper Bitcoin3.0 (PDF):
Bitcoin3.0_Whitepaper.pdf

Repositório GitHub:
https://github.com/Bitcoin3554/Bitcoin3.0

Conclusão

O Bitcoin3.0 (BTC3) oferece uma instância local customizada do protocolo Bitcoin para gerar BTC3, rodando exclusivamente em 127.0.0.1. Ele inclui:

Explorer próprio via HTTP local

Mineração PoW com bloco configurável

Carteira BTC compatível e importação de chaves WIF

Rede P2P isolada à sua máquina

Este projeto é ideal para testes e aprendizado. Não há deployment em testnet/mainnet nem peers externos, portanto não representa uma criptomoeda com rede real nem liquidez.

© 2025 Crypito Labs. Todos os direitos reservados.

