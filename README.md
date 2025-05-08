# Crypito Bitcoin3.0 e Bitcoin

## Visão Geral do Funcionamento “Local” do Bitcoin3.0

O **Bitcoin3.0**, conforme distribuído no repositório de Bitcoin3554, é uma implementação local (única máquina) que engloba:

- **Block explorer** próprio rodando como um servidor HTTP local.
- **Minerador embutido** que cria blocos “normais” usando prova de trabalho (PoW).
- **Carteira compatível com Bitcoin (BTC)** — mesmas chaves privadas/WIF e formatos de endereço.
- **Rede P2P restrita a 127.0.0.1** — não há peers externos; tudo acontece na sua máquina.

### Componentes e Funcionalidades

#### 1. Block Explorer e API HTTP Local
O **block explorer** e a API HTTP permitem explorar blocos e transações na blockchain local. Abaixo estão os principais endpoints disponíveis:

- **GET /chain** — Retorna a cadeia de blocos atual.
- **GET /block/{hash}** — Detalhes de um bloco específico.
- **GET /tx/{txid}** — Detalhes de uma transação.

**Como usar**:
1. Execute o arquivo `Bitcoin3.0.exe`.
2. Abra o navegador em [http://127.0.0.1](http://127.0.0.1) (verifique o README ou configurações do `.exe` para a porta, se necessário).
3. Você terá acesso a uma interface web simples para navegar blocos, transações e endereços.

#### 2. Mineração “Normal” em Prova de Trabalho (PoW)
O módulo de mineração permite criar blocos via prova de trabalho (PoW) com um endpoint embutido.

- **POST /mine**: Envie uma requisição POST para este endpoint ou utilize o botão “Mine” na interface para iniciar a mineração.
- O nó tentará encontrar o nonce válido e adicionará um novo bloco à cadeia local.
- A recompensa será creditada ao endereço definido nos parâmetros de gênese.

**Configuração**:
- O arquivo `chainparams.cpp` no fork do **Bitcoin Core** define o parâmetro `nPowTargetSpacing` (intervalo de blocos entre 1–10 minutos). Para alterar esse valor, recompile alterando o valor de `static const int64_t nPowTargetSpacing`.

#### 3. Carteira e Chaves Privadas Compatíveis com BTC
**Bitcoin3.0** reutiliza o formato de endereços WIF/P2PKH do Bitcoin original, permitindo usar as mesmas carteiras e chaves privadas.

**Prefixos**:
- Endereços começam com `M` (exemplo: `Mxxx...`).
- As chaves privadas seguem o padrão WIF e começam com o prefixo `151`.

**Importação/Exportação**:
- No cliente GUI local, há uma opção para importar chaves via o formato **WIF**.
- Os endereços gerados são compatíveis com qualquer carteira que utilize esse prefixo, como o **Bitcoin Core**.

#### 4. Rede P2P Isolada a 127.0.0.1
Não existem seeds DNS nem peers públicos. A comunicação P2P acontece exclusivamente entre instâncias locais.

**Configuração de Peers**:
O arquivo de configuração (`bitcoin3.conf`) inclui parâmetros como:
```ini
listen=1
bind=127.0.0.1
port=80
