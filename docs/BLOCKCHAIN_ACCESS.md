# Direct Blockchain Access - Sentinela Web3

## Overview

Sentinela Web3 agora possui acesso **direto** à blockchain usando **web3.py**, eliminando a dependência de explorers externos como Etherscan. Isso significa:

- ✅ **Sem rate limits** de APIs externas
- ✅ **Sem custos** de API keys (para operações básicas)
- ✅ **Mais rápido** - Conexão direta com nós RPC
- ✅ **Mais privado** - Não compartilha queries com terceiros
- ✅ **Multi-chain** - Suporte para Ethereum, Polygon, BSC, Arbitrum, Optimism

## Arquitetura

```
┌─────────────────┐
│  Sentinela Web3 │
└────────┬────────┘
         │
    ┌────┴─────┐
    │          │
    v          v
┌────────┐  ┌──────────┐
│   RPC  │  │ Explorer │  ← Fallback (source code verificado)
│ Client │  │   API    │
└────┬───┘  └─────────┘
     │
     v
┌─────────────────┐
│  Blockchain     │
│  - Ethereum     │
│  - Polygon      │
│  - BSC          │
│  - Arbitrum     │
│  - Optimism     │
└─────────────────┘
```

## Componentes

### 1. RPC Client (`src/sentinela/integrations/rpc.py`)

Cliente unificado para interação direta com blockchain:

```python
from sentinela.integrations.rpc import RPCClient, NetworkType

# Conectar à Ethereum Mainnet
rpc = RPCClient(network=NetworkType.ETHEREUM_MAINNET)

# Verificar conexão
connected = await rpc.is_connected()

# Consultar balance
balance = await rpc.get_balance("0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045")

# Verificar se é contrato
is_contract = await rpc.is_contract("0x...")

# Buscar transação
tx = await rpc.get_transaction("0x...")

# Buscar logs/eventos
logs = await rpc.get_logs(
    contract_address="0x...",
    from_block=1000000,
    to_block=1000100
)
```

**Recursos:**
- ✅ Consulta de balances (ETH/tokens nativos)
- ✅ Verificação de contratos
- ✅ Leitura de bytecode
- ✅ Busca de transações
- ✅ Busca de eventos/logs
- ✅ Leitura de storage slots
- ✅ Chamadas de funções read-only
- ✅ Estimativa de gas

### 2. Blockchain Indexer (`src/sentinela/integrations/indexer.py`)

Indexador local de eventos e transações:

```python
from sentinela.integrations.indexer import BlockchainIndexer

# Inicializar indexer
indexer = BlockchainIndexer(
    rpc_client=rpc,
    storage_dir="./data/blockchain_index"
)

# Rastrear contrato
indexer.track_contract("0xdAC17F958D2ee523a2206206994597C13D831ec7")  # USDT

# Indexar blocos
await indexer.index_block_range(
    from_block=24000000,
    to_block=24001000,
    batch_size=100
)

# Consultar eventos indexados
events = indexer.query_events(
    contract_address="0x...",
    event_name="Transfer",
    from_block=24000000,
    limit=100
)

# Indexação contínua (live)
await indexer.start_live_indexing(poll_interval=12)
```

**Recursos:**
- ✅ Indexação incremental (retoma do último bloco)
- ✅ Armazenamento local em JSONL
- ✅ Queries eficientes por contrato/evento/bloco
- ✅ Estatísticas de indexação
- ✅ Modo live (indexação contínua)
- ✅ Histórico de transações

### 3. Unified Explorer (`src/sentinela/integrations/explorer.py`)

Interface unificada que usa RPC primeiro e fallback para explorers:

```python
from sentinela.integrations.explorer import UnifiedExplorer

# Inicializar (usa RPC por padrão)
explorer = UnifiedExplorer(
    network=NetworkType.ETHEREUM_MAINNET,
    rpc_url=None,  # Usa endpoint padrão
    explorer_api_key="YOUR_ETHERSCAN_KEY"  # Opcional
)

# Consultas via RPC (grátis, sem limites)
balance = await explorer.get_balance("0x...")
is_contract = await explorer.is_contract("0x...")
code = await explorer.get_code("0x...")

# Buscar código verificado (requer API key)
source = await explorer.get_contract_source("0x...")
if source:
    print(source.source_code)
    print(source.abi)
    print(source.compiler_version)

# Buscar transações (requer API key para eficiência)
txs = await explorer.search_transactions(
    address="0x...",
    start_block=24000000
)
```

**Estratégia:**
1. **Primeira opção**: RPC direto (grátis, rápido)
2. **Fallback**: Explorer API (quando necessário)

**Quando usar Explorer API:**
- ✅ Buscar código-fonte verificado
- ✅ Buscar ABIs de contratos
- ✅ Histórico completo de transações (mais eficiente que scan de blocos)
- ✅ Cross-referência com dados públicos

## Configuração

### 1. RPC Endpoints

Configure no `.env`:

```bash
# Ethereum
MAINNET_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR-API-KEY
SEPOLIA_RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR-API-KEY

# Polygon
POLYGON_RPC_URL=https://polygon-mainnet.g.alchemy.com/v2/YOUR-API-KEY
POLYGON_MUMBAI_RPC_URL=https://polygon-mumbai.g.alchemy.com/v2/YOUR-API-KEY

# BSC (gratuito)
BSC_RPC_URL=https://bsc-dataseed.binance.org/

# Arbitrum
ARBITRUM_RPC_URL=https://arb-mainnet.g.alchemy.com/v2/YOUR-API-KEY

# Optimism
OPTIMISM_RPC_URL=https://opt-mainnet.g.alchemy.com/v2/YOUR-API-KEY

# Nó local (se rodar seu próprio)
LOCAL_NODE_URL=http://localhost:8545
```

### 2. Explorer API Keys (Opcional)

Configure apenas se precisar buscar contratos verificados:

```bash
ETHERSCAN_API_KEY=YOUR-KEY
POLYGONSCAN_API_KEY=YOUR-KEY
BSCSCAN_API_KEY=YOUR-KEY
```

**Como obter:**
- Etherscan: https://etherscan.io/apis (grátis)
- Polygonscan: https://polygonscan.com/apis (grátis)
- BscScan: https://bscscan.com/apis (grátis)

## Provedores RPC

### Opções Gratuitas

1. **Alchemy** (Recomendado)
   - 300M compute units/mês grátis
   - https://www.alchemy.com/

2. **Infura**
   - 100k requests/dia grátis
   - https://www.infura.io/

3. **Endpoints Públicos**
   ```
   Ethereum: https://eth.llamarpc.com
   Polygon: https://polygon-rpc.com
   BSC: https://bsc-dataseed.binance.org
   ```

### Rodar Seu Próprio Nó

**Ethereum (Geth):**
```bash
# Instalar Geth
# Windows: https://geth.ethereum.org/downloads/

# Iniciar nó (modo light)
geth --http --http.api eth,net,web3 --syncmode light

# Acessar em: http://localhost:8545
```

**Vantagens:**
- ✅ Sem limites de rate
- ✅ Controle total
- ✅ Máxima privacidade

**Desvantagens:**
- ❌ Requer ~500GB storage (full node)
- ❌ Sincronização inicial lenta
- ❌ Manutenção necessária

## Casos de Uso

### 1. Auditoria Sem Depender de Explorers

```python
# Analisar contrato apenas com RPC
rpc = RPCClient(NetworkType.ETHEREUM_MAINNET)

# Verificar se é contrato
is_contract = await rpc.is_contract(contract_address)

# Buscar bytecode
bytecode = await rpc.get_code(contract_address)

# Analisar eventos históricos
logs = await rpc.get_logs(
    contract_address=contract_address,
    from_block=deployment_block,
    to_block="latest"
)

# Sentinela pode auditar sem API keys!
```

### 2. Monitoramento em Tempo Real

```python
# Iniciar indexação contínua
indexer = BlockchainIndexer(rpc_client=rpc)
indexer.track_contract(target_contract)

# Indexar novos blocos automaticamente
await indexer.start_live_indexing(poll_interval=12)

# Em outra thread, query eventos em tempo real
while True:
    new_events = indexer.query_events(
        contract_address=target_contract,
        from_block=last_checked_block
    )
    
    for event in new_events:
        analyze_suspicious_activity(event)
```

### 3. Análise Cross-Chain

```python
from sentinela.integrations.explorer import MultiChainExplorer

multi = MultiChainExplorer()
multi.add_network(NetworkType.ETHEREUM_MAINNET)
multi.add_network(NetworkType.POLYGON)
multi.add_network(NetworkType.BSC)

# Verificar se contrato existe em múltiplas chains
results = await multi.find_contract_on_networks(
    address="0x...",
    networks=[
        NetworkType.ETHEREUM_MAINNET,
        NetworkType.POLYGON,
        NetworkType.BSC
    ]
)

print(f"Contract on Ethereum: {results[NetworkType.ETHEREUM_MAINNET]}")
print(f"Contract on Polygon: {results[NetworkType.POLYGON]}")
print(f"Contract on BSC: {results[NetworkType.BSC]}")
```

## Comparação: RPC vs Explorer

| Funcionalidade | RPC Client | Explorer API | Vencedor |
|----------------|------------|--------------|----------|
| Consultar balance | ✅ Grátis | ✅ Grátis | RPC (mais rápido) |
| Verificar se é contrato | ✅ Grátis | ✅ Grátis | RPC (mais rápido) |
| Buscar bytecode | ✅ Grátis | ✅ Grátis | RPC (mais rápido) |
| Buscar transação | ✅ Grátis | ✅ Grátis | RPC (mais rápido) |
| Buscar eventos/logs | ✅ Grátis | ✅ Grátis | RPC (mais rápido) |
| **Código verificado** | ❌ N/A | ✅ Requer key | Explorer |
| **ABI de contrato** | ❌ N/A | ✅ Requer key | Explorer |
| **Histórico tx completo** | ⚠️ Lento | ✅ Rápido | Explorer |
| Rate limits | ✅ Nenhum* | ⚠️ 5 req/sec | RPC |
| Custo | ✅ Grátis** | ✅ Grátis*** | Empate |

\* Depende do provedor RPC  
\*\* Até limite do provedor (Alchemy: 300M compute units)  
\*\*\* API keys gratuitas disponíveis

## Performance

### RPC Client
- **Latência**: ~50-200ms por request
- **Throughput**: Limitado pelo provedor
- **Storage**: Nenhum (stateless)

### Indexer
- **Indexação**: ~100 blocos/segundo
- **Storage**: ~1KB por evento
- **Queries**: Instantâneas (leitura local)

### Unified Explorer
- **RPC queries**: ~50-200ms
- **Explorer queries**: ~200-500ms
- **Fallback automático**: Transparente

## Exemplos

Execute o exemplo completo:

```bash
python examples/blockchain_access.py
```

Saída esperada:
```
=== Example 1: Basic RPC Operations ===
Connected: True
Chain ID: 1
Latest Block: 24,287,274

Vitalik's Balance:
  Wei: 32112475373385816706
  ETH: 32.1125

Uniswap Router is contract: True
Bytecode length: 21943 characters
```

## Próximos Passos

1. **Integração com Auditor**: Usar RPC para buscar dados on-chain durante auditorias
2. **Cache inteligente**: Armazenar queries frequentes localmente
3. **MEV detection**: Indexar transações suspeitas automaticamente
4. **Cross-chain analysis**: Comparar vulnerabilidades entre chains
5. **Gas optimization**: Analisar custos de transações históricas

## Limitações

### O que NÃO é possível apenas com RPC:
- ❌ Buscar código-fonte verificado (precisa Explorer)
- ❌ Buscar ABIs publicadas (precisa Explorer)
- ❌ Buscar todas as transações de um endereço de forma eficiente
- ❌ Verificar novos contratos automaticamente

### Soluções:
1. **Código verificado**: Use Explorer API como fallback
2. **ABIs**: Mantenha banco local ou use Explorer
3. **Histórico tx**: Use Indexer para rastrear desde bloco específico
4. **Verificação**: Implemente próprio serviço de verificação

## Recursos

- **web3.py Documentation**: https://web3py.readthedocs.io/
- **Alchemy Docs**: https://docs.alchemy.com/
- **Etherscan API**: https://docs.etherscan.io/
- **Running Ethereum Node**: https://geth.ethereum.org/docs/

## Troubleshooting

### Erro: "Connection failed"
- Verifique se RPC_URL está correto no `.env`
- Teste manualmente: `curl -X POST YOUR_RPC_URL -H "Content-Type: application/json" -d '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}'`

### Erro: "Rate limit exceeded"
- Use provedor diferente (Alchemy, Infura)
- Implemente retry com exponential backoff
- Considere rodar seu próprio nó

### Indexação muito lenta
- Reduza `batch_size`
- Use RPC mais rápido
- Indexe apenas contratos relevantes
- Use período de blocos menor

## Contribuindo

Para adicionar suporte a nova network:

1. Adicione em `NetworkType` enum
2. Configure `DEFAULT_NETWORKS`
3. Adicione RPC endpoint no `.env`
4. Teste com exemplo

---

**Sentinela Web3** agora é **verdadeiramente autônomo** - pode auditar contratos sem depender de serviços externos! 🚀
