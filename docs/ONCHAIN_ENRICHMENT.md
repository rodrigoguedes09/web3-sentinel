# On-Chain Data Enrichment - Quick Start

## Overview

O Auditor agora enriquece automaticamente os relatórios de vulnerabilidade com dados on-chain em tempo real quando uma vulnerabilidade é comprovada.

## Funcionalidades Integradas

### 1. **Enriquecimento Automático**
Quando uma vulnerabilidade é comprovada, o sistema automaticamente:
- ✅ Verifica o saldo do contrato
- ✅ Obtém o tamanho do bytecode
- ✅ Busca código verificado (se API key disponível)
- ✅ Avalia o nível de risco baseado no valor em risco
- ✅ Detecta deployments multi-chain

### 2. **Recomendações Contextualizadas**
As recomendações agora são adaptadas com base nos dados on-chain:

```python
# Exemplo de recomendação gerada automaticamente:
"⚠️ URGENT: Contract holds 543.21 ETH - Deploy fix immediately"
"🌍 CRITICAL: Deploy fix on ALL chains simultaneously: ethereum, polygon, bsc"
```

### 3. **Relatórios Enriquecidos**
Os relatórios de vulnerabilidade agora incluem:

```python
VulnerabilityReport(
    hypothesis=...,
    exploit_test=...,
    test_result=...,
    severity="CRITICAL",
    recommendations=[...],
    
    # Novos campos:
    onchain_data={
        "contract_balance_eth": 543.21,
        "bytecode_size": 21943,
        "is_verified": True,
        "compiler_version": "v0.8.19",
        "risk_level": "CRITICAL - High value contract",
        "current_block": 24287410
    },
    
    cross_chain_deployments={
        "ethereum": True,
        "polygon": True,
        "bsc": True
    }
)
```

## Configuração

### Mínima (Grátis)
```bash
# .env
ENABLE_RPC_INTEGRATION=true

# Usa endpoints RPC públicos gratuitos
# Sem necessidade de API keys
```

### Recomendada
```bash
# .env
ENABLE_RPC_INTEGRATION=true
ENABLE_CROSS_CHAIN_ANALYSIS=true
ENABLE_QUERY_CACHE=true

# Opcional: Para código verificado
ETHERSCAN_API_KEY=your-key-here

# Opcional: RPC nodes próprios (mais rápido)
MAINNET_RPC_URL=https://your-alchemy-url
POLYGON_RPC_URL=https://your-alchemy-url
```

## Uso

### Método 1: Com Endereço Conhecido
```python
from sentinela.core.orchestrator import SentinelaOrchestrator

orchestrator = SentinelaOrchestrator()

result = await orchestrator.audit(
    contract_path="contracts/src/MyContract.sol",
    contract_address="0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"  # Endereço deployed
)

# Relatórios incluirão dados on-chain automaticamente
for report in result.reports:
    print(f"Balance: {report.onchain_data['contract_balance_eth']} ETH")
    print(f"Risk: {report.onchain_data['risk_level']}")
```

### Método 2: Extração Automática
```python
# Se não fornecer endereço, o sistema tenta extrair do output dos testes
result = await orchestrator.audit(
    contract_path="contracts/src/MyContract.sol"
    # Sistema procura por padrões como "Contract deployed at: 0x..."
)
```

### Método 3: Via Linha de Comando
```bash
# Futuro: quando CLI for implementado
sentinela audit contracts/src/MyContract.sol --address 0x742d35...
```

## Workflow Integrado

```
┌─────────────────────────────────────────────────────────────┐
│ 1. Auditor executa teste de exploit                        │
│    → forge test --match-path contracts/test/Exploit_H1.sol │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
         ┌───────────────────────┐
         │ Teste PASSOU?         │
         └───────┬───────────────┘
                 │ SIM
                 ▼
┌─────────────────────────────────────────────────────────────┐
│ 2. Vulnerabilidade COMPROVADA                               │
│    → Marca hypothesis como PROVEN                           │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 3. ENRIQUECIMENTO ON-CHAIN (NOVO!)                          │
│    ├─ Busca endereço em state["contract_address"]          │
│    ├─ Se não encontrar, extrai do output do teste          │
│    ├─ Chama enrich_with_onchain_data()                     │
│    │   ├─ get_balance() [cached 60s]                       │
│    │   ├─ get_code() [cached 24h]                          │
│    │   ├─ get_verified_source() [se API key]               │
│    │   └─ Avalia risk_level baseado no balance             │
│    └─ Chama check_cross_chain_deployment()                 │
│        └─ Busca contrato em ethereum, polygon, bsc         │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────────────────────────┐
│ 4. GERA RELATÓRIO ENRIQUECIDO                               │
│    ├─ Adiciona onchain_data ao relatório                   │
│    ├─ Adiciona cross_chain_deployments                     │
│    └─ Gera recomendações contextualizadas                  │
│        ├─ Se balance > 100 ETH: "URGENT: Deploy fix"       │
│        ├─ Se multi-chain: "Deploy on ALL chains"           │
│        └─ Se não verificado: "Verify source code"          │
└────────────────────┬────────────────────────────────────────┘
                     │
                     ▼
           [Próxima hypothesis]
```

## Exemplos de Output

### Sem Enriquecimento (Antes)
```
🚨 VULNERABILITY FOUND: Unauthorized Withdrawal
   Type: access_control
   Severity: CRITICAL
   
   Recommendations:
   - Implement proper access control checks
   - Add appropriate modifiers
   - Conduct thorough testing
```

### Com Enriquecimento (Agora)
```
🚨 VULNERABILITY FOUND: Unauthorized Withdrawal
   Type: access_control
   Severity: CRITICAL
   
   📊 On-Chain Data:
      Balance: 543.2100 ETH
      Bytecode: 21,943 bytes
      Risk: CRITICAL - High value contract
      Verified: ✅ Yes
      Compiler: v0.8.19+commit.7dd6d404
   
   🌍 Cross-Chain Deployments:
      Found on 3 networks: ethereum, polygon, bsc
      ⚠️  Vulnerability may propagate across all chains!
   
   Recommendations:
   1. ⚠️ URGENT: Contract holds 543.21 ETH - Deploy fix immediately
   2. 🌍 CRITICAL: Deploy fix on ALL chains simultaneously: ethereum, polygon, bsc
   3. Implement proper access control checks with onlyOwner modifier
   4. Add emergency pause functionality
   5. Set up real-time monitoring with alerts
   6. Consider bug bounty program given high TVL
```

## Desempenho

### Cache Hits
- Balance queries: **60 segundos de cache** (blocos mudam frequentemente)
- Bytecode queries: **24 horas de cache** (imutável)
- RPC direto: **50-100ms por query**
- Cache hit: **<5ms**

### Custo
- RPC queries: **$0** (leitura é grátis)
- Etherscan API: **$0** (grátis com rate limit)
- Com cache: **90%+ de redução** em queries redundantes

## Troubleshooting

### Enriquecimento não funciona
1. Verifique `ENABLE_RPC_INTEGRATION=true` em `.env`
2. Confirme que RPC endpoints estão acessíveis
3. Verifique logs para erros de conexão

### Endereço não detectado
1. Forneça `contract_address` explicitamente no `audit()`
2. Ou certifique-se que testes imprimem endereço no formato `0x...`

### Cross-chain não funciona
1. Defina `ENABLE_CROSS_CHAIN_ANALYSIS=true`
2. Configure RPC URLs para redes adicionais
3. Verifique conectividade com cada rede

## Próximos Passos

### Já Implementado ✅
- [x] Enriquecimento automático no workflow
- [x] Cache inteligente
- [x] Detecção cross-chain
- [x] Recomendações contextualizadas
- [x] Extração automática de endereço

### Roadmap Futuro 🚀
- [ ] Suporte para testnets (Goerli, Sepolia)
- [ ] Integração com DefiLlama para TVL
- [ ] Análise histórica de transações
- [ ] Detecção de padrões suspeitos
- [ ] Simulação de exploit em fork

## Documentação Completa

Para mais detalhes técnicos, veja:
- [BLOCKCHAIN_ACCESS.md](../docs/BLOCKCHAIN_ACCESS.md) - Documentação completa
- [IMPLEMENTATION_SUMMARY.md](../IMPLEMENTATION_SUMMARY.md) - Resumo da implementação
- [examples/audit_with_onchain.py](../examples/audit_with_onchain.py) - Exemplo completo

## Suporte

Para problemas ou dúvidas:
1. Verifique os logs com `--verbose`
2. Consulte a documentação de troubleshooting
3. Abra uma issue no GitHub com logs e configuração
