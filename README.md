# Sentinela Web3

**Autonomous Multi-Agent Security Swarm for Ethereum Smart Contract Auditing**

Sentinela Web3 is an intelligent security auditing system that goes beyond traditional static analysis tools. Using a multi-agent orchestration approach powered by LangGraph, it not only finds potential vulnerabilities but attempts to **prove** them by writing and executing real exploit scripts in a sandboxed environment.

## Architecture Overview

```
                                    +-------------------+
                                    |   Orchestrator    |
                                    |   (LangGraph)     |
                                    +--------+----------+
                                             |
         +-----------------------------------+-----------------------------------+
         |                   |                   |                   |           |
         v                   v                   v                   v           v
+----------------+  +----------------+  +----------------+  +----------------+   |
|   Explorer     |  |  Red Teamer    |  |    Prover      |  |    Auditor     |   |
|  (Archivist)   |  |   (Attacker)   |  | (Exploit Eng.) |  |   (Reporter)   |   |
+----------------+  +----------------+  +----------------+  +----------------+   |
         |                   |                   |                   |           |
         v                   v                   v                   v           |
   +----------+        +-----------+       +-----------+       +-----------+     |
   | Slither  |        | ChromaDB  |       | Foundry   |       | Markdown  |<----+
   | Analysis |        | (RAG DB)  |       | (Forge)   |       | Reports   |
   +----------+        +-----------+       +-----------+       +-----------+
```

### Agent Roles

1. **Explorer (Archivist)**: Parses Solidity code, executes Slither static analysis, extracts Control Flow Graphs, and identifies critical entry points (withdraw, transfer, onlyOwner functions).

2. **Red Teamer (Attacker)**: Uses the Explorer's analysis and a RAG database of historical hacks to formulate logical attack hypotheses (Reentrancy, Logic Flaws, Access Control issues).

3. **Prover (Exploit Engineer)**: Receives a hypothesis and writes a real Solidity exploit test using Foundry's Forge framework.

4. **Auditor (Reporter)**: Orchestrates the testing loop, runs `forge test`, captures terminal output, and handles the reflection loop for error recovery.

## Key Features

### Core Security Capabilities
- **Business Logic Focus**: Unlike traditional tools, Sentinela focuses on logical vulnerabilities that require understanding contract intent.
- **Proof-Based Auditing**: Every vulnerability is proven through executable exploit tests.
- **Reflection Loop**: Automatic error recovery when exploit tests fail to compile.
- **Historical Context**: RAG-powered retrieval of similar past exploits for informed hypothesis generation.
- **Structured Output**: All agents use Pydantic models for reliable, typed outputs.

### Advanced Blockchain Integration (NEW)
- **Direct RPC Access**: Query blockchain data directly without rate limits or API costs
- **Intelligent Caching**: Reduce redundant queries with TTL-based cache (90%+ reduction)
- **Transaction Monitoring**: Real-time detection of suspicious patterns (large transfers, reentrancy, drains)
- **Cross-Chain Analysis**: Identify vulnerability propagation across multiple networks
- **On-Chain Enrichment**: Contextual data (balances, bytecode, risk levels) for better reporting

> 📘 See [Blockchain Access Guide](docs/BLOCKCHAIN_ACCESS.md) for detailed documentation

## Installation

### Prerequisites

- Python 3.10+
- [Foundry](https://getfoundry.sh) (Forge, Anvil)
- [Slither](https://github.com/crytic/slither) (`pip install slither-analyzer`)
- OpenAI or Anthropic API key

### Setup

```bash
# Clone the repository
git clone https://github.com/your-org/web3-sentinel.git
cd web3-sentinel

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -e ".[dev]"

# Install Foundry dependencies
cd contracts
forge install foundry-rs/forge-std
cd ..

# Copy environment template
cp env.example .env
# Edit .env with your API keys
```

### Verify Installation

```bash
# Check all tools are available
sentinela check
```

## Usage

### Basic Audit

```bash
# Audit a single contract
sentinela audit contracts/src/VulnerableVault.sol

# With custom options
sentinela audit contracts/src/MyContract.sol \
  --max-hypotheses 10 \
  --max-reflections 5 \
  --output ./reports \
  --verbose
```

### Advanced Blockchain Features

```bash
# Audit with on-chain enrichment
sentinela audit contracts/src/MyContract.sol --enable-rpc

# Monitor suspicious transactions
sentinela monitor 0xContractAddress --network ethereum

# Analyze cross-chain deployment
sentinela cross-chain 0xContractAddress

# View cache statistics
sentinela cache stats
```

### Initialize RAG Database

```bash
# Load default historical hacks
sentinela init-rag

# Load from custom directory
sentinela init-rag --data-dir ./my-hacks --load-defaults
```

### Programmatic Usage

```python
import asyncio
from sentinela import SentinelaOrchestrator
from sentinela.integrations.rpc import RPCClient, NetworkType

async def main():
    orchestrator = SentinelaOrchestrator()
    
    # Basic audit
    result = await orchestrator.audit(
        contract_path="./contracts/src/VulnerableVault.sol"
    )
    
    print(f"Vulnerabilities found: {result.vulnerabilities_found}")
    for vuln in result.vulnerabilities_proven:
        print(f"  - {vuln.title}: {vuln.vulnerability_type}")

    # Advanced: Enrich with on-chain data
    rpc = RPCClient(NetworkType.ETHEREUM_MAINNET)
    contract = "0x..."
    
    balance = await rpc.get_balance(contract)
    is_contract = await rpc.is_contract(contract)
    
    print(f"Balance: {balance} wei")
    print(f"Is Contract: {is_contract}")

asyncio.run(main())
```

## Project Structure

```
web3-sentinel/
├── src/
│   └── sentinela/
│       ├── __init__.py
│       ├── cli.py                 # Command-line interface
│       ├── agents/
│       │   ├── __init__.py
│       │   ├── base.py            # Base agent class
│       │   ├── explorer.py        # Contract analysis agent
│       │   ├── red_teamer.py      # Hypothesis generation agent
│       │   ├── prover.py          # Exploit writing agent
│       │   └── auditor.py         # Test execution agent
│       ├── core/
│       │   ├── __init__.py
│       │   ├── config.py          # Configuration management
│       │   ├── state.py           # LangGraph state definitions
│       │   └── orchestrator.py    # Main LangGraph workflow
│       ├── integrations/
│       │   ├── __init__.py
│       │   ├── slither.py         # Slither integration
│       │   └── foundry.py         # Forge/Anvil integration
│       └── rag/
│           ├── __init__.py
│           ├── retriever.py       # ChromaDB retrieval
│           └── loader.py          # Document loading
├── contracts/
│   ├── src/                       # Contracts to audit
│   ├── test/                      # Generated exploit tests
│   └── lib/                       # Foundry libraries
├── data/
│   └── vector_db/                 # ChromaDB persistence
├── tests/                         # Python tests
├── pyproject.toml
├── foundry.toml
└── README.md
```

## State Machine

The LangGraph workflow implements the following state machine:

```
[Explorer] --> [Red Teamer] --> [Prover] --> [Auditor]
                                    ^            |
                                    |            |
                              [Reflection] <-----+
                                    |            |
                                    v            v
                            [Next Hypothesis] --> [Report] --> [END]
```

### AgentState Definition

```python
class AgentState(TypedDict, total=False):
    messages: Annotated[list[Any], add_messages]
    phase: AgentPhase
    source_code: str
    contract_path: str
    explorer_output: ExplorerOutput | None
    hypotheses: list[AttackHypothesis]
    current_hypothesis_index: int
    exploit_tests: list[ExploitTest]
    test_results: list[TestResult]
    reflection_feedback: ReflectionFeedback | None
    reflection_count: int
    max_reflections: int
    proven_vulnerabilities: list[AttackHypothesis]
    final_reports: list[VulnerabilityReport]
    error: str | None
```

## Error Handling & Reflection Loop

The reflection loop handles different error types:

| Error Type | Action |
|------------|--------|
| Compilation Error | Parse error, generate fixes, retry with Prover |
| Runtime Revert | Analyze cause, adjust exploit logic, retry |
| Assertion Failure | Hypothesis disproven, move to next |
| Timeout | Skip hypothesis, log for manual review |
| Max Reflections | Abandon hypothesis, continue pipeline |

## Vulnerability Categories

Sentinela focuses on vulnerabilities that require semantic understanding:

- **Reentrancy**: Classic, cross-function, read-only
- **Access Control**: Missing modifiers, privilege escalation
- **Logic Flaws**: State machine errors, incorrect calculations
- **Oracle Manipulation**: Price feed exploits
- **Flash Loan Attacks**: Governance, collateral manipulation
- **Front-Running**: MEV, sandwich attacks
- **Signature Replay**: Missing nonces, chain ID issues

## Configuration

Environment variables (`.env`):

```bash
# LLM Configuration
OPENAI_API_KEY=sk-...
ANTHROPIC_API_KEY=sk-ant-...
PRIMARY_MODEL=gpt-4o

# Tool Paths (optional, uses system PATH)
SLITHER_PATH=
FORGE_PATH=

# Agent Settings
MAX_REFLECTION_LOOPS=3
EXPLOIT_TIMEOUT_SECONDS=120
MAX_HYPOTHESES_PER_RUN=5

# RAG Database
CHROMA_PERSIST_DIR=./data/vector_db
CHROMA_COLLECTION_NAME=hack_postmortems

# Blockchain RPC Endpoints (NEW)
MAINNET_RPC_URL=https://eth.llamarpc.com
POLYGON_RPC_URL=https://polygon-rpc.com
BSC_RPC_URL=https://bsc-dataseed.binance.org
ARBITRUM_RPC_URL=https://arb1.arbitrum.io/rpc
OPTIMISM_RPC_URL=https://mainnet.optimism.io

# Explorer API Keys (Optional - for verified source code)
ETHERSCAN_API_KEY=
POLYGONSCAN_API_KEY=
BSCSCAN_API_KEY=

# Cache Configuration (NEW)
ENABLE_QUERY_CACHE=true
CACHE_DIR=./data/cache
CACHE_TTL_SECONDS=3600
CACHE_MAX_SIZE_MB=100

# Indexer Configuration (NEW)
ENABLE_BLOCKCHAIN_INDEXER=false
INDEXER_STORAGE_DIR=./data/indexer
INDEXER_BATCH_SIZE=100

# Advanced Features (NEW)
ENABLE_RPC_INTEGRATION=true
ENABLE_CROSS_CHAIN_ANALYSIS=false
ENABLE_SUSPICIOUS_TX_MONITORING=false
```

### Performance Optimization

| Feature | Impact | Cost Reduction |
|---------|--------|----------------|
| Query Cache | 90%+ faster queries | Eliminates redundant API calls |
| Direct RPC | No rate limits | 100% free for read operations |
| Batch Indexing | 10x faster event retrieval | One-time sync, infinite queries |
| Cross-Chain | Detect systemic risks | Early warning across networks |

📖 **Full Configuration Guide**: See [docs/BLOCKCHAIN_ACCESS.md](docs/BLOCKCHAIN_ACCESS.md)

## Development

```bash
# Run tests
pytest

# Type checking
mypy src/sentinela

# Linting
ruff check src/

# Format code
ruff format src/
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass
5. Submit a pull request

## License

MIT License - see [LICENSE](LICENSE) for details.

## Disclaimer

This tool is for educational and authorized security research purposes only. Always obtain proper authorization before testing smart contracts you do not own. The authors are not responsible for misuse of this software.

## Acknowledgments

- [LangGraph](https://github.com/langchain-ai/langgraph) for the agent orchestration framework
- [Foundry](https://github.com/foundry-rs/foundry) for the Ethereum development toolkit
- [Slither](https://github.com/crytic/slither) for static analysis
- The Web3 security research community for documented post-mortems
