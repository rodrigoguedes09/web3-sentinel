"""
Loader for Hack Post-Mortem Documents

Loads and processes hack post-mortem documents from various sources
into the ChromaDB vector database for RAG retrieval.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

from sentinela.core.config import Settings, get_settings
from sentinela.rag.retriever import HackRetriever


logger = logging.getLogger(__name__)


class HackPostmortemLoader:
    """
    Loads hack post-mortem documents into the vector database.
    
    Supports loading from:
    - JSON files
    - YAML files
    - Markdown files with frontmatter
    - Directory of documents
    """

    def __init__(
        self,
        settings: Settings | None = None,
        retriever: HackRetriever | None = None,
    ) -> None:
        """
        Initialize the loader.
        
        Args:
            settings: Application settings
            retriever: HackRetriever instance to use
        """
        self.settings = settings or get_settings()
        self.retriever = retriever or HackRetriever(settings=self.settings)

    async def load_from_json(self, file_path: Path | str) -> int:
        """
        Load hack post-mortems from a JSON file.
        
        Expected format:
        [
            {
                "name": "Hack Name",
                "date": "2024-01-01",
                "loss_amount": "$1M",
                "vulnerability_type": "reentrancy",
                "summary": "Brief summary",
                "attack_vector": "Step by step attack",
                "affected_contracts": ["0x..."],
                "references": ["https://..."]
            }
        ]
        
        Args:
            file_path: Path to JSON file
            
        Returns:
            Number of documents loaded
        """
        file_path = Path(file_path)
        
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        if not isinstance(data, list):
            data = [data]

        count = 0
        for hack in data:
            await self._process_hack(hack)
            count += 1

        logger.info(f"Loaded {count} hacks from {file_path}")
        return count

    async def load_from_yaml(self, file_path: Path | str) -> int:
        """
        Load hack post-mortems from a YAML file.
        
        Args:
            file_path: Path to YAML file
            
        Returns:
            Number of documents loaded
        """
        file_path = Path(file_path)

        with open(file_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        if not isinstance(data, list):
            data = [data]

        count = 0
        for hack in data:
            await self._process_hack(hack)
            count += 1

        logger.info(f"Loaded {count} hacks from {file_path}")
        return count

    async def load_from_directory(self, dir_path: Path | str) -> int:
        """
        Load all hack post-mortems from a directory.
        
        Supports .json, .yaml, .yml, and .md files.
        
        Args:
            dir_path: Path to directory
            
        Returns:
            Number of documents loaded
        """
        dir_path = Path(dir_path)
        count = 0

        for file_path in dir_path.iterdir():
            if file_path.suffix == ".json":
                count += await self.load_from_json(file_path)
            elif file_path.suffix in (".yaml", ".yml"):
                count += await self.load_from_yaml(file_path)
            elif file_path.suffix == ".md":
                count += await self.load_from_markdown(file_path)

        return count

    async def load_from_markdown(self, file_path: Path | str) -> int:
        """
        Load a hack post-mortem from a Markdown file with YAML frontmatter.
        
        Expected format:
        ---
        name: Hack Name
        date: 2024-01-01
        vulnerability_type: reentrancy
        ---
        
        # Detailed Analysis
        
        Content here...
        
        Args:
            file_path: Path to Markdown file
            
        Returns:
            Number of documents loaded (0 or 1)
        """
        file_path = Path(file_path)

        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()

        # Parse frontmatter
        if content.startswith("---"):
            parts = content.split("---", 2)
            if len(parts) >= 3:
                frontmatter = yaml.safe_load(parts[1])
                body = parts[2].strip()

                hack = {**frontmatter, "content": body}
                await self._process_hack(hack)
                return 1

        logger.warning(f"No frontmatter found in {file_path}")
        return 0

    async def _process_hack(self, hack: dict[str, Any]) -> None:
        """
        Process and store a single hack document.
        
        Args:
            hack: Hack document data
        """
        # Build document text for embedding
        document_parts = []

        if "name" in hack:
            document_parts.append(f"Name: {hack['name']}")

        if "summary" in hack:
            document_parts.append(f"Summary: {hack['summary']}")

        if "attack_vector" in hack:
            document_parts.append(f"Attack Vector: {hack['attack_vector']}")

        if "content" in hack:
            document_parts.append(hack["content"])

        document = "\n\n".join(document_parts)

        # Build metadata
        metadata = {
            "name": hack.get("name", "Unknown"),
            "date": hack.get("date", "Unknown"),
            "loss_amount": hack.get("loss_amount", "Unknown"),
            "vulnerability_type": hack.get("vulnerability_type", "unknown"),
        }

        # Add optional metadata
        if "affected_contracts" in hack:
            metadata["affected_contracts"] = ",".join(hack["affected_contracts"])

        if "references" in hack:
            metadata["references"] = ",".join(hack["references"][:5])

        # Store in vector database
        doc_id = f"hack_{hack.get('name', 'unknown').lower().replace(' ', '_')}"
        await self.retriever.add_document(
            document=document,
            metadata=metadata,
            doc_id=doc_id,
        )

    async def load_default_hacks(self) -> int:
        """
        Load a set of well-known hacks as initial database content.
        
        Returns:
            Number of hacks loaded
        """
        default_hacks = [
            {
                "name": "The DAO Hack",
                "date": "2016-06-17",
                "loss_amount": "$60M",
                "vulnerability_type": "reentrancy",
                "summary": "Classic reentrancy attack exploiting recursive calls before state update in splitDAO function.",
                "attack_vector": """
1. Attacker creates malicious contract with fallback function
2. Calls splitDAO to withdraw funds
3. During ETH transfer, fallback is triggered
4. Fallback calls splitDAO again before balance is updated
5. Process repeats until contract is drained
6. Only after all recursive calls complete does balance update
                """,
                "content": """
The DAO was a decentralized investment fund on Ethereum. The attack exploited
a reentrancy vulnerability in the splitDAO function. The function sent ETH to
the caller before updating internal balances, allowing an attacker's fallback
function to recursively call splitDAO and drain funds.

Key vulnerable pattern:
```solidity
function withdraw(uint amount) public {
    require(balances[msg.sender] >= amount);
    (bool success,) = msg.sender.call{value: amount}("");  // External call first
    balances[msg.sender] -= amount;  // State update after
}
```

The fix requires the Checks-Effects-Interactions pattern:
1. Check conditions
2. Update state
3. Make external calls
                """,
            },
            {
                "name": "Parity Wallet Freeze",
                "date": "2017-11-06",
                "loss_amount": "$150M frozen",
                "vulnerability_type": "access_control",
                "summary": "Unprotected library initialization allowed anyone to become owner and self-destruct the library.",
                "attack_vector": """
1. Library contract deployed with initWallet function
2. initWallet had no access control
3. Attacker calls initWallet to become owner
4. Attacker calls kill() to self-destruct library
5. All wallets depending on library become non-functional
6. Funds permanently frozen
                """,
                "content": """
The Parity multi-sig wallet used a library pattern where wallet logic was in a
separate library contract. The library's initWallet function was unprotected,
allowing anyone to call it and become the library owner.

The attacker then called the kill() function, destroying the library contract.
Since all wallet instances delegated calls to this library, they all became
non-functional, freezing approximately $150M worth of ETH.

Vulnerable pattern:
```solidity
function initWallet(address[] _owners, uint _required) {
    // No access control!
    owners = _owners;
    required = _required;
}
```
                """,
            },
            {
                "name": "Cream Finance Flash Loan Attack",
                "date": "2021-10-27",
                "loss_amount": "$130M",
                "vulnerability_type": "oracle_manipulation",
                "summary": "Flash loan used to manipulate oracle prices and drain lending pools through over-collateralized borrowing.",
                "attack_vector": """
1. Flash loan large amount of token A
2. Deposit token A to inflate exchange rate
3. Use inflated collateral to borrow maximum token B
4. Repeat with multiple tokens in same transaction
5. Walk away with borrowed assets
6. Flash loan auto-repays from profits
                """,
                "content": """
Cream Finance was a lending protocol that relied on on-chain oracles for price
feeds. The attacker exploited the fact that depositing large amounts could
temporarily manipulate the perceived value of collateral.

Using a flash loan, the attacker:
1. Borrowed large amounts without collateral (flash loan)
2. Deposited to inflate collateral token's exchange rate
3. Borrowed against the artificially inflated collateral
4. Repeated across multiple pools in the same transaction
5. Repaid flash loan and kept the profits

This attack highlighted the risks of using manipulable on-chain oracles.
                """,
            },
            {
                "name": "Wormhole Bridge Hack",
                "date": "2022-02-02",
                "loss_amount": "$320M",
                "vulnerability_type": "signature_replay",
                "summary": "Signature verification bypass allowed minting of unbacked wrapped ETH.",
                "attack_vector": """
1. Attacker exploits bug in signature verification
2. Creates valid-looking but fraudulent transfer message
3. Bypasses guardian signature checks
4. Mints 120,000 wETH without depositing actual ETH
5. Bridges fake wETH to Ethereum
6. Sells for real assets
                """,
                "content": """
Wormhole is a cross-chain bridge that uses guardian signatures to verify
transfers. The attack exploited a vulnerability in the signature verification
logic that allowed the attacker to bypass the guardian checks.

The attacker was able to mint wrapped ETH on Solana without actually depositing
real ETH on Ethereum. They then bridged this unbacked wETH to Ethereum and
exchanged it for real assets.

The vulnerability was in how the contract verified the authenticity of signed
messages from the guardian network, allowing forged messages to be accepted.
                """,
            },
            {
                "name": "Nomad Bridge Hack",
                "date": "2022-08-01",
                "loss_amount": "$190M",
                "vulnerability_type": "logic_flaw",
                "summary": "Faulty upgrade made zero hash a valid Merkle root, allowing anyone to drain funds.",
                "attack_vector": """
1. Protocol upgrade introduces bug
2. Zero hash becomes valid Merkle root
3. Anyone can prove fake deposits using zero hash
4. Multiple attackers copy-paste successful transactions
5. Bridge drained by hundreds of wallets
6. Classic chaotic "free for all" exploit
                """,
                "content": """
Nomad is a cross-chain bridge that uses Merkle proofs to verify deposits.
A routine upgrade accidentally initialized the trusted Merkle root to zero.

In Merkle proof verification, a zero root made ANY proof valid. This meant
anyone could claim fake deposits by providing a proof that verified against
the zero root.

The exploit was notable because it required no technical skill - once the first
attacker showed a successful transaction, others simply copied it, changing
only the recipient address. This led to a chaotic "free for all" where hundreds
of wallets drained the bridge.

Vulnerable pattern:
```solidity
// After upgrade, confirmAt[root] was zero
// Zero was treated as a valid root
function process(bytes memory _message, bytes32[32] calldata _proof, uint256 _index) public {
    bytes32 _root = ...; // Calculate from proof
    require(confirmAt[_root] != 0, "Invalid root");  // Zero root passed this check!
    ...
}
```
                """,
            },
        ]

        for hack in default_hacks:
            await self._process_hack(hack)

        logger.info(f"Loaded {len(default_hacks)} default hacks")
        return len(default_hacks)
