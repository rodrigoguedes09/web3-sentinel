"""
Unified Blockchain Explorer API

Provides unified interface to both direct RPC and external explorers (as fallback).
Supports multiple networks with automatic provider selection.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

import httpx
from eth_typing import Address, ChecksumAddress, HexStr
from eth_utils import to_checksum_address
from pydantic import BaseModel, Field

from sentinela.integrations.rpc import NetworkType, RPCClient

logger = logging.getLogger(__name__)


class ExplorerProvider(str, Enum):
    """Supported block explorer providers."""

    ETHERSCAN = "etherscan"
    POLYGONSCAN = "polygonscan"
    BSCSCAN = "bscscan"
    ARBISCAN = "arbiscan"
    OPTIMISM_ETHERSCAN = "optimism_etherscan"


# Explorer API endpoints
EXPLORER_URLS = {
    ExplorerProvider.ETHERSCAN: "https://api.etherscan.io/api",
    ExplorerProvider.POLYGONSCAN: "https://api.polygonscan.com/api",
    ExplorerProvider.BSCSCAN: "https://api.bscscan.com/api",
    ExplorerProvider.ARBISCAN: "https://api.arbiscan.io/api",
    ExplorerProvider.OPTIMISM_ETHERSCAN: "https://api-optimistic.etherscan.io/api",
}


# Network to Explorer mapping
NETWORK_TO_EXPLORER = {
    NetworkType.ETHEREUM_MAINNET: ExplorerProvider.ETHERSCAN,
    NetworkType.ETHEREUM_SEPOLIA: ExplorerProvider.ETHERSCAN,
    NetworkType.POLYGON: ExplorerProvider.POLYGONSCAN,
    NetworkType.POLYGON_MUMBAI: ExplorerProvider.POLYGONSCAN,
    NetworkType.BSC: ExplorerProvider.BSCSCAN,
    NetworkType.BSC_TESTNET: ExplorerProvider.BSCSCAN,
    NetworkType.ARBITRUM: ExplorerProvider.ARBISCAN,
    NetworkType.OPTIMISM: ExplorerProvider.OPTIMISM_ETHERSCAN,
}


class ContractSource(BaseModel):
    """Contract source code information."""

    source_code: str = Field(..., description="Solidity source code")
    abi: list[dict[str, Any]] = Field(..., description="Contract ABI")
    contract_name: str = Field(..., description="Contract name")
    compiler_version: str = Field(..., description="Solidity compiler version")
    optimization_used: bool = Field(default=False, description="Optimization enabled")
    runs: int = Field(default=200, description="Optimizer runs")
    constructor_arguments: str = Field(default="", description="Constructor arguments")
    evm_version: str = Field(default="default", description="EVM version")
    license: str = Field(default="", description="License type")


class TransactionInfo(BaseModel):
    """Transaction information from explorer."""

    hash: HexStr = Field(..., description="Transaction hash")
    from_address: ChecksumAddress = Field(..., description="Sender")
    to_address: ChecksumAddress | None = Field(None, description="Recipient")
    value: str = Field(..., description="Value in wei")
    gas_used: str = Field(..., description="Gas used")
    gas_price: str = Field(..., description="Gas price")
    block_number: int = Field(..., description="Block number")
    timestamp: int = Field(..., description="Block timestamp")
    status: str = Field(..., description="Status (1=success, 0=fail)")


class UnifiedExplorer:
    """
    Unified interface for blockchain data access.
    
    Strategy:
    1. Try RPC client first (fastest, no rate limits)
    2. Fallback to explorer API if needed (for verified contracts)
    3. Cache results for efficiency
    """

    def __init__(
        self,
        network: NetworkType = NetworkType.ETHEREUM_MAINNET,
        rpc_url: str | None = None,
        explorer_api_key: str | None = None,
    ):
        """
        Initialize unified explorer.
        
        Args:
            network: Blockchain network
            rpc_url: Custom RPC URL
            explorer_api_key: API key for explorer (optional)
        """
        self.network = network
        self.rpc = RPCClient(network, rpc_url)
        self.explorer_api_key = explorer_api_key

        # Get explorer provider for this network
        self.explorer_provider = NETWORK_TO_EXPLORER.get(network)
        if self.explorer_provider:
            self.explorer_url = EXPLORER_URLS[self.explorer_provider]
        else:
            self.explorer_url = None

        logger.info(f"Initialized UnifiedExplorer for {network.value}")

    async def get_contract_source(
        self,
        address: str | Address,
    ) -> ContractSource | None:
        """
        Get verified contract source code.
        
        This REQUIRES explorer API as RPC doesn't have source code.
        
        Args:
            address: Contract address
            
        Returns:
            Contract source or None if not verified
        """
        if not self.explorer_url or not self.explorer_api_key:
            logger.warning("Explorer API not configured, cannot fetch source code")
            return None

        checksum_addr = to_checksum_address(address)

        params = {
            "module": "contract",
            "action": "getsourcecode",
            "address": checksum_addr,
            "apikey": self.explorer_api_key,
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.explorer_url, params=params, timeout=30.0)
                response.raise_for_status()
                data = response.json()

                if data["status"] != "1":
                    logger.warning(f"Explorer API error: {data.get('message', 'Unknown')}")
                    return None

                result = data["result"][0]
                
                if not result.get("SourceCode"):
                    logger.info(f"Contract {checksum_addr} is not verified")
                    return None

                # Parse ABI
                import json
                abi = json.loads(result["ABI"]) if result.get("ABI") != "Contract source code not verified" else []

                return ContractSource(
                    source_code=result["SourceCode"],
                    abi=abi,
                    contract_name=result["ContractName"],
                    compiler_version=result["CompilerVersion"],
                    optimization_used=result["OptimizationUsed"] == "1",
                    runs=int(result.get("Runs", 200)),
                    constructor_arguments=result.get("ConstructorArguments", ""),
                    evm_version=result.get("EVMVersion", "default"),
                    license=result.get("LicenseType", ""),
                )

        except Exception as e:
            logger.error(f"Failed to fetch contract source: {e}")
            return None

    async def get_contract_abi(
        self,
        address: str | Address,
    ) -> list[dict[str, Any]] | None:
        """
        Get contract ABI.
        
        Args:
            address: Contract address
            
        Returns:
            Contract ABI or None
        """
        source = await self.get_contract_source(address)
        return source.abi if source else None

    async def get_balance(self, address: str | Address) -> int:
        """
        Get address balance (uses RPC).
        
        Args:
            address: Address to query
            
        Returns:
            Balance in wei
        """
        return await self.rpc.get_balance(address)

    async def get_transaction(self, tx_hash: str | HexStr) -> TransactionInfo | None:
        """
        Get transaction details.
        
        Uses RPC first, falls back to explorer if needed.
        
        Args:
            tx_hash: Transaction hash
            
        Returns:
            Transaction info
        """
        try:
            # Try RPC first
            tx = await self.rpc.get_transaction(tx_hash)
            receipt = await self.rpc.get_transaction_receipt(tx_hash)

            return TransactionInfo(
                hash=tx["hash"].hex(),
                from_address=to_checksum_address(tx["from"]),
                to_address=to_checksum_address(tx["to"]) if tx.get("to") else None,
                value=str(tx["value"]),
                gas_used=str(receipt["gasUsed"]),
                gas_price=str(tx["gasPrice"]),
                block_number=tx["blockNumber"],
                timestamp=0,  # Would need to fetch block for timestamp
                status=str(receipt["status"]),
            )

        except Exception as e:
            logger.error(f"Failed to get transaction from RPC: {e}")
            return None

    async def is_contract(self, address: str | Address) -> bool:
        """Check if address is a contract (uses RPC)."""
        return await self.rpc.is_contract(address)

    async def get_code(self, address: str | Address) -> HexStr:
        """Get contract bytecode (uses RPC)."""
        return await self.rpc.get_code(address)

    async def get_logs(
        self,
        contract_address: str | Address,
        from_block: int | str = "earliest",
        to_block: int | str = "latest",
        topics: list[str] | None = None,
    ) -> list[Any]:
        """Get contract event logs (uses RPC)."""
        return await self.rpc.get_logs(
            contract_address=contract_address,
            topics=topics,
            from_block=from_block,
            to_block=to_block,
        )

    async def search_transactions(
        self,
        address: str | Address,
        start_block: int = 0,
        end_block: int | str = "latest",
    ) -> list[TransactionInfo]:
        """
        Search transactions for address.
        
        Note: This requires explorer API for efficient search.
        Using RPC would require scanning all blocks (very slow).
        
        Args:
            address: Address to search
            start_block: Start block
            end_block: End block
            
        Returns:
            List of transactions
        """
        if not self.explorer_url or not self.explorer_api_key:
            logger.warning("Explorer API required for transaction search")
            return []

        checksum_addr = to_checksum_address(address)

        params = {
            "module": "account",
            "action": "txlist",
            "address": checksum_addr,
            "startblock": start_block,
            "endblock": end_block if isinstance(end_block, int) else 99999999,
            "sort": "desc",
            "apikey": self.explorer_api_key,
        }

        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(self.explorer_url, params=params, timeout=30.0)
                response.raise_for_status()
                data = response.json()

                if data["status"] != "1":
                    return []

                return [
                    TransactionInfo(
                        hash=tx["hash"],
                        from_address=to_checksum_address(tx["from"]),
                        to_address=to_checksum_address(tx["to"]) if tx.get("to") else None,
                        value=tx["value"],
                        gas_used=tx["gasUsed"],
                        gas_price=tx["gasPrice"],
                        block_number=int(tx["blockNumber"]),
                        timestamp=int(tx["timeStamp"]),
                        status=tx.get("txreceipt_status", "1"),
                    )
                    for tx in data["result"]
                ]

        except Exception as e:
            logger.error(f"Failed to search transactions: {e}")
            return []


class MultiChainExplorer:
    """
    Manage explorers for multiple chains.
    
    Useful for cross-chain contract analysis.
    """

    def __init__(self):
        """Initialize multi-chain explorer."""
        self.explorers: dict[NetworkType, UnifiedExplorer] = {}

    def add_network(
        self,
        network: NetworkType,
        rpc_url: str | None = None,
        explorer_api_key: str | None = None,
    ) -> UnifiedExplorer:
        """Add network explorer."""
        if network not in self.explorers:
            self.explorers[network] = UnifiedExplorer(
                network=network,
                rpc_url=rpc_url,
                explorer_api_key=explorer_api_key,
            )
        return self.explorers[network]

    def get_explorer(self, network: NetworkType) -> UnifiedExplorer | None:
        """Get explorer for network."""
        return self.explorers.get(network)

    async def find_contract_on_networks(
        self,
        address: str | Address,
        networks: list[NetworkType] | None = None,
    ) -> dict[NetworkType, bool]:
        """
        Check if contract exists on multiple networks.
        
        Useful for finding same contract deployed cross-chain.
        """
        if networks is None:
            networks = list(self.explorers.keys())

        results = {}
        for network in networks:
            explorer = self.get_explorer(network)
            if explorer:
                results[network] = await explorer.is_contract(address)

        return results
