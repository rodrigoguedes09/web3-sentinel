"""
RPC Client - Direct Blockchain Interaction

Provides unified interface to interact with multiple blockchain networks
using web3.py, eliminating dependency on external explorers.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Any

from eth_typing import Address, ChecksumAddress, HexStr
from eth_utils import to_checksum_address
from pydantic import BaseModel, Field
from web3 import AsyncHTTPProvider, AsyncWeb3
from web3.contract import AsyncContract
from web3.exceptions import ContractLogicError, Web3Exception
from web3.types import BlockData, EventData, TxData, TxReceipt

logger = logging.getLogger(__name__)


class NetworkType(str, Enum):
    """Supported blockchain networks."""

    ETHEREUM_MAINNET = "ethereum"
    ETHEREUM_SEPOLIA = "sepolia"
    POLYGON = "polygon"
    POLYGON_MUMBAI = "mumbai"
    BSC = "bsc"
    BSC_TESTNET = "bsc_testnet"
    ARBITRUM = "arbitrum"
    OPTIMISM = "optimism"
    LOCAL = "local"


class NetworkConfig(BaseModel):
    """Configuration for a blockchain network."""

    name: str = Field(..., description="Network name")
    network_type: NetworkType = Field(..., description="Network type")
    rpc_url: str = Field(..., description="RPC endpoint URL")
    chain_id: int = Field(..., description="Chain ID")
    explorer_url: str = Field(default="", description="Block explorer URL")
    native_token: str = Field(default="ETH", description="Native token symbol")


# Default network configurations
DEFAULT_NETWORKS = {
    NetworkType.ETHEREUM_MAINNET: NetworkConfig(
        name="Ethereum Mainnet",
        network_type=NetworkType.ETHEREUM_MAINNET,
        rpc_url="https://eth.llamarpc.com",
        chain_id=1,
        explorer_url="https://etherscan.io",
        native_token="ETH",
    ),
    NetworkType.ETHEREUM_SEPOLIA: NetworkConfig(
        name="Sepolia Testnet",
        network_type=NetworkType.ETHEREUM_SEPOLIA,
        rpc_url="https://rpc.sepolia.org",
        chain_id=11155111,
        explorer_url="https://sepolia.etherscan.io",
        native_token="ETH",
    ),
    NetworkType.POLYGON: NetworkConfig(
        name="Polygon Mainnet",
        network_type=NetworkType.POLYGON,
        rpc_url="https://polygon-rpc.com",
        chain_id=137,
        explorer_url="https://polygonscan.com",
        native_token="MATIC",
    ),
    NetworkType.BSC: NetworkConfig(
        name="Binance Smart Chain",
        network_type=NetworkType.BSC,
        rpc_url="https://bsc-dataseed.binance.org",
        chain_id=56,
        explorer_url="https://bscscan.com",
        native_token="BNB",
    ),
    NetworkType.LOCAL: NetworkConfig(
        name="Local Node",
        network_type=NetworkType.LOCAL,
        rpc_url="http://localhost:8545",
        chain_id=31337,  # Foundry/Hardhat default
        explorer_url="",
        native_token="ETH",
    ),
}


class RPCClient:
    """
    Unified RPC client for interacting with blockchain networks.
    
    Supports multiple networks and provides methods for:
    - Querying balances
    - Reading contract state
    - Fetching transactions and events
    - Getting block data
    """

    def __init__(
        self,
        network: NetworkType | str = NetworkType.ETHEREUM_MAINNET,
        rpc_url: str | None = None,
    ):
        """
        Initialize RPC client.
        
        Args:
            network: Network type or custom network name
            rpc_url: Custom RPC URL (overrides default)
        """
        # Convert string to enum if needed
        if isinstance(network, str):
            try:
                network = NetworkType(network)
            except ValueError:
                network = NetworkType.LOCAL

        self.network_type = network
        
        # Get network config
        self.config = DEFAULT_NETWORKS.get(network)
        if not self.config:
            raise ValueError(f"Unsupported network: {network}")

        # Override RPC URL if provided
        if rpc_url:
            self.config.rpc_url = rpc_url

        # Initialize web3
        self.w3 = AsyncWeb3(AsyncHTTPProvider(self.config.rpc_url))
        logger.info(f"Initialized RPC client for {self.config.name}")

    async def is_connected(self) -> bool:
        """Check if connected to the network."""
        try:
            return await self.w3.is_connected()
        except Exception as e:
            logger.error(f"Connection check failed: {e}")
            return False

    async def get_chain_id(self) -> int:
        """Get current chain ID."""
        return await self.w3.eth.chain_id

    async def get_block_number(self) -> int:
        """Get latest block number."""
        return await self.w3.eth.block_number

    async def get_balance(self, address: str | Address) -> int:
        """
        Get ETH/native token balance for address.
        
        Args:
            address: Wallet or contract address
            
        Returns:
            Balance in wei
        """
        checksum_addr = to_checksum_address(address)
        return await self.w3.eth.get_balance(checksum_addr)

    async def get_balance_ether(self, address: str | Address) -> float:
        """Get balance in ether (human-readable)."""
        balance_wei = await self.get_balance(address)
        return float(self.w3.from_wei(balance_wei, "ether"))

    async def get_code(self, address: str | Address) -> HexStr:
        """
        Get bytecode of a contract.
        
        Args:
            address: Contract address
            
        Returns:
            Contract bytecode as hex string
        """
        checksum_addr = to_checksum_address(address)
        return await self.w3.eth.get_code(checksum_addr)

    async def is_contract(self, address: str | Address) -> bool:
        """Check if address is a contract."""
        code = await self.get_code(address)
        return code != HexStr("0x")

    async def get_transaction(self, tx_hash: str | HexStr) -> TxData:
        """
        Get transaction details.
        
        Args:
            tx_hash: Transaction hash
            
        Returns:
            Transaction data
        """
        return await self.w3.eth.get_transaction(tx_hash)

    async def get_transaction_receipt(self, tx_hash: str | HexStr) -> TxReceipt:
        """
        Get transaction receipt.
        
        Args:
            tx_hash: Transaction hash
            
        Returns:
            Transaction receipt with logs
        """
        return await self.w3.eth.get_transaction_receipt(tx_hash)

    async def get_block(
        self,
        block_identifier: int | str = "latest",
        full_transactions: bool = False,
    ) -> BlockData:
        """
        Get block data.
        
        Args:
            block_identifier: Block number or "latest"/"pending"
            full_transactions: Include full transaction data
            
        Returns:
            Block data
        """
        return await self.w3.eth.get_block(block_identifier, full_transactions)

    async def get_logs(
        self,
        contract_address: str | Address | None = None,
        topics: list[str] | None = None,
        from_block: int | str = "earliest",
        to_block: int | str = "latest",
    ) -> list[EventData]:
        """
        Get contract event logs.
        
        Args:
            contract_address: Filter by contract address
            topics: Event topics to filter by
            from_block: Start block
            to_block: End block
            
        Returns:
            List of event logs
        """
        filter_params: dict[str, Any] = {
            "fromBlock": from_block,
            "toBlock": to_block,
        }

        if contract_address:
            filter_params["address"] = to_checksum_address(contract_address)

        if topics:
            filter_params["topics"] = topics

        return await self.w3.eth.get_logs(filter_params)

    def get_contract(
        self,
        address: str | Address,
        abi: list[dict[str, Any]],
    ) -> AsyncContract:
        """
        Get contract instance for interaction.
        
        Args:
            address: Contract address
            abi: Contract ABI
            
        Returns:
            Contract instance
        """
        checksum_addr = to_checksum_address(address)
        return self.w3.eth.contract(address=checksum_addr, abi=abi)

    async def call_contract_function(
        self,
        contract_address: str | Address,
        abi: list[dict[str, Any]],
        function_name: str,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """
        Call read-only contract function.
        
        Args:
            contract_address: Contract address
            abi: Contract ABI
            function_name: Function to call
            *args: Function arguments
            **kwargs: Additional call parameters
            
        Returns:
            Function return value
        """
        contract = self.get_contract(contract_address, abi)
        function = getattr(contract.functions, function_name)
        
        try:
            return await function(*args).call(**kwargs)
        except ContractLogicError as e:
            logger.error(f"Contract call reverted: {e}")
            raise
        except Web3Exception as e:
            logger.error(f"Web3 error: {e}")
            raise

    async def get_storage_at(
        self,
        address: str | Address,
        position: int,
        block_identifier: int | str = "latest",
    ) -> HexStr:
        """
        Read raw storage slot.
        
        Args:
            address: Contract address
            position: Storage slot position
            block_identifier: Block to query
            
        Returns:
            Storage value as hex
        """
        checksum_addr = to_checksum_address(address)
        return await self.w3.eth.get_storage_at(
            checksum_addr,
            position,
            block_identifier,
        )

    async def estimate_gas(
        self,
        transaction: dict[str, Any],
    ) -> int:
        """
        Estimate gas for a transaction.
        
        Args:
            transaction: Transaction parameters
            
        Returns:
            Estimated gas units
        """
        return await self.w3.eth.estimate_gas(transaction)

    async def get_gas_price(self) -> int:
        """Get current gas price in wei."""
        return await self.w3.eth.gas_price

    async def get_transaction_count(self, address: str | Address) -> int:
        """Get nonce for address."""
        checksum_addr = to_checksum_address(address)
        return await self.w3.eth.get_transaction_count(checksum_addr)


class MultiNetworkClient:
    """
    Manage multiple RPC clients for different networks.
    
    Useful for cross-chain analysis and comparison.
    """

    def __init__(self):
        """Initialize multi-network client."""
        self.clients: dict[NetworkType, RPCClient] = {}

    def add_network(
        self,
        network: NetworkType,
        rpc_url: str | None = None,
    ) -> RPCClient:
        """Add and return RPC client for network."""
        if network not in self.clients:
            self.clients[network] = RPCClient(network, rpc_url)
        return self.clients[network]

    def get_client(self, network: NetworkType) -> RPCClient | None:
        """Get RPC client for network."""
        return self.clients.get(network)

    async def check_all_connections(self) -> dict[NetworkType, bool]:
        """Check connection status for all networks."""
        results = {}
        for network, client in self.clients.items():
            results[network] = await client.is_connected()
        return results
