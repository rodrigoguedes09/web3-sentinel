"""
Integration tests for advanced blockchain features.

Tests:
1. RPC client connection and queries
2. Cache hit/miss behavior
3. Indexer event tracking
4. Monitor suspicious activity detection
5. Cross-chain deployment detection
6. End-to-end workflow
"""

import asyncio
import os
import tempfile
from pathlib import Path

import pytest

from sentinela.core.config import get_settings
from sentinela.integrations.cache import BlockchainQueryCache, QueryCache
from sentinela.integrations.cross_chain import CrossChainAnalyzer
from sentinela.integrations.explorer import MultiChainExplorer, UnifiedExplorer
from sentinela.integrations.indexer import BlockchainIndexer
from sentinela.integrations.monitor import TransactionMonitor
from sentinela.integrations.rpc import NetworkType, RPCClient


@pytest.fixture
def temp_cache_dir():
    """Create temporary cache directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
def temp_indexer_dir():
    """Create temporary indexer directory."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


@pytest.fixture
async def rpc_client():
    """Create RPC client for Ethereum mainnet."""
    return RPCClient(NetworkType.ETHEREUM_MAINNET)


@pytest.fixture
async def query_cache(temp_cache_dir):
    """Create query cache."""
    return QueryCache(cache_dir=temp_cache_dir, ttl_seconds=60)


@pytest.fixture
async def blockchain_cache(query_cache):
    """Create blockchain query cache."""
    return BlockchainQueryCache(query_cache)


class TestRPCClient:
    """Test RPC client functionality."""

    @pytest.mark.asyncio
    async def test_get_balance(self, rpc_client):
        """Test balance query."""
        # Vitalik's address
        address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        balance = await rpc_client.get_balance(address)

        assert isinstance(balance, int)
        assert balance >= 0

        # Convert to ETH
        balance_eth = float(rpc_client.w3.from_wei(balance, "ether"))
        print(f"\nVitalik balance: {balance_eth:.4f} ETH")

    @pytest.mark.asyncio
    async def test_is_contract(self, rpc_client):
        """Test contract detection."""
        # Uniswap V2 Router
        contract = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
        is_contract = await rpc_client.is_contract(contract)

        assert is_contract is True
        print(f"\nUniswap Router is contract: {is_contract}")

        # Known EOA (Binance Hot Wallet)
        eoa = "0x28C6c06298d514Db089934071355E5743bf21d60"
        is_eoa_contract = await rpc_client.is_contract(eoa)

        # Note: Even large wallets can be contracts (Safe multisig, etc)
        # So we just check it doesn't error
        print(f"Test address is contract: {is_eoa_contract}")
        print(f"Vitalik (EOA) is contract: {is_eoa_contract}")

    @pytest.mark.asyncio
    async def test_get_code(self, rpc_client):
        """Test bytecode retrieval."""
        # Uniswap V2 Router
        contract = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
        code = await rpc_client.get_code(contract)

        assert isinstance(code, bytes)
        assert len(code) > 0
        print(f"\nUniswap Router bytecode: {len(code):,} bytes")

    @pytest.mark.asyncio
    async def test_get_block_number(self, rpc_client):
        """Test current block retrieval."""
        block = await rpc_client.get_block_number()

        assert isinstance(block, int)
        assert block > 0
        print(f"\nCurrent Ethereum block: {block:,}")


class TestQueryCache:
    """Test query caching functionality."""

    @pytest.mark.asyncio
    async def test_cache_miss_then_hit(self, blockchain_cache, rpc_client):
        """Test cache miss followed by cache hit."""
        address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        block = await rpc_client.get_block_number()

        # First query (miss)
        balance1 = await blockchain_cache.get_balance(address, "ethereum", block)
        assert balance1 is None  # Cache miss

        # Fetch and cache
        actual_balance = await rpc_client.get_balance(address)
        await blockchain_cache.set_balance(address, "ethereum", block, actual_balance)

        # Second query (hit)
        balance2 = await blockchain_cache.get_balance(address, "ethereum", block)
        assert balance2 == actual_balance  # Cache hit
        print(f"\n✅ Cache hit! Balance: {balance2}")

    @pytest.mark.asyncio
    async def test_cache_statistics(self, query_cache, blockchain_cache, rpc_client):
        """Test cache statistics tracking."""
        address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
        block = await rpc_client.get_block_number()

        # Generate some cache activity
        for _ in range(3):
            balance = await blockchain_cache.get_balance(address, "ethereum", block)
            if balance is None:
                balance = await rpc_client.get_balance(address)
                await blockchain_cache.set_balance(
                    address, "ethereum", block, balance
                )

        # Check statistics
        stats = query_cache.get_stats()
        assert stats["entries"] > 0
        assert stats["hits"] >= 2  # Should have 2 hits
        assert stats["misses"] >= 1  # Should have 1 miss
        print(f"\nCache stats: {stats}")

    @pytest.mark.asyncio
    async def test_bytecode_caching(self, blockchain_cache, rpc_client):
        """Test bytecode caching (immutable data)."""
        contract = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"

        # First query (miss)
        bytecode1 = await blockchain_cache.get_bytecode(contract, "ethereum")
        assert bytecode1 is None

        # Fetch and cache
        actual_code = await rpc_client.get_code(contract)
        await blockchain_cache.set_bytecode(contract, "ethereum", actual_code)

        # Second query (hit)
        bytecode2 = await blockchain_cache.get_bytecode(contract, "ethereum")
        
        # Compare as hex strings (cache stores as hex string)
        actual_code_hex = actual_code.hex() if hasattr(actual_code, 'hex') else actual_code
        assert bytecode2 == actual_code_hex
        print(f"\n✅ Bytecode cached! Size: {len(bytecode2)} characters")


class TestBlockchainIndexer:
    """Test blockchain event indexing."""

    @pytest.mark.asyncio
    async def test_track_contract(self, rpc_client, temp_indexer_dir):
        """Test contract tracking."""
        indexer = BlockchainIndexer(rpc_client, storage_dir=temp_indexer_dir)

        # Track USDT
        usdt = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
        indexer.track_contract(usdt)

        assert usdt in indexer.tracked_contracts
        print(f"\n✅ Tracking {usdt}")

    @pytest.mark.asyncio
    async def test_index_blocks(self, rpc_client, temp_indexer_dir):
        """Test block indexing."""
        indexer = BlockchainIndexer(rpc_client, storage_dir=temp_indexer_dir)

        # Track Uniswap Router
        router = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
        indexer.track_contract(router)

        # Index recent blocks (small range for speed)
        current_block = await rpc_client.get_block_number()
        from_block = current_block - 5
        to_block = current_block

        stats = await indexer.index_block_range(from_block, to_block, batch_size=5)

        assert stats.total_blocks_indexed > 0
        print(f"\n✅ Indexed {stats.total_blocks_indexed} blocks")
        print(f"   Events: {stats.total_events_indexed}")
        print(f"   Transactions: {stats.total_transactions_indexed}")


class TestTransactionMonitor:
    """Test suspicious transaction monitoring."""

    @pytest.mark.asyncio
    async def test_monitor_setup(self, rpc_client, temp_indexer_dir):
        """Test monitor initialization."""
        indexer = BlockchainIndexer(rpc_client, storage_dir=temp_indexer_dir)
        monitor = TransactionMonitor(indexer, rpc_client)

        # Track high-value contract
        usdt = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
        monitor.track_contract(usdt)

        assert usdt in monitor.tracked_contracts
        print(f"\n✅ Monitoring {usdt}")

    @pytest.mark.asyncio
    async def test_analyze_block(self, rpc_client, temp_indexer_dir):
        """Test block analysis for suspicious activity."""
        indexer = BlockchainIndexer(rpc_client, storage_dir=temp_indexer_dir)
        monitor = TransactionMonitor(indexer, rpc_client)

        # Track USDT
        usdt = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
        monitor.track_contract(usdt)

        # Index and analyze recent block
        current_block = await rpc_client.get_block_number()
        await indexer.index_block_range(current_block - 1, current_block)

        alerts = await monitor.analyze_block(current_block)

        # May or may not have alerts
        print(f"\n✅ Analyzed block {current_block}")
        print(f"   Alerts: {len(alerts)}")
        if alerts:
            for alert in alerts[:3]:
                print(f"   - {alert.severity}: {alert.activity_type.value}")


class TestCrossChainAnalyzer:
    """Test cross-chain vulnerability analysis."""

    @pytest.mark.asyncio
    async def test_find_deployments(self):
        """Test finding contract across chains."""
        multi_explorer = MultiChainExplorer()
        multi_explorer.add_network(NetworkType.ETHEREUM_MAINNET)
        multi_explorer.add_network(NetworkType.POLYGON)

        analyzer = CrossChainAnalyzer(multi_explorer)

        # USDC exists on multiple chains
        usdc_eth = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"

        deployments = await analyzer.find_contract_deployments(
            usdc_eth,
            networks=[NetworkType.ETHEREUM_MAINNET, NetworkType.POLYGON],
        )

        print(f"\n✅ Found {len(deployments)} deployments")
        for deployment in deployments:
            print(f"   - {deployment.network.value}: {deployment.address[:20]}...")

    @pytest.mark.asyncio
    async def test_network_comparison(self):
        """Test network security comparison."""
        multi_explorer = MultiChainExplorer()
        multi_explorer.add_network(NetworkType.ETHEREUM_MAINNET)
        multi_explorer.add_network(NetworkType.POLYGON)

        analyzer = CrossChainAnalyzer(multi_explorer)

        stats = await analyzer.compare_network_security(
            [NetworkType.ETHEREUM_MAINNET, NetworkType.POLYGON]
        )

        print(f"\n✅ Network comparison:")
        for network, data in stats.items():
            if "error" not in data:
                print(
                    f"   {network}: Block {data['current_block']:,}, "
                    f"Gas {data['gas_price_gwei']:.2f} Gwei"
                )


class TestEndToEnd:
    """End-to-end integration tests."""

    @pytest.mark.asyncio
    async def test_complete_workflow(
        self, rpc_client, blockchain_cache, temp_indexer_dir
    ):
        """Test complete workflow with all features."""
        # 1. Setup - Use Uniswap Router (known contract)
        target = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
        print(f"\n🎯 Target: {target}")

        # 2. Get balance (with caching)
        current_block = await rpc_client.get_block_number()
        balance = await blockchain_cache.get_balance(target, "ethereum", current_block)

        if balance is None:
            balance = await rpc_client.get_balance(target)
            await blockchain_cache.set_balance(target, "ethereum", current_block, balance)

        balance_eth = float(rpc_client.w3.from_wei(balance, "ether"))
        print(f"💰 Balance: {balance_eth:.4f} ETH")

        # 3. Check if contract
        is_contract = await rpc_client.is_contract(target)
        print(f"📜 Is Contract: {is_contract}")

        # 4. If contract, get bytecode
        if is_contract:
            bytecode = await blockchain_cache.get_bytecode(target, "ethereum")
            if bytecode is None:
                bytecode = await rpc_client.get_code(target)
                await blockchain_cache.set_bytecode(target, "ethereum", bytecode)

            print(f"🔢 Bytecode: {len(bytecode):,} bytes")

        # 5. Assess risk
        if balance_eth > 1000:
            risk = "CRITICAL"
        elif balance_eth > 100:
            risk = "HIGH"
        elif balance_eth > 10:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        print(f"⚠️  Risk Level: {risk}")

        # 6. Cache stats
        stats = blockchain_cache.cache.get_stats()
        print(f"\n📊 Cache Statistics:")
        print(f"   Hits: {stats['hits']}")
        print(f"   Misses: {stats['misses']}")
        print(f"   Hit Rate: {stats['hit_rate']}%")

        print(f"\n✅ Workflow complete!")


def run_tests():
    """Run all integration tests."""
    pytest.main([__file__, "-v", "-s"])


if __name__ == "__main__":
    run_tests()
