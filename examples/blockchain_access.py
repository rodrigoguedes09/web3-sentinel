"""
Example: Using Direct RPC and Blockchain Indexer

This example demonstrates how to use the RPC client and indexer
to interact with blockchain without relying on external explorers.
"""

import asyncio
from pathlib import Path

from sentinela.integrations.explorer import UnifiedExplorer
from sentinela.integrations.indexer import BlockchainIndexer
from sentinela.integrations.rpc import NetworkType, RPCClient


async def example_rpc_basic():
    """Basic RPC operations."""
    print("\n=== Example 1: Basic RPC Operations ===")
    
    # Initialize RPC client for Ethereum mainnet
    rpc = RPCClient(network=NetworkType.ETHEREUM_MAINNET)
    
    # Check connection
    connected = await rpc.is_connected()
    print(f"Connected: {connected}")
    
    if not connected:
        print("Failed to connect to RPC endpoint")
        return
    
    # Get chain info
    chain_id = await rpc.get_chain_id()
    block_number = await rpc.get_block_number()
    print(f"Chain ID: {chain_id}")
    print(f"Latest Block: {block_number}")
    
    # Check balance
    vitalik_address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    balance_wei = await rpc.get_balance(vitalik_address)
    balance_eth = await rpc.get_balance_ether(vitalik_address)
    print(f"\nVitalik's Balance:")
    print(f"  Wei: {balance_wei}")
    print(f"  ETH: {balance_eth:.4f}")
    
    # Check if address is contract
    uniswap_router = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
    is_contract = await rpc.is_contract(uniswap_router)
    print(f"\nUniswap Router is contract: {is_contract}")
    
    # Get contract bytecode
    if is_contract:
        code = await rpc.get_code(uniswap_router)
        print(f"Bytecode length: {len(code)} characters")


async def example_indexer():
    """Blockchain event indexing."""
    print("\n=== Example 2: Blockchain Indexer ===")
    
    # Initialize RPC and indexer
    rpc = RPCClient(network=NetworkType.ETHEREUM_MAINNET)
    indexer = BlockchainIndexer(
        rpc_client=rpc,
        storage_dir=Path("./data/blockchain_index"),
    )
    
    # Track a contract (e.g., USDT)
    usdt_address = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
    indexer.track_contract(usdt_address)
    
    # Index recent blocks (last 100 blocks)
    latest_block = await rpc.get_block_number()
    from_block = latest_block - 100
    
    print(f"Indexing blocks {from_block} to {latest_block}...")
    await indexer.index_block_range(from_block, latest_block, batch_size=10)
    
    # Get statistics
    stats = indexer.get_stats()
    print(f"\nIndexer Stats:")
    print(f"  Blocks indexed: {stats.total_blocks_indexed}")
    print(f"  Events indexed: {stats.total_events_indexed}")
    print(f"  Transactions indexed: {stats.total_transactions_indexed}")
    
    # Query indexed events
    events = indexer.query_events(
        contract_address=usdt_address,
        limit=10,
    )
    print(f"\nFound {len(events)} events for USDT")
    for event in events[:3]:
        print(f"  - {event.event_name} at block {event.block_number}")


async def example_unified_explorer():
    """Using unified explorer (RPC + external API)."""
    print("\n=== Example 3: Unified Explorer ===")
    
    # Initialize explorer (uses RPC, falls back to Etherscan if needed)
    explorer = UnifiedExplorer(
        network=NetworkType.ETHEREUM_MAINNET,
        explorer_api_key=None,  # Optional: Add Etherscan API key
    )
    
    # Check balance (uses RPC)
    address = "0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045"
    balance = await explorer.get_balance(address)
    print(f"Balance (RPC): {balance} wei")
    
    # Check if contract
    contract_addr = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"
    is_contract = await explorer.is_contract(contract_addr)
    print(f"Is contract (RPC): {is_contract}")
    
    # Get contract source (requires Etherscan API key)
    print("\nTo fetch verified source code, set explorer_api_key")
    print("Example: explorer = UnifiedExplorer(..., explorer_api_key='YOUR_KEY')")


async def example_transaction_analysis():
    """Analyze a specific transaction."""
    print("\n=== Example 4: Transaction Analysis ===")
    
    rpc = RPCClient(network=NetworkType.ETHEREUM_MAINNET)
    
    # Analyze a transaction
    tx_hash = "0x5c504ed432cb51138bcf09aa5e8a410dd4a1e204ef84bfed1be16dfba1b22060"
    
    print(f"Analyzing transaction: {tx_hash}")
    
    try:
        tx = await rpc.get_transaction(tx_hash)
        receipt = await rpc.get_transaction_receipt(tx_hash)
        
        print(f"\nTransaction Details:")
        print(f"  From: {tx['from']}")
        print(f"  To: {tx.get('to', 'Contract Creation')}")
        print(f"  Value: {rpc.w3.from_wei(tx['value'], 'ether')} ETH")
        print(f"  Gas Used: {receipt['gasUsed']}")
        print(f"  Status: {'Success' if receipt['status'] == 1 else 'Failed'}")
        print(f"  Block: {tx['blockNumber']}")
        
        # Check logs/events
        if receipt['logs']:
            print(f"\n  Events emitted: {len(receipt['logs'])}")
            for i, log in enumerate(receipt['logs'][:3]):
                print(f"    Log {i}: {log['address']}")
        
    except Exception as e:
        print(f"Error: {e}")


async def example_multi_network():
    """Working with multiple networks."""
    print("\n=== Example 5: Multi-Network ===")
    
    networks = [
        NetworkType.ETHEREUM_MAINNET,
        NetworkType.POLYGON,
        NetworkType.BSC,
    ]
    
    # Same contract address on different networks
    test_address = "0x0000000000000000000000000000000000000000"
    
    for network in networks:
        try:
            rpc = RPCClient(network=network)
            connected = await rpc.is_connected()
            
            if connected:
                block = await rpc.get_block_number()
                print(f"{network.value:20} - Block: {block:,}")
            else:
                print(f"{network.value:20} - Not connected")
                
        except Exception as e:
            print(f"{network.value:20} - Error: {e}")


async def main():
    """Run all examples."""
    print("=" * 60)
    print("Sentinela Web3 - Direct Blockchain Access Examples")
    print("=" * 60)
    
    try:
        await example_rpc_basic()
        # await example_indexer()  # Uncomment to test indexing
        await example_unified_explorer()
        # await example_transaction_analysis()  # Uncomment to test
        await example_multi_network()
        
    except KeyboardInterrupt:
        print("\n\nExamples interrupted")
    except Exception as e:
        print(f"\nError running examples: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
