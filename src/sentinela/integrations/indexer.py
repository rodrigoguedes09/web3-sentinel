"""
Blockchain Event Indexer

Indexes contract events, transactions, and state changes for efficient querying.
Eliminates need for external explorers by maintaining local index.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from eth_typing import Address, ChecksumAddress, HexStr
from eth_utils import to_checksum_address
from pydantic import BaseModel, Field
from web3.types import EventData, TxReceipt

from sentinela.integrations.rpc import NetworkType, RPCClient

logger = logging.getLogger(__name__)


class IndexedEvent(BaseModel):
    """Indexed blockchain event."""

    event_name: str = Field(..., description="Event name")
    contract_address: ChecksumAddress = Field(..., description="Contract address")
    transaction_hash: HexStr = Field(..., description="Transaction hash")
    block_number: int = Field(..., description="Block number")
    block_timestamp: int = Field(..., description="Block timestamp")
    log_index: int = Field(..., description="Log index")
    args: dict[str, Any] = Field(default_factory=dict, description="Event arguments")
    raw_log: dict[str, Any] = Field(default_factory=dict, description="Raw log data")


class IndexedTransaction(BaseModel):
    """Indexed transaction."""

    transaction_hash: HexStr = Field(..., description="Transaction hash")
    from_address: ChecksumAddress = Field(..., description="Sender address")
    to_address: ChecksumAddress | None = Field(None, description="Recipient address")
    value: int = Field(..., description="Value in wei")
    gas_used: int = Field(..., description="Gas used")
    gas_price: int = Field(..., description="Gas price")
    block_number: int = Field(..., description="Block number")
    block_timestamp: int = Field(..., description="Block timestamp")
    status: int = Field(..., description="Transaction status (1=success, 0=fail)")
    input_data: HexStr = Field(default=HexStr("0x"), description="Input data")


class ContractInteraction(BaseModel):
    """Contract interaction summary."""

    contract_address: ChecksumAddress = Field(..., description="Contract address")
    function_signature: str = Field(..., description="Function signature")
    caller: ChecksumAddress = Field(..., description="Caller address")
    transaction_hash: HexStr = Field(..., description="Transaction hash")
    block_number: int = Field(..., description="Block number")
    success: bool = Field(..., description="Whether call succeeded")
    events_emitted: list[str] = Field(default_factory=list, description="Events emitted")


@dataclass
class IndexerStats:
    """Indexer statistics."""

    total_blocks_indexed: int = 0
    total_transactions_indexed: int = 0
    total_events_indexed: int = 0
    total_contracts_tracked: int = 0
    last_indexed_block: int = 0
    indexing_start_time: datetime = field(default_factory=datetime.now)
    indexing_end_time: datetime | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "total_blocks_indexed": self.total_blocks_indexed,
            "total_transactions_indexed": self.total_transactions_indexed,
            "total_events_indexed": self.total_events_indexed,
            "total_contracts_tracked": self.total_contracts_tracked,
            "last_indexed_block": self.last_indexed_block,
            "indexing_start_time": self.indexing_start_time.isoformat(),
            "indexing_end_time": self.indexing_end_time.isoformat() if self.indexing_end_time else None,
        }


class BlockchainIndexer:
    """
    Indexes blockchain events and transactions for efficient querying.
    
    Features:
    - Event indexing with automatic decoding
    - Transaction history tracking
    - Contract interaction monitoring
    - Incremental indexing (resume from last block)
    - Local storage for offline access
    """

    def __init__(
        self,
        rpc_client: RPCClient,
        storage_dir: Path | str = "./data/blockchain_index",
    ):
        """
        Initialize indexer.
        
        Args:
            rpc_client: RPC client for blockchain access
            storage_dir: Directory for storing indexed data
        """
        self.rpc = rpc_client
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # Storage files
        self.events_file = self.storage_dir / "events.jsonl"
        self.transactions_file = self.storage_dir / "transactions.jsonl"
        self.stats_file = self.storage_dir / "stats.json"

        # Load existing stats
        self.stats = self._load_stats()

        # In-memory cache
        self.tracked_contracts: set[ChecksumAddress] = set()
        self.event_signatures: dict[str, str] = {}  # topic -> event name

    def _load_stats(self) -> IndexerStats:
        """Load indexer statistics."""
        if self.stats_file.exists():
            try:
                with open(self.stats_file, "r") as f:
                    data = json.load(f)
                    stats = IndexerStats(**data)
                    stats.indexing_start_time = datetime.fromisoformat(data["indexing_start_time"])
                    if data.get("indexing_end_time"):
                        stats.indexing_end_time = datetime.fromisoformat(data["indexing_end_time"])
                    return stats
            except Exception as e:
                logger.warning(f"Failed to load stats: {e}")

        return IndexerStats()

    def _save_stats(self) -> None:
        """Save indexer statistics."""
        try:
            with open(self.stats_file, "w") as f:
                json.dump(self.stats.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"Failed to save stats: {e}")

    def track_contract(
        self,
        address: str | Address,
        abi: list[dict[str, Any]] | None = None,
    ) -> None:
        """
        Add contract to tracking list.
        
        Args:
            address: Contract address
            abi: Contract ABI (for event decoding)
        """
        checksum_addr = to_checksum_address(address)
        self.tracked_contracts.add(checksum_addr)

        # Extract event signatures from ABI
        if abi:
            for item in abi:
                if item.get("type") == "event":
                    event_name = item["name"]
                    # Compute topic0 (event signature hash)
                    # This is simplified - full implementation would use web3's event signature
                    self.event_signatures[event_name] = event_name

        self.stats.total_contracts_tracked = len(self.tracked_contracts)
        logger.info(f"Now tracking contract: {checksum_addr}")

    async def index_block_range(
        self,
        from_block: int,
        to_block: int,
        batch_size: int = 100,
    ) -> IndexerStats:
        """
        Index blocks in specified range.
        
        Args:
            from_block: Start block
            to_block: End block
            batch_size: Number of blocks per batch
            
        Returns:
            IndexerStats with updated statistics
        """
        logger.info(f"Indexing blocks {from_block} to {to_block}")

        for start in range(from_block, to_block + 1, batch_size):
            end = min(start + batch_size - 1, to_block)
            
            try:
                await self._index_batch(start, end)
            except Exception as e:
                logger.error(f"Failed to index batch {start}-{end}: {e}")
                continue

        self.stats.indexing_end_time = datetime.now()
        self._save_stats()
        logger.info("Indexing complete")
        
        return self.stats

    async def _index_batch(self, from_block: int, to_block: int) -> None:
        """Index a batch of blocks."""
        # Get logs for tracked contracts
        for contract_addr in self.tracked_contracts:
            try:
                logs = await self.rpc.get_logs(
                    contract_address=contract_addr,
                    from_block=from_block,
                    to_block=to_block,
                )

                await self._process_logs(logs)
            except Exception as e:
                logger.warning(f"Failed to get logs for {contract_addr}: {e}")

        self.stats.last_indexed_block = to_block
        self.stats.total_blocks_indexed += (to_block - from_block + 1)

    async def _process_logs(self, logs: list[EventData]) -> None:
        """Process and store event logs."""
        for log in logs:
            try:
                # Get block to extract timestamp
                block = await self.rpc.get_block(log["blockNumber"])

                # Create indexed event
                event = IndexedEvent(
                    event_name=log.get("event", "Unknown"),
                    contract_address=to_checksum_address(log["address"]),
                    transaction_hash=log["transactionHash"].hex(),
                    block_number=log["blockNumber"],
                    block_timestamp=block["timestamp"],
                    log_index=log["logIndex"],
                    args=dict(log.get("args", {})),
                    raw_log={k: str(v) for k, v in log.items()},
                )

                # Append to storage
                with open(self.events_file, "a") as f:
                    f.write(event.model_dump_json() + "\n")

                self.stats.total_events_indexed += 1

            except Exception as e:
                logger.warning(f"Failed to process log: {e}")

    async def index_transaction(self, tx_hash: str | HexStr) -> IndexedTransaction | None:
        """
        Index a specific transaction.
        
        Args:
            tx_hash: Transaction hash
            
        Returns:
            Indexed transaction or None if failed
        """
        try:
            # Get transaction and receipt
            tx = await self.rpc.get_transaction(tx_hash)
            receipt = await self.rpc.get_transaction_receipt(tx_hash)
            block = await self.rpc.get_block(tx["blockNumber"])

            # Create indexed transaction
            indexed_tx = IndexedTransaction(
                transaction_hash=tx["hash"].hex(),
                from_address=to_checksum_address(tx["from"]),
                to_address=to_checksum_address(tx["to"]) if tx.get("to") else None,
                value=tx["value"],
                gas_used=receipt["gasUsed"],
                gas_price=tx["gasPrice"],
                block_number=tx["blockNumber"],
                block_timestamp=block["timestamp"],
                status=receipt["status"],
                input_data=tx["input"].hex(),
            )

            # Save to storage
            with open(self.transactions_file, "a") as f:
                f.write(indexed_tx.model_dump_json() + "\n")

            self.stats.total_transactions_indexed += 1
            return indexed_tx

        except Exception as e:
            logger.error(f"Failed to index transaction {tx_hash}: {e}")
            return None

    def query_events(
        self,
        contract_address: str | Address | None = None,
        event_name: str | None = None,
        from_block: int | None = None,
        to_block: int | None = None,
        limit: int = 100,
    ) -> list[IndexedEvent]:
        """
        Query indexed events.
        
        Args:
            contract_address: Filter by contract
            event_name: Filter by event name
            from_block: Start block
            to_block: End block
            limit: Maximum results
            
        Returns:
            List of matching events
        """
        if not self.events_file.exists():
            return []

        results: list[IndexedEvent] = []
        checksum_addr = to_checksum_address(contract_address) if contract_address else None

        with open(self.events_file, "r") as f:
            for line in f:
                if len(results) >= limit:
                    break

                try:
                    event = IndexedEvent.model_validate_json(line)

                    # Apply filters
                    if checksum_addr and event.contract_address != checksum_addr:
                        continue
                    if event_name and event.event_name != event_name:
                        continue
                    if from_block and event.block_number < from_block:
                        continue
                    if to_block and event.block_number > to_block:
                        continue

                    results.append(event)

                except Exception as e:
                    logger.warning(f"Failed to parse event line: {e}")

        return results

    def query_transactions(
        self,
        address: str | Address | None = None,
        from_block: int | None = None,
        to_block: int | None = None,
        limit: int = 100,
    ) -> list[IndexedTransaction]:
        """
        Query indexed transactions.
        
        Args:
            address: Filter by from/to address
            from_block: Start block
            to_block: End block
            limit: Maximum results
            
        Returns:
            List of matching transactions
        """
        if not self.transactions_file.exists():
            return []

        results: list[IndexedTransaction] = []
        checksum_addr = to_checksum_address(address) if address else None

        with open(self.transactions_file, "r") as f:
            for line in f:
                if len(results) >= limit:
                    break

                try:
                    tx = IndexedTransaction.model_validate_json(line)

                    # Apply filters
                    if checksum_addr and tx.from_address != checksum_addr and tx.to_address != checksum_addr:
                        continue
                    if from_block and tx.block_number < from_block:
                        continue
                    if to_block and tx.block_number > to_block:
                        continue

                    results.append(tx)

                except Exception as e:
                    logger.warning(f"Failed to parse transaction line: {e}")

        return results

    async def start_live_indexing(
        self,
        poll_interval: int = 12,  # ~1 block time
    ) -> None:
        """
        Start continuous indexing of new blocks.
        
        Args:
            poll_interval: Seconds between checks
        """
        logger.info("Starting live indexing...")

        while True:
            try:
                current_block = await self.rpc.get_block_number()
                last_indexed = self.stats.last_indexed_block

                if current_block > last_indexed:
                    await self.index_block_range(last_indexed + 1, current_block)

                await asyncio.sleep(poll_interval)

            except KeyboardInterrupt:
                logger.info("Stopping live indexing...")
                break
            except Exception as e:
                logger.error(f"Live indexing error: {e}")
                await asyncio.sleep(poll_interval)

    def get_stats(self) -> IndexerStats:
        """Get indexer statistics."""
        return self.stats
