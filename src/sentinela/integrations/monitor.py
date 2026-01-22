"""
Suspicious Transaction Monitor

Monitors blockchain for suspicious activities and potential exploits
in real-time using the blockchain indexer.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from sentinela.integrations.indexer import BlockchainIndexer, IndexedTransaction
from sentinela.integrations.rpc import NetworkType, RPCClient

logger = logging.getLogger(__name__)


class SuspiciousActivityType(str, Enum):
    """Types of suspicious activities."""

    LARGE_TRANSFER = "large_transfer"
    RAPID_TRANSACTIONS = "rapid_transactions"
    CONTRACT_DRAIN = "contract_drain"
    UNUSUAL_GAS = "unusual_gas"
    FAILED_EXPLOIT_ATTEMPT = "failed_exploit_attempt"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    REENTRANCY_PATTERN = "reentrancy_pattern"
    FLASH_LOAN = "flash_loan"


class SuspiciousActivity(BaseModel):
    """Suspicious activity detection result."""

    activity_type: SuspiciousActivityType = Field(..., description="Type of activity")
    severity: str = Field(..., description="Severity: LOW, MEDIUM, HIGH, CRITICAL")
    contract_address: str = Field(..., description="Affected contract")
    transaction_hash: str = Field(..., description="Transaction hash")
    block_number: int = Field(..., description="Block number")
    timestamp: datetime = Field(..., description="Detection timestamp")
    description: str = Field(..., description="Activity description")
    details: dict[str, Any] = Field(default_factory=dict, description="Additional details")
    confidence: float = Field(..., description="Detection confidence (0-1)")


class TransactionMonitor:
    """
    Monitor blockchain transactions for suspicious activities.
    
    Uses pattern matching and heuristics to detect potential exploits.
    """

    def __init__(
        self,
        indexer: BlockchainIndexer,
        rpc_client: RPCClient,
    ):
        """
        Initialize monitor.
        
        Args:
            indexer: Blockchain indexer
            rpc_client: RPC client for queries
        """
        self.indexer = indexer
        self.rpc = rpc_client

        # Detection thresholds
        self.large_transfer_threshold_eth = 100.0  # 100 ETH
        self.rapid_tx_threshold = 10  # 10 tx in 1 block
        self.failed_tx_threshold = 5  # 5 consecutive failures

        # Tracking
        self.tracked_contracts: set[str] = set()
        self.alerts: list[SuspiciousActivity] = []
        self.last_checked_block = 0

    def track_contract(self, contract_address: str) -> None:
        """Add contract to monitoring."""
        self.tracked_contracts.add(contract_address)
        self.indexer.track_contract(contract_address)
        logger.info(f"Now monitoring contract: {contract_address}")

    async def analyze_transaction(
        self,
        tx: IndexedTransaction,
    ) -> list[SuspiciousActivity]:
        """
        Analyze transaction for suspicious patterns.
        
        Args:
            tx: Transaction to analyze
            
        Returns:
            List of detected suspicious activities
        """
        alerts: list[SuspiciousActivity] = []

        # Check for large transfers
        if await self._is_large_transfer(tx):
            alerts.append(
                SuspiciousActivity(
                    activity_type=SuspiciousActivityType.LARGE_TRANSFER,
                    severity="HIGH",
                    contract_address=tx.to_address or "",
                    transaction_hash=tx.transaction_hash,
                    block_number=tx.block_number,
                    timestamp=datetime.fromtimestamp(tx.block_timestamp),
                    description=f"Large transfer detected: {self.rpc.w3.from_wei(tx.value, 'ether')} ETH",
                    details={"value_wei": tx.value, "from": tx.from_address},
                    confidence=0.9,
                )
            )

        # Check for failed transactions (potential exploit attempts)
        if tx.status == 0:
            alerts.append(
                SuspiciousActivity(
                    activity_type=SuspiciousActivityType.FAILED_EXPLOIT_ATTEMPT,
                    severity="MEDIUM",
                    contract_address=tx.to_address or "",
                    transaction_hash=tx.transaction_hash,
                    block_number=tx.block_number,
                    timestamp=datetime.fromtimestamp(tx.block_timestamp),
                    description="Failed transaction - possible exploit attempt",
                    details={"gas_used": tx.gas_used, "from": tx.from_address},
                    confidence=0.6,
                )
            )

        # Check for unusual gas usage
        if await self._is_unusual_gas(tx):
            alerts.append(
                SuspiciousActivity(
                    activity_type=SuspiciousActivityType.UNUSUAL_GAS,
                    severity="LOW",
                    contract_address=tx.to_address or "",
                    transaction_hash=tx.transaction_hash,
                    block_number=tx.block_number,
                    timestamp=datetime.fromtimestamp(tx.block_timestamp),
                    description=f"Unusual gas usage: {tx.gas_used}",
                    details={"gas_used": tx.gas_used, "gas_price": tx.gas_price},
                    confidence=0.7,
                )
            )

        # Check for potential reentrancy (multiple calls in same tx)
        if await self._is_reentrancy_pattern(tx):
            alerts.append(
                SuspiciousActivity(
                    activity_type=SuspiciousActivityType.REENTRANCY_PATTERN,
                    severity="CRITICAL",
                    contract_address=tx.to_address or "",
                    transaction_hash=tx.transaction_hash,
                    block_number=tx.block_number,
                    timestamp=datetime.fromtimestamp(tx.block_timestamp),
                    description="Potential reentrancy pattern detected",
                    details={"input_data": tx.input_data[:100]},
                    confidence=0.8,
                )
            )

        return alerts

    async def _is_large_transfer(self, tx: IndexedTransaction) -> bool:
        """Check if transaction is a large transfer."""
        value_eth = float(self.rpc.w3.from_wei(tx.value, "ether"))
        return value_eth > self.large_transfer_threshold_eth

    async def _is_unusual_gas(self, tx: IndexedTransaction) -> bool:
        """Check if gas usage is unusual."""
        # Heuristic: Very high gas usage might indicate complex exploit
        return tx.gas_used > 5_000_000

    async def _is_reentrancy_pattern(self, tx: IndexedTransaction) -> bool:
        """Check for reentrancy patterns."""
        # Simplified: Check if transaction has multiple internal calls
        # In real implementation, would analyze call trace
        try:
            receipt = await self.rpc.get_transaction_receipt(tx.transaction_hash)
            # Multiple logs might indicate multiple state changes
            return len(receipt.get("logs", [])) > 10
        except Exception:
            return False

    async def analyze_block(self, block_number: int) -> list[SuspiciousActivity]:
        """
        Analyze all transactions in a block.
        
        Args:
            block_number: Block to analyze
            
        Returns:
            List of suspicious activities
        """
        alerts: list[SuspiciousActivity] = []

        # Get transactions from indexer
        transactions = self.indexer.query_transactions(
            from_block=block_number,
            to_block=block_number,
        )

        # Filter to tracked contracts only
        relevant_txs = [
            tx for tx in transactions
            if tx.to_address in self.tracked_contracts
        ]

        # Check for rapid transactions
        if len(relevant_txs) > self.rapid_tx_threshold:
            for contract in self.tracked_contracts:
                contract_txs = [
                    tx for tx in relevant_txs if tx.to_address == contract
                ]
                if len(contract_txs) > self.rapid_tx_threshold:
                    alerts.append(
                        SuspiciousActivity(
                            activity_type=SuspiciousActivityType.RAPID_TRANSACTIONS,
                            severity="MEDIUM",
                            contract_address=contract,
                            transaction_hash=contract_txs[0].transaction_hash,
                            block_number=block_number,
                            timestamp=datetime.now(),
                            description=f"Rapid transactions detected: {len(contract_txs)} tx in one block",
                            details={"tx_count": len(contract_txs)},
                            confidence=0.8,
                        )
                    )

        # Analyze each transaction
        for tx in relevant_txs:
            tx_alerts = await self.analyze_transaction(tx)
            alerts.extend(tx_alerts)

        return alerts

    async def check_contract_drain(
        self,
        contract_address: str,
        time_window_blocks: int = 10,
    ) -> SuspiciousActivity | None:
        """
        Check if contract is being drained.
        
        Args:
            contract_address: Contract to check
            time_window_blocks: Number of blocks to analyze
            
        Returns:
            Alert if drain detected
        """
        current_block = await self.rpc.get_block_number()
        from_block = current_block - time_window_blocks

        # Get recent transactions
        transactions = self.indexer.query_transactions(
            address=contract_address,
            from_block=from_block,
            to_block=current_block,
        )

        # Calculate net outflow
        total_out = sum(
            tx.value for tx in transactions if tx.from_address == contract_address
        )
        total_in = sum(
            tx.value for tx in transactions if tx.to_address == contract_address
        )

        net_outflow = total_out - total_in

        # Check if significant drain
        if net_outflow > self.rpc.w3.to_wei(50, "ether"):
            return SuspiciousActivity(
                activity_type=SuspiciousActivityType.CONTRACT_DRAIN,
                severity="CRITICAL",
                contract_address=contract_address,
                transaction_hash="",
                block_number=current_block,
                timestamp=datetime.now(),
                description=f"Contract drain detected: {self.rpc.w3.from_wei(net_outflow, 'ether')} ETH outflow",
                details={
                    "net_outflow_wei": net_outflow,
                    "total_out": total_out,
                    "total_in": total_in,
                    "time_window_blocks": time_window_blocks,
                },
                confidence=0.95,
            )

        return None

    async def start_monitoring(
        self,
        poll_interval: int = 12,
    ) -> None:
        """
        Start continuous monitoring.
        
        Args:
            poll_interval: Seconds between checks
        """
        logger.info("Starting transaction monitoring...")

        if not self.tracked_contracts:
            logger.warning("No contracts tracked, monitoring will not detect anything")

        # Get starting block
        if self.last_checked_block == 0:
            self.last_checked_block = await self.rpc.get_block_number()

        while True:
            try:
                current_block = await self.rpc.get_block_number()

                if current_block > self.last_checked_block:
                    # Analyze new blocks
                    for block in range(
                        self.last_checked_block + 1, current_block + 1
                    ):
                        alerts = await self.analyze_block(block)

                        for alert in alerts:
                            self.alerts.append(alert)
                            logger.warning(
                                f"🚨 {alert.severity} ALERT: {alert.activity_type.value} "
                                f"at {alert.contract_address[:10]}... "
                                f"(Block {alert.block_number})"
                            )

                    # Check for contract drains
                    for contract in self.tracked_contracts:
                        drain_alert = await self.check_contract_drain(contract)
                        if drain_alert:
                            self.alerts.append(drain_alert)
                            logger.critical(
                                f"🔥 CONTRACT DRAIN: {contract[:10]}... "
                                f"- {drain_alert.description}"
                            )

                    self.last_checked_block = current_block

                await asyncio.sleep(poll_interval)

            except KeyboardInterrupt:
                logger.info("Stopping monitoring...")
                break
            except Exception as e:
                logger.error(f"Monitoring error: {e}")
                await asyncio.sleep(poll_interval)

    def get_alerts(
        self,
        severity: str | None = None,
        activity_type: SuspiciousActivityType | None = None,
        limit: int = 100,
    ) -> list[SuspiciousActivity]:
        """
        Get recent alerts.
        
        Args:
            severity: Filter by severity
            activity_type: Filter by activity type
            limit: Maximum alerts to return
            
        Returns:
            List of alerts
        """
        filtered = self.alerts

        if severity:
            filtered = [a for a in filtered if a.severity == severity]

        if activity_type:
            filtered = [a for a in filtered if a.activity_type == activity_type]

        return filtered[-limit:]

    def get_stats(self) -> dict[str, Any]:
        """Get monitoring statistics."""
        return {
            "tracked_contracts": len(self.tracked_contracts),
            "total_alerts": len(self.alerts),
            "critical_alerts": len([a for a in self.alerts if a.severity == "CRITICAL"]),
            "high_alerts": len([a for a in self.alerts if a.severity == "HIGH"]),
            "last_checked_block": self.last_checked_block,
        }
