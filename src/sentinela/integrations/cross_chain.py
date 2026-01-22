"""
Cross-Chain Vulnerability Analyzer

Analyzes vulnerabilities across multiple blockchain networks
to detect patterns and systemic risks.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, Field

from sentinela.core.state import AttackHypothesis, VulnerabilityType
from sentinela.integrations.explorer import MultiChainExplorer, UnifiedExplorer
from sentinela.integrations.rpc import NetworkType

logger = logging.getLogger(__name__)


class CrossChainVulnerability(BaseModel):
    """Vulnerability detected across multiple chains."""

    vulnerability_type: VulnerabilityType = Field(..., description="Vulnerability type")
    title: str = Field(..., description="Vulnerability title")
    severity: str = Field(..., description="Severity level")
    affected_networks: list[NetworkType] = Field(..., description="Affected networks")
    contract_addresses: dict[str, str] = Field(..., description="Contract per network")
    common_pattern: str = Field(..., description="Common vulnerability pattern")
    exploit_technique: str = Field(..., description="Common exploit technique")
    recommendations: list[str] = Field(..., description="Remediation steps")


@dataclass
class ContractDeployment:
    """Contract deployment information."""

    network: NetworkType
    address: str
    bytecode: str
    bytecode_hash: str


class CrossChainAnalyzer:
    """
    Analyze vulnerabilities across multiple blockchain networks.
    
    Features:
    - Detect same contract on multiple chains
    - Compare vulnerability patterns
    - Identify systemic risks
    - Generate cross-chain reports
    """

    def __init__(self, multi_explorer: MultiChainExplorer):
        """
        Initialize analyzer.
        
        Args:
            multi_explorer: Multi-chain explorer
        """
        self.explorer = multi_explorer
        self.deployments: dict[str, list[ContractDeployment]] = {}

    async def find_contract_deployments(
        self,
        contract_address: str,
        networks: list[NetworkType] | None = None,
    ) -> list[ContractDeployment]:
        """
        Find where contract is deployed across chains.
        
        Args:
            contract_address: Contract address to search
            networks: Networks to check (all if None)
            
        Returns:
            List of deployments
        """
        if networks is None:
            networks = list(self.explorer.explorers.keys())

        deployments: list[ContractDeployment] = []

        for network in networks:
            explorer = self.explorer.get_explorer(network)
            if not explorer:
                continue

            try:
                # Check if contract exists
                is_contract = await explorer.is_contract(contract_address)
                if not is_contract:
                    continue

                # Get bytecode
                code = await explorer.get_code(contract_address)
                bytecode_hash = hash(code)

                deployment = ContractDeployment(
                    network=network,
                    address=contract_address,
                    bytecode=code,
                    bytecode_hash=str(bytecode_hash),
                )

                deployments.append(deployment)
                logger.info(f"Found contract on {network.value}: {contract_address[:10]}...")

            except Exception as e:
                logger.warning(f"Failed to check {network.value}: {e}")

        return deployments

    async def compare_bytecode(
        self,
        deployments: list[ContractDeployment],
    ) -> dict[str, list[ContractDeployment]]:
        """
        Group deployments by identical bytecode.
        
        Args:
            deployments: List of contract deployments
            
        Returns:
            Dictionary mapping bytecode_hash to deployments
        """
        groups: dict[str, list[ContractDeployment]] = {}

        for deployment in deployments:
            if deployment.bytecode_hash not in groups:
                groups[deployment.bytecode_hash] = []
            groups[deployment.bytecode_hash].append(deployment)

        return groups

    async def analyze_vulnerability_propagation(
        self,
        hypothesis: AttackHypothesis,
        source_network: NetworkType,
        contract_address: str,
    ) -> CrossChainVulnerability | None:
        """
        Check if vulnerability exists on other chains.
        
        Args:
            hypothesis: Vulnerability hypothesis
            source_network: Network where vulnerability was found
            contract_address: Vulnerable contract address
            
        Returns:
            Cross-chain vulnerability if found on multiple chains
        """
        # Find all deployments
        deployments = await self.find_contract_deployments(contract_address)

        if len(deployments) <= 1:
            logger.info("Contract only on one chain, no cross-chain risk")
            return None

        # Group by bytecode
        bytecode_groups = await self.compare_bytecode(deployments)

        # Find group with most deployments
        largest_group = max(bytecode_groups.values(), key=len)

        if len(largest_group) <= 1:
            logger.info("Different bytecode on each chain")
            return None

        # Vulnerability likely exists on all chains with same bytecode
        affected_networks = [d.network for d in largest_group]
        contract_addresses = {d.network.value: d.address for d in largest_group}

        logger.warning(
            f"🌍 Cross-chain vulnerability detected! "
            f"Affected networks: {', '.join(n.value for n in affected_networks)}"
        )

        return CrossChainVulnerability(
            vulnerability_type=hypothesis.vulnerability_type,
            title=f"Cross-Chain: {hypothesis.title}",
            severity="CRITICAL",  # Cross-chain = higher severity
            affected_networks=affected_networks,
            contract_addresses=contract_addresses,
            common_pattern=hypothesis.reasoning,
            exploit_technique=hypothesis.attack_vector,
            recommendations=[
                f"Patch vulnerability on ALL {len(affected_networks)} affected chains immediately",
                "Coordinate emergency response across all deployments",
                "Consider pausing contracts on all chains until fixed",
                "Implement circuit breakers for cross-chain scenarios",
                *hypothesis.expected_behavior.split("\n"),
            ],
        )

    async def scan_common_vulnerabilities(
        self,
        contract_address: str,
        known_vulnerabilities: list[AttackHypothesis],
    ) -> list[CrossChainVulnerability]:
        """
        Scan for known vulnerabilities across all chains.
        
        Args:
            contract_address: Contract to scan
            known_vulnerabilities: List of known vulnerabilities
            
        Returns:
            List of cross-chain vulnerabilities
        """
        cross_chain_vulns: list[CrossChainVulnerability] = []

        # Get all deployments
        deployments = await self.find_contract_deployments(contract_address)

        if len(deployments) <= 1:
            return []

        # For each known vulnerability, check if it propagates
        for vuln in known_vulnerabilities:
            result = await self.analyze_vulnerability_propagation(
                hypothesis=vuln,
                source_network=NetworkType.ETHEREUM_MAINNET,  # Assume source
                contract_address=contract_address,
            )

            if result:
                cross_chain_vulns.append(result)

        return cross_chain_vulns

    async def generate_cross_chain_report(
        self,
        vulnerabilities: list[CrossChainVulnerability],
    ) -> str:
        """
        Generate markdown report for cross-chain vulnerabilities.
        
        Args:
            vulnerabilities: List of cross-chain vulnerabilities
            
        Returns:
            Markdown report
        """
        report = ["# Cross-Chain Vulnerability Report", ""]

        if not vulnerabilities:
            report.extend([
                "✅ **No cross-chain vulnerabilities detected.**",
                "",
                "All vulnerabilities are isolated to single chains.",
            ])
            return "\n".join(report)

        report.extend([
            f"⚠️ **{len(vulnerabilities)} cross-chain vulnerabilities detected!**",
            "",
            "These vulnerabilities affect multiple blockchain networks and require coordinated response.",
            "",
        ])

        for i, vuln in enumerate(vulnerabilities, 1):
            report.extend([
                f"## {i}. {vuln.title}",
                "",
                f"**Severity:** {vuln.severity}",
                f"**Type:** {vuln.vulnerability_type.value}",
                "",
                "### Affected Networks",
                "",
            ])

            for network in vuln.affected_networks:
                address = vuln.contract_addresses.get(network.value, "N/A")
                report.append(f"- **{network.value}**: `{address}`")

            report.extend([
                "",
                "### Common Pattern",
                "",
                vuln.common_pattern,
                "",
                "### Exploit Technique",
                "",
                vuln.exploit_technique,
                "",
                "### Recommendations",
                "",
            ])

            for rec in vuln.recommendations:
                if rec.strip():
                    report.append(f"- {rec}")

            report.extend(["", "---", ""])

        report.extend([
            "## Summary",
            "",
            f"- **Total Cross-Chain Vulnerabilities:** {len(vulnerabilities)}",
            f"- **Networks Affected:** {len(set(n for v in vulnerabilities for n in v.affected_networks))}",
            "",
            "### Immediate Actions Required",
            "",
            "1. 🚨 **Emergency Response**: Coordinate with all affected chains",
            "2. 🛑 **Contract Pause**: Consider pausing all affected contracts",
            "3. 🔧 **Patch Development**: Create unified fix for all chains",
            "4. 📢 **Public Disclosure**: Inform users across all networks",
            "5. 🔍 **Post-Mortem**: Analyze how vulnerability propagated",
        ])

        return "\n".join(report)

    async def compare_network_security(
        self,
        networks: list[NetworkType],
    ) -> dict[str, Any]:
        """
        Compare security characteristics across networks.
        
        Args:
            networks: Networks to compare
            
        Returns:
            Comparison statistics
        """
        stats = {}

        for network in networks:
            explorer = self.explorer.get_explorer(network)
            if not explorer:
                continue

            try:
                # Get current block
                block_number = await explorer.rpc.get_block_number()

                # Get gas price
                gas_price = await explorer.rpc.get_gas_price()

                stats[network.value] = {
                    "current_block": block_number,
                    "gas_price_gwei": float(explorer.rpc.w3.from_wei(gas_price, "gwei")),
                    "chain_id": await explorer.rpc.get_chain_id(),
                }

            except Exception as e:
                logger.error(f"Failed to get stats for {network.value}: {e}")
                stats[network.value] = {"error": str(e)}

        return stats


async def example_cross_chain_analysis():
    """Example cross-chain vulnerability analysis."""
    print("\n=== Cross-Chain Vulnerability Analysis ===")

    # Initialize multi-chain explorer
    multi_explorer = MultiChainExplorer()
    multi_explorer.add_network(NetworkType.ETHEREUM_MAINNET)
    multi_explorer.add_network(NetworkType.POLYGON)
    multi_explorer.add_network(NetworkType.BSC)

    # Initialize analyzer
    analyzer = CrossChainAnalyzer(multi_explorer)

    # Example: Check if USDT exists on multiple chains (it does!)
    usdt_ethereum = "0xdAC17F958D2ee523a2206206994597C13D831ec7"

    deployments = await analyzer.find_contract_deployments(
        usdt_ethereum,
        networks=[
            NetworkType.ETHEREUM_MAINNET,
            NetworkType.POLYGON,
            NetworkType.BSC,
        ],
    )

    print(f"\nFound {len(deployments)} deployments:")
    for deployment in deployments:
        print(f"  - {deployment.network.value}: {deployment.address}")

    # Compare network security
    stats = await analyzer.compare_network_security(
        [NetworkType.ETHEREUM_MAINNET, NetworkType.POLYGON, NetworkType.BSC]
    )

    print("\nNetwork Comparison:")
    for network, data in stats.items():
        if "error" not in data:
            print(
                f"  {network}: Block {data['current_block']:,}, "
                f"Gas {data['gas_price_gwei']:.2f} Gwei"
            )


if __name__ == "__main__":
    asyncio.run(example_cross_chain_analysis())
