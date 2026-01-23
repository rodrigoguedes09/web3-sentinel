"""
Example: Smart Contract Audit with On-Chain Data Enrichment

Demonstrates how to run a security audit with real-time on-chain data integration:
- Balance checking for risk assessment
- Bytecode verification
- Cross-chain deployment detection
- Context-aware recommendations
"""

import asyncio
from pathlib import Path

from sentinela.core.orchestrator import SentinelaOrchestrator


async def main():
    """Run audit with on-chain enrichment."""
    print("\n" + "="*60)
    print("SENTINELA WEB3 - AUDIT WITH ON-CHAIN ENRICHMENT")
    print("="*60)

    # Initialize orchestrator
    orchestrator = SentinelaOrchestrator()
    
    # Contract to audit
    contract_path = Path("contracts/src/VulnerableVault.sol")
    
    # Optional: Provide deployed contract address for on-chain enrichment
    # If not provided, system will try to extract from test output
    deployed_address = None  # e.g., "0x742d35Cc6634C0532925a3b844Bc9e7595f0bEb"
    
    print(f"\n🔍 Auditing: {contract_path}")
    if deployed_address:
        print(f"📍 Contract Address: {deployed_address}")
        print(f"💡 On-chain data will be included in reports")
    else:
        print(f"💡 No address provided - will attempt to extract from test output")
    
    # Run audit
    print(f"\n🚀 Starting audit...")
    
    result = await orchestrator.audit(
        contract_path=contract_path,
        max_hypotheses=5,
        max_reflections=3,
        contract_address=deployed_address,  # Pass address if available
    )
    
    # Display results
    print(f"\n" + "="*60)
    print("AUDIT RESULTS")
    print("="*60)
    
    print(f"\n📊 Summary:")
    print(f"   Hypotheses Tested: {len(result.hypotheses)}")
    print(f"   Vulnerabilities Found: {result.vulnerabilities_found}")
    print(f"   Vulnerabilities Proven: {len(result.vulnerabilities_proven)}")
    
    # Show proven vulnerabilities with on-chain context
    if result.vulnerabilities_proven:
        print(f"\n🚨 PROVEN VULNERABILITIES:")
        for i, vuln in enumerate(result.vulnerabilities_proven, 1):
            print(f"\n{i}. {vuln.title}")
            print(f"   Type: {vuln.vulnerability_type.value}")
            print(f"   Severity: {vuln.severity if hasattr(vuln, 'severity') else 'Unknown'}")
            
            # Display on-chain enrichment if available
            if hasattr(vuln, 'onchain_data') and vuln.onchain_data:
                print(f"\n   📊 On-Chain Data:")
                onchain = vuln.onchain_data
                
                if 'contract_balance_eth' in onchain:
                    print(f"      Balance: {onchain['contract_balance_eth']:.4f} ETH")
                
                if 'bytecode_size' in onchain:
                    print(f"      Bytecode: {onchain['bytecode_size']:,} bytes")
                
                if 'risk_level' in onchain:
                    print(f"      Risk: {onchain['risk_level']}")
                
                if 'is_verified' in onchain:
                    verified = "✅ Yes" if onchain['is_verified'] else "❌ No"
                    print(f"      Verified: {verified}")
                
                if 'compiler_version' in onchain:
                    print(f"      Compiler: {onchain['compiler_version']}")
            
            # Display cross-chain deployment info
            if hasattr(vuln, 'cross_chain_deployments') and vuln.cross_chain_deployments:
                chains = list(vuln.cross_chain_deployments.keys())
                print(f"\n   🌍 Cross-Chain Deployments:")
                print(f"      Found on {len(chains)} networks: {', '.join(chains)}")
                print(f"      ⚠️  Vulnerability may propagate across all chains!")
    
    # Show reports
    if result.reports:
        print(f"\n📝 DETAILED REPORTS:")
        for i, report in enumerate(result.reports, 1):
            print(f"\n{'='*60}")
            print(f"Report #{i}: {report.hypothesis.title}")
            print(f"{'='*60}")
            
            print(f"\nSeverity: {report.severity}")
            print(f"\nDescription:")
            print(f"{report.hypothesis.reasoning}")
            
            print(f"\nRecommendations:")
            for j, rec in enumerate(report.recommendations, 1):
                print(f"  {j}. {rec}")
            
            # Show enhanced recommendations based on on-chain data
            if report.onchain_data:
                balance = report.onchain_data.get('contract_balance_eth', 0)
                if balance > 10:
                    print(f"\n⚠️  HIGH VALUE CONTRACT: {balance:.2f} ETH at risk!")
                    print(f"   → Prioritize immediate patching")
                    print(f"   → Consider pausing contract until fix deployed")
            
            if report.cross_chain_deployments and len(report.cross_chain_deployments) > 1:
                print(f"\n🌍 CROSS-CHAIN IMPACT:")
                print(f"   → Deploy fixes on ALL chains simultaneously")
                print(f"   → Affected networks: {', '.join(report.cross_chain_deployments.keys())}")
                print(f"   → Monitor all networks for exploit attempts")
    
    print(f"\n{'='*60}")
    print("AUDIT COMPLETE")
    print(f"{'='*60}")
    
    # Configuration tips
    print(f"\n💡 Configuration Tips:")
    print(f"   • Set ENABLE_RPC_INTEGRATION=true in .env")
    print(f"   • Add Etherscan API key for verified source code")
    print(f"   • Enable ENABLE_CROSS_CHAIN_ANALYSIS for multi-network checks")
    print(f"   • RPC endpoints are free - no rate limits!")
    
    return result


async def example_with_mainnet_contract():
    """Example: Audit a deployed mainnet contract."""
    print("\n" + "="*60)
    print("EXAMPLE: AUDITING DEPLOYED MAINNET CONTRACT")
    print("="*60)
    
    # Example: Audit a deployed contract
    # NOTE: This would require the source code to be available
    mainnet_address = "0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D"  # Uniswap V2 Router
    
    print(f"\n📍 Target: {mainnet_address}")
    print(f"💡 For mainnet contracts, you need:")
    print(f"   1. Verified source code on Etherscan")
    print(f"   2. Or local copy of the contract code")
    print(f"   3. Etherscan API key (optional but recommended)")
    
    print(f"\n🔧 Workflow:")
    print(f"   1. Fetch verified source from Etherscan")
    print(f"   2. Run static analysis (Slither)")
    print(f"   3. Generate attack hypotheses")
    print(f"   4. Test exploits in fork environment")
    print(f"   5. Enrich with on-chain data (balance, bytecode)")
    print(f"   6. Check cross-chain deployments")
    print(f"   7. Generate contextualized reports")


if __name__ == "__main__":
    # Run basic example
    asyncio.run(main())
    
    # Show mainnet example workflow (conceptual)
    print("\n")
    asyncio.run(example_with_mainnet_contract())
