"""
Sentinela Web3 CLI

Command-line interface for running smart contract security audits.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from sentinela.core.config import Settings, get_settings
from sentinela.core.orchestrator import SentinelaOrchestrator
from sentinela.rag.loader import HackPostmortemLoader


app = typer.Typer(
    name="sentinela",
    help="Sentinela Web3 - Autonomous Smart Contract Security Auditor",
    add_completion=False,
)
console = Console()


def setup_logging(verbose: bool = False) -> None:
    """Configure rich logging."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(message)s",
        handlers=[RichHandler(console=console, rich_tracebacks=True)],
    )


@app.command()
def audit(
    contract: Path = typer.Argument(
        ...,
        help="Path to the Solidity contract file to audit",
        exists=True,
        readable=True,
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output", "-o",
        help="Output directory for reports",
    ),
    max_hypotheses: int = typer.Option(
        5,
        "--max-hypotheses", "-n",
        help="Maximum number of hypotheses to generate",
    ),
    max_reflections: int = typer.Option(
        3,
        "--max-reflections", "-r",
        help="Maximum reflection loop iterations",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Enable verbose logging",
    ),
) -> None:
    """
    Run a security audit on a Solidity smart contract.
    
    Analyzes the contract for vulnerabilities, generates attack hypotheses,
    and attempts to prove them by writing and executing exploit tests.
    """
    setup_logging(verbose)

    console.print(Panel.fit(
        "[bold blue]Sentinela Web3[/bold blue]\n"
        "Autonomous Smart Contract Security Auditor",
        border_style="blue",
    ))

    console.print(f"\nAuditing: [cyan]{contract}[/cyan]\n")

    # Run the audit
    asyncio.run(_run_audit(
        contract_path=contract,
        output_dir=output,
        max_hypotheses=max_hypotheses,
        max_reflections=max_reflections,
    ))


async def _run_audit(
    contract_path: Path,
    output_dir: Optional[Path],
    max_hypotheses: int,
    max_reflections: int,
) -> None:
    """Execute the audit pipeline."""
    settings = get_settings()
    settings.max_hypotheses_per_run = max_hypotheses
    settings.max_reflection_loops = max_reflections

    orchestrator = SentinelaOrchestrator(settings=settings)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Running security audit...", total=None)

        try:
            result = await orchestrator.audit(contract_path=contract_path)

            progress.update(task, completed=True)

            # Display results
            _display_results(result)

            # Save report if output specified
            if output_dir:
                await _save_report(result, output_dir)

        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"\n[red]Audit failed:[/red] {e}")
            raise typer.Exit(1)


def _display_results(result) -> None:
    """Display audit results in a rich table."""
    console.print("\n")

    if result.success:
        status = "[green]COMPLETED[/green]"
    else:
        status = "[red]FAILED[/red]"

    # Summary panel
    summary = f"""
Contract: [cyan]{result.contract_name}[/cyan]
Status: {status}
Hypotheses Generated: {result.hypotheses_generated}
Hypotheses Tested: {result.hypotheses_tested}
Vulnerabilities Proven: [bold red]{result.vulnerabilities_found}[/bold red]
"""
    console.print(Panel(summary, title="Audit Summary", border_style="blue"))

    # Vulnerabilities table
    if result.vulnerabilities_proven:
        table = Table(title="Proven Vulnerabilities", border_style="red")
        table.add_column("Type", style="red")
        table.add_column("Title", style="white")
        table.add_column("Severity", style="yellow")
        table.add_column("Confidence", style="cyan")

        for vuln in result.vulnerabilities_proven:
            severity = "Critical" if hasattr(vuln, 'vulnerability_type') else "Unknown"
            table.add_row(
                vuln.vulnerability_type.value if hasattr(vuln, 'vulnerability_type') else "Unknown",
                vuln.title if hasattr(vuln, 'title') else str(vuln),
                severity,
                f"{vuln.confidence_score:.0%}" if hasattr(vuln, 'confidence_score') else "N/A",
            )

        console.print(table)

    elif result.success:
        console.print("\n[green]No vulnerabilities were proven exploitable.[/green]")

    if result.error:
        console.print(f"\n[red]Error:[/red] {result.error}")


async def _save_report(result, output_dir: Path) -> None:
    """Save the audit report to files."""
    import json
    from datetime import datetime

    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_name = f"{result.contract_name}_{timestamp}"

    # Save JSON report
    json_path = output_dir / f"{report_name}.json"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(result.to_dict(), f, indent=2, default=str)

    console.print(f"\nReport saved to: [cyan]{json_path}[/cyan]")


@app.command()
def init_rag(
    data_dir: Optional[Path] = typer.Option(
        None,
        "--data-dir", "-d",
        help="Directory containing hack post-mortem files",
    ),
    load_defaults: bool = typer.Option(
        True,
        "--load-defaults/--no-defaults",
        help="Load default historical hacks",
    ),
    verbose: bool = typer.Option(
        False,
        "--verbose", "-v",
        help="Enable verbose logging",
    ),
) -> None:
    """
    Initialize the RAG database with historical hack data.
    
    Loads hack post-mortem documents into ChromaDB for retrieval
    during hypothesis generation.
    """
    setup_logging(verbose)

    console.print(Panel.fit(
        "[bold blue]Initializing RAG Database[/bold blue]",
        border_style="blue",
    ))

    asyncio.run(_init_rag(data_dir, load_defaults))


async def _init_rag(data_dir: Optional[Path], load_defaults: bool) -> None:
    """Initialize the RAG database."""
    loader = HackPostmortemLoader()

    total = 0

    if load_defaults:
        console.print("Loading default historical hacks...")
        count = await loader.load_default_hacks()
        total += count
        console.print(f"  Loaded {count} default hacks")

    if data_dir and data_dir.exists():
        console.print(f"Loading from {data_dir}...")
        count = await loader.load_from_directory(data_dir)
        total += count
        console.print(f"  Loaded {count} additional hacks")

    console.print(f"\n[green]RAG database initialized with {total} documents[/green]")


@app.command()
def check() -> None:
    """
    Check system requirements and tool availability.
    
    Verifies that Slither, Forge, and Anvil are installed and accessible.
    """
    import asyncio

    console.print(Panel.fit(
        "[bold blue]System Check[/bold blue]",
        border_style="blue",
    ))

    asyncio.run(_check_tools())


async def _check_tools() -> None:
    """Check tool availability."""
    from sentinela.integrations.slither import SlitherRunner
    from sentinela.integrations.foundry import ForgeRunner, AnvilManager

    table = Table(title="Tool Status")
    table.add_column("Tool", style="cyan")
    table.add_column("Status", style="white")
    table.add_column("Path", style="dim")

    # Check Slither
    try:
        slither = SlitherRunner()
        available = await slither.check_available()
        table.add_row(
            "Slither",
            "[green]Available[/green]" if available else "[red]Not Available[/red]",
            slither.slither_path if available else "Not found",
        )
    except Exception as e:
        table.add_row("Slither", "[red]Error[/red]", str(e))

    # Check Forge
    try:
        forge = ForgeRunner()
        available = await forge.check_available()
        table.add_row(
            "Forge",
            "[green]Available[/green]" if available else "[red]Not Available[/red]",
            forge.forge_path if available else "Not found",
        )
    except Exception as e:
        table.add_row("Forge", "[red]Error[/red]", str(e))

    # Check Anvil
    try:
        anvil = AnvilManager()
        table.add_row(
            "Anvil",
            "[green]Available[/green]",
            anvil.anvil_path,
        )
    except Exception as e:
        table.add_row("Anvil", "[red]Error[/red]", str(e))

    console.print(table)


@app.command()
def version() -> None:
    """Show version information."""
    from sentinela import __version__

    console.print(f"Sentinela Web3 v{__version__}")


if __name__ == "__main__":
    app()
