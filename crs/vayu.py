import os
import sys
from pathlib import Path

import click
from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.text import Text
from rich.table import Table
from rich.syntax import Syntax

from crs.core.schemas import CRSRunResult
from crs.orchestrator import CRSPipeline, PipelineError, NoFindingsError
from crs.reasoning.ollama_client import OllamaClientError, OllamaLLMClient
from crs.reasoning.ollama_config import load_ollama_config
from crs.ingestion.repository_loader import RepositoryLoader
from crs.patching.patch_generator import PatchGenerator
from crs.patching.patch_validator import PatchValidator
from crs.reasoning.evidence_builder import EvidenceBuilder
from crs.reasoning.reasoning_engine import ReasoningEngine
from crs.static_analysis.scanner import StaticScanner
from crs.verification.verification_engine import VerificationEngine

console = Console()

ASCII_LOGO = """[bold orange3]
██╗   ██╗ █████╗ ██╗   ██╗██╗   ██╗
██║   ██║██╔══██╗╚██╗ ██╔╝██║   ██║
██║   ██║███████║ ╚████╔╝ ██║   ██║
╚██╗ ██╔╝██╔══██║  ╚██╔╝  ██║   ██║
 ╚████╔╝ ██║  ██║   ██║   ╚██████╔╝
  ╚═══╝  ╚═╝  ╚═╝   ╚═╝    ╚═════╝ 
[/bold orange3]
[dim orange3]Autonomous Cyber Reasoning System[/dim orange3]
"""

def render_finding(finding):
    # Base info table
    info_table = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
    info_table.add_column("Key", style="bold white")
    info_table.add_column("Value")
    
    info_table.add_row("ID:", f"[cyan]{finding.finding_id}[/]")
    info_table.add_row("Type:", f"[yellow]{finding.vulnerability_type}[/]")
    
    severity = getattr(finding.severity, "value", finding.severity)
    color = "red" if severity == "HIGH" else "yellow"
    icon = "✗" if severity == "HIGH" else "⚠"
    info_table.add_row("Severity:", f"[{color}]{icon} {severity}[/]")
    info_table.add_row("Location:", f"{finding.file}:{finding.line_start}")
    
    elements = [info_table]
    
    # Try to extract code snippet
    if finding.file and finding.line_start:
        try:
            with open(finding.file, "r") as f:
                lines = f.readlines()
            
            start_idx = max(0, finding.line_start - 3)
            end_idx = min(len(lines), finding.line_start + 2)
            snippet_lines = lines[start_idx:end_idx]
            code_str = "".join(snippet_lines)
            
            syntax = Syntax(
                code_str,
                lexer="python",
                theme="monokai",
                line_numbers=True,
                start_line=start_idx + 1,
                highlight_lines={finding.line_start},
                background_color="default"
            )
            
            snippet_panel = Panel(syntax, title="[dim]Code Context[/]", border_style="dim")
            elements.extend([Text(""), snippet_panel])
        except Exception:
            pass # Fail gracefully if file can't be read
            
    return Panel(
        Group(*elements), 
        title="[bold orange3]1. Vulnerability Detected[/]", 
        border_style="orange3"
    )


def render_reasoning(reasoning):
    table = Table(show_header=False, box=None, padding=(0, 2, 1, 0))
    table.add_column("Icon", justify="center")
    table.add_column("Content")
    
    # Root Cause
    rc_text = Text()
    rc_text.append("Root Cause\n", style="bold white")
    rc_text.append(reasoning.root_cause, style="dim white")
    table.add_row("[red]✗[/]", rc_text)
    
    # Security Impact
    si_text = Text()
    si_text.append("Security Impact\n", style="bold white")
    si_text.append(reasoning.security_impact, style="dim white")
    table.add_row("[yellow]⚠[/]", si_text)
    
    # Remediation
    rem_text = Text()
    rem_text.append("Remediation Strategy\n", style="bold white")
    rem_text.append(reasoning.remediation_strategy, style="dim white")
    table.add_row("[green]✓[/]", rem_text)
    
    # Confidence
    conf_color = "green" if reasoning.confidence >= 0.8 else "yellow"
    table.add_row("[cyan]ℹ[/]", f"[bold white]Confidence:[/] [{conf_color}]{reasoning.confidence:.0%}[/]")
    
    return Panel(
        table, 
        title="[bold orange3]2. AI Reasoning[/]", 
        border_style="orange3"
    )


def render_patch(patch):
    table = Table(show_header=False, box=None, padding=(0, 2, 0, 0))
    table.add_column("Icon", justify="center")
    table.add_column("Content")
    
    table.add_row("[cyan]ℹ[/]", f"[bold white]Target File:[/] [cyan]{patch.target_file}[/]")
    table.add_row("[green]✓[/]", f"[bold white]Validation:[/] [green]PASSED[/]")
    
    effect_text = Text()
    effect_text.append("Expected Security Effect\n", style="bold white")
    effect_text.append(patch.expected_security_effect, style="dim white")
    table.add_row("[orange3]⚡[/]", effect_text)

    return Panel(
        table, 
        title="[bold orange3]3. Patch Generation[/]", 
        border_style="orange3"
    )


def _status_color(passed: bool) -> str:
    return "[bold green]✓ PASSED[/]" if passed else "[bold red]✗ FAILED[/]"


def render_verification(verification):
    table = Table(show_header=False, box=None, padding=(0, 4, 0, 0))
    table.add_column("Check", style="bold white")
    table.add_column("Result", justify="right")
    
    table.add_row("Build Integration", _status_color(verification.build_passed))
    table.add_row("Functional Tests", _status_color(verification.tests_passed))
    table.add_row("Security Regression", _status_color(verification.security_test_passed))
    table.add_row("Static Rescan", _status_color(verification.static_rescan_clean))
    
    decision_color = "bold green" if verification.approved else "bold red"
    decision_icon = "✓" if verification.approved else "✗"
    decision_text = f"{decision_icon} VERIFIED (Approved for Deployment)" if verification.approved else f"{decision_icon} REJECTED"
    
    text = Text()
    text.append("\nFinal Decision: ", style="bold")
    text.append(decision_text, style=decision_color)
    
    return Panel.fit(
        Group(table, text),
        title="[bold orange3]4. Formal Verification[/]", 
        border_style="orange3"
    )


def render_actionable_error(title: str, description: str, action: str):
    """Render a beautiful, actionable error message based on SKILL.md Example 3."""
    table = Table(show_header=False, box=None, padding=(0, 2, 1, 0))
    table.add_column("Icon", justify="center")
    table.add_column("Content")
    
    table.add_row("[red]✗[/]", f"[bold white]{description}[/]")
    table.add_row("", "") # spacer
    
    action_text = Text()
    action_text.append("To fix this, run:\n", style="dim white")
    action_text.append(f"  {action}", style="bold cyan")
    
    table.add_row("[green]✓[/]", action_text)
    
    console.print(Panel(table, title=f"[bold red]{title}[/]", border_style="red"))


@click.command()
@click.argument('target_path', type=click.Path(exists=True))
def main(target_path):
    """Run the Vayu Autonomous Cyber Reasoning System on a target repository."""
    console.print(ASCII_LOGO)
    
    provider = os.environ.get("AIKAVACH_LLM_PROVIDER", "").strip().lower()
    if provider != "ollama":
        render_actionable_error(
            "Configuration Error",
            "Environment variables are not loaded or missing.",
            "source .env.local"
        )
        sys.exit(1)
        
    try:
        config = load_ollama_config()
        client = OllamaLLMClient(
            base_url=config.base_url,
            model=config.model,
            timeout=config.timeout,
        )
    except Exception as e:
        render_actionable_error(
            "Ollama Connection Error",
            f"Could not connect to Ollama: {str(e)}",
            "Ensure Ollama is running and the model is pulled (e.g., 'ollama run llama3')"
        )
        sys.exit(1)

    console.print(f"[dim]Model:[/] [orange3]{config.model}[/]\n")
    
    # Initialize components
    repository_loader = RepositoryLoader()
    scanner = StaticScanner()
    evidence_builder = EvidenceBuilder()
    reasoning_engine = ReasoningEngine(client, evidence_builder=evidence_builder)
    patch_validator = PatchValidator()
    patch_generator = PatchGenerator(client, validator=patch_validator)
    verifier = VerificationEngine(patch_validator=patch_validator)
    
    target_dir = str(Path(target_path).expanduser())
    
    try:
        # Enhanced progress bar with elapsed time
        with Progress(
            SpinnerColumn(style="orange3"),
            TextColumn("[progress.description]{task.description}"),
            TextColumn("•"),
            TimeElapsedColumn(),
            transient=True,
            console=console
        ) as progress:
            
            # Stage 1: FIND
            task_id = progress.add_task("[orange3]Scanning for vulnerabilities...", total=None)
            target = repository_loader.load(target_dir)
            findings = scanner.scan(target.path)
            
            if not findings:
                progress.stop()
                console.print(Panel("[bold green]✓ No vulnerabilities detected.[/]", title="[bold orange3]Scan Complete[/]", border_style="orange3"))
                sys.exit(0)
                
            finding = findings[0]
            progress.stop()
            console.print(render_finding(finding))
            progress.start()
            
            # Stage 2: REASON
            progress.update(task_id, description="[orange3]AI is reasoning about exploitability...")
            evidence = evidence_builder.build(finding, target.path, target.repository_hash)
            reasoning = reasoning_engine.reason_from_evidence(evidence)
            
            progress.stop()
            console.print(render_reasoning(reasoning))
            progress.start()
            
            # Stage 3: PATCH
            progress.update(task_id, description="[orange3]AI is generating secure patch...")
            patch = patch_generator.generate(finding, reasoning, evidence.code_context)
            validation = patch_validator.validate(
                patch,
                finding,
                repository_root=target.path,
                intended_file=evidence.code_context.file,
            )
            if not validation.valid:
                raise ValueError(validation.reason or "Patch proposal is invalid")
                
            progress.stop()
            console.print(render_patch(patch))
            progress.start()
            
            # Stage 4: VERIFY
            progress.update(task_id, description="[orange3]Verifying patch via regression tests...")
            verification = verifier.verify(target.path, finding, patch)
            
            progress.stop()
            console.print(render_verification(verification))
            
    except OllamaClientError as exc:
        progress.stop()
        render_actionable_error(
            "AI Provider Error",
            f"The LLM provider failed: {str(exc)}",
            "Check that the model exists locally by running 'ollama list'"
        )
        sys.exit(1)
    except Exception as exc:
        progress.stop()
        render_actionable_error(
            "Pipeline Error",
            f"An unexpected error occurred during execution:\n{str(exc)}",
            "Review the target code or restart the process."
        )
        sys.exit(1)

if __name__ == "__main__":
    main()
