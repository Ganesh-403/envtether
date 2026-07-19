"""envtether CLI application.

Built with Typer and Rich, providing a professional command-line interface
for all configuration intelligence operations.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
from rich.progress import Progress, SpinnerColumn, TextColumn

from envtether.cli.rendering import (
    console,
    output_console,
    render_banner,
    render_findings_table,
    render_health_score,
    render_project_info,
    render_recommendations,
    render_variable_explain,
    setup_logging,
)
from envtether.config import EnvtetherConfig
from envtether.core.engine import AnalysisEngine
from envtether.documentation.doc_generator import DocumentationGenerator
from envtether.graph.exporter import GraphExporter
from envtether.models.findings import Severity
from envtether.models.report import FullReport, ReportFormat
from envtether.reporting.generator import ReportGenerator

app = typer.Typer(
    name="envtether",
    help="Static Configuration Intelligence for Modern Python Applications.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    add_completion=True,
)


def _run_analysis(path: Path, verbose: bool = False) -> FullReport:
    """Run the analysis pipeline with progress feedback."""
    setup_logging(verbose)
    config = EnvtetherConfig.discover(path)
    engine = AnalysisEngine(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Scanning repository...", total=None)
        report = engine.analyze(path)

    return report


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Path to the repository root.")] = Path("."),
    verbose: Annotated[bool, typer.Option("--verbose", "-v", help="Enable verbose output.")] = False,
    json_output: Annotated[bool, typer.Option("--json", help="Output as JSON.")] = False,
) -> None:
    """Scan a repository and display configuration analysis results."""
    render_banner()
    path = path.resolve()
    report = _run_analysis(path, verbose)

    if json_output:
        output_console.print(report.model_dump_json(indent=2))
        return

    if report.project:
        render_project_info(report.project)

    if report.health:
        render_health_score(report.health)

    render_findings_table(list(report.findings))

    if report.health:
        render_recommendations(report.health)


@app.command()
def doctor(
    path: Annotated[Path, typer.Argument(help="Path to the repository root.")] = Path("."),
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
    strict: Annotated[bool, typer.Option("--strict", help="Fail on any finding.")] = False,
) -> None:
    """Run a comprehensive health check and report issues.

    Returns exit code 1 if critical/high issues are found (or any issues in strict mode).
    """
    render_banner()
    path = path.resolve()
    report = _run_analysis(path, verbose)

    if report.project:
        render_project_info(report.project)

    if report.health:
        render_health_score(report.health)
        render_recommendations(report.health)

    render_findings_table(list(report.findings))

    # Exit code logic
    if strict and report.findings:
        console.print("\n[red bold]Doctor found issues (strict mode).[/red bold]")
        raise typer.Exit(code=1)

    critical_or_high = [
        f for f in report.findings
        if f.severity in {Severity.CRITICAL, Severity.HIGH}
    ]
    if critical_or_high:
        console.print(f"\n[red bold]Doctor found {len(critical_or_high)} critical/high issues.[/red bold]")
        raise typer.Exit(code=1)

    console.print("\n[green bold]All checks passed.[/green bold]")


@app.command()
def health(
    path: Annotated[Path, typer.Argument(help="Path to the repository root.")] = Path("."),
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Display the configuration health score."""
    render_banner()
    path = path.resolve()
    report = _run_analysis(path, verbose)

    if report.health:
        render_health_score(report.health)
        render_recommendations(report.health)


@app.command()
def secrets(
    path: Annotated[Path, typer.Argument(help="Path to the repository root.")] = Path("."),
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
    redact: Annotated[bool, typer.Option("--redact", help="Redact secret values in output.")] = True,
) -> None:
    """Scan for exposed secrets and credentials."""
    render_banner()
    path = path.resolve()
    report = _run_analysis(path, verbose)

    secret_findings = [
        f for f in report.findings
        if f.category.value in {"exposed_secret", "hardcoded_secret"}
    ]

    if not secret_findings:
        console.print("[green bold]No secrets detected.[/green bold]")
        return

    console.print(f"[yellow bold]Found {len(secret_findings)} potential secrets:[/yellow bold]\n")
    render_findings_table(secret_findings)

    if secret_findings:
        raise typer.Exit(code=1)


@app.command()
def graph(
    path: Annotated[Path, typer.Argument(help="Path to the repository root.")] = Path("."),
    output: Annotated[Path, typer.Option("--output", "-o", help="Output file path.")] = Path(".envtether/graph.mmd"),
    fmt: Annotated[str, typer.Option("--format", "-f", help="Export format: mermaid, dot, json, html.")] = "mermaid",
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Generate a configuration dependency graph."""
    render_banner()
    path = path.resolve()

    setup_logging(verbose)
    config = EnvtetherConfig.discover(path)
    engine = AnalysisEngine(config)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        transient=True,
    ) as progress:
        progress.add_task("Analysing...", total=None)
        report = engine.analyze(path)

    exporter = GraphExporter()
    nx_graph = engine.graph_builder.graph
    output_path = exporter.save(nx_graph, output.resolve(), fmt)

    console.print(f"[green]Graph exported to {output_path}[/green]")


@app.command()
def report(
    path: Annotated[Path, typer.Argument(help="Path to the repository root.")] = Path("."),
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".envtether/report.md"),
    fmt: Annotated[str, typer.Option("--format", "-f", help="Format: markdown, html, json, csv, sarif.")] = "markdown",
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Generate a configuration analysis report."""
    render_banner()
    path = path.resolve()
    full_report = _run_analysis(path, verbose)

    format_map = {
        "markdown": ReportFormat.MARKDOWN,
        "md": ReportFormat.MARKDOWN,
        "html": ReportFormat.HTML,
        "json": ReportFormat.JSON,
        "csv": ReportFormat.CSV,
        "sarif": ReportFormat.SARIF,
    }

    report_fmt = format_map.get(fmt.lower())
    if report_fmt is None:
        console.print(f"[red]Unsupported format: {fmt}[/red]")
        raise typer.Exit(code=1)

    generator = ReportGenerator()
    generator.generate(full_report, report_fmt, output.resolve())
    console.print(f"[green]Report written to {output.resolve()}[/green]")


@app.command()
def docs(
    path: Annotated[Path, typer.Argument(help="Path to the repository root.")] = Path("."),
    output: Annotated[Path, typer.Option("--output", "-o")] = Path(".envtether/config-docs.md"),
    fmt: Annotated[str, typer.Option("--format", "-f", help="Format: markdown or html.")] = "markdown",
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Generate configuration documentation."""
    render_banner()
    path = path.resolve()
    full_report = _run_analysis(path, verbose)

    generator = DocumentationGenerator()
    generator.save(full_report, output.resolve(), fmt)
    console.print(f"[green]Documentation written to {output.resolve()}[/green]")


@app.command()
def explain(
    variable: Annotated[str, typer.Argument(help="Variable name to explain.")],
    path: Annotated[Path, typer.Option("--path", "-p")] = Path("."),
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Explain a single configuration variable in detail."""
    render_banner()
    path = path.resolve()
    full_report = _run_analysis(path, verbose)
    render_variable_explain(variable, full_report)


@app.command(name="ci")
def ci_check(
    path: Annotated[Path, typer.Argument(help="Path to the repository root.")] = Path("."),
    format_output: Annotated[str, typer.Option("--format", "-f", help="Output format: text, json, sarif.")] = "text",
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Run CI-optimised analysis with machine-readable output.

    Returns exit code 0 if no critical/high issues, 1 otherwise.
    """
    setup_logging(verbose)
    path = path.resolve()

    config = EnvtetherConfig.discover(path)
    engine = AnalysisEngine(config)
    full_report = engine.analyze(path)

    if format_output == "json":
        output_console.print(full_report.model_dump_json(indent=2))
    elif format_output == "sarif":
        generator = ReportGenerator()
        sarif = generator.generate(full_report, ReportFormat.SARIF)
        output_console.print(sarif)
    else:
        score = full_report.health.score.overall if full_report.health else 0
        total = len(full_report.findings)
        critical = sum(1 for f in full_report.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in full_report.findings if f.severity == Severity.HIGH)

        output_console.print(f"Score: {score:.0f}/100")
        output_console.print(f"Findings: {total} (critical={critical}, high={high})")

    critical_or_high = [
        f for f in full_report.findings
        if f.severity in {Severity.CRITICAL, Severity.HIGH}
    ]
    if critical_or_high:
        raise typer.Exit(code=1)


@app.command()
def check(
    path: Annotated[Path, typer.Argument(help="Path to the repository root.")] = Path("."),
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
) -> None:
    """Quick check — alias for ``envtether doctor``."""
    doctor(path=path, verbose=verbose, strict=False)


@app.command()
def init(
    path: Annotated[Path, typer.Argument(help="Path to initialise.")] = Path("."),
) -> None:
    """Initialise envtether configuration in a project."""
    render_banner()
    path = path.resolve()
    config = EnvtetherConfig()
    config_path = path / ".envtether.toml"

    if config_path.exists():
        console.print(f"[yellow]Configuration already exists: {config_path}[/yellow]")
        return

    config_path.write_text(config.generate_default_toml(), encoding="utf-8")
    console.print(f"[green]Created {config_path}[/green]")
    console.print("Edit this file to customise envtether behaviour.")


@app.command()
def fix(
    path: Annotated[Path, typer.Argument(help="Path to the repository root.")] = Path("."),
    verbose: Annotated[bool, typer.Option("--verbose", "-v")] = False,
    dry_run: Annotated[bool, typer.Option("--dry-run", help="Show what would be fixed without making changes.")] = False,
) -> None:
    """Auto-fix configuration issues where possible.

    Currently supports:
    - Generating missing ``.env.example`` entries
    - Removing dead variables from ``.env``
    """
    render_banner()
    path = path.resolve()
    full_report = _run_analysis(path, verbose)

    fixable = [f for f in full_report.findings if f.is_fixable]

    if not fixable:
        console.print("[green]No auto-fixable issues found.[/green]")
        return

    console.print(f"[yellow]Found {len(fixable)} fixable issues.[/yellow]")

    if dry_run:
        for finding in fixable:
            for rec in finding.recommendations:
                if rec.fix_command:
                    console.print(f"  Would run: {rec.fix_command}")
        return

    # Generate .env.example from discovered variables
    env_example_path = path / ".env.example"
    missing_vars = [v for v in full_report.variables if v.is_used and not v.is_secret]

    if missing_vars and not env_example_path.exists():
        lines: list[str] = [
            "# Environment variables for this project",
            "# Generated by envtether",
            "",
        ]
        for var in sorted(missing_vars, key=lambda v: v.name):
            desc = f"  # {var.description}" if var.description else ""
            default = ""
            for source in var.sources:
                if source.default_value and not source.is_secret:
                    default = source.default_value.raw
                    break
            lines.append(f"{var.name}={default}{desc}")

        env_example_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        console.print(f"[green]Generated {env_example_path}[/green]")

    console.print("[green]Fix complete.[/green]")


def main() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
