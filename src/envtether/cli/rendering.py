"""Rich console rendering for CLI output.

Provides a shared :class:`Console` instance and helper functions for
rendering analysis results with Rich panels, tables, trees, and progress bars.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.tree import Tree

if TYPE_CHECKING:
    from envtether.models.findings import Finding, Severity
    from envtether.models.health import HealthReport
    from envtether.models.project import ProjectInfo
    from envtether.models.report import FullReport

console = Console(stderr=True)
output_console = Console()


def setup_logging(verbose: bool = False) -> None:
    """Configure logging with Rich handler.

    Args:
        verbose: If ``True``, set log level to DEBUG.
    """
    level = logging.DEBUG if verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(console=console, show_path=False, rich_tracebacks=True)],
    )


def render_banner() -> None:
    """Render the envtether startup banner."""
    banner_text = Text()
    banner_text.append("env", style="bold #818cf8")
    banner_text.append("tether", style="bold #c084fc")

    console.print(
        Panel(
            banner_text,
            subtitle="Static Configuration Intelligence",
            style="dim",
            border_style="#334155",
            padding=(0, 2),
        )
    )


def render_health_score(health: HealthReport) -> None:
    """Render the health score as a Rich panel."""
    score = health.score
    colour = _score_colour(score.overall)

    score_text = Text()
    score_text.append(f" {score.overall:.0f}", style=f"bold {colour}")
    score_text.append(" / 100  ", style="dim")
    score_text.append(f"Grade {score.grade}", style=f"bold {colour}")

    console.print(
        Panel(
            score_text,
            title="[bold]Health Score[/bold]",
            border_style=colour,
            padding=(0, 1),
        )
    )

    # Production readiness
    if health.is_production_ready:
        console.print("  ✅ [green bold]Production Ready[/green bold]")
    else:
        console.print("  ⚠️  [yellow bold]Not Production Ready[/yellow bold]")
        for blocker in health.production_blockers:
            console.print(f"     • {blocker}", style="yellow")

    console.print()

    # Dimension bars
    for dim in sorted(score.dimensions, key=lambda d: d.score):
        bar_colour = _score_colour(dim.score)
        name = dim.dimension.value.replace("_", " ").title()
        bar_filled = int(dim.score / 5)
        bar_empty = 20 - bar_filled
        bar = f"[{bar_colour}]{'█' * bar_filled}[/{bar_colour}][dim]{'░' * bar_empty}[/dim]"
        console.print(f"  {name:<26s} {bar} {dim.score:5.0f}  ({dim.issue_count} issues)")

    console.print()


def render_findings_table(findings: list[Finding]) -> None:
    """Render findings as a Rich table."""
    if not findings:
        console.print("  [green]No findings — configuration looks clean![/green]")
        return

    table = Table(
        title="Findings",
        show_lines=True,
        border_style="#334155",
        header_style="bold #818cf8",
    )
    table.add_column("ID", style="dim", width=8)
    table.add_column("Severity", width=10)
    table.add_column("Title", min_width=30)
    table.add_column("Variable", width=20)
    table.add_column("Location", width=25)

    for finding in sorted(findings, key=lambda f: _severity_order(f.severity)):
        sev_style = _severity_style(finding.severity)
        location = ""
        if finding.locations:
            loc = finding.locations[0]
            location = f"{loc.file_path}:{loc.line}"

        table.add_row(
            finding.finding_id,
            Text(finding.severity.value.upper(), style=sev_style),
            finding.title,
            finding.variable_name or "",
            location,
        )

    console.print(table)


def render_project_info(project: ProjectInfo) -> None:
    """Render project information as a Rich tree."""
    tree = Tree(
        f"[bold #818cf8]{project.name}[/bold #818cf8]",
        guide_style="#334155",
    )

    info = tree.add("[bold]Project Info[/bold]")
    info.add(f"Files scanned: {project.total_files_scanned}")
    info.add(f"Config files: {project.total_config_files}")
    info.add(f"Python files: {project.total_python_files}")
    info.add(f"Duration: {project.scan_duration_ms:.0f}ms")

    if project.is_monorepo:
        info.add("[yellow]Monorepo detected[/yellow]")
        for sub in project.sub_projects:
            info.add(f"  └ {sub}")

    arch = project.architecture
    if arch.project_types:
        types_node = tree.add("[bold]Frameworks[/bold]")
        for pt in sorted(arch.project_types, key=lambda p: p.value):
            types_node.add(pt.value)

    if arch.cloud_providers:
        cloud_node = tree.add("[bold]Cloud Providers[/bold]")
        for cp in sorted(arch.cloud_providers, key=lambda c: c.value):
            cloud_node.add(cp.value)

    if arch.services:
        svc_node = tree.add("[bold]Services[/bold]")
        for svc in arch.services:
            svc_node.add(f"{svc.name} ({svc.role.value}) — {svc.provider}")

    console.print(tree)
    console.print()


def render_recommendations(health: HealthReport) -> None:
    """Render top recommendations."""
    if not health.top_recommendations:
        return

    console.print("[bold]Top Recommendations[/bold]")
    for i, rec in enumerate(health.top_recommendations[:5], start=1):
        priority_badge = f"[dim]P{rec.priority}[/dim]"
        console.print(f"  {i}. {priority_badge} {rec.message}")
    console.print()


def render_variable_explain(
    name: str, report: FullReport
) -> None:
    """Render detailed explanation of a single variable."""
    matching = [v for v in report.variables if v.name == name]

    if not matching:
        console.print(f"[yellow]Variable '{name}' not found in analysis results.[/yellow]")
        return

    var = matching[0]

    console.print(Panel(
        f"[bold #818cf8]{var.name}[/bold #818cf8]",
        subtitle=", ".join(s.value for s in var.statuses) if var.statuses else "active",
        border_style="#334155",
    ))

    if var.description:
        console.print(f"  [dim]Description:[/dim] {var.description}")

    console.print(f"  [dim]Defined in {var.definition_count} source(s)[/dim]")
    for source in var.sources:
        console.print(
            f"    • {source.source_type.value} — "
            f"{source.location.file_path}:{source.location.line}"
        )
        if source.default_value:
            console.print(f"      Default: {source.default_value.raw}")
        if source.is_secret:
            console.print("      [red]🔒 Secret[/red]")
        if source.is_required:
            console.print("      [yellow]Required[/yellow]")

    console.print(f"\n  [dim]Used in {len(var.usages)} location(s)[/dim]")
    for usage in var.usages:
        console.print(
            f"    • {usage.location.file_path}:{usage.location.line}"
            f" ({usage.context})"
        )

    # Related findings
    related = [f for f in report.findings if f.variable_name == name]
    if related:
        console.print(f"\n  [dim]Related findings ({len(related)})[/dim]")
        for finding in related:
            sev_style = _severity_style(finding.severity)
            console.print(
                f"    • [{sev_style}]{finding.severity.value.upper()}[/{sev_style}] "
                f"{finding.title}"
            )

    console.print()


def _score_colour(score: float) -> str:
    """Return a Rich colour string for a score value."""
    if score >= 90:
        return "#22c55e"
    if score >= 70:
        return "#eab308"
    if score >= 50:
        return "#f97316"
    return "#ef4444"


def _severity_style(severity: Severity) -> str:
    """Return a Rich style string for a severity level."""
    from envtether.models.findings import Severity

    return {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "bold #f97316",
        Severity.MEDIUM: "bold yellow",
        Severity.LOW: "bold blue",
        Severity.INFO: "dim",
    }[severity]


def _severity_order(severity: Severity) -> int:
    """Return a sort key for severity (critical first)."""
    from envtether.models.findings import Severity

    return {
        Severity.CRITICAL: 0,
        Severity.HIGH: 1,
        Severity.MEDIUM: 2,
        Severity.LOW: 3,
        Severity.INFO: 4,
    }[severity]
