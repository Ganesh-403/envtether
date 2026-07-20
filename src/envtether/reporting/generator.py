"""Multi-format report generator.

Generates reports in Markdown, HTML (standalone dark-mode dashboard), JSON,
CSV, and SARIF formats from a :class:`FullReport`.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from typing import TYPE_CHECKING

from envtether.models.findings import Severity
from envtether.models.report import FullReport, ReportFormat

if TYPE_CHECKING:
    from pathlib import Path

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates configuration analysis reports in multiple formats."""

    def generate(
        self,
        report: FullReport,
        fmt: ReportFormat,
        output_path: Path | None = None,
    ) -> str:
        """Generate a report in the specified format.

        Args:
            report: The full analysis report.
            fmt: The desired output format.
            output_path: Optional file path to write the report to.

        Returns:
            The rendered report content as a string.
        """
        generators = {
            ReportFormat.MARKDOWN: self._to_markdown,
            ReportFormat.HTML: self._to_html,
            ReportFormat.JSON: self._to_json,
            ReportFormat.CSV: self._to_csv,
            ReportFormat.SARIF: self._to_sarif,
        }

        generator = generators[fmt]
        content = generator(report)

        if output_path:
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_text(content, encoding="utf-8")
            logger.info("Report written to %s", output_path)

        return content

    def _to_markdown(self, report: FullReport) -> str:
        """Generate a Markdown report."""
        lines: list[str] = [
            "# envtether Configuration Report",
            "",
        ]

        # Metadata
        lines.extend(
            [
                f"**Generated**: {report.metadata.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
                f"**Scan root**: `{report.metadata.scan_root}`",
                f"**Duration**: {report.metadata.scan_duration_ms:.0f}ms",
                f"**Files scanned**: {report.metadata.total_files}",
                f"**Variables found**: {report.metadata.total_variables}",
                f"**Findings**: {report.metadata.total_findings}",
                "",
            ]
        )

        # Health Score
        if report.health:
            score = report.health.score
            lines.extend(
                [
                    "## Health Score",
                    "",
                    f"### {score.overall:.0f} / 100 — Grade {score.grade}",
                    "",
                    report.health.summary,
                    "",
                ]
            )

            if not report.health.is_production_ready:
                lines.extend(
                    [
                        "### ⚠️ Production Blockers",
                        "",
                    ]
                )
                for blocker in report.health.production_blockers:
                    lines.append(f"- {blocker}")
                lines.append("")

            lines.extend(
                [
                    "### Dimension Scores",
                    "",
                    "| Dimension | Score | Issues | Details |",
                    "|-----------|-------|--------|---------|",
                ]
            )
            for dim in score.dimensions:
                lines.append(
                    f"| {dim.dimension.value.replace('_', ' ').title()} "
                    f"| {dim.score:.0f} | {dim.issue_count} | {dim.details} |"
                )
            lines.append("")

        # Findings
        if report.findings:
            lines.extend(
                [
                    "## Findings",
                    "",
                ]
            )
            for severity in [
                Severity.CRITICAL,
                Severity.HIGH,
                Severity.MEDIUM,
                Severity.LOW,
                Severity.INFO,
            ]:
                findings = [f for f in report.findings if f.severity == severity]
                if findings:
                    emoji = {
                        "critical": "🔴",
                        "high": "🟠",
                        "medium": "🟡",
                        "low": "🔵",
                        "info": "ℹ️",
                    }.get(severity.value, "")
                    lines.extend(
                        [
                            f"### {emoji} {severity.value.title()} ({len(findings)})",
                            "",
                        ]
                    )
                    for finding in findings:
                        lines.extend(
                            [
                                f"#### {finding.finding_id}: {finding.title}",
                                "",
                                finding.description,
                                "",
                            ]
                        )
                        if finding.recommendations:
                            lines.append("**Recommendations:**")
                            for rec in finding.recommendations:
                                lines.append(f"- {rec.message}")
                            lines.append("")

        # Variables summary
        if report.variables:
            lines.extend(
                [
                    "## Variables",
                    "",
                    "| Name | Sources | Status | Secret |",
                    "|------|---------|--------|--------|",
                ]
            )
            for var in sorted(report.variables, key=lambda v: v.name):
                source_types = ", ".join(sorted({s.source_type.value for s in var.sources}))
                statuses = ", ".join(sorted(s.value for s in var.statuses)) or "active"
                secret = "🔒" if var.is_secret else ""
                lines.append(f"| `{var.name}` | {source_types} | {statuses} | {secret} |")
            lines.append("")

        # Cross-file comparison
        if report.cross_file and report.cross_file.has_drift:
            lines.extend(
                [
                    "## Cross-file Drift",
                    "",
                    f"**Consistent variables**: {len(report.cross_file.consistent_variables)}",
                    f"**Drift issues**: {report.cross_file.drift_count}",
                    "",
                ]
            )

        lines.append("---")
        lines.append("*Generated by [envtether](https://github.com/envtether/envtether)*")
        return "\n".join(lines)

    def _to_html(self, report: FullReport) -> str:
        """Generate a standalone HTML dashboard."""
        score_val = report.health.score.overall if report.health else 0
        grade = report.health.score.grade if report.health else "N/A"
        summary = report.health.summary if report.health else ""

        critical = sum(1 for f in report.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in report.findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in report.findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in report.findings if f.severity == Severity.LOW)

        # Build findings HTML
        findings_html = []
        for finding in report.findings:
            severity_colour = {
                "critical": "#ef4444",
                "high": "#f97316",
                "medium": "#eab308",
                "low": "#3b82f6",
                "info": "#6b7280",
            }.get(finding.severity.value, "#6b7280")

            recs_html = ""
            if finding.recommendations:
                recs_items = "".join(f"<li>{r.message}</li>" for r in finding.recommendations)
                recs_html = f"<ul class='recs'>{recs_items}</ul>"

            findings_html.append(f"""
            <div class="finding">
                <div class="finding-header">
                    <span class="severity" style="background:{severity_colour}">{finding.severity.value.upper()}</span>
                    <span class="finding-id">{finding.finding_id}</span>
                    <span class="finding-title">{finding.title}</span>
                </div>
                <p class="finding-desc">{finding.description}</p>
                {recs_html}
            </div>""")

        # Build variables table
        vars_rows = []
        for var in sorted(report.variables, key=lambda v: v.name):
            source_types = ", ".join(sorted({s.source_type.value for s in var.sources}))
            statuses = ", ".join(sorted(s.value for s in var.statuses)) or "active"
            secret_badge = '<span class="badge secret">SECRET</span>' if var.is_secret else ""
            vars_rows.append(
                f"<tr><td><code>{var.name}</code></td><td>{source_types}</td>"
                f"<td>{statuses}</td><td>{secret_badge}</td></tr>"
            )

        dimensions_html = ""
        if report.health:
            dim_bars = []
            for dim in report.health.score.dimensions:
                colour = (
                    "#22c55e" if dim.score >= 80 else "#eab308" if dim.score >= 50 else "#ef4444"
                )
                dim_name = dim.dimension.value.replace("_", " ").title()
                dim_bars.append(f"""
                <div class="dim-row">
                    <span class="dim-name">{dim_name}</span>
                    <div class="dim-bar-bg">
                        <div class="dim-bar" style="width:{dim.score}%;background:{colour}"></div>
                    </div>
                    <span class="dim-score">{dim.score:.0f}</span>
                </div>""")
            dimensions_html = "\n".join(dim_bars)

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>envtether Report</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:'Inter',system-ui,-apple-system,sans-serif;background:#0f172a;color:#e2e8f0;line-height:1.6}}
.container{{max-width:1200px;margin:0 auto;padding:2rem}}
header{{text-align:center;padding:3rem 0;border-bottom:1px solid #1e293b}}
h1{{font-size:2rem;font-weight:800;background:linear-gradient(135deg,#818cf8,#c084fc,#f472b6);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:.5rem}}
.tagline{{color:#94a3b8;font-size:1rem}}
.score-section{{display:flex;align-items:center;gap:3rem;padding:2rem 0;justify-content:center;flex-wrap:wrap}}
.score-ring{{width:160px;height:160px;border-radius:50%;background:conic-gradient(#818cf8 0deg,#818cf8 {score_val * 3.6}deg,#1e293b {score_val * 3.6}deg);display:flex;align-items:center;justify-content:center;position:relative}}
.score-inner{{width:120px;height:120px;border-radius:50%;background:#0f172a;display:flex;flex-direction:column;align-items:center;justify-content:center}}
.score-num{{font-size:2.5rem;font-weight:800;color:#818cf8}}
.score-grade{{font-size:1rem;color:#94a3b8}}
.summary{{max-width:500px;color:#cbd5e1}}
.stats-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:1rem;padding:2rem 0}}
.stat-card{{background:#1e293b;border-radius:12px;padding:1.5rem;text-align:center;border:1px solid #334155}}
.stat-value{{font-size:2rem;font-weight:700;color:#818cf8}}
.stat-label{{color:#94a3b8;font-size:.875rem;margin-top:.25rem}}
.dimensions{{padding:2rem 0}}
.dim-row{{display:flex;align-items:center;gap:1rem;margin:.5rem 0}}
.dim-name{{width:180px;font-size:.875rem;color:#94a3b8;text-align:right}}
.dim-bar-bg{{flex:1;height:8px;background:#1e293b;border-radius:4px;overflow:hidden}}
.dim-bar{{height:100%;border-radius:4px;transition:width .5s}}
.dim-score{{width:40px;text-align:right;font-weight:600;font-size:.875rem}}
h2{{font-size:1.5rem;font-weight:700;margin:2rem 0 1rem;padding-top:1rem;border-top:1px solid #1e293b}}
.finding{{background:#1e293b;border-radius:8px;padding:1rem;margin:.75rem 0;border:1px solid #334155}}
.finding-header{{display:flex;align-items:center;gap:.75rem;margin-bottom:.5rem}}
.severity{{padding:2px 8px;border-radius:4px;font-size:.75rem;font-weight:700;color:white}}
.finding-id{{color:#64748b;font-family:monospace;font-size:.75rem}}
.finding-title{{font-weight:600}}
.finding-desc{{color:#94a3b8;font-size:.875rem}}
.recs{{margin-top:.5rem;padding-left:1.5rem}}
.recs li{{color:#cbd5e1;font-size:.875rem;margin:.25rem 0}}
table{{width:100%;border-collapse:collapse;margin:1rem 0}}
th,td{{padding:.75rem 1rem;text-align:left;border-bottom:1px solid #1e293b}}
th{{color:#94a3b8;font-size:.75rem;text-transform:uppercase;letter-spacing:.05em}}
td code{{background:#334155;padding:2px 6px;border-radius:4px;font-size:.8rem}}
.badge{{padding:2px 6px;border-radius:3px;font-size:.7rem;font-weight:700}}
.badge.secret{{background:#ef444433;color:#ef4444}}
footer{{text-align:center;padding:2rem;color:#475569;font-size:.75rem;border-top:1px solid #1e293b}}
</style>
</head>
<body>
<div class="container">
<header>
<h1>envtether</h1>
<p class="tagline">Configuration Intelligence Report</p>
</header>
<div class="score-section">
<div class="score-ring"><div class="score-inner"><span class="score-num">{score_val:.0f}</span><span class="score-grade">Grade {grade}</span></div></div>
<p class="summary">{summary}</p>
</div>
<div class="stats-grid">
<div class="stat-card"><div class="stat-value">{report.metadata.total_variables}</div><div class="stat-label">Variables</div></div>
<div class="stat-card"><div class="stat-value">{report.metadata.total_files}</div><div class="stat-label">Files Scanned</div></div>
<div class="stat-card"><div class="stat-value">{critical}</div><div class="stat-label">Critical</div></div>
<div class="stat-card"><div class="stat-value">{high}</div><div class="stat-label">High</div></div>
<div class="stat-card"><div class="stat-value">{medium}</div><div class="stat-label">Medium</div></div>
<div class="stat-card"><div class="stat-value">{low}</div><div class="stat-label">Low</div></div>
</div>
<div class="dimensions"><h2>Dimension Scores</h2>{dimensions_html}</div>
<h2>Findings ({len(report.findings)})</h2>
{"".join(findings_html)}
<h2>Variables ({len(report.variables)})</h2>
<table><thead><tr><th>Name</th><th>Sources</th><th>Status</th><th></th></tr></thead><tbody>{"".join(vars_rows)}</tbody></table>
</div>
<footer>Generated by envtether &bull; {report.metadata.generated_at.strftime("%Y-%m-%d %H:%M UTC")}</footer>
</body>
</html>"""

    def _to_json(self, report: FullReport) -> str:
        """Generate a JSON report."""
        return report.model_dump_json(indent=2)

    def _to_csv(self, report: FullReport) -> str:
        """Generate a CSV report of variables."""
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(
            [
                "Variable",
                "Sources",
                "Statuses",
                "Is Secret",
                "Definition Count",
                "Usage Count",
                "Description",
            ]
        )
        for var in sorted(report.variables, key=lambda v: v.name):
            writer.writerow(
                [
                    var.name,
                    "; ".join(sorted({s.source_type.value for s in var.sources})),
                    "; ".join(sorted(s.value for s in var.statuses)),
                    str(var.is_secret),
                    var.definition_count,
                    len(var.usages),
                    var.description,
                ]
            )
        return output.getvalue()

    def _to_sarif(self, report: FullReport) -> str:
        """Generate a SARIF v2.1.0 report for CI integration."""
        rules: list[dict[str, object]] = []
        results: list[dict[str, object]] = []
        rule_ids_seen: set[str] = set()

        for finding in report.findings:
            # Register rule if not already seen
            if finding.category.value not in rule_ids_seen:
                rule_ids_seen.add(finding.category.value)
                rules.append(
                    {
                        "id": finding.category.value,
                        "name": finding.category.value.replace("_", " ").title(),
                        "shortDescription": {
                            "text": finding.category.value.replace("_", " ").title()
                        },
                        "defaultConfiguration": {
                            "level": self._sarif_level(finding.severity),
                        },
                    }
                )

            locations: list[dict[str, object]] = []
            for loc in finding.locations:
                locations.append(
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": loc.file_path},
                            "region": {"startLine": loc.line, "startColumn": loc.column + 1},
                        },
                    }
                )

            results.append(
                {
                    "ruleId": finding.category.value,
                    "ruleIndex": next(
                        i for i, r in enumerate(rules) if r["id"] == finding.category.value
                    ),
                    "level": self._sarif_level(finding.severity),
                    "message": {"text": finding.description},
                    "locations": locations,
                    "fingerprints": {"envtether/id": finding.finding_id},
                }
            )

        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "envtether",
                            "version": report.metadata.envtether_version,
                            "informationUri": "https://github.com/envtether/envtether",
                            "rules": rules,
                        }
                    },
                    "results": results,
                    "invocations": [
                        {
                            "executionSuccessful": True,
                            "startTimeUtc": report.metadata.generated_at.isoformat(),
                        }
                    ],
                }
            ],
        }

        return json.dumps(sarif, indent=2, default=str)

    @staticmethod
    def _sarif_level(severity: Severity) -> str:
        """Map envtether severity to SARIF level."""
        return {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }[severity]
