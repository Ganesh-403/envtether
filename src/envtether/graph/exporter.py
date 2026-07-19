"""Graph export to multiple formats.

Supports Mermaid, Graphviz DOT, JSON, and interactive HTML exports.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

import networkx as nx  # type: ignore[import-untyped]

from envtether.exceptions import GraphExportError

logger = logging.getLogger(__name__)

# Node-type → Mermaid shape
_MERMAID_SHAPES: dict[str, tuple[str, str]] = {
    "variable": ("((", "))"),
    "file": ("[", "]"),
    "service": ("{{", "}}"),
    "framework": ("([", "])"),
}

# Node-type → colour (for HTML)
_NODE_COLOURS: dict[str, str] = {
    "variable": "#6366f1",
    "file": "#22c55e",
    "service": "#f59e0b",
    "framework": "#ec4899",
}


class GraphExporter:
    """Exports a configuration dependency graph to various formats."""

    def to_mermaid(self, graph: nx.DiGraph) -> str:
        """Export the graph as a Mermaid flowchart.

        Args:
            graph: The NetworkX graph to export.

        Returns:
            A Mermaid flowchart string.
        """
        lines: list[str] = ["graph TD"]

        # Define nodes
        for node, data in graph.nodes(data=True):
            node_type = data.get("node_type", "variable")
            label = data.get("label", node)
            safe_id = self._safe_mermaid_id(node)
            safe_label = label.replace('"', "'")
            open_bracket, close_bracket = _MERMAID_SHAPES.get(node_type, ("[", "]"))
            lines.append(f"    {safe_id}{open_bracket}\"{safe_label}\"{close_bracket}")

        # Define edges
        for src, dst, data in graph.edges(data=True):
            safe_src = self._safe_mermaid_id(src)
            safe_dst = self._safe_mermaid_id(dst)
            edge_label = data.get("edge_type", "")
            if edge_label:
                lines.append(f"    {safe_src} -->|{edge_label}| {safe_dst}")
            else:
                lines.append(f"    {safe_src} --> {safe_dst}")

        # Style classes
        lines.append("")
        for node_type, colour in _NODE_COLOURS.items():
            node_ids = [
                self._safe_mermaid_id(n)
                for n, d in graph.nodes(data=True)
                if d.get("node_type") == node_type
            ]
            if node_ids:
                lines.append(f"    classDef {node_type} fill:{colour},stroke:#333,color:#fff")
                lines.append(f"    class {','.join(node_ids)} {node_type}")

        return "\n".join(lines)

    def to_dot(self, graph: nx.DiGraph) -> str:
        """Export the graph as Graphviz DOT format.

        Args:
            graph: The NetworkX graph to export.

        Returns:
            A DOT format string.
        """
        lines: list[str] = [
            "digraph envtether {",
            '    rankdir=LR;',
            '    node [fontname="Inter", fontsize=11];',
            '    edge [fontname="Inter", fontsize=9, color="#666"];',
            "",
        ]

        for node, data in graph.nodes(data=True):
            node_type = data.get("node_type", "variable")
            label = data.get("label", node).replace('"', '\\"')
            colour = _NODE_COLOURS.get(node_type, "#999")
            shape = {"variable": "ellipse", "file": "box", "service": "hexagon", "framework": "diamond"}.get(
                node_type, "box"
            )
            safe = self._safe_dot_id(node)
            lines.append(
                f'    {safe} [label="{label}", shape={shape}, '
                f'style=filled, fillcolor="{colour}", fontcolor="white"];'
            )

        lines.append("")
        for src, dst, data in graph.edges(data=True):
            safe_src = self._safe_dot_id(src)
            safe_dst = self._safe_dot_id(dst)
            edge_label = data.get("edge_type", "")
            if edge_label:
                lines.append(f'    {safe_src} -> {safe_dst} [label="{edge_label}"];')
            else:
                lines.append(f"    {safe_src} -> {safe_dst};")

        lines.append("}")
        return "\n".join(lines)

    def to_json(self, graph: nx.DiGraph) -> str:
        """Export the graph as a JSON structure.

        Args:
            graph: The NetworkX graph to export.

        Returns:
            A JSON string.
        """
        data = nx.node_link_data(graph)
        return json.dumps(data, indent=2, default=str)

    def to_html(self, graph: nx.DiGraph) -> str:
        """Export the graph as an interactive HTML page using embedded Mermaid.

        Args:
            graph: The NetworkX graph to export.

        Returns:
            A complete HTML document string.
        """
        mermaid_code = self.to_mermaid(graph)
        stats = {
            "nodes": graph.number_of_nodes(),
            "edges": graph.number_of_edges(),
        }

        node_counts: dict[str, int] = {}
        for _, data in graph.nodes(data=True):
            nt = data.get("node_type", "unknown")
            node_counts[nt] = node_counts.get(nt, 0) + 1

        stats_html_parts: list[str] = []
        for nt, count in sorted(node_counts.items()):
            colour = _NODE_COLOURS.get(nt, "#999")
            stats_html_parts.append(
                f'<span style="color:{colour};font-weight:600">{nt}: {count}</span>'
            )
        stats_line = " &bull; ".join(stats_html_parts)

        return f"""<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>envtether — Configuration Graph</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: 'Inter', system-ui, -apple-system, sans-serif;
    background: #0f172a;
    color: #e2e8f0;
    min-height: 100vh;
    display: flex;
    flex-direction: column;
  }}
  header {{
    background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
    border-bottom: 1px solid #334155;
    padding: 1.5rem 2rem;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }}
  header h1 {{
    font-size: 1.5rem;
    font-weight: 700;
    background: linear-gradient(135deg, #818cf8, #c084fc);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
  }}
  .stats {{
    font-size: 0.875rem;
    color: #94a3b8;
  }}
  main {{
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 2rem;
  }}
  .mermaid {{
    width: 100%;
    max-width: 1200px;
  }}
  footer {{
    padding: 1rem 2rem;
    text-align: center;
    font-size: 0.75rem;
    color: #475569;
    border-top: 1px solid #1e293b;
  }}
</style>
</head>
<body>
<header>
  <h1>envtether Configuration Graph</h1>
  <div class="stats">
    {stats["nodes"]} nodes &bull; {stats["edges"]} edges &bull; {stats_line}
  </div>
</header>
<main>
  <pre class="mermaid">
{mermaid_code}
  </pre>
</main>
<footer>Generated by envtether</footer>
<script type="module">
  import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';
  mermaid.initialize({{ startOnLoad: true, theme: 'dark' }});
</script>
</body>
</html>"""

    def save(
        self,
        graph: nx.DiGraph,
        output_path: Path,
        fmt: str = "mermaid",
    ) -> Path:
        """Save the graph to a file.

        Args:
            graph: The graph to export.
            output_path: Target file path.
            fmt: Export format (``mermaid``, ``dot``, ``json``, ``html``).

        Returns:
            The path the file was written to.

        Raises:
            GraphExportError: If the format is not supported.
        """
        exporters = {
            "mermaid": self.to_mermaid,
            "dot": self.to_dot,
            "json": self.to_json,
            "html": self.to_html,
        }

        exporter = exporters.get(fmt)
        if exporter is None:
            raise GraphExportError(
                f"Unsupported graph format: {fmt}",
                hint=f"Supported formats: {', '.join(exporters)}",
            )

        content = exporter(graph)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
        logger.info("Graph exported to %s (%s)", output_path, fmt)
        return output_path

    @staticmethod
    def _safe_mermaid_id(node_id: str) -> str:
        """Convert a node ID to a Mermaid-safe identifier."""
        return node_id.replace(":", "_").replace("/", "_").replace(".", "_").replace("-", "_")

    @staticmethod
    def _safe_dot_id(node_id: str) -> str:
        """Convert a node ID to a DOT-safe identifier."""
        safe = node_id.replace(":", "_").replace("/", "_").replace(".", "_").replace("-", "_")
        return f'"{safe}"'
