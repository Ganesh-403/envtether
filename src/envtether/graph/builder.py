"""Configuration dependency graph builder.

Creates a NetworkX directed graph from configuration analysis results,
linking variables to their definition sites, usage sites, services,
and deployment targets.
"""

from __future__ import annotations

import logging

import networkx as nx  # type: ignore[import-untyped]

from envtether.models.config import ConfigVariable
from envtether.models.project import ArchitectureInfo, ServiceDependency

logger = logging.getLogger(__name__)


class GraphBuilder:
    """Builds a configuration dependency graph.

    The graph has the following node types:
    - ``variable``: A configuration variable
    - ``file``: A file that defines or uses a variable
    - ``service``: A service dependency (database, cache, etc.)
    - ``framework``: A detected framework
    """

    def __init__(self) -> None:
        self._graph = nx.DiGraph()

    @property
    def graph(self) -> nx.DiGraph:
        """Return the underlying NetworkX graph."""
        return self._graph

    def build(
        self,
        variables: list[ConfigVariable],
        architecture: ArchitectureInfo | None = None,
    ) -> nx.DiGraph:
        """Build the dependency graph from analysis results.

        Args:
            variables: All discovered configuration variables.
            architecture: Optional architecture info for service nodes.

        Returns:
            The constructed NetworkX directed graph.
        """
        self._graph = nx.DiGraph()

        # Add variable nodes and their file connections
        for var in variables:
            var_node = f"var:{var.name}"
            self._graph.add_node(
                var_node,
                node_type="variable",
                label=var.name,
                is_secret=var.is_secret,
                is_dead=var.is_dead,
                is_missing=var.is_missing,
                definition_count=var.definition_count,
            )

            # Connect to definition files
            for source in var.sources:
                file_node = f"file:{source.location.file_path}"
                if not self._graph.has_node(file_node):
                    self._graph.add_node(
                        file_node,
                        node_type="file",
                        label=source.location.file_path,
                        source_type=source.source_type.value,
                    )
                self._graph.add_edge(
                    file_node,
                    var_node,
                    edge_type="defines",
                    line=source.location.line,
                )

            # Connect to usage files
            for usage in var.usages:
                file_node = f"file:{usage.location.file_path}"
                if not self._graph.has_node(file_node):
                    self._graph.add_node(
                        file_node,
                        node_type="file",
                        label=usage.location.file_path,
                    )
                self._graph.add_edge(
                    var_node,
                    file_node,
                    edge_type="used_in",
                    context=usage.context,
                    line=usage.location.line,
                )

        # Add service nodes from architecture
        if architecture:
            for svc in architecture.services:
                self._add_service_node(svc)

            for pt in architecture.project_types:
                fw_node = f"framework:{pt.value}"
                self._graph.add_node(
                    fw_node,
                    node_type="framework",
                    label=pt.value,
                )

        logger.info(
            "Built graph with %d nodes and %d edges",
            self._graph.number_of_nodes(),
            self._graph.number_of_edges(),
        )
        return self._graph

    def _add_service_node(self, svc: ServiceDependency) -> None:
        """Add a service node and connect it to its config variables."""
        svc_node = f"service:{svc.name}"
        self._graph.add_node(
            svc_node,
            node_type="service",
            label=svc.name,
            role=svc.role.value,
            provider=svc.provider,
        )

        for var_name in svc.config_variables:
            var_node = f"var:{var_name}"
            if self._graph.has_node(var_node):
                self._graph.add_edge(
                    var_node,
                    svc_node,
                    edge_type="configures",
                )

    def get_variable_dependencies(self, var_name: str) -> list[str]:
        """Return all nodes downstream from a variable.

        Args:
            var_name: The variable name (without ``var:`` prefix).

        Returns:
            A list of dependent node labels.
        """
        var_node = f"var:{var_name}"
        if not self._graph.has_node(var_node):
            return []
        descendants = nx.descendants(self._graph, var_node)
        return [self._graph.nodes[n].get("label", n) for n in descendants]

    def get_orphaned_variables(self) -> list[str]:
        """Return variable names that have no connections.

        Returns:
            A list of orphaned variable names.
        """
        orphans: list[str] = []
        for node, data in self._graph.nodes(data=True):
            if data.get("node_type") == "variable" and self._graph.degree(node) == 0:
                orphans.append(data.get("label", node))
        return orphans

    def get_stats(self) -> dict[str, int]:
        """Return summary statistics about the graph.

        Returns:
            A dict with counts of nodes by type and total edges.
        """
        stats: dict[str, int] = {"total_nodes": 0, "total_edges": 0}
        for _, data in self._graph.nodes(data=True):
            node_type = data.get("node_type", "unknown")
            key = f"{node_type}_nodes"
            stats[key] = stats.get(key, 0) + 1
            stats["total_nodes"] += 1
        stats["total_edges"] = self._graph.number_of_edges()
        return stats
