"""Kubernetes manifest analyser.

Extracts environment variables from:
- ``spec.containers[].env``
- ``spec.containers[].envFrom``
- ConfigMap ``data``
- Secret ``data`` / ``stringData``
"""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from envtether.models.config import (
    ConfigSource,
    ConfigSourceType,
    ConfigVariable,
    VariableLocation,
)

logger = logging.getLogger(__name__)


class KubernetesAnalyzer:
    """Parses Kubernetes manifest YAML for environment variable definitions."""

    def analyze(
        self,
        file_path: Path,
        relative_path: str,
    ) -> list[ConfigVariable]:
        """Parse a Kubernetes manifest and return discovered variables.

        Args:
            file_path: Absolute path to the manifest.
            relative_path: Path relative to the repository root.

        Returns:
            A list of :class:`ConfigVariable` instances.
        """
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.warning("Cannot read %s: %s", file_path, exc)
            return []

        variables: list[ConfigVariable] = []
        source_lines = content.splitlines()

        # Handle multi-document YAML
        try:
            documents = list(yaml.safe_load_all(content))
        except yaml.YAMLError as exc:
            logger.warning("Cannot parse YAML in %s: %s", relative_path, exc)
            return []

        for doc in documents:
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind", "")
            variables.extend(
                self._extract_from_document(doc, kind, relative_path, source_lines)
            )

        logger.debug("Parsed %d variables from %s", len(variables), relative_path)
        return variables

    def _extract_from_document(
        self,
        doc: dict[str, object],
        kind: str,
        relative_path: str,
        source_lines: list[str],
    ) -> list[ConfigVariable]:
        """Extract variables from a single Kubernetes document."""
        variables: list[ConfigVariable] = []

        if kind in {"ConfigMap"}:
            variables.extend(
                self._extract_configmap(doc, relative_path, source_lines)
            )
        elif kind in {"Secret"}:
            variables.extend(
                self._extract_secret(doc, relative_path, source_lines)
            )
        else:
            # Look for container env definitions in pod specs
            spec = doc.get("spec", {})
            if isinstance(spec, dict):
                variables.extend(
                    self._extract_from_pod_spec(spec, kind, relative_path, source_lines)
                )

                # Template spec (Deployment, StatefulSet, etc.)
                template = spec.get("template", {})
                if isinstance(template, dict):
                    template_spec = template.get("spec", {})
                    if isinstance(template_spec, dict):
                        variables.extend(
                            self._extract_from_pod_spec(
                                template_spec, kind, relative_path, source_lines
                            )
                        )

        return variables

    def _extract_from_pod_spec(
        self,
        spec: dict[str, object],
        kind: str,
        relative_path: str,
        source_lines: list[str],
    ) -> list[ConfigVariable]:
        """Extract env vars from containers in a pod spec."""
        variables: list[ConfigVariable] = []
        containers = spec.get("containers", [])
        if not isinstance(containers, list):
            return variables

        for container in containers:
            if not isinstance(container, dict):
                continue
            container_name = container.get("name", "unknown")

            # Direct env entries
            env_list = container.get("env", [])
            if isinstance(env_list, list):
                for env_entry in env_list:
                    if not isinstance(env_entry, dict):
                        continue
                    name = env_entry.get("name")
                    if not isinstance(name, str):
                        continue

                    value = env_entry.get("value")
                    value_from = env_entry.get("valueFrom")

                    line_no = self._find_key_line(source_lines, name)
                    location = VariableLocation(
                        file_path=relative_path,
                        line=line_no,
                        column=0,
                        snippet=source_lines[line_no - 1] if line_no <= len(source_lines) else "",
                    )

                    is_secret = False
                    metadata: dict[str, str] = {
                        "kind": kind,
                        "container": container_name,
                    }

                    if value_from and isinstance(value_from, dict):
                        if "secretKeyRef" in value_from:
                            is_secret = True
                            ref = value_from["secretKeyRef"]
                            if isinstance(ref, dict):
                                metadata["secret_name"] = str(ref.get("name", ""))
                                metadata["secret_key"] = str(ref.get("key", ""))
                        elif "configMapKeyRef" in value_from:
                            ref = value_from["configMapKeyRef"]
                            if isinstance(ref, dict):
                                metadata["configmap_name"] = str(ref.get("name", ""))
                                metadata["configmap_key"] = str(ref.get("key", ""))

                    raw_value = str(value) if value is not None and not is_secret else None

                    source = ConfigSource(
                        source_type=ConfigSourceType.KUBERNETES,
                        location=location,
                        raw_value=raw_value,
                        is_secret=is_secret,
                        metadata=metadata,
                    )

                    var = ConfigVariable(
                        name=name,
                        sources=(source,),
                        tags=frozenset({"kubernetes", f"kind:{kind}", f"container:{container_name}"}),
                    )
                    variables.append(var)

        return variables

    def _extract_configmap(
        self,
        doc: dict[str, object],
        relative_path: str,
        source_lines: list[str],
    ) -> list[ConfigVariable]:
        """Extract variables from a ConfigMap."""
        variables: list[ConfigVariable] = []
        data = doc.get("data", {})
        if not isinstance(data, dict):
            return variables

        cm_name = ""
        metadata = doc.get("metadata", {})
        if isinstance(metadata, dict):
            cm_name = str(metadata.get("name", ""))

        for key, value in data.items():
            line_no = self._find_key_line(source_lines, str(key))
            location = VariableLocation(
                file_path=relative_path,
                line=line_no,
                column=0,
                snippet=source_lines[line_no - 1] if line_no <= len(source_lines) else "",
            )
            source = ConfigSource(
                source_type=ConfigSourceType.KUBERNETES,
                location=location,
                raw_value=str(value) if value is not None else None,
                metadata={"kind": "ConfigMap", "configmap_name": cm_name},
            )
            var = ConfigVariable(
                name=str(key),
                sources=(source,),
                tags=frozenset({"kubernetes", "configmap", f"configmap:{cm_name}"}),
            )
            variables.append(var)

        return variables

    def _extract_secret(
        self,
        doc: dict[str, object],
        relative_path: str,
        source_lines: list[str],
    ) -> list[ConfigVariable]:
        """Extract variables from a Secret."""
        variables: list[ConfigVariable] = []

        secret_name = ""
        meta = doc.get("metadata", {})
        if isinstance(meta, dict):
            secret_name = str(meta.get("name", ""))

        for data_key in ("data", "stringData"):
            data = doc.get(data_key, {})
            if not isinstance(data, dict):
                continue

            for key in data:
                line_no = self._find_key_line(source_lines, str(key))
                location = VariableLocation(
                    file_path=relative_path,
                    line=line_no,
                    column=0,
                    snippet=source_lines[line_no - 1] if line_no <= len(source_lines) else "",
                )
                source = ConfigSource(
                    source_type=ConfigSourceType.KUBERNETES,
                    location=location,
                    is_secret=True,
                    metadata={"kind": "Secret", "secret_name": secret_name},
                )
                var = ConfigVariable(
                    name=str(key),
                    sources=(source,),
                    tags=frozenset({"kubernetes", "secret", f"secret:{secret_name}"}),
                )
                variables.append(var)

        return variables

    @staticmethod
    def _find_key_line(lines: list[str], key: str) -> int:
        """Find the line number where a key appears."""
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith(f"- name: {key}") or stripped.startswith(f"{key}:"):
                return i + 1
            if f'name: "{key}"' in stripped or f"name: '{key}'" in stripped:
                return i + 1
        return 1
