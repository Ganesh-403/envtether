"""Secret detection engine.

Combines pattern matching with entropy analysis to detect secrets in
configuration values and source code.
"""

from __future__ import annotations

import logging

from envtether.config import SecurityConfig
from envtether.models.config import ConfigVariable, VariableLocation
from envtether.models.findings import (
    Finding,
    FindingCategory,
    Recommendation,
    Severity,
)
from envtether.utils.hashing import deterministic_id
from envtether.utils.text import redact_value

from .entropy import shannon_entropy
from .patterns import SecretPattern, SecretPatternRegistry

logger = logging.getLogger(__name__)


class SecretDetector:
    """Detects secrets in configuration variable values and raw text.

    Combines regex-based pattern matching with Shannon entropy analysis to
    minimise both false positives and false negatives.

    Args:
        config: Security configuration controlling thresholds and ignored vars.
        registry: Optional custom pattern registry.
    """

    def __init__(
        self,
        config: SecurityConfig | None = None,
        registry: SecretPatternRegistry | None = None,
    ) -> None:
        self._config = config or SecurityConfig()
        self._registry = registry or SecretPatternRegistry()

    def scan_variables(
        self, variables: list[ConfigVariable]
    ) -> list[Finding]:
        """Scan a list of configuration variables for exposed secrets.

        Args:
            variables: The variables to check.

        Returns:
            A list of :class:`Finding` objects for detected secrets.
        """
        findings: list[Finding] = []

        for var in variables:
            if var.name in self._config.ignored_variables:
                continue

            for source in var.sources:
                if source.raw_value is None:
                    continue

                value = source.raw_value
                if len(value) < self._config.min_secret_length:
                    continue

                # Check entropy
                entropy = shannon_entropy(value)
                high_entropy = entropy >= self._config.entropy_threshold

                # Check patterns
                matched_patterns = self._match_patterns(value)

                # Also check variable name against patterns
                name_patterns = self._match_patterns(f"{var.name}={value}")

                all_patterns = matched_patterns | name_patterns

                if all_patterns or (high_entropy and self._looks_like_secret_name(var.name)):
                    redacted = redact_value(value) if self._config.redact_secrets else value

                    pattern_names = ", ".join(p.name for p in all_patterns) if all_patterns else "high entropy"

                    finding = Finding(
                        finding_id=deterministic_id(
                            "exposed_secret",
                            var.name,
                            source.location.file_path,
                            str(source.location.line),
                        ),
                        title=f"Exposed secret: {var.name}",
                        description=(
                            f"The variable ``{var.name}`` contains what appears to be a "
                            f"secret value (detected by: {pattern_names}). "
                            f"The value ``{redacted}`` was found in "
                            f"``{source.location.file_path}`` at line {source.location.line}. "
                            f"Shannon entropy: {entropy:.2f} bits."
                        ),
                        severity=Severity.CRITICAL if all_patterns else Severity.HIGH,
                        category=FindingCategory.EXPOSED_SECRET,
                        variable_name=var.name,
                        locations=(source.location,),
                        recommendations=self._build_recommendations(var.name, all_patterns),
                        tags=frozenset(
                            {"security", "secret"}
                            | {tag for p in all_patterns for tag in p.tags}
                        ),
                    )
                    findings.append(finding)

        logger.info("Secret scan found %d potential secrets", len(findings))
        return findings

    def scan_text(
        self,
        text: str,
        file_path: str,
    ) -> list[Finding]:
        """Scan raw text content for secret patterns.

        Used for scanning non-structured files like Dockerfiles and shell scripts.

        Args:
            text: The file content to scan.
            file_path: Relative path for location reporting.

        Returns:
            A list of :class:`Finding` objects.
        """
        findings: list[Finding] = []
        lines = text.splitlines()

        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            for pattern in self._registry.patterns:
                match = pattern.regex.search(line)
                if match:
                    secret_group = match.groupdict().get("secret", match.group(0))
                    redacted = (
                        redact_value(secret_group)
                        if self._config.redact_secrets
                        else secret_group
                    )

                    location = VariableLocation(
                        file_path=file_path,
                        line=line_no,
                        column=match.start(),
                        snippet=line,
                    )

                    finding = Finding(
                        finding_id=deterministic_id(
                            "secret_in_file", pattern.pattern_id, file_path, str(line_no)
                        ),
                        title=f"{pattern.name} detected",
                        description=(
                            f"A {pattern.name} pattern was found in ``{file_path}`` at "
                            f"line {line_no}. {pattern.description} "
                            f"Matched value: ``{redacted}``."
                        ),
                        severity=Severity.CRITICAL
                        if pattern.severity == "critical"
                        else Severity.HIGH,
                        category=FindingCategory.EXPOSED_SECRET,
                        locations=(location,),
                        recommendations=(
                            Recommendation(
                                message=pattern.remediation or (
                                    f"Remove the {pattern.name} from source code and "
                                    f"store it in an environment variable or secrets manager."
                                ),
                                priority=1,
                            ),
                        ),
                        tags=frozenset({"security", "secret"} | pattern.tags),
                    )
                    findings.append(finding)

        return findings

    def _match_patterns(self, text: str) -> set[SecretPattern]:
        """Run all registered patterns against *text*.

        Returns:
            The set of patterns that matched.
        """
        matched: set[SecretPattern] = set()
        for pattern in self._registry.patterns:
            if pattern.regex.search(text):
                matched.add(pattern)
        return matched

    @staticmethod
    def _looks_like_secret_name(name: str) -> bool:
        """Heuristic: does the variable name suggest a secret?"""
        lower = name.lower()
        secret_words = {
            "secret", "password", "passwd", "token", "api_key", "apikey",
            "access_key", "private_key", "signing_key", "encryption_key",
            "auth_token", "client_secret", "jwt_secret", "db_password",
            "smtp_password", "openai", "anthropic", "stripe", "twilio",
        }
        return any(word in lower for word in secret_words)

    @staticmethod
    def _build_recommendations(
        var_name: str,
        patterns: set[SecretPattern],
    ) -> tuple[Recommendation, ...]:
        """Build recommendations from matched patterns."""
        recs: list[Recommendation] = [
            Recommendation(
                message=(
                    f"Remove ``{var_name}`` from all committed files. Use an environment "
                    f"variable or a secrets manager (e.g. AWS Secrets Manager, HashiCorp "
                    f"Vault, or Doppler)."
                ),
                priority=1,
            ),
            Recommendation(
                message=(
                    f"Add the file containing ``{var_name}`` to ``.gitignore`` if it is "
                    f"a ``.env`` file."
                ),
                priority=2,
            ),
        ]

        # Add pattern-specific remediation
        for pattern in patterns:
            if pattern.remediation:
                recs.append(
                    Recommendation(
                        message=pattern.remediation,
                        priority=3,
                    )
                )

        return tuple(recs)
