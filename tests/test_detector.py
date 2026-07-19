"""Tests for the Security Secret Detector."""

from __future__ import annotations

import pytest

from envtether.config import SecurityConfig
from envtether.models.config import (
    ConfigSource,
    ConfigSourceType,
    ConfigVariable,
    VariableLocation,
)
from envtether.security.detector import SecretDetector
from envtether.security.entropy import shannon_entropy


class TestSecretDetector:
    """Tests for SecretDetector."""

    @pytest.fixture()
    def detector(self) -> SecretDetector:
        return SecretDetector(SecurityConfig())

    def _create_variable(self, name: str, value: str) -> ConfigVariable:
        location = VariableLocation(
            file_path=".env",
            line=1,
            column=0,
            snippet=f"{name}={value}",
        )
        source = ConfigSource(
            source_type=ConfigSourceType.ENV_FILE,
            location=location,
            raw_value=value,
        )
        return ConfigVariable(name=name, sources=(source,))

    def test_detect_aws_access_key(self, detector: SecretDetector) -> None:
        var = self._create_variable("MY_KEY", "AKIAIOSFODNN7EXAMPLE")
        findings = detector.scan_variables([var])
        
        assert len(findings) == 1
        assert findings[0].category.value == "exposed_secret"
        assert "AWS Access Key ID" in findings[0].description

    def test_detect_high_entropy_secret(self, detector: SecretDetector) -> None:
        # High entropy but no specific pattern
        var = self._create_variable("WEIRD_TOKEN", "x8f93qjd8c4m1!@#$%^&*()_+-=[]{}|;':,./<>?~`")
        findings = detector.scan_variables([var])
        
        assert len(findings) == 1
        assert "high entropy" in findings[0].description.lower()
        
    def test_ignore_low_entropy_non_secrets(self, detector: SecretDetector) -> None:
        var = self._create_variable("APP_NAME", "my-awesome-app")
        findings = detector.scan_variables([var])
        
        assert len(findings) == 0

    def test_scan_text(self, detector: SecretDetector) -> None:
        text = "RUN echo 'AKIAIOSFODNN7EXAMPLE' > /etc/aws/credentials\n"
        findings = detector.scan_text(text, "Dockerfile")
        
        assert len(findings) == 1
        assert "AWS Access Key ID" in findings[0].title


class TestEntropy:
    """Tests for Shannon entropy calculation."""

    def test_shannon_entropy_empty(self) -> None:
        assert shannon_entropy("") == 0.0

    def test_shannon_entropy_single_char(self) -> None:
        assert shannon_entropy("aaaa") == 0.0

    def test_shannon_entropy_high(self) -> None:
        # A 16 char string with 16 distinct chars should have log2(16) = 4.0 entropy
        assert shannon_entropy("0123456789abcdef") == 4.0
