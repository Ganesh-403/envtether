"""Known secret patterns for credential detection.

Each pattern combines a regex with metadata about the credential type,
severity, and remediation guidance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class SecretPattern:
    """A single secret detection pattern."""

    pattern_id: str
    name: str
    regex: re.Pattern[str]
    severity: str = "critical"
    description: str = ""
    remediation: str = ""
    tags: frozenset[str] = field(default_factory=frozenset)


class SecretPatternRegistry:
    """Registry of known secret patterns.

    All patterns are compiled at class-load time for performance.
    """

    def __init__(self) -> None:
        self._patterns: list[SecretPattern] = list(_BUILTIN_PATTERNS)

    @property
    def patterns(self) -> list[SecretPattern]:
        """Return all registered patterns."""
        return list(self._patterns)

    def add_pattern(self, pattern: SecretPattern) -> None:
        """Register a custom pattern.

        Args:
            pattern: The pattern to add.
        """
        self._patterns.append(pattern)

    def add_custom(self, name: str, regex_str: str) -> None:
        """Register a custom pattern from a name and regex string.

        Args:
            name: Human-readable name.
            regex_str: The regex pattern string.
        """
        pattern = SecretPattern(
            pattern_id=f"custom_{name.lower().replace(' ', '_')}",
            name=name,
            regex=re.compile(regex_str),
            severity="high",
            description=f"Custom secret pattern: {name}",
            tags=frozenset({"custom"}),
        )
        self._patterns.append(pattern)


def _p(
    pattern_id: str,
    name: str,
    regex: str,
    severity: str = "critical",
    description: str = "",
    remediation: str = "",
    tags: frozenset[str] | None = None,
) -> SecretPattern:
    """Helper to build a :class:`SecretPattern`."""
    return SecretPattern(
        pattern_id=pattern_id,
        name=name,
        regex=re.compile(regex),
        severity=severity,
        description=description,
        remediation=remediation,
        tags=tags or frozenset(),
    )


_BUILTIN_PATTERNS: tuple[SecretPattern, ...] = (
    # AWS
    _p(
        "aws_access_key",
        "AWS Access Key ID",
        r"(?:^|[^A-Za-z0-9/+=])(?P<secret>AKIA[0-9A-Z]{16})(?:[^A-Za-z0-9/+=]|$)",
        description="AWS Access Key IDs start with 'AKIA' followed by 16 alphanumeric characters.",
        remediation="Rotate the key immediately in the AWS IAM console and use environment variables or AWS Secrets Manager.",
        tags=frozenset({"aws", "iam"}),
    ),
    _p(
        "aws_secret_key",
        "AWS Secret Access Key",
        r"(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*['\"]?(?P<secret>[A-Za-z0-9/+=]{40})['\"]?",
        description="AWS Secret Access Keys are 40-character base64 strings.",
        remediation="Rotate the key in AWS IAM and store it in a secrets manager.",
        tags=frozenset({"aws", "iam"}),
    ),
    # Azure
    _p(
        "azure_connection_string",
        "Azure Connection String",
        r"(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*(?P<secret>[A-Za-z0-9+/=]{20,})",
        description="Azure Storage connection strings contain account keys.",
        remediation="Rotate the storage account key and use managed identities where possible.",
        tags=frozenset({"azure", "storage"}),
    ),
    _p(
        "azure_client_secret",
        "Azure Client Secret",
        r"(?:AZURE_CLIENT_SECRET|azure_client_secret)\s*[=:]\s*['\"]?(?P<secret>[A-Za-z0-9~._-]{34,})['\"]?",
        description="Azure AD application client secrets.",
        remediation="Rotate the client secret in Azure AD and use managed identities.",
        tags=frozenset({"azure", "ad"}),
    ),
    # GCP
    _p(
        "gcp_service_account",
        "GCP Service Account Key",
        r'"type"\s*:\s*"service_account"',
        severity="critical",
        description="GCP service account JSON key files should never be committed to source control.",
        remediation="Delete the key, generate a new one, and use Workload Identity Federation.",
        tags=frozenset({"gcp", "iam"}),
    ),
    _p(
        "gcp_api_key",
        "GCP API Key",
        r"AIza[0-9A-Za-z_-]{35}",
        description="GCP API keys start with 'AIza'.",
        remediation="Restrict the API key by IP/referrer and rotate it.",
        tags=frozenset({"gcp"}),
    ),
    # JWT / Auth
    _p(
        "jwt_secret",
        "JWT Secret",
        r"(?:JWT_SECRET|jwt_secret|JWT_SECRET_KEY|jwt_secret_key)\s*[=:]\s*['\"]?(?P<secret>[^\s'\"]{16,})['\"]?",
        description="JWT signing secrets should be strong and stored securely.",
        remediation="Generate a new secret using a cryptographically secure random generator.",
        tags=frozenset({"auth", "jwt"}),
    ),
    # Private Keys
    _p(
        "private_key",
        "Private Key",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        description="Private keys must never be stored in source code.",
        remediation="Remove the key from source code and use a secrets manager or certificate store.",
        tags=frozenset({"crypto", "pem"}),
    ),
    # Generic Passwords
    _p(
        "generic_password",
        "Generic Password",
        r"(?:PASSWORD|password|PASSWD|passwd|DB_PASSWORD|db_password)\s*[=:]\s*['\"]?(?P<secret>[^\s'\"]{8,})['\"]?",
        severity="high",
        description="Passwords should never be hardcoded.",
        remediation="Move the password to an environment variable or secrets manager.",
        tags=frozenset({"password"}),
    ),
    # GitHub Token
    _p(
        "github_token",
        "GitHub Token",
        r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}",
        description="GitHub personal access tokens and OAuth tokens.",
        remediation="Revoke the token on GitHub and generate a new one with minimal scopes.",
        tags=frozenset({"github", "token"}),
    ),
    # OpenAI
    _p(
        "openai_api_key",
        "OpenAI API Key",
        r"sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,}",
        description="OpenAI API keys start with 'sk-'.",
        remediation="Rotate the key in the OpenAI dashboard.",
        tags=frozenset({"openai", "llm"}),
    ),
    _p(
        "openai_api_key_v2",
        "OpenAI API Key (v2 format)",
        r"sk-proj-[A-Za-z0-9_-]{40,}",
        description="OpenAI project API keys start with 'sk-proj-'.",
        remediation="Rotate the key in the OpenAI dashboard.",
        tags=frozenset({"openai", "llm"}),
    ),
    # Anthropic
    _p(
        "anthropic_api_key",
        "Anthropic API Key",
        r"sk-ant-[A-Za-z0-9_-]{40,}",
        description="Anthropic API keys start with 'sk-ant-'.",
        remediation="Rotate the key in the Anthropic console.",
        tags=frozenset({"anthropic", "llm"}),
    ),
    # Google Gemini
    _p(
        "gemini_api_key",
        "Google Gemini API Key",
        r"(?:GEMINI_API_KEY|GOOGLE_API_KEY)\s*[=:]\s*['\"]?(?P<secret>AIza[0-9A-Za-z_-]{35})['\"]?",
        description="Google Gemini API keys.",
        remediation="Rotate the key in Google Cloud Console.",
        tags=frozenset({"google", "gemini", "llm"}),
    ),
    # Stripe
    _p(
        "stripe_key",
        "Stripe API Key",
        r"(?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{20,}",
        description="Stripe API keys for live or test environments.",
        remediation="Rotate the key in the Stripe dashboard.",
        tags=frozenset({"stripe", "payment"}),
    ),
    # Twilio
    _p(
        "twilio_api_key",
        "Twilio API Key or Auth Token",
        r"(?:TWILIO_AUTH_TOKEN|twilio_auth_token)\s*[=:]\s*['\"]?(?P<secret>[a-f0-9]{32})['\"]?",
        description="Twilio auth tokens are 32-character hex strings.",
        remediation="Rotate the token in the Twilio console.",
        tags=frozenset({"twilio", "sms"}),
    ),
    # Slack
    _p(
        "slack_token",
        "Slack Token",
        r"xox[bprs]-[A-Za-z0-9-]{10,}",
        description="Slack bot, user, or app tokens.",
        remediation="Revoke and regenerate the token in Slack app settings.",
        tags=frozenset({"slack", "messaging"}),
    ),
    _p(
        "slack_webhook",
        "Slack Webhook URL",
        r"https://hooks\.slack\.com/services/T[A-Za-z0-9]+/B[A-Za-z0-9]+/[A-Za-z0-9]+",
        description="Slack incoming webhook URLs.",
        remediation="Regenerate the webhook URL in Slack app configuration.",
        tags=frozenset({"slack", "webhook"}),
    ),
    # Discord
    _p(
        "discord_token",
        "Discord Bot Token",
        r"(?:discord_token|DISCORD_TOKEN|DISCORD_BOT_TOKEN)\s*[=:]\s*['\"]?(?P<secret>[A-Za-z0-9._-]{50,})['\"]?",
        severity="high",
        description="Discord bot tokens.",
        remediation="Regenerate the token in the Discord Developer Portal.",
        tags=frozenset({"discord", "messaging"}),
    ),
    # Database URLs
    _p(
        "database_url",
        "Database URL with Credentials",
        r"(?:postgres|mysql|mongodb|redis|amqp|rabbitmq)(?:ql)?://[^:]+:(?P<secret>[^@]+)@[^\s'\"]+",
        severity="high",
        description="Database connection strings with embedded passwords.",
        remediation="Remove the password from the URL and use environment variables.",
        tags=frozenset({"database", "connection"}),
    ),
    # OAuth
    _p(
        "oauth_client_secret",
        "OAuth Client Secret",
        r"(?:CLIENT_SECRET|client_secret|OAUTH_SECRET|oauth_secret)\s*[=:]\s*['\"]?(?P<secret>[^\s'\"]{16,})['\"]?",
        severity="high",
        description="OAuth client secrets should be stored securely.",
        remediation="Move the client secret to a secrets manager.",
        tags=frozenset({"oauth", "auth"}),
    ),
    # Generic API Key
    _p(
        "generic_api_key",
        "Generic API Key",
        r"(?:API_KEY|api_key|APIKEY|apikey)\s*[=:]\s*['\"]?(?P<secret>[A-Za-z0-9_-]{20,})['\"]?",
        severity="high",
        description="Generic API keys should not be hardcoded.",
        remediation="Move the API key to an environment variable.",
        tags=frozenset({"api-key"}),
    ),
    # PEM Certificate
    _p(
        "pem_certificate",
        "PEM Certificate",
        r"-----BEGIN CERTIFICATE-----",
        severity="medium",
        description="PEM certificates in source code may indicate embedded credentials.",
        remediation="Store certificates in a certificate store or secrets manager.",
        tags=frozenset({"crypto", "pem"}),
    ),
)
