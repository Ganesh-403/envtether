# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.x.x   | :white_check_mark: |

## Reporting a Vulnerability

We take security seriously. If you discover a security vulnerability in envtether,
please report it responsibly.

### How to Report

1. **Do NOT open a public issue.**
2. Email **security@envtether.dev** with:
   - A description of the vulnerability
   - Steps to reproduce
   - Impact assessment
   - Suggested fix (if any)
3. You will receive an acknowledgment within **48 hours**.
4. We will work with you to understand and address the issue before any public disclosure.

### What to Expect

- **Acknowledgment**: Within 48 hours of your report.
- **Status Update**: Within 7 days, including an initial assessment.
- **Resolution**: A fix will be developed and released as soon as possible.
- **Credit**: We will credit you in the release notes (unless you prefer anonymity).

### Scope

The following are in scope:

- Vulnerabilities in the envtether Python package
- Secret detection bypass
- Path traversal issues in scanning
- Unsafe deserialization of configuration files
- Information leakage through reports or logs

### Out of Scope

- Vulnerabilities in dependencies (report these upstream)
- Social engineering attacks
- Denial of service attacks against the CLI tool

### Security Design Principles

envtether is designed with security in mind:

- **No network calls**: envtether never phones home or sends telemetry data externally.
- **Read-only scanning**: envtether only reads files; it never modifies your source code
  unless explicitly invoked with `envtether fix` and user confirmation.
- **Local processing**: All analysis happens locally on your machine.
- **No credential storage**: envtether never stores or caches discovered secrets.
- **Redaction by default**: Detected secrets are redacted in all output formats.

## Security Best Practices

When using envtether in CI/CD pipelines:

1. Pin to a specific version in your CI configuration.
2. Review the SARIF output before acting on recommendations.
3. Use `envtether secrets --redact` to ensure secrets are never logged.
4. Store envtether configuration in version control.

Thank you for helping keep envtether and its users safe.
