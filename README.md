# envtether

> **Static Configuration Intelligence for Modern Python Applications**

[![PyPI version](https://img.shields.io/pypi/v/envtether.svg)](https://pypi.org/project/envtether/)
[![Python versions](https://img.shields.io/pypi/pyversions/envtether.svg)](https://pypi.org/project/envtether/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

`envtether` is an enterprise-grade static analysis tool designed to help developers understand, validate, secure, and maintain project configuration before deployment.

It acts as the Ruff, SonarQube, or ESLint of application configuration, providing deep insights into how your configuration variables are defined, used, and deployed across your entire stack.

---

## 🌟 Key Features

- **Comprehensive Discovery**: Parses Python code (AST-level), `.env` files, Docker Compose, Kubernetes manifests, GitHub Actions, Terraform, and more.
- **Deep Framework Support**: Native support for FastAPI, Flask, Django, Pydantic `BaseSettings`, Dynaconf, and standard `os.getenv`.
- **Advanced Secret Detection**: Combines heuristic regex patterns with Shannon entropy analysis to detect hardcoded and exposed credentials (AWS, Azure, GCP, OpenAI, Stripe, etc.) with minimal false positives.
- **Cross-File Drift Detection**: Identifies misalignments between your `.env.example`, Docker Compose, and CI/CD pipelines.
- **Health Scoring**: Computes a holistic health score (0-100) based on 11 dimensions of configuration hygiene, giving you an immediate sense of production readiness.
- **Dependency Graph**: Builds a directed dependency graph connecting variables to services, files, and deployment targets. Exportable to Mermaid, Graphviz DOT, JSON, and interactive HTML.
- **Automated Documentation**: Generates beautiful Markdown and HTML documentation of your project's configuration variables.
- **CI/CD Integration**: Supports SARIF output for GitHub Advanced Security and other CI/CD dashboards.

## 🚀 Installation

`envtether` requires Python 3.12 or newer.

```bash
pip install envtether
```

Or using `uv`:

```bash
uv tool install envtether
```

## 🛠️ Quick Start

Navigate to your project's root directory and run the CLI:

### 1. Scan and Analyze

```bash
# Full interactive scan with Rich console output
envtether scan .

# Run a comprehensive health check (fails on critical issues)
envtether doctor .
```

### 2. Generate a Dependency Graph

Visualise how your configuration connects to your codebase and infrastructure:

```bash
envtether graph . --format html --output config-graph.html
```

### 3. Generate Documentation

Auto-generate a beautiful configuration reference for your team:

```bash
envtether docs . --format markdown --output CONFIG.md
```

### 4. CI/CD Integration

Run `envtether` in your CI pipeline to catch configuration drift and exposed secrets before they are merged:

```bash
envtether ci . --format sarif > envtether-results.sarif
```

## 🧠 How It Works

1. **Scanning**: Recursively finds all relevant files (ignoring `.gitignore`, `node_modules`, etc.).
2. **Architecture Discovery**: Detects the project type (e.g. FastAPI, Docker), cloud providers, and service dependencies (e.g. Redis, PostgreSQL).
3. **AST Analysis**: Parses Python code using `ast` to find `os.getenv`, `os.environ`, and Pydantic `BaseSettings` declarations.
4. **Format Analysis**: Parses `.env`, Docker Compose, Kubernetes manifests, and Terraform files to track variable definitions.
5. **Cross-Validation**: Compares variable sets across files to detect drift (e.g. variable defined in Docker Compose but missing in `.env.example`).
6. **Secret Detection**: Runs high-performance entropy checks and pattern matching on configuration values.
7. **Reporting**: Aggregates findings, computes a health score, and exports to the requested format.

## ⚙️ Configuration

Initialise a configuration file in your repository:

```bash
envtether init .
```

This creates a `.envtether.toml` file where you can customise rules, secret detection thresholds, ignore paths, and more.

## 🔌 Plugin System

`envtether` is designed with a robust protocol-based plugin architecture. You can easily extend it to support proprietary configuration formats, internal tools, or new frameworks.

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🛡️ Security

If you discover a security vulnerability within `envtether`, please review our [Security Policy](SECURITY.md) for reporting guidelines.
