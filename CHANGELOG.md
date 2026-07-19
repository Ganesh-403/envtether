# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Calendar Versioning](https://calver.org/).

## [Unreleased]

### Added

- **Repository Scanner**: Recursive scanning with configurable ignore patterns and monorepo support.
- **Configuration Discovery**: Automatic detection of environment variables across Python, Docker, CI/CD, and IaC files.
- **AST Analysis Engine**: Python AST-based detection of `os.getenv()`, `os.environ`, Pydantic `BaseSettings`, default values, and dead references.
- **Configuration Graph**: Dependency graph construction with Mermaid, Graphviz, JSON, SVG, PNG, and interactive HTML export.
- **Health Score Engine**: Composite scoring across 11 dimensions with actionable recommendations.
- **Secret Detection**: Entropy analysis and pattern matching for 20+ credential types including AWS, Azure, GCP, JWT, API keys, and database URLs.
- **Hardcoded Configuration Detection**: AST-based detection of secrets and configuration embedded directly in source code.
- **Dead Configuration Detection**: Cross-reference analysis to find variables defined but never consumed.
- **Cross-file Validation**: Drift detection between `.env`, `.env.example`, Docker Compose, GitHub Actions, Terraform, and Kubernetes manifests.
- **Documentation Generator**: Automatic generation of configuration docs in Markdown, HTML, JSON, CSV, and SARIF formats.
- **Architecture Discovery**: Automatic identification of ORMs, databases, caches, queues, cloud providers, LLM providers, and monitoring stacks.
- **CI/CD Integration**: `envtether doctor` and `envtether ci` commands with proper exit codes for GitHub Actions and GitLab CI.
- **Interactive Terminal Dashboard**: Rich-powered TUI with progress bars, panels, trees, tables, and syntax highlighting.
- **HTML Report**: Standalone dark-mode HTML dashboard with charts, health metrics, and dependency visualization.
- **Plugin System**: Extensible plugin architecture supporting FastAPI, Flask, Django, Docker, Terraform, AWS, Azure, GCP, and Kubernetes.
- **CLI**: Full command suite — `scan`, `doctor`, `graph`, `report`, `docs`, `secrets`, `health`, `explain`, `ci`, `init`, `fix`.

[Unreleased]: https://github.com/envtether/envtether/commits/main
