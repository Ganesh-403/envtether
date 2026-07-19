# Contributing to envtether

Thank you for your interest in contributing to envtether! This guide will help you
get started.

## Development Setup

### Prerequisites

- Python 3.12 or later
- [uv](https://docs.astral.sh/uv/) (recommended) or pip
- Git

### Clone and Install

```bash
git clone https://github.com/envtether/envtether.git
cd envtether
uv venv
uv pip install -e ".[dev,docs]"
pre-commit install
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=envtether --cov-report=html

# Run specific test modules
pytest tests/test_scanner.py

# Run in parallel
pytest -n auto
```

### Code Quality

```bash
# Lint
ruff check src/ tests/

# Format
ruff format src/ tests/

# Type check
mypy src/envtether/
```

## Development Workflow

### Branching Strategy

- `main` — stable, release-ready code
- `feature/<name>` — new features
- `fix/<name>` — bug fixes
- `docs/<name>` — documentation updates

### Making Changes

1. Fork the repository and create your branch from `main`.
2. Write your code following the project's conventions.
3. Add tests for any new functionality.
4. Ensure all tests pass and linting is clean.
5. Update documentation if needed.
6. Submit a pull request.

### Code Style

- **Formatting**: Enforced by ruff (line length 99).
- **Type Hints**: 100% type hints required. Use `from __future__ import annotations`.
- **Docstrings**: Google-style docstrings on all public functions and classes.
- **Imports**: Sorted by ruff/isort. Use `from __future__ import annotations`.
- **Naming**: Follow PEP 8. No abbreviations except widely understood ones.

### Commit Messages

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add Terraform variable detection
fix: handle missing .env.example gracefully
docs: update CLI reference for explain command
test: add snapshot tests for HTML report
refactor: extract secret pattern matching to dedicated module
```

### Pull Request Guidelines

- Keep PRs focused and reasonably sized.
- Reference related issues using `Fixes #123` or `Closes #123`.
- Include a clear description of what changed and why.
- Add screenshots or terminal output for UI changes.
- Ensure CI passes before requesting review.

## Architecture Overview

```
src/envtether/
├── cli/           # Typer CLI application and command handlers
├── core/          # Core scanning orchestration and configuration
├── scanner/       # File system scanning and file type detection
├── analyzers/     # Analysis engines (AST, YAML, Docker, etc.)
├── ast_engine/    # Python AST parsing and analysis
├── graph/         # Configuration dependency graph
├── security/      # Secret detection and security analysis
├── documentation/ # Documentation generation
├── reporting/     # Report generation (HTML, SARIF, etc.)
├── plugins/       # Plugin system and built-in plugins
├── models/        # Pydantic data models
├── schemas/       # JSON schemas and validation
├── utils/         # Shared utilities
├── exceptions/    # Custom exception hierarchy
└── config/        # Tool configuration and defaults
```

### Key Design Decisions

- **AST over regex**: We use Python's `ast` module for parsing Python code. Regex
  is only used for non-Python file formats where AST parsing isn't applicable.
- **Pydantic models**: All data flows through Pydantic v2 models for validation
  and serialization.
- **Plugin architecture**: New project type support is added via plugins, not
  core modifications.
- **Dependency injection**: Core services are injected, not imported globally.

## Adding a New Plugin

1. Create a new module in `src/envtether/plugins/`.
2. Implement the `PluginProtocol` interface.
3. Register the plugin in `src/envtether/plugins/registry.py`.
4. Add tests in `tests/plugins/`.
5. Update documentation.

Example plugin skeleton:

```python
from __future__ import annotations

from envtether.models.config import ConfigVariable
from envtether.plugins.protocol import AnalysisContext, PluginProtocol


class MyPlugin(PluginProtocol):
    name = "my-plugin"
    description = "Support for MyFramework"
    version = "0.1.0"
    supported_files = {"*.myext"}

    def can_handle(self, context: AnalysisContext) -> bool:
        return any(f.name.endswith(".myext") for f in context.files)

    def analyze(self, context: AnalysisContext) -> list[ConfigVariable]:
        # Your analysis logic here
        ...
```

## Adding a New Secret Pattern

1. Add the pattern to `src/envtether/security/patterns.py`.
2. Add test cases in `tests/security/test_patterns.py`.
3. Ensure the pattern has both a regex matcher and entropy check.

## Reporting Bugs

- Use the [GitHub Issues](https://github.com/envtether/envtether/issues) tracker.
- Include your Python version, OS, and envtether version.
- Provide a minimal reproducible example when possible.
- Attach relevant configuration files (with secrets redacted).

## Feature Requests

- Open an issue with the `enhancement` label.
- Describe the use case and expected behavior.
- If you'd like to implement it yourself, mention that in the issue.

## Code of Conduct

By participating in this project, you agree to abide by our
[Code of Conduct](CODE_OF_CONDUCT.md).

## License

By contributing, you agree that your contributions will be licensed under the
MIT License.
