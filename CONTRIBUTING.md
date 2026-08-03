# Contributing

## Development workflow

1. Create and activate `.venv`.
2. Install dependencies with `python -m pip install -e .[dev]`.
3. Run the quality checks from the README.
4. Open an issue or draft PR before large changes.

## Coding standards

- Python 3.12+
- Type hints everywhere
- Small functions and focused classes
- Business rules stay in the application layer
- No plaintext secrets in commits, fixtures, or logs

## Pull requests

- Add or update tests for behavior changes.
- Keep docs aligned with code changes.
- Prefer incremental PRs over large rewrites.
