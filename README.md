# VaultPy

VaultPy is a lightweight secrets manager for local environments and small teams. It combines **FastAPI**, **NiceGUI**, **SQLAlchemy**, **JWT**, **PBKDF2-HMAC-SHA256**, and **Fernet** to provide a secure Python-only vault with a web interface and REST API.

## Features

- Master password bootstrap with password policy enforcement
- Encryption at rest for secret values
- Support for one secret containing multiple named key/value entries
- JWT authentication with refresh support
- NiceGUI dashboard and secret management interface
- CRUD, search, soft delete, and password generation
- Audit logs for setup, login, logout, create, update, delete, and secret access
- SQLite MVP storage with Clean Architecture-inspired package layout

## Architecture

```text
src/vaultpy/
├── application/
├── domain/
├── infrastructure/
├── presentation/
└── shared/
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for the component map.

## Quick Start

1. Create the environment:

   ```powershell
   python -m venv .venv
   .\.venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   python -m pip install -e .[dev]
   npm.cmd install
   ```

2. Run the application:

   ```powershell
   python main.py
   ```

3. Open:
   - UI: `http://127.0.0.1:8000/`
   - API docs: `http://127.0.0.1:8000/docs`

## Main API Endpoints

- `POST /api/v1/setup`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/refresh`
- `POST /api/v1/auth/logout`
- `GET /api/v1/status`
- `GET /api/v1/dashboard`
- `GET /api/v1/audit-logs`
- `POST /api/v1/passwords/generate`
- `POST /api/v1/secrets`
- `GET /api/v1/secrets`
- `GET /api/v1/secrets/search?q=...`
- `GET /api/v1/secrets/{id}`
- `PUT /api/v1/secrets/{id}`
- `DELETE /api/v1/secrets/{id}`
- `GET /api/v1/secrets/{id}/value`

## Security Notes

- Only the master password hash and salts are stored.
- A separate vault data key is encrypted with a key derived from the master password.
- Secret values are encrypted before persistence.
- Sensitive values are returned only to authenticated requests.

See [SECURITY.md](SECURITY.md) and [API.md](API.md) for details.

## Tests and Quality

```powershell
.\.venv\Scripts\python -m pytest
.\.venv\Scripts\python -m ruff check .
.\.venv\Scripts\python -m black --check .
.\.venv\Scripts\python -m isort --check-only .
```

## Git Hooks

`npm.cmd install` enables Husky and installs a `pre-push` hook that runs:

```powershell
.\.venv\Scripts\python -m pre_commit run --hook-stage push --all-files
```

The pre-commit pipeline checks `ruff`, `black --check`, and `isort --check-only` before the push is accepted.

## Screenshots Placeholders

Placeholder files for future screenshots live in `docs\screenshots\`.
