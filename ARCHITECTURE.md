# Architecture

VaultPy uses a pragmatic Clean Architecture split:

- `domain`: entities and business exceptions
- `application`: DTOs, security services, and use-case orchestration
- `infrastructure`: SQLAlchemy persistence and unit of work
- `presentation`: FastAPI routes, dependencies, NiceGUI pages
- `shared`: settings and logging

## Security flow

1. The first startup creates a master password.
2. PBKDF2-HMAC-SHA256 stores only the password hash and salt.
3. A separate vault data key is generated and encrypted with a key derived from the master password.
4. Secret values are encrypted with the unlocked vault data key.
5. JWT access and refresh tokens authorize API and UI actions.

## Runtime composition

- `vaultpy.presentation.app:create_app` is the composition root.
- FastAPI serves the REST API and OpenAPI docs.
- NiceGUI is mounted on the same ASGI app for the web interface.
- SQLite is initialized automatically for the MVP.
