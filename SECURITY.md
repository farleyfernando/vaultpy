# Security

## Controls implemented

- PBKDF2-HMAC-SHA256 password hashing
- Fernet encryption at rest for secret values
- Separate encrypted vault data key
- JWT access and refresh tokens
- Secure response headers
- Soft delete for secrets
- Audit logging for sensitive operations

## Operational guidance

- Override `VAULTPY_JWT_SECRET_KEY` in production.
- Override `VAULTPY_UI_STORAGE_SECRET` in production.
- Protect the SQLite file and host filesystem backups.
- Rotate the master password by re-encrypting the vault data key in a future release.
- Use HTTPS and a reverse proxy in exposed environments.
