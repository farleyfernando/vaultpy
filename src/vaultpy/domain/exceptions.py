"""Custom domain exceptions."""


class VaultPyError(Exception):
    """Base exception for domain and application failures."""


class SecretNotFoundError(VaultPyError):
    """Raised when a secret cannot be found."""


class InvalidMasterPasswordError(VaultPyError):
    """Raised when the provided master password is invalid."""


class EncryptionError(VaultPyError):
    """Raised when a cryptographic operation fails."""


class AuthenticationError(VaultPyError):
    """Raised when authentication fails."""


class AuthorizationError(VaultPyError):
    """Raised when authorization fails."""


class ValidationError(VaultPyError):
    """Raised when input validation fails."""
