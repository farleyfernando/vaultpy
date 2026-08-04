"""Unit tests for security services."""

from __future__ import annotations

from datetime import timedelta

import pytest

from vaultpy.application.security import (
    DataKeyManager,
    JwtService,
    PasswordGenerator,
    PasswordHasher,
    SessionRegistry,
    utcnow,
)
from vaultpy.domain.exceptions import AuthorizationError, EncryptionError, ValidationError


def test_password_hasher_round_trip() -> None:
    """Hashing and verifying the master password should succeed."""
    hasher = PasswordHasher(iterations=10_000)
    password_hash, password_salt = hasher.hash_password("VaultMaster#2026")

    assert hasher.verify_password("VaultMaster#2026", password_hash, password_salt) is True
    assert hasher.verify_password("wrong", password_hash, password_salt) is False


def test_password_strength_validation_rejects_weak_passwords() -> None:
    """Weak passwords should be rejected."""
    hasher = PasswordHasher(iterations=10_000)

    with pytest.raises(ValidationError):
        hasher.validate_strength("weakpass")


def test_data_key_manager_encrypts_and_decrypts_values() -> None:
    """Encrypted values should be reversible with the unlocked data key."""
    manager = DataKeyManager(iterations=10_000)
    encrypted_key, key_salt = manager.create("VaultMaster#2026")
    data_key = manager.unlock("VaultMaster#2026", encrypted_key, key_salt)

    ciphertext = manager.encrypt_value(data_key, "my-secret-value")

    assert ciphertext != "my-secret-value"
    assert manager.decrypt_value(data_key, ciphertext) == "my-secret-value"


def test_data_key_manager_rejects_invalid_master_password() -> None:
    """Unlocking with the wrong master password should fail."""
    manager = DataKeyManager(iterations=10_000)
    encrypted_key, key_salt = manager.create("VaultMaster#2026")

    with pytest.raises(EncryptionError):
        manager.unlock("WrongPassword#2026", encrypted_key, key_salt)


def test_password_generator_uses_requested_character_sets() -> None:
    """Generated passwords should satisfy the requested policy."""
    generator = PasswordGenerator()
    password = generator.generate(
        length=32,
        include_symbols=True,
        include_numbers=True,
        include_uppercase=True,
        include_lowercase=True,
    )

    assert len(password) == 32
    assert any(character.islower() for character in password)
    assert any(character.isupper() for character in password)
    assert any(character.isdigit() for character in password)
    assert any(not character.isalnum() for character in password)


def test_data_key_manager_rejects_invalid_fernet_key() -> None:
    """Encryption should fail when the provided key material is invalid."""
    manager = DataKeyManager(iterations=10_000)

    with pytest.raises(EncryptionError):
        manager.encrypt_value(b"too-short", "my-secret-value")


def test_jwt_service_rejects_invalid_tokens() -> None:
    """JWT validation should reject the wrong token type and malformed tokens."""
    service = JwtService(
        secret_key="jwt-test-secret-with-32-bytes!!!",
        algorithm="HS256",
        access_minutes=5,
        refresh_minutes=10,
    )
    access_token = service.create_access_token("session-1")

    with pytest.raises(AuthorizationError):
        service.decode_token(access_token, expected_type="refresh")

    with pytest.raises(AuthorizationError):
        service.decode_token("not-a-token", expected_type="access")


def test_session_registry_handles_refresh_revoke_and_expiry() -> None:
    """Active sessions should refresh, expire, and revoke predictably."""
    registry = SessionRegistry(session_ttl_minutes=1)
    session_id = registry.create(b"data-key")

    context = registry.get_context(session_id)
    assert context.session_id == session_id

    registry.refresh(session_id)

    with pytest.raises(AuthorizationError):
        registry.refresh("missing-session")

    registry._sessions[session_id].expires_at = utcnow() - timedelta(minutes=1)

    with pytest.raises(AuthorizationError):
        registry.get_context(session_id)

    revoked_session = registry.create(b"other-data-key")
    registry.revoke(revoked_session)

    with pytest.raises(AuthorizationError):
        registry.get_context(revoked_session)


def test_password_generator_requires_at_least_one_group() -> None:
    """At least one password character group must be selected."""
    generator = PasswordGenerator()

    with pytest.raises(ValidationError):
        generator.generate(
            length=12,
            include_symbols=False,
            include_numbers=False,
            include_uppercase=False,
            include_lowercase=False,
        )
