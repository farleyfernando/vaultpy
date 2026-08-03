"""Unit tests for security services."""

from __future__ import annotations

import pytest

from vaultpy.application.security import DataKeyManager, PasswordGenerator, PasswordHasher
from vaultpy.domain.exceptions import EncryptionError, ValidationError


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
