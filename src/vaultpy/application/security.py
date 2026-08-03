"""Security services for password hashing, encryption, JWT, and sessions."""

from __future__ import annotations

import base64
import hashlib
import secrets
import string
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from threading import Lock
from uuid import uuid4

import jwt
from cryptography.fernet import Fernet, InvalidToken

from vaultpy.domain.entities import AuthenticatedContext
from vaultpy.domain.exceptions import AuthorizationError, EncryptionError, ValidationError


def utcnow() -> datetime:
    """Return the current UTC time."""
    return datetime.now(UTC)


class PasswordHasher:
    """Hash and verify the master password using PBKDF2-HMAC-SHA256."""

    def __init__(self, iterations: int) -> None:
        self._iterations = iterations

    def validate_strength(self, password: str) -> None:
        """Validate the minimum master password policy."""
        checks = (
            len(password) >= 12,
            any(char.isupper() for char in password),
            any(char.islower() for char in password),
            any(char.isdigit() for char in password),
            any(not char.isalnum() for char in password),
        )
        if not all(checks):
            raise ValidationError(
                "Master password must have at least 12 characters, uppercase, lowercase, number, and special character."
            )

    def hash_password(self, password: str) -> tuple[str, str]:
        """Return the derived password hash and base64-encoded salt."""
        salt = secrets.token_bytes(16)
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            self._iterations,
        )
        return self._b64(digest), self._b64(salt)

    def verify_password(self, password: str, stored_hash: str, stored_salt: str) -> bool:
        """Verify a plaintext password against the stored hash."""
        digest = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            self._from_b64(stored_salt),
            self._iterations,
        )
        return secrets.compare_digest(self._b64(digest), stored_hash)

    @staticmethod
    def _b64(value: bytes) -> str:
        return base64.b64encode(value).decode("utf-8")

    @staticmethod
    def _from_b64(value: str) -> bytes:
        return base64.b64decode(value.encode("utf-8"))


class DataKeyManager:
    """Create and unlock the encrypted data key used for secret storage."""

    def __init__(self, iterations: int) -> None:
        self._iterations = iterations

    def create(self, master_password: str) -> tuple[str, str]:
        """Create an encrypted data key and return it with its salt."""
        key_salt = secrets.token_bytes(16)
        wrapping_key = self._derive_fernet_key(master_password, key_salt)
        data_key = Fernet.generate_key()
        encrypted_data_key = Fernet(wrapping_key).encrypt(data_key)
        return self._b64(encrypted_data_key), self._b64(key_salt)

    def unlock(self, master_password: str, encrypted_data_key: str, key_salt: str) -> bytes:
        """Unlock and return the plaintext data key."""
        wrapping_key = self._derive_fernet_key(master_password, self._from_b64(key_salt))
        try:
            return Fernet(wrapping_key).decrypt(self._from_b64(encrypted_data_key))
        except InvalidToken as exc:
            raise EncryptionError("Unable to unlock the vault data key.") from exc

    def encrypt_value(self, data_key: bytes, plaintext: str) -> str:
        """Encrypt a secret value with the unlocked data key."""
        try:
            return Fernet(data_key).encrypt(plaintext.encode("utf-8")).decode("utf-8")
        except (TypeError, ValueError) as exc:
            raise EncryptionError("Unable to encrypt secret value.") from exc

    def decrypt_value(self, data_key: bytes, ciphertext: str) -> str:
        """Decrypt a secret value with the unlocked data key."""
        try:
            return Fernet(data_key).decrypt(ciphertext.encode("utf-8")).decode("utf-8")
        except InvalidToken as exc:
            raise EncryptionError("Unable to decrypt secret value.") from exc

    def _derive_fernet_key(self, password: str, salt: bytes) -> bytes:
        raw_key = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            self._iterations,
            dklen=32,
        )
        return base64.urlsafe_b64encode(raw_key)

    @staticmethod
    def _b64(value: bytes) -> str:
        return base64.b64encode(value).decode("utf-8")

    @staticmethod
    def _from_b64(value: str) -> bytes:
        return base64.b64decode(value.encode("utf-8"))


class JwtService:
    """Issue and validate JWT access and refresh tokens."""

    def __init__(
        self,
        secret_key: str,
        algorithm: str,
        access_minutes: int,
        refresh_minutes: int,
    ) -> None:
        self._secret_key = secret_key
        self._algorithm = algorithm
        self._access_minutes = access_minutes
        self._refresh_minutes = refresh_minutes

    def create_access_token(self, session_id: str) -> str:
        """Create an access token for a session."""
        return self._create_token(session_id=session_id, token_type="access", minutes=self._access_minutes)

    def create_refresh_token(self, session_id: str) -> str:
        """Create a refresh token for a session."""
        return self._create_token(session_id=session_id, token_type="refresh", minutes=self._refresh_minutes)

    def decode_token(
        self,
        token: str,
        expected_type: str,
        *,
        verify_exp: bool = True,
    ) -> dict[str, object]:
        """Decode a JWT and validate its type."""
        try:
            payload = jwt.decode(
                token,
                self._secret_key,
                algorithms=[self._algorithm],
                options={"verify_exp": verify_exp},
            )
        except jwt.PyJWTError as exc:
            raise AuthorizationError("Invalid or expired token.") from exc
        if payload.get("type") != expected_type:
            raise AuthorizationError("Invalid token type.")
        return payload

    def _create_token(self, session_id: str, token_type: str, minutes: int) -> str:
        expires_at = utcnow() + timedelta(minutes=minutes)
        payload = {
            "sub": "master",
            "sid": session_id,
            "type": token_type,
            "exp": expires_at,
            "iat": utcnow(),
        }
        return jwt.encode(payload, self._secret_key, algorithm=self._algorithm)


@dataclass(slots=True)
class SessionState:
    """In-memory authenticated session state."""

    session_id: str
    data_key: bytes
    expires_at: datetime


class SessionRegistry:
    """Hold unlocked data keys in memory for active JWT sessions."""

    def __init__(self, session_ttl_minutes: int) -> None:
        self._session_ttl_minutes = session_ttl_minutes
        self._sessions: dict[str, SessionState] = {}
        self._lock = Lock()

    def create(self, data_key: bytes) -> str:
        """Create and store an authenticated session."""
        session_id = uuid4().hex
        state = SessionState(
            session_id=session_id,
            data_key=data_key,
            expires_at=utcnow() + timedelta(minutes=self._session_ttl_minutes),
        )
        with self._lock:
            self._sessions[session_id] = state
        return session_id

    def refresh(self, session_id: str) -> None:
        """Refresh an existing session expiration."""
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None:
                raise AuthorizationError("Session is no longer active.")
            state.expires_at = utcnow() + timedelta(minutes=self._session_ttl_minutes)

    def get_context(self, session_id: str) -> AuthenticatedContext:
        """Return the authenticated context for a session."""
        with self._lock:
            state = self._sessions.get(session_id)
            if state is None or state.expires_at <= utcnow():
                self._sessions.pop(session_id, None)
                raise AuthorizationError("Session is no longer active.")
            state.expires_at = utcnow() + timedelta(minutes=self._session_ttl_minutes)
        return AuthenticatedContext(session_id=session_id, data_key=state.data_key)

    def revoke(self, session_id: str) -> None:
        """Revoke a session."""
        with self._lock:
            self._sessions.pop(session_id, None)


class PasswordGenerator:
    """Generate strong passwords for the UI and API."""

    SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>/?"

    def generate(
        self,
        *,
        length: int,
        include_symbols: bool,
        include_numbers: bool,
        include_uppercase: bool,
        include_lowercase: bool,
    ) -> str:
        """Generate a password using the selected character groups."""
        groups: list[str] = []
        if include_symbols:
            groups.append(self.SYMBOLS)
        if include_numbers:
            groups.append(string.digits)
        if include_uppercase:
            groups.append(string.ascii_uppercase)
        if include_lowercase:
            groups.append(string.ascii_lowercase)
        if not groups:
            raise ValidationError("Select at least one character group for password generation.")

        password_chars = [secrets.choice(group) for group in groups]
        pool = "".join(groups)
        password_chars.extend(secrets.choice(pool) for _ in range(length - len(password_chars)))
        secrets.SystemRandom().shuffle(password_chars)
        return "".join(password_chars)
