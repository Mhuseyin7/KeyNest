import hashlib
import secrets
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

_passwords = PasswordHasher()


def hash_password(password: str) -> str:
    if len(password) < 12:
        raise ValueError("password must be at least 12 characters")
    return _passwords.hash(password)


def verify_password(value: str, password: str) -> bool:
    try:
        return _passwords.verify(value, password)
    except VerifyMismatchError:
        return False


def new_token() -> tuple[str, str, str]:
    """Return display token, non-secret prefix, and SHA-256 digest for storage."""
    raw = secrets.token_urlsafe(32)
    token = f"knst_{raw}"
    return token, token[:13], hashlib.sha256(token.encode()).hexdigest()


def token_digest(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

