"""Envelope encryption using trusted AES-GCM primitives; no custom cryptography."""
from dataclasses import dataclass
import base64
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENC_VERSION = 1
NONCE_BYTES = 12


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value.encode("ascii"))


@dataclass(frozen=True)
class EncryptedSecret:
    ciphertext: str
    nonce: str
    wrapped_dek: str
    wrapped_dek_nonce: str
    encryption_version: int


def encrypt_value(plaintext: str, master_key: bytes, aad: bytes) -> EncryptedSecret:
    """Encrypt one value using a new DEK and unique nonce for both AES-GCM operations."""
    if len(master_key) != 32:
        raise ValueError("master key must be 32 bytes")
    dek = secrets.token_bytes(32)
    value_nonce, wrap_nonce = secrets.token_bytes(NONCE_BYTES), secrets.token_bytes(NONCE_BYTES)
    ciphertext = AESGCM(dek).encrypt(value_nonce, plaintext.encode("utf-8"), aad)
    wrapped_dek = AESGCM(master_key).encrypt(wrap_nonce, dek, aad)
    return EncryptedSecret(_b64(ciphertext), _b64(value_nonce), _b64(wrapped_dek), _b64(wrap_nonce), ENC_VERSION)


def decrypt_value(envelope: EncryptedSecret, master_key: bytes, aad: bytes) -> str:
    if envelope.encryption_version != ENC_VERSION:
        raise ValueError("unsupported encryption version")
    dek = AESGCM(master_key).decrypt(_unb64(envelope.wrapped_dek_nonce), _unb64(envelope.wrapped_dek), aad)
    return AESGCM(dek).decrypt(_unb64(envelope.nonce), _unb64(envelope.ciphertext), aad).decode("utf-8")

