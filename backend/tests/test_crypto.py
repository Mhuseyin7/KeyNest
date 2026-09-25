import os
import pytest
from app.crypto import decrypt_value, encrypt_value


def test_envelope_round_trip_and_fresh_nonces() -> None:
    master_key = os.urandom(32)
    one = encrypt_value("s3cr3t", master_key, b"tenant-a")
    two = encrypt_value("s3cr3t", master_key, b"tenant-a")
    assert one.nonce != two.nonce
    assert one.wrapped_dek_nonce != two.wrapped_dek_nonce
    assert one.ciphertext != two.ciphertext
    assert decrypt_value(one, master_key, b"tenant-a") == "s3cr3t"


def test_wrong_context_fails_authentication() -> None:
    encrypted = encrypt_value("secret", os.urandom(32), b"expected")
    with pytest.raises(Exception):
        decrypt_value(encrypted, os.urandom(32), b"wrong")

