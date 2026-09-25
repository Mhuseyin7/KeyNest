from app.security import hash_password, new_token, token_digest, verify_password


def test_password_and_token_never_need_plaintext_storage() -> None:
    hashed = hash_password("a secure password")
    assert verify_password(hashed, "a secure password")
    token, prefix, digest = new_token()
    assert token.startswith(prefix)
    assert digest == token_digest(token)
    assert token not in digest

