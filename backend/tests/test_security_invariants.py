from pathlib import Path


ROOT = Path(__file__).parents[1] / "app"


def test_no_application_logging_of_sensitive_fields() -> None:
    source = "\n".join(path.read_text(encoding="utf-8") for path in ROOT.glob("*.py"))
    assert "logger." not in source
    assert "print(body.value" not in source
    assert "print(token" not in source


def test_list_endpoint_does_not_serialize_ciphertext_or_values() -> None:
    source = (ROOT / "main.py").read_text(encoding="utf-8")
    list_route = source[source.index("def list_secrets"):source.index("def set_secret")]
    assert "ciphertext" not in list_route
    assert '"value"' not in list_route

