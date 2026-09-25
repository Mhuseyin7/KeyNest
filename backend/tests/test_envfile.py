from app.envfile import parse_env


def test_dotenv_handles_comments_quotes_empty_and_escapes() -> None:
    assert parse_env('A=one # comment\nB="two\\nlines"\nEMPTY=\n# ignored\n') == {"A": "one", "B": "two\nlines", "EMPTY": ""}

