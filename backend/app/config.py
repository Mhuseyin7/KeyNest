import base64
import os
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=None, env_prefix="KEYNEST_")
    database_url: str = ""
    master_key: str = ""
    session_secret: str = ""
    public_origin: str = "https://keynest.invalid"
    production: bool = True

    def master_key_bytes(self) -> bytes:
        try:
            value = base64.urlsafe_b64decode(self.master_key + "=" * (-len(self.master_key) % 4))
        except Exception as exc:
            raise RuntimeError("KEYNEST_MASTER_KEY must be URL-safe base64") from exc
        if len(value) != 32:
            raise RuntimeError("KEYNEST_MASTER_KEY must decode to exactly 32 bytes")
        return value


@lru_cache
def settings() -> Settings:
    def from_secret(name: str) -> str:
        direct = os.environ.get(name)
        file_name = os.environ.get(f"{name}_FILE")
        if direct and file_name:
            raise RuntimeError(f"configure only one of {name} or {name}_FILE")
        if file_name:
            try:
                return open(file_name, encoding="utf-8").read().strip()
            except OSError as exc:
                raise RuntimeError(f"cannot read {name}_FILE") from exc
        if not direct:
            raise RuntimeError(f"{name} must be configured")
        return direct
    configured = Settings(database_url=from_secret("KEYNEST_DATABASE_URL"), master_key=from_secret("KEYNEST_MASTER_KEY"), session_secret=from_secret("KEYNEST_SESSION_SECRET"))
    configured.master_key_bytes()  # Fail closed before accepting requests.
    if len(configured.session_secret) < 32:
        raise RuntimeError("KEYNEST_SESSION_SECRET must contain at least 32 characters")
    if configured.production and not configured.public_origin.startswith("https://"):
        raise RuntimeError("KEYNEST_PUBLIC_ORIGIN must be HTTPS in production")
    return configured
