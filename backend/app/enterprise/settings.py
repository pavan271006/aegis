"""Phase-1 enterprise settings. Loaded from environment / secret manager.

Nothing security-sensitive is defaulted to a usable value in production: the KEK
and DB credentials MUST be provided or the app refuses to start (fail closed)."""
import os
from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class EnterpriseSettings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env", extra="ignore")

    # ── Database (app connects as the least-privilege RLS role) ──────────
    database_url: str = "postgresql+psycopg2://aegis_app:change-me@localhost:5432/aegis"

    # ── Key-encryption key (envelope encryption for signing keys + MFA) ──
    # 32-byte urlsafe-base64 key. In prod: AWS KMS / GCP KMS / Vault transit.
    kek: str = os.getenv("AEGIS_KEK", "")

    # ── Access / refresh tokens ──────────────────────────────────────────
    access_ttl_seconds: int = 900            # 15 min
    refresh_ttl_seconds: int = 60 * 60 * 24 * 14   # 14 days
    issuer: str = "https://aegis.example.com"
    audience: str = "aegis-api"
    signing_key_rotation_days: int = 30

    # ── Password policy ──────────────────────────────────────────────────
    pw_min_length: int = 12
    pw_require_classes: int = 3              # of {lower, upper, digit, symbol}
    pw_history: int = 5
    pw_max_age_days: int = 90
    pw_breach_check: bool = True            # HIBP k-anonymity range check

    # ── Lockout / MFA ────────────────────────────────────────────────────
    max_failed_logins: int = 5
    lockout_minutes: int = 15
    mfa_required_roles: tuple = ("owner", "admin")

    # ── CORS ─────────────────────────────────────────────────────────────
    cors_allowed_origins: str = "https://app.aegis.example.com"

    # ── Redis (rate limiting + token denylist) ───────────────────────────
    redis_url: str = "redis://localhost:6379/0"

    def origins(self) -> list[str]:
        return [o.strip() for o in self.cors_allowed_origins.split(",") if o.strip()]

    def validate_prod(self) -> None:
        if not self.kek or len(self.kek) < 32:
            raise RuntimeError("AEGIS_KEK is required (>=32 bytes, KMS-managed in prod)")
        if "change-me" in self.database_url:
            raise RuntimeError("DATABASE_URL must be set to the aegis_app credentials")


@lru_cache
def get_settings() -> EnterpriseSettings:
    return EnterpriseSettings()
