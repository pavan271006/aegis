"""Central configuration. Everything is driven by environment variables so
secrets never live in code. See .env.example."""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Core
    app_name: str = "AEGIS Lite"
    database_url: str = "sqlite:///./aegis.db"   # override with postgres in prod
    redis_url: str = "redis://localhost:6379/0"
    api_key: str = "change-me"                   # simple shared key for ingest/admin

    # Autonomy: "dry-run" (log only), "approval" (queue for human OK), "auto" (act)
    response_mode: str = "dry-run"
    block_ttl_hours: int = 24                    # auto-expire blocks (rollback)
    auto_block_min_severity: str = "high"        # only auto-block at/above this

    # Cloudflare (optional)
    cf_api_token: str = ""
    cf_zone_id: str = ""

    # CrowdSec LAPI (optional)
    crowdsec_url: str = ""
    crowdsec_api_key: str = ""

    # Telegram alerts (optional)
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""

    # GeoIP enrichment (free, no key): ip-api.com. Disable to avoid external calls.
    geoip_enabled: bool = True

    # Detection thresholds
    failed_auth_threshold: int = 5
    scan_404_threshold: int = 15
    rate_z_threshold: float = 3.0

    # Scheduler
    monitoring_interval_minutes: int = 5
    digest_cron: str = "0 9 * * 1"  # Monday 9am

    # Rate limiting
    rate_limit_window_seconds: int = 60
    rate_limit_max_requests: int = 100

    # Upload quarantine
    quarantine_dir: str = "/tmp/aegis_quarantine"
    max_upload_size_mb: int = 10
    allowed_upload_extensions: str = ".pdf,.doc,.docx,.xlsx,.csv,.txt,.png,.jpg,.jpeg,.gif"

    # Wazuh (optional)
    wazuh_url: str = ""
    wazuh_user: str = ""
    wazuh_password: str = ""


settings = Settings()
