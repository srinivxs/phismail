"""
PhisMail — Application Configuration
Loads settings from environment variables via .env file.
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import List
from functools import lru_cache


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # --- Application ---
    app_name: str = "PhisMail"
    app_version: str = "0.1.0"
    debug: bool = False
    secret_key: str = "change-me-in-production"
    allowed_origins: str = "http://localhost:3000,http://localhost:8000"

    # --- Database ---
    database_url: str = "postgresql://phismail:phismail_secret@localhost:5432/phismail"
    database_echo: bool = False

    # --- Redis ---
    redis_url: str = "redis://localhost:6379/0"

    # --- Celery ---
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # --- File Upload ---
    max_upload_size_mb: int = 5
    storage_path: str = "./storage"
    allowed_mime_types: str = "message/rfc822,application/octet-stream"

    # --- Rate Limiting ---
    rate_limit_per_hour: int = 100

    # --- Threat Intelligence ---
    phishtank_api_key: str = ""
    urlhaus_auth_key: str = ""
    openphish_feed_url: str = "https://openphish.com/feed.txt"
    abuseipdb_api_key: str = ""

    # --- Cache TTL (seconds) ---
    cache_ttl_domain_intel: int = 86400  # 24 hours
    cache_ttl_threat_lookup: int = 86400
    cache_ttl_dns_records: int = 86400

    # --- ML ---
    ml_model_path: str = "./ml_models"
    ml_random_seed: int = 42

    @property
    def max_upload_size_bytes(self) -> int:
        return self.max_upload_size_mb * 1024 * 1024

    @property
    def allowed_origins_list(self) -> List[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",")]

    @property
    def allowed_mime_types_list(self) -> List[str]:
        return [mime.strip() for mime in self.allowed_mime_types.split(",")]

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
    }


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton."""
    return Settings()
