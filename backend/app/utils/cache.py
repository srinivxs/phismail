"""
PhisMail — Redis Cache Service
Cache abstraction for domain intel, DNS, and threat lookups.
"""

import json
from typing import Optional, Any
import redis

from app.core.config import get_settings
from app.core.logging import get_logger, LogEvents

logger = get_logger(__name__)
settings = get_settings()


class CacheService:
    """Redis cache abstraction with configurable TTL."""

    def __init__(self):
        self._client = None

    @property
    def client(self) -> redis.Redis:
        if self._client is None:
            self._client = redis.from_url(settings.redis_url, decode_responses=True)
        return self._client

    def get(self, key: str) -> Optional[Any]:
        """Get cached value by key."""
        try:
            value = self.client.get(key)
            if value:
                logger.debug(LogEvents.CACHE_HIT, key=key)
                return json.loads(value)
        except Exception as e:
            logger.warning("cache_get_error", key=key, error=str(e))
        return None

    def set(self, key: str, value: Any, ttl: int = 86400) -> bool:
        """Set cached value with TTL."""
        try:
            self.client.setex(key, ttl, json.dumps(value, default=str))
            return True
        except Exception as e:
            logger.warning("cache_set_error", key=key, error=str(e))
            return False

    def invalidate(self, key: str) -> bool:
        """Invalidate a cached key."""
        try:
            self.client.delete(key)
            return True
        except Exception as e:
            logger.warning("cache_invalidate_error", key=key, error=str(e))
            return False

    def get_domain_intel(self, domain: str) -> Optional[dict]:
        return self.get(f"domain_intel:{domain}")

    def set_domain_intel(self, domain: str, data: dict):
        self.set(f"domain_intel:{domain}", data, settings.cache_ttl_domain_intel)

    def get_dns_records(self, domain: str) -> Optional[dict]:
        return self.get(f"dns_records:{domain}")

    def set_dns_records(self, domain: str, data: dict):
        self.set(f"dns_records:{domain}", data, settings.cache_ttl_dns_records)

    def get_threat_lookup(self, url: str) -> Optional[dict]:
        return self.get(f"threat_lookup:{url}")

    def set_threat_lookup(self, url: str, data: dict):
        self.set(f"threat_lookup:{url}", data, settings.cache_ttl_threat_lookup)


# Singleton instance
cache = CacheService()
