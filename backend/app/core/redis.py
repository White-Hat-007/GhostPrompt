"""
GhostPrompt Redis Client

Async Redis client with connection pooling for caching,
rate limiting, and pub/sub messaging.
"""

import redis.asyncio as redis
from typing import Optional, Any
import orjson
from app.core.config import get_settings

settings = get_settings()

# Redis connection pool
redis_pool: Optional[redis.Redis] = None


async def get_redis() -> redis.Redis:
    """Get Redis client instance."""
    global redis_pool
    if redis_pool is None:
        redis_pool = redis.from_url(
            settings.REDIS_URL,
            decode_responses=False,
            max_connections=50,
        )
    return redis_pool


async def close_redis() -> None:
    """Close Redis connection pool."""
    global redis_pool
    if redis_pool is not None:
        await redis_pool.close()
        redis_pool = None


class CacheService:
    """Redis-based caching service with JSON serialization."""

    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.default_ttl = settings.REDIS_CACHE_TTL

    async def get(self, key: str) -> Optional[Any]:
        """Get a cached value."""
        data = await self.redis.get(f"cache:{key}")
        if data is not None:
            return orjson.loads(data)
        return None

    async def set(
        self, key: str, value: Any, ttl: Optional[int] = None
    ) -> None:
        """Set a cached value with optional TTL."""
        serialized = orjson.dumps(value)
        await self.redis.set(
            f"cache:{key}",
            serialized,
            ex=ttl or self.default_ttl,
        )

    async def delete(self, key: str) -> None:
        """Delete a cached value."""
        await self.redis.delete(f"cache:{key}")

    async def increment(self, key: str, amount: int = 1) -> int:
        """Increment a counter."""
        return await self.redis.incr(f"counter:{key}", amount)

    async def get_counter(self, key: str) -> int:
        """Get a counter value."""
        val = await self.redis.get(f"counter:{key}")
        return int(val) if val else 0

    async def publish(self, channel: str, message: Any) -> None:
        """Publish a message to a Redis channel."""
        serialized = orjson.dumps(message)
        await self.redis.publish(channel, serialized)

    async def add_to_stream(
        self, stream: str, data: dict, maxlen: int = 10000
    ) -> str:
        """Add an entry to a Redis stream."""
        # Convert all values to strings for Redis streams
        str_data = {k: str(v) for k, v in data.items()}
        return await self.redis.xadd(stream, str_data, maxlen=maxlen)
