"""
DLP Vault

Securely stores original PII values mapped to placeholders (e.g., [CREDIT_CARD_1] -> 4111-...)
Backed by Redis with automatic expiration to ensure sensitive data is never persisted.
"""
import uuid
import json
from app.core.redis import get_redis
from app.core.logging import get_logger

logger = get_logger("dlp.vault")

class DLPVault:
    def __init__(self, ttl_seconds: int = 3600): # 1 hour TTL
        self.ttl = ttl_seconds

    async def store_mappings(self, request_id: str, mappings: dict[str, str]) -> None:
        """Store placeholder -> real value mappings for a specific request."""
        if not mappings:
            return
            
        redis = await get_redis()
        key = f"dlp_vault:{request_id}"
        await redis.setex(key, self.ttl, json.dumps(mappings))
        logger.info("dlp_mappings_stored", request_id=request_id, count=len(mappings))

    async def retrieve_mappings(self, request_id: str) -> dict[str, str]:
        """Retrieve the mappings to unredact a response."""
        redis = await get_redis()
        key = f"dlp_vault:{request_id}"
        data = await redis.get(key)
        
        if not data:
            return {}
            
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            logger.error("dlp_vault_corruption", request_id=request_id)
            return {}

dlp_vault = DLPVault()
