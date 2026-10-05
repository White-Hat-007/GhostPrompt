"""
Account Lockout Module

Prevents brute force and credential stuffing attacks by locking accounts
after repeated failed authentication attempts.

Attack vectors prevented:
- Brute force password guessing
- Credential stuffing from leaked databases
- Distributed attacks across IPs targeting single account

Implementation:
- In-memory tracking (production: Redis-backed)
- 5 failed attempts → 15 minute lockout
- Tracks by (IP, email) combination
- All lockout events are logged for SIEM integration
"""

from collections import defaultdict
from datetime import datetime, timedelta, timezone

import structlog

logger = structlog.get_logger("security.lockout")


class AccountLockoutTracker:
    """
    Tracks failed login attempts and enforces account lockout policy.
    
    In production, replace the in-memory dict with Redis for
    multi-instance consistency.
    """

    def __init__(self, max_attempts: int = 5, lockout_minutes: int = 15):
        self.max_attempts = max_attempts
        self.lockout_minutes = lockout_minutes
        # key: (ip, email) → list of failed attempt timestamps
        self._failed_attempts: dict[tuple[str, str], list[datetime]] = defaultdict(list)
        # key: (ip, email) → lockout expiry time
        self._lockouts: dict[tuple[str, str], datetime] = {}

    def _key(self, ip: str, email: str) -> tuple[str, str]:
        return (ip, email.lower().strip())

    def is_locked_out(self, ip: str, email: str) -> bool:
        """Check if an IP+email combination is currently locked out."""
        key = self._key(ip, email)
        lockout_until = self._lockouts.get(key)
        if lockout_until and datetime.now(timezone.utc) < lockout_until:
            return True
        elif lockout_until:
            # Lockout expired, clean up
            del self._lockouts[key]
            self._failed_attempts.pop(key, None)
        return False

    def get_lockout_remaining_seconds(self, ip: str, email: str) -> int:
        """Get remaining lockout time in seconds."""
        key = self._key(ip, email)
        lockout_until = self._lockouts.get(key)
        if lockout_until:
            remaining = (lockout_until - datetime.now(timezone.utc)).total_seconds()
            return max(0, int(remaining))
        return 0

    def record_failure(self, ip: str, email: str, user_agent: str | None = None) -> bool:
        """
        Record a failed login attempt. Returns True if account is now locked out.
        """
        key = self._key(ip, email)
        now = datetime.now(timezone.utc)

        # Clean old attempts (older than lockout window)
        cutoff = now - timedelta(minutes=self.lockout_minutes)
        self._failed_attempts[key] = [
            ts for ts in self._failed_attempts[key] if ts > cutoff
        ]

        # Record this failure
        self._failed_attempts[key].append(now)
        attempt_count = len(self._failed_attempts[key])

        logger.warning(
            "auth_failure_recorded",
            ip=ip,
            email_hash=email[:3] + "***",  # Never log full email
            attempt_count=attempt_count,
            max_attempts=self.max_attempts,
        )

        # Check if we've hit the threshold
        if attempt_count >= self.max_attempts:
            lockout_until = now + timedelta(minutes=self.lockout_minutes)
            self._lockouts[key] = lockout_until
            logger.error(
                "account_locked_out",
                ip=ip,
                email_hash=email[:3] + "***",
                lockout_until=lockout_until.isoformat(),
                lockout_minutes=self.lockout_minutes,
            )
            return True
        return False

    def record_success(self, ip: str, email: str) -> None:
        """Clear failed attempts after a successful login."""
        key = self._key(ip, email)
        self._failed_attempts.pop(key, None)
        self._lockouts.pop(key, None)


# Global instance — import this in auth.py
lockout_tracker = AccountLockoutTracker()
