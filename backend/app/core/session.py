"""
Session & Context Manager

Redis-backed session store for multi-turn conversation tracking.
Stores conversation history, running risk scores, attack attempt counts,
and flagged patterns per session. Risk score decays over time for legit users.
"""

import json
import time
from typing import Optional
from app.core.logging import get_logger

logger = get_logger("session")


class SessionManager:
    """
    Manages conversation sessions for multi-turn threat analysis.
    
    Uses in-memory store (falls back gracefully when Redis unavailable).
    In production, backed by Redis with TTL-based expiry.
    """

    def __init__(self):
        self._sessions: dict[str, dict] = {}
        self._redis = None

    async def _get_redis(self):
        if self._redis is None:
            try:
                from app.core.redis import get_redis
                self._redis = await get_redis()
                await self._redis.ping()
            except Exception:
                self._redis = None
        return self._redis

    async def get_session(self, session_id: str) -> dict:
        """Get or create a session."""
        redis = await self._get_redis()

        if redis:
            try:
                data = await redis.get(f"session:{session_id}")
                if data:
                    return json.loads(data)
            except Exception:
                pass

        if session_id not in self._sessions:
            self._sessions[session_id] = {
                "session_id": session_id,
                "turns": [],
                "risk_score": 0.0,
                "attack_count": 0,
                "flagged_patterns": [],
                "created_at": time.time(),
                "last_activity": time.time(),
            }
        return self._sessions[session_id]

    async def save_session(self, session_id: str, session: dict):
        """Persist session state."""
        self._sessions[session_id] = session
        redis = await self._get_redis()
        if redis:
            try:
                await redis.set(
                    f"session:{session_id}",
                    json.dumps(session, default=str),
                    ex=3600,  # 1 hour TTL
                )
            except Exception:
                pass

    async def record_turn(
        self,
        session_id: str,
        prompt: str,
        threat_score: float,
        categories: list[str],
    ):
        """Record a conversation turn with its threat analysis."""
        session = await self.get_session(session_id)

        turn = {
            "index": len(session["turns"]),
            "prompt_preview": prompt[:200],
            "threat_score": threat_score,
            "categories": categories,
            "timestamp": time.time(),
        }
        session["turns"].append(turn)

        # Keep last 20 turns
        if len(session["turns"]) > 20:
            session["turns"] = session["turns"][-20:]

        # Update running risk score with decay
        session["risk_score"] = self._compute_session_risk(session)
        session["last_activity"] = time.time()

        if threat_score > 0.3:
            session["attack_count"] = session.get("attack_count", 0) + 1
            for cat in categories:
                if cat not in session.get("flagged_patterns", []):
                    session.setdefault("flagged_patterns", []).append(cat)

        await self.save_session(session_id, session)
        return session

    async def get_session_risk(self, session_id: str) -> float:
        """Get the current session risk score."""
        session = await self.get_session(session_id)
        return session.get("risk_score", 0.0)

    async def get_conversation_history(self, session_id: str) -> list[dict]:
        """Get the conversation turn history."""
        session = await self.get_session(session_id)
        return session.get("turns", [])

    async def terminate_session(self, session_id: str):
        """Terminate a session due to confirmed attack."""
        session = await self.get_session(session_id)
        session["terminated"] = True
        session["terminated_at"] = time.time()
        session["risk_score"] = 1.0
        await self.save_session(session_id, session)
        logger.warning("session_terminated", session_id=session_id)

    def _compute_session_risk(self, session: dict) -> float:
        """
        Compute cumulative session risk score.

        Factors:
        - Individual turn threat scores (recent turns weighted more)
        - Number of attack attempts
        - Pattern diversity (different attack types = higher risk)
        - Time decay (older threats decay)
        - Escalation detection (increasing threat scores)
        """
        turns = session.get("turns", [])
        if not turns:
            return 0.0

        now = time.time()
        weighted_scores = []

        for turn in turns:
            age_seconds = now - turn.get("timestamp", now)
            # Decay: half-life of 10 minutes
            decay = 0.5 ** (age_seconds / 600)
            # Recency boost: newer turns matter more
            recency = 1.0 + (turn["index"] / max(len(turns), 1)) * 0.5
            weighted_scores.append(turn["threat_score"] * decay * recency)

        if not weighted_scores:
            return 0.0

        # Base: max weighted score
        max_score = max(weighted_scores)

        # Attack count penalty
        attack_count = session.get("attack_count", 0)
        attack_penalty = min(attack_count * 0.1, 0.3)

        # Pattern diversity penalty
        patterns = session.get("flagged_patterns", [])
        diversity_penalty = min(len(patterns) * 0.05, 0.2)

        # Escalation detection: are scores increasing?
        escalation = 0.0
        recent_scores = [t["threat_score"] for t in turns[-5:]]
        if len(recent_scores) >= 3:
            increasing = all(
                recent_scores[i] <= recent_scores[i + 1]
                for i in range(len(recent_scores) - 1)
            )
            if increasing and recent_scores[-1] > 0.3:
                escalation = 0.15

        combined = min(max_score + attack_penalty + diversity_penalty + escalation, 1.0)
        return round(combined, 4)


# Singleton
session_manager = SessionManager()
