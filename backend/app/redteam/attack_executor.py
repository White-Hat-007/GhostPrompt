"""
Red Team Attack Executor — Executes generated attacks against GhostPrompt

Runs attack prompts through the firewall engine in sandboxed mode
(no forwarding to real LLMs) and records results.
"""

import time
import asyncio
from datetime import datetime, timezone
from typing import Optional
from app.core.logging import get_logger
from app.core.database import async_session_factory
from app.models.scan_event import ScanEvent
from app.core.events import event_broadcaster

logger = get_logger("redteam.executor")


class AttackExecutor:
    """Executes red team attacks against the firewall engine."""

    def __init__(self):
        self._results: list[dict] = []
        self._false_negatives: list[dict] = []
        self._total_executed = 0

    async def execute_attack(self, attack: dict, org_id: str = "redteam-org", engine=None) -> dict:
        """Execute a single attack against the firewall."""
        from app.services.firewall.engine import firewall_engine
        from app.schemas.schemas import ScanRequest

        eng = engine or firewall_engine
        if not eng._initialized:
            await eng.initialize()

        prompt = attack.get("prompt", "")
        expected = attack.get("expected_action", "blocked")
        
        # Use attack's session_id, or default to its unique id to ensure state isolation
        api_key = attack.get("session_id") or attack.get("id", "redteam")

        # If org_id is literally "redteam-org", fall back to deterministic mock UUID
        if org_id == "redteam-org":
            import uuid
            import hashlib
            org_uuid = str(uuid.UUID(hashlib.md5(api_key.encode()).hexdigest()))
        else:
            org_uuid = org_id

        start = time.perf_counter()
        try:
            # We pass session_id to isolate stateful detectors like Pack Hunt per attack cycle
            # Use org_uuid for org_id to ensure complete state isolation during tests without DB errors
            result = await eng.scan(
                ScanRequest(prompt=prompt, model="redteam-test", provider="internal", scan_type="prompt"),
                org_id=org_uuid,
                session_id=api_key
            )
            duration = (time.perf_counter() - start) * 1000

            actual = result.action
            # Determine pass/fail
            if expected == "blocked":
                passed = actual in ("blocked", "flagged", "sanitized")
            elif expected == "flagged":
                passed = actual in ("blocked", "flagged", "sanitized")
            elif expected == "sanitized":
                # Sanitized means PII/secret was detected — blocked/flagged/sanitized all count as caught
                passed = actual in ("blocked", "flagged", "sanitized")
            elif expected == "any":
                # Ambiguous setup prompts (e.g. early multi-turn turns) — either outcome is acceptable
                passed = True
            else:
                passed = actual in ("allowed", "sanitized")

            record = {
                "attack_id": attack.get("id", ""),
                "category": attack.get("category") or "uncategorized",
                "name": attack.get("name", ""),
                "technique": attack.get("technique", ""),
                "prompt_preview": prompt[:100],
                "expected_action": expected,
                "actual_action": actual,
                "threat_level": result.threat_level,
                "threat_score": result.threat_score,
                "passed": passed,
                "detections": [{"category": d.category, "confidence": d.confidence, "severity": d.severity} for d in result.detections],
                "scan_duration_ms": round(duration, 2),
                "timestamp": time.time(),
            }

            self._results.append(record)
            self._total_executed += 1

            # Only record to DB and broadcast if we have a real org_id
            if org_id != "redteam-org":
                async with async_session_factory() as session:
                    scan_event = ScanEvent(
                        organization_id=org_id,
                        request_id=result.request_id,
                        source_ip="127.0.0.1",
                        user_agent=f"GhostPrompt-RedTeam/{attack.get('category', 'unknown')}",
                        model_provider="internal",
                        model_name="redteam-test",
                        scan_type="prompt",
                        prompt_text=prompt[:10000],
                        prompt_length=len(prompt),
                        threat_level=result.threat_level,
                        threat_score=result.threat_score,
                        threat_categories=[d.category for d in result.detections],
                        detections=[d.model_dump() for d in result.detections],
                        action=result.action,
                        is_blocked=result.action == "blocked",
                        scan_duration_ms=result.scan_duration_ms,
                        event_metadata={"generator": attack.get("category")}
                    )
                    session.add(scan_event)
                    await session.commit()
                    
                await event_broadcaster.broadcast_scan({
                    "organization_id": str(org_id),
                    "source_ip": "127.0.0.1",
                    "user_agent": f"GhostPrompt-RedTeam/{attack.get('category', 'unknown')}",
                    **result.model_dump(),
                    "created_at": datetime.now(timezone.utc).isoformat(),
                    "model": "redteam-test",
                    "provider": "internal"
                })

            if not passed and expected == "blocked":
                self._false_negatives.append(record)
                logger.warning("red_team_false_negative", attack_id=attack.get("id"), category=attack.get("category"))

            return record

        except Exception as e:
            logger.error("red_team_execution_error", error=str(e), attack_id=attack.get("id"))
            return {"attack_id": attack.get("id"), "error": str(e), "passed": False}

    async def execute_batch(self, attacks: list[dict], org_id: str = "redteam-org") -> list[dict]:
        """Execute a batch of attacks sequentially."""
        results = []
        for attack in attacks:
            r = await self.execute_attack(attack, org_id=org_id)
            results.append(r)
        return results

    def get_false_negatives(self) -> list[dict]:
        return list(self._false_negatives)

    def get_results(self, limit: int = 100) -> list[dict]:
        return self._results[-limit:]

    def get_stats(self) -> dict:
        total = self._total_executed
        fn = len(self._false_negatives)
        return {
            "total_executed": total,
            "false_negatives": fn,
            "false_negative_rate": round(fn / total * 100, 2) if total > 0 else 0,
            "results_stored": len(self._results),
        }
