"""
WebSocket Event Broadcasting

Manages WebSocket connections and broadcasts scan events
to all connected dashboard clients in real-time.
"""

import time as _time

from fastapi import WebSocket

from app.core.geo import resolve_geo
from app.core.logging import get_logger

logger = get_logger("events")


class EventBroadcaster:
    """Manages WebSocket connections and broadcasts events."""

    def __init__(self):
        # Maps WebSocket to dict with org_id and is_admin
        self._connections: dict[WebSocket, dict] = {}
        self._scan_history: dict[str, list[dict]] = {}  # org_id -> recent scans
        self._stats: dict[str, dict] = {}  # org_id -> stats
        self._last_db_load: dict[str, float] = {}  # org_id -> timestamp of last DB load

    def _get_stats(self, org_id: str) -> dict:
        if org_id not in self._stats:
            self._stats[org_id] = {
                "total_scans": 0,
                "blocked": 0,
                "flagged": 0,
                "allowed": 0,
                "threat_categories": {},
            }
        return self._stats[org_id]

    def _get_history(self, org_id: str) -> list[dict]:
        if org_id not in self._scan_history:
            self._scan_history[org_id] = []
        return self._scan_history[org_id]

    async def connect(self, websocket: WebSocket, org_id: str = None, is_admin: bool = False):
        await websocket.accept()
        self._connections[websocket] = {"org_id": org_id, "is_admin": is_admin}
        logger.info("ws_client_connected", total_connections=len(self._connections), org_id=org_id, is_admin=is_admin)

        # Always reload from DB on connect (with 5s cooldown to prevent hammering)
        now = _time.time()
        last_load = self._last_db_load.get(org_id, 0)
        
        # If admin, we use the 'global' key for db caching
        load_key = "global" if is_admin else org_id
        last_load = self._last_db_load.get(load_key, 0)

        if org_id and (now - last_load > 2):
            from sqlalchemy import and_, func, select

            from app.core.database import async_session_factory
            from app.models.scan_event import ScanEvent

            try:
                async with async_session_factory() as session:
                    # Load recent scans
                    if is_admin:
                        query = select(ScanEvent).order_by(ScanEvent.created_at.desc()).limit(100)
                    else:
                        query = select(ScanEvent).where(ScanEvent.organization_id == org_id).order_by(ScanEvent.created_at.desc()).limit(100)
                        
                    result = await session.execute(query)
                    events = result.scalars().all()
                    history = []
                    for e in reversed(events):
                        geo = resolve_geo(e.source_ip or str(e.id), extra_entropy=e.request_id)
                        profile = e.event_metadata.get("attacker_profile", {}) if e.event_metadata else {}
                        real_ip = profile.get("source_ip") or e.source_ip
                        
                        history.append({
                            "id": str(e.id),
                            "request_id": e.request_id,
                            "threat_level": e.threat_level,
                            "threat_score": e.threat_score,
                            "action": e.action,
                            "scan_type": e.scan_type,
                            "model": e.model_name or "unknown",
                            "created_at": e.created_at.isoformat(),
                            "prompt": e.prompt_text,
                            "detections": e.detections,
                            "scan_duration_ms": e.scan_duration_ms,
                            "attacker_profile": e.event_metadata.get("attacker_profile") if e.event_metadata else None,
                            "organization_id": str(e.organization_id),
                            "ip": real_ip if real_ip and real_ip != "127.0.0.1" else geo.get("generated_ip"),
                            "user_agent": e.user_agent or "",
                            "browser": profile.get("browser") or geo.get("browser", {}).get("short", "Unknown"),
                            "browser_full": profile.get("user_agent") or geo.get("browser", {}).get("browser", "Unknown"),
                            "os": profile.get("os") or geo.get("browser", {}).get("os", "Unknown"),
                            "lat": profile.get("latitude") or geo["lat"],
                            "lng": profile.get("longitude") or geo["lng"],
                            "city": profile.get("city") or geo["city"],
                            "country": profile.get("country") or geo["country"],
                            "asn": profile.get("asn_number") or "",
                            "isp": profile.get("isp_name") or profile.get("asn_org") or "",
                            "timezone": profile.get("timezone") or "",
                            "postal_code": profile.get("postal_code") or "",
                        })
                    self._scan_history[load_key] = history

                    # Initialize stats from DB
                    stats = self._get_stats(load_key)

                    if is_admin:
                        total_res = await session.execute(select(func.count(ScanEvent.id)))
                        blocked_res = await session.execute(select(func.count(ScanEvent.id)).where(ScanEvent.action == 'blocked'))
                        flagged_res = await session.execute(select(func.count(ScanEvent.id)).where(ScanEvent.action == 'flagged'))
                        allowed_res = await session.execute(select(func.count(ScanEvent.id)).where(ScanEvent.action == 'allowed'))
                        all_events_res = await session.execute(select(ScanEvent.threat_categories, ScanEvent.detections))
                    else:
                        total_res = await session.execute(select(func.count(ScanEvent.id)).where(ScanEvent.organization_id == org_id))
                        blocked_res = await session.execute(select(func.count(ScanEvent.id)).where(and_(ScanEvent.organization_id == org_id, ScanEvent.action == 'blocked')))
                        flagged_res = await session.execute(select(func.count(ScanEvent.id)).where(and_(ScanEvent.organization_id == org_id, ScanEvent.action == 'flagged')))
                        allowed_res = await session.execute(select(func.count(ScanEvent.id)).where(and_(ScanEvent.organization_id == org_id, ScanEvent.action == 'allowed')))
                        all_events_res = await session.execute(select(ScanEvent.threat_categories, ScanEvent.detections).where(ScanEvent.organization_id == org_id))

                    stats["total_scans"] = total_res.scalar() or 0
                    stats["blocked"] = blocked_res.scalar() or 0
                    stats["flagged"] = flagged_res.scalar() or 0
                    stats["allowed"] = allowed_res.scalar() or 0

                    cat_counts: dict[str, int] = {}
                    for t_cats, t_dets in all_events_res.all():
                        for cat in t_cats or []:
                            cat_counts[cat] = cat_counts.get(cat, 0) + 1
                        for det in t_dets or []:
                            if isinstance(det, dict):
                                dcat = det.get("category")
                                if dcat and dcat not in (t_cats or []):
                                    cat_counts[dcat] = cat_counts.get(dcat, 0) + 1
                    stats["threat_categories"] = cat_counts

                    self._last_db_load[load_key] = now

            except Exception as ex:
                logger.error("failed_to_load_history", error=str(ex))

        # Send current state on connect
        load_key = "global" if is_admin else org_id
        org_stats = self._get_stats(load_key) if load_key else {"total_scans": 0, "blocked": 0, "flagged": 0, "allowed": 0, "threat_categories": {}}
        org_history = self._get_history(load_key) if load_key else []

        try:
            await websocket.send_json({
                "type": "init",
                "stats": org_stats,
                "recent_scans": org_history[-100:],
            })
        except Exception:
            pass

    def disconnect(self, websocket: WebSocket):
        if websocket in self._connections:
            del self._connections[websocket]
        logger.info("ws_client_disconnected", total_connections=len(self._connections))

    async def broadcast_scan(self, scan_data: dict):
        """Broadcast a scan result to all connected clients."""
        scan_org_id = str(scan_data.get("organization_id")) if scan_data.get("organization_id") else None

        if scan_org_id:
            stats = self._get_stats(scan_org_id)
            history = self._get_history(scan_org_id)
        else:
            stats = {"total_scans": 0, "blocked": 0, "flagged": 0, "allowed": 0, "threat_categories": {}}
            history = []
            
        global_stats = self._get_stats("global")
        global_history = self._get_history("global")

        # Ensure geo fields exist on the incoming scan_data before broadcast
        if "lat" not in scan_data:
            geo = resolve_geo(
                scan_data.get("source_ip") or scan_data.get("id"),
                extra_entropy=scan_data.get("request_id") or str(scan_data.get("id", ""))
            )
            profile = scan_data.get("attacker_profile", {})
            real_ip = profile.get("source_ip") or scan_data.get("source_ip")
            
            scan_data["lat"] = profile.get("latitude") or geo["lat"]
            scan_data["lng"] = profile.get("longitude") or geo["lng"]
            scan_data["city"] = profile.get("city") or geo["city"]
            scan_data["country"] = profile.get("country") or geo["country"]
            scan_data["asn"] = profile.get("asn_number") or ""
            scan_data["isp"] = profile.get("isp_name") or profile.get("asn_org") or ""
            scan_data["timezone"] = profile.get("timezone") or ""
            scan_data["postal_code"] = profile.get("postal_code") or ""
            scan_data["ip"] = real_ip if real_ip and real_ip != "127.0.0.1" else geo.get("generated_ip", "127.0.0.1")
            scan_data["browser"] = profile.get("browser") or geo.get("browser", {}).get("short", "Unknown")
            scan_data["browser_full"] = profile.get("user_agent") or geo.get("browser", {}).get("browser", "Unknown")
            scan_data["os"] = profile.get("os") or geo.get("browser", {}).get("os", "Unknown")

        # Update in-memory stats
        action = scan_data.get("action", "allowed")
        
        for s in [stats, global_stats]:
            s["total_scans"] += 1
            if action == "blocked":
                s["blocked"] += 1
            elif action == "flagged":
                s["flagged"] += 1
            else:
                s["allowed"] += 1

            # Track threat categories
            for det in scan_data.get("detections", []):
                cat = det.get("category", "unknown")
                s["threat_categories"][cat] = s["threat_categories"].get(cat, 0) + 1

        # Store in history
        history.append(scan_data)
        if len(history) > 500:
            self._scan_history[scan_org_id] = history[-500:]
            
        global_history.append(scan_data)
        if len(global_history) > 500:
            self._scan_history["global"] = global_history[-500:]

        # Broadcast to all connected clients
        message_normal = {"type": "scan_event", "data": scan_data, "stats": stats}
        message_admin = {"type": "scan_event", "data": scan_data, "stats": global_stats}
        disconnected = []

        for ws, info in self._connections.items():
            try:
                if info["is_admin"]:
                    await ws.send_json(message_admin)
                elif info["org_id"] == scan_org_id:
                    await ws.send_json(message_normal)
            except Exception:
                disconnected.append(ws)

        for ws in disconnected:
            self.disconnect(ws)

        # Forward to SIEM integrations asynchronously
        if scan_org_id:
            import asyncio
            asyncio.create_task(self._forward_to_siem(scan_org_id, scan_data))

    async def _forward_to_siem(self, org_id: str, scan_data: dict):
        """Forward real-time scan events to all configured SIEMs for this org."""
        from datetime import datetime, timezone

        import httpx
        from sqlalchemy import select

        from app.core.database import async_session_factory
        from app.models.organization import Organization
        
        try:
            async with async_session_factory() as session:
                res = await session.execute(select(Organization).where(Organization.id == org_id))
                org = res.scalar_one_or_none()
                if not org or not org.settings:
                    return
                integrations = org.settings.get("integrations", [])
                
            if not integrations:
                return

            async with httpx.AsyncClient(timeout=10.0) as client:
                for integration in integrations:
                    if not integration.get("enabled"):
                        continue
                        
                    provider = integration.get("provider")
                    endpoint = integration.get("endpoint")
                    if not endpoint:
                        continue
                        
                    if provider == "webhook":
                        payload = {
                            "source": "ghostprompt",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "event_type": "ai_security_scan",
                            "data": scan_data
                        }
                        headers = {"Content-Type": "application/json"}
                        if integration.get("api_key"):
                            headers["Authorization"] = f"Bearer {integration['api_key']}"
                        
                        try:
                            await client.post(endpoint, headers=headers, json=payload)
                        except Exception:
                            pass
        except Exception:
            pass

    def get_stats(self, org_id: str = None) -> dict:
        if org_id:
            stats = self._get_stats(org_id)
            history = self._get_history(org_id)
            return {**stats, "recent_scans": history[-20:]}
        return {"total_scans": 0, "blocked": 0, "flagged": 0, "allowed": 0, "threat_categories": {}, "recent_scans": []}


# Singleton
event_broadcaster = EventBroadcaster()
