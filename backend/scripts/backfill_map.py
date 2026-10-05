import asyncio
import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from types import SimpleNamespace

from sqlalchemy import select

from app.core.database import async_session_factory
from app.models.scan_event import ScanEvent
from app.services.firewall.detectors.attacker_profiler import attacker_profiler


async def main():
    async with async_session_factory() as session:
        result = await session.execute(
            select(ScanEvent).where(ScanEvent.action.in_(["blocked", "flagged"]))
        )
        events = result.scalars().all()
        
        await attacker_profiler.initialize()
        
        class FakeRequest:
            class FakeClient:
                host = "127.0.0.1"
            client = FakeClient()
            headers = {}
            
        updated = 0
        for event in events:
            md = event.event_metadata or {}
            if "attacker_profile" not in md or not md["attacker_profile"].get("latitude"):
                request = FakeRequest()
                
                det_objs = [SimpleNamespace(**d) for d in event.detections] if event.detections else []
                
                profile = await attacker_profiler.profile_request(
                    request,
                    session_id="backfill",
                    action=event.action,
                    threat_level=event.threat_level,
                    detections=det_objs
                )
                
                md["attacker_profile"] = profile.model_dump()
                event.event_metadata = md
                
                from sqlalchemy.orm.attributes import flag_modified
                flag_modified(event, "event_metadata")
                updated += 1
                
        await session.commit()
        print(f"Backfilled {updated} events!")

if __name__ == "__main__":
    asyncio.run(main())
