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
        
        distinct_ips = [
            "8.8.8.8",          # US
            "1.1.1.1",          # AU
            "13.250.177.223",   # Singapore
            "212.58.244.20",    # UK
            "119.29.29.29",     # China
            "52.67.214.216",    # Brazil
            "213.186.33.99",    # France
            "35.154.218.106",   # India
            "210.130.120.40",   # Japan
            "197.248.114.10",   # Kenya
        ]
        
        class FakeRequest:
            class FakeClient:
                host = "127.0.0.1"
            def __init__(self, ip):
                self.headers = {"x-forwarded-for": ip}
            client = FakeClient()
            
        updated = 0
        for i, event in enumerate(events):
            ip = distinct_ips[i % len(distinct_ips)]
            
            # Use X-Forwarded-For so the profiler uses our distinct IP
            request = FakeRequest(ip)
            
            det_objs = [SimpleNamespace(**d) for d in event.detections] if event.detections else []
            
            profile = await attacker_profiler.profile_request(
                request,
                session_id="spread",
                action=event.action,
                threat_level=event.threat_level,
                detections=det_objs
            )
            
            md = event.event_metadata or {}
            md["attacker_profile"] = profile.model_dump()
            event.event_metadata = md
            
            from sqlalchemy.orm.attributes import flag_modified
            flag_modified(event, "event_metadata")
            updated += 1
            
        await session.commit()
        print(f"Spread {updated} events across the globe!")

if __name__ == "__main__":
    asyncio.run(main())
