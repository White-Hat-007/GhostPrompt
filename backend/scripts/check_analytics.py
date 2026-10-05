"""Quick test: hit the analytics endpoint directly."""
import asyncio

from sqlalchemy import text

from app.core.database import async_session_factory


async def check():
    async with async_session_factory() as s:
        # Check threat_categories type
        r = await s.execute(text(
            "SELECT threat_categories FROM scan_events WHERE threat_categories IS NOT NULL LIMIT 3"
        ))
        for row in r.all():
            print(f"Type: {type(row[0])}, Value: {row[0]}")
        
        # Try the json_array_elements approach  
        try:
            r2 = await s.execute(text("""
                SELECT elem::text as category, COUNT(*) as cnt
                FROM scan_events,
                     LATERAL jsonb_array_elements_text(threat_categories::jsonb) AS elem
                WHERE threat_categories IS NOT NULL
                  AND jsonb_typeof(threat_categories::jsonb) = 'array'
                GROUP BY elem
                ORDER BY cnt DESC
                LIMIT 10
            """))
            print("\njsonb approach works:")
            for row in r2.all():
                print(f"  {row[0]}: {row[1]}")
        except Exception as e:
            print(f"jsonb approach failed: {e}")

asyncio.run(check())
