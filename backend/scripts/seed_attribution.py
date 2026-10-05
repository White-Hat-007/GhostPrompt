import asyncio
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import delete, select

from app.core.database import async_session_factory
from app.models.attribution import (
    AdversarialMediaEvent,
    AttackCluster,
    ExfiltrationEvent,
    GroomingTimeline,
    ModelIntegrityEvent,
    ThreatActor,
    ThreatCampaign,
    TokenizerThreat,
)
from app.models.organization import Organization


async def seed():
    async with async_session_factory() as db:
        result = await db.execute(select(Organization))
        orgs = result.scalars().all()

        if not orgs:
            print("No organizations found")
            return

        for org in orgs:
            print(f"Injecting threat attribution data for org: {org.name}")

            # Clear existing data for idempotency
            await db.execute(delete(ThreatActor).where(ThreatActor.organization_id == org.id))
            await db.execute(delete(ThreatCampaign).where(ThreatCampaign.organization_id == org.id))
            await db.execute(delete(AttackCluster).where(AttackCluster.organization_id == org.id))
            await db.execute(delete(ModelIntegrityEvent).where(ModelIntegrityEvent.organization_id == org.id))
            await db.execute(delete(GroomingTimeline).where(GroomingTimeline.organization_id == org.id))
            await db.execute(delete(ExfiltrationEvent).where(ExfiltrationEvent.organization_id == org.id))
            await db.execute(delete(AdversarialMediaEvent).where(AdversarialMediaEvent.organization_id == org.id))
            await db.execute(delete(TokenizerThreat).where(TokenizerThreat.organization_id == org.id))

            now = datetime.now(timezone.utc)

            # 1. THREAT CAMPAIGNS
            c1_id = uuid.uuid4().hex[:16]
            c1 = ThreatCampaign(
                organization_id=org.id, campaign_id=f"CAMP-{c1_id}",
                name="Operation Silent Sand", description="Coordinated model evasion targeting enterprise billing APIs.",
                campaign_type="apt", threat_family="SandWorm AI", severity="critical", risk_score=0.98,
                total_events=1450, total_actors=3, total_ips=12,
                attack_types=["tool_hijack", "intent_evasion", "data_exfiltration"], status="active",
                first_seen=now - timedelta(days=14), last_seen=now
            )
            c2_id = uuid.uuid4().hex[:16]
            c2 = ThreatCampaign(
                organization_id=org.id, campaign_id=f"CAMP-{c2_id}",
                name="Sleeper Synthetic Swarm", description="Bot swarm attempting long-horizon semantic grooming.",
                campaign_type="bot_swarm", threat_family="VoidSpider", severity="high", risk_score=0.85,
                total_events=3200, total_actors=45, total_ips=120,
                attack_types=["semantic_drift", "trust_building", "prompt_injection"], status="active",
                first_seen=now - timedelta(days=45), last_seen=now - timedelta(hours=2)
            )
            db.add_all([c1, c2])

            # 2. THREAT ACTORS
            a1 = ThreatActor(
                organization_id=org.id, actor_id=f"TA-{uuid.uuid4().hex[:8]}",
                alias="VoidSpider Node 4", actor_type="bot", confidence_score=0.94,
                attribution_method="typing_cadence_match",
                ip_addresses=["185.10.4.5", "185.10.4.9"], asn_list=["AS5089"],
                is_vpn=True, is_tor=False, is_proxy=False,
                typing_cadence_ms=12.5, attack_sophistication="high",
                primary_country="Russia", primary_city="St Petersburg",
                total_requests=450, total_attacks=89, total_blocked=89,
                campaign_ids=[c2.campaign_id], risk_score=0.91, risk_level="critical",
                first_seen=now - timedelta(days=12), last_seen=now
            )
            a2 = ThreatActor(
                organization_id=org.id, actor_id=f"TA-{uuid.uuid4().hex[:8]}",
                alias="SandWorm Operative", actor_type="apt_group", confidence_score=0.88,
                attribution_method="semantic_fingerprint",
                ip_addresses=["45.33.12.99"], asn_list=["AS1234"],
                is_vpn=False, is_tor=True, is_proxy=True,
                typing_cadence_ms=250.0, attack_sophistication="nation_state",
                primary_country="Unknown",
                total_requests=12, total_attacks=12, total_blocked=12,
                campaign_ids=[c1.campaign_id], risk_score=0.99, risk_level="critical",
                first_seen=now - timedelta(days=4), last_seen=now - timedelta(minutes=15)
            )
            db.add_all([a1, a2])

            # 3. ATTACK CLUSTERS
            ac1 = AttackCluster(
                organization_id=org.id, cluster_id=f"CLS-{uuid.uuid4().hex[:8]}",
                family_name="Logprob Fishing (Oracle)", attack_category="oracle",
                variant_count=14, total_occurrences=450, block_rate=0.98, avg_threat_score=0.85,
                common_patterns=["translate identical string", "logprob extraction"]
            )
            ac2 = AttackCluster(
                organization_id=org.id, cluster_id=f"CLS-{uuid.uuid4().hex[:8]}",
                family_name="Zero-Width Unicode Splitting", attack_category="tokenizer",
                variant_count=8, total_occurrences=120, block_rate=1.0, avg_threat_score=0.95,
                common_patterns=["U+200B injection", "bidi_override"]
            )
            db.add_all([ac1, ac2])

            # 4. MODEL INTEGRITY EVENTS
            mie1 = ModelIntegrityEvent(
                organization_id=org.id, event_type="poisoning_detected",
                model_name="gpt-4-finetune-v2", model_provider="openai",
                risk_score=0.97, risk_level="critical", confidence=0.92,
                description="Detected anomalous activation patterns corresponding to known sleeper agent trigger sequences in training data.",
                indicators=["activation_spike_layer_24", "sudden_alignment_drop"],
                action_taken="model_quarantined", was_mitigated=True
            )
            mie2 = ModelIntegrityEvent(
                organization_id=org.id, event_type="drift_detected",
                model_name="claude-3-opus", model_provider="anthropic",
                risk_score=0.65, risk_level="medium", confidence=0.88,
                description="Semantic drift detected in compliance boundary responses.",
                action_taken="alert_generated", was_mitigated=False
            )
            db.add_all([mie1, mie2])

            # 5. GROOMING TIMELINES
            gt1 = GroomingTimeline(
                organization_id=org.id, session_id=f"sess_{uuid.uuid4().hex}",
                actor_id=a1.actor_id, grooming_type="progressive_manipulation",
                risk_score=0.89, risk_level="high", stage="exploiting",
                interaction_count=45, span_days=14,
                manipulation_indicators=["gaslighting", "authority_mimicry", "context_window_flooding"],
                trust_score_history=[0.1, 0.3, 0.6, 0.9],
                first_interaction=now - timedelta(days=14), last_interaction=now
            )
            db.add(gt1)

            # 6. EXFILTRATION EVENTS
            ex1 = ExfiltrationEvent(
                organization_id=org.id, channel_type="timing_channel",
                confidence_score=0.94, severity="critical",
                description="Detected covert timing channel: Attack forcing the model to delay responses by exact milliseconds to encode binary data.",
                indicators=["bimodal_latency_distribution", "high_entropy_token_delay"],
                source_ip="185.10.4.5", action_taken="rate_limited", was_blocked=True
            )
            db.add(ex1)

            # 7. ADVERSARIAL MEDIA
            am1 = AdversarialMediaEvent(
                organization_id=org.id, media_type="image", attack_type="adversarial_patch",
                confidence_score=0.96, severity="critical",
                description="Detected robust adversarial patch in uploaded receipt image designed to blind OCR pipeline.",
                attack_fingerprint="patch_v4_pgd", detection_method="latent_space_anomaly",
                action_taken="image_rejected", was_blocked=True
            )
            am2 = AdversarialMediaEvent(
                organization_id=org.id, media_type="audio", attack_type="audio_noise",
                confidence_score=0.91, severity="high",
                description="Detected high-frequency adversarial noise in voice prompt designed to hallucinate a command.",
                detection_method="spectrogram_entropy", action_taken="audio_scrubbed", was_blocked=True
            )
            db.add_all([am1, am2])

            # 8. TOKENIZER THREATS
            tt1 = TokenizerThreat(
                organization_id=org.id, threat_type="unknown_split",
                description="Novel unicode combination causing catastrophic backtracking in BPE tokenizer.",
                affected_tokenizer="cl100k_base", affected_models=["gpt-4", "gpt-3.5-turbo"],
                anomaly_score=0.99, severity="critical", exploitability="demonstrated",
                status="investigating"
            )
            db.add(tt1)

            await db.commit()
            print(f"  [OK] Successfully injected threat attribution data for {org.name}")

if __name__ == "__main__":
    asyncio.run(seed())
