"""
IP Intelligence & VPN/Proxy Attribution Engine

Detects anonymization layers and performs multi-signal attribution:
- VPN/proxy/Tor/datacenter detection
- JA3/JA4 TLS fingerprinting
- Accept-Language locale vs geo mismatch
- Behavioral correlation across sessions
- Actor-cluster identification

HONEST: Never claims to "unmask" VPN IPs. Labels estimates vs. facts.
"""

import hashlib
import time
import re
from datetime import datetime, timezone
from typing import Optional
from dataclasses import dataclass, field
from collections import defaultdict

from app.core.logging import get_logger

logger = get_logger("attribution.ip_intel")


# ── Known anonymizer ASN ranges (sample — real deployment uses IP intel API) ──
KNOWN_VPN_ASNS = {
    "AS9009",    # M247 (NordVPN, Surfshark)
    "AS20473",   # Choopa/Vultr (many VPNs)
    "AS14061",   # DigitalOcean
    "AS16276",   # OVH
    "AS24940",   # Hetzner
    "AS63949",   # Linode
    "AS174",     # Cogent (some datacenter hosting)
    "AS396982",  # Google Cloud
    "AS16509",   # Amazon AWS
    "AS8075",    # Microsoft Azure
}

KNOWN_TOR_EXIT_INDICATORS = [
    "tor-exit", ".torproject.org", "tor-relay",
]

# ── User-Agent parsing patterns ──
UA_OS_PATTERNS = {
    "Windows": re.compile(r"Windows NT (\d+\.\d+)"),
    "macOS": re.compile(r"Mac OS X (\d+[._]\d+)"),
    "Linux": re.compile(r"Linux"),
    "Android": re.compile(r"Android (\d+)"),
    "iOS": re.compile(r"iPhone OS (\d+)"),
}


@dataclass
class ConnectionProfile:
    """Full attribution profile for a connection."""
    # Raw data
    source_ip: str = ""
    user_agent: str = ""
    accept_language: str = ""
    
    # Anonymizer detection
    connection_type: str = "direct"  # direct, vpn, proxy, tor, datacenter, residential
    anonymity_score: float = 0.0     # 0.0 = definitely direct, 1.0 = definitely anonymized
    anonymizer_provider: Optional[str] = None
    asn: str = ""
    asn_org: str = ""
    is_datacenter: bool = False
    
    # Fingerprinting
    ja3_hash: str = ""
    tls_version: str = ""
    http2_fingerprint: str = ""
    
    # Behavioral signals
    os_from_ua: str = ""
    browser_from_ua: str = ""
    locale_from_accept_lang: str = ""
    timezone_offset: Optional[int] = None
    
    # Geo mismatch
    geo_ip_country: str = ""
    geo_ip_city: str = ""
    locale_country: str = ""
    geo_locale_mismatch: bool = False
    
    # Actor clustering
    actor_cluster_id: Optional[str] = None
    linked_ips: list[str] = field(default_factory=list)
    linked_sessions: int = 0
    
    # Estimated real origin (best-effort)
    estimated_region: Optional[str] = None
    estimate_confidence: float = 0.0
    estimate_method: str = ""
    
    # Confidence metadata
    overall_confidence: float = 0.0
    attribution_chain: list[str] = field(default_factory=list)


@dataclass
class ActorCluster:
    """Groups sessions by the same real actor across IPs."""
    id: str
    fingerprint_hash: str
    ips_seen: set = field(default_factory=set)
    sessions: int = 0
    attack_styles: set = field(default_factory=set)
    estimated_region: Optional[str] = None
    first_seen: str = ""
    last_seen: str = ""


class IPIntelligenceEngine:
    """
    Multi-signal attribution engine.
    
    Detects VPN/proxy/Tor usage and correlates sessions
    by fingerprint + behavior to identify actors across IP rotation.
    """

    def __init__(self):
        # fingerprint_hash → ActorCluster
        self._actor_clusters: dict[str, ActorCluster] = {}
        # IP → connection profiles
        self._ip_profiles: dict[str, list[ConnectionProfile]] = defaultdict(list)

    def analyze_connection(
        self,
        source_ip: str,
        user_agent: str = "",
        accept_language: str = "",
        ja3_hash: str = "",
        asn: str = "",
        asn_org: str = "",
        geo_country: str = "",
        geo_city: str = "",
        timezone_offset: Optional[int] = None,
    ) -> ConnectionProfile:
        """
        Perform full attribution analysis on a connection.
        Returns a ConnectionProfile with anonymizer verdict + actor clustering.
        """
        profile = ConnectionProfile(
            source_ip=source_ip,
            user_agent=user_agent,
            accept_language=accept_language,
            ja3_hash=ja3_hash,
            asn=asn,
            asn_org=asn_org,
            geo_ip_country=geo_country,
            geo_ip_city=geo_city,
            timezone_offset=timezone_offset,
        )

        # ── 1. Anonymizer Detection ──
        self._detect_anonymizer(profile)

        # ── 2. Parse User-Agent ──
        self._parse_ua(profile)

        # ── 3. Locale Analysis ──
        self._analyze_locale(profile)

        # ── 4. Geo-Locale Mismatch ──
        self._check_geo_mismatch(profile)

        # ── 5. Build Fingerprint ──
        fp_hash = self._build_fingerprint(profile)

        # ── 6. Actor Clustering ──
        self._cluster_actor(profile, fp_hash)

        # ── 7. Estimate Real Origin ──
        self._estimate_origin(profile)

        # ── 8. Build Attribution Chain ──
        self._build_chain(profile)

        # Store for future correlation
        self._ip_profiles[source_ip].append(profile)

        return profile

    def _detect_anonymizer(self, p: ConnectionProfile):
        """Detect if the connection is via VPN/proxy/Tor/datacenter."""
        signals = []
        score = 0.0

        # ASN-based detection
        if p.asn in KNOWN_VPN_ASNS:
            score += 0.4
            signals.append(f"ASN {p.asn} is known hosting/VPN provider")
            p.is_datacenter = True

        # ASN org name heuristics
        asn_lower = p.asn_org.lower()
        vpn_keywords = ["vpn", "proxy", "private", "tunnel", "anonymo", "mullvad", "nord", "express"]
        dc_keywords = ["hosting", "cloud", "datacenter", "server", "digital ocean", "aws", "azure", "google"]

        for kw in vpn_keywords:
            if kw in asn_lower:
                score += 0.3
                signals.append(f"ASN org '{p.asn_org}' matches VPN keyword '{kw}'")
                p.anonymizer_provider = p.asn_org

        for kw in dc_keywords:
            if kw in asn_lower:
                score += 0.2
                signals.append(f"ASN org '{p.asn_org}' matches datacenter keyword '{kw}'")
                p.is_datacenter = True

        # Tor exit detection
        for indicator in KNOWN_TOR_EXIT_INDICATORS:
            if indicator in asn_lower:
                score = max(score, 0.9)
                signals.append("Tor exit node indicator detected")
                p.connection_type = "tor"
                break

        # Classify
        if p.connection_type != "tor":
            if score >= 0.6:
                p.connection_type = "vpn" if any("vpn" in s.lower() for s in signals) else "datacenter"
            elif score >= 0.3:
                p.connection_type = "proxy"
            else:
                p.connection_type = "direct"

        p.anonymity_score = min(1.0, score)

    def _parse_ua(self, p: ConnectionProfile):
        """Extract OS and browser from User-Agent."""
        ua = p.user_agent
        for os_name, pattern in UA_OS_PATTERNS.items():
            if pattern.search(ua):
                p.os_from_ua = os_name
                break

        browsers = [
            ("Chrome", r"Chrome/(\d+)"),
            ("Firefox", r"Firefox/(\d+)"),
            ("Safari", r"Safari/(\d+)"),
            ("Edge", r"Edg/(\d+)"),
        ]
        for name, pat in browsers:
            if re.search(pat, ua):
                p.browser_from_ua = name
                break

    def _analyze_locale(self, p: ConnectionProfile):
        """Extract locale info from Accept-Language header."""
        if not p.accept_language:
            return
        # Parse primary language tag
        parts = p.accept_language.split(",")
        if parts:
            primary = parts[0].strip().split(";")[0].strip()
            p.locale_from_accept_lang = primary
            # Try to extract country
            if "-" in primary:
                p.locale_country = primary.split("-")[-1].upper()
            elif "_" in primary:
                p.locale_country = primary.split("_")[-1].upper()

    def _check_geo_mismatch(self, p: ConnectionProfile):
        """Check if Accept-Language locale mismatches GeoIP country."""
        if p.locale_country and p.geo_ip_country:
            if p.locale_country != p.geo_ip_country.upper():
                p.geo_locale_mismatch = True
                # This is a strong VPN indicator
                p.anonymity_score = min(1.0, p.anonymity_score + 0.2)

    def _build_fingerprint(self, p: ConnectionProfile) -> str:
        """Build a composite fingerprint for actor clustering."""
        components = [
            p.os_from_ua,
            p.browser_from_ua,
            p.locale_from_accept_lang,
            p.ja3_hash,
            str(p.timezone_offset or ""),
        ]
        raw = "|".join(components)
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _cluster_actor(self, p: ConnectionProfile, fp_hash: str):
        """Assign to an actor cluster based on fingerprint."""
        if fp_hash not in self._actor_clusters:
            self._actor_clusters[fp_hash] = ActorCluster(
                id=f"ACTOR-{fp_hash[:8].upper()}",
                fingerprint_hash=fp_hash,
                first_seen=datetime.now(timezone.utc).isoformat(),
            )

        cluster = self._actor_clusters[fp_hash]
        cluster.ips_seen.add(p.source_ip)
        cluster.sessions += 1
        cluster.last_seen = datetime.now(timezone.utc).isoformat()

        p.actor_cluster_id = cluster.id
        p.linked_ips = list(cluster.ips_seen - {p.source_ip})[:10]
        p.linked_sessions = cluster.sessions

    def _estimate_origin(self, p: ConnectionProfile):
        """Best-effort estimate of real origin region."""
        if p.connection_type == "direct":
            p.estimated_region = f"{p.geo_ip_city}, {p.geo_ip_country}" if p.geo_ip_city else p.geo_ip_country
            p.estimate_confidence = 0.95
            p.estimate_method = "Direct connection — GeoIP"
            return

        # Use locale as primary signal for VPN users
        if p.locale_country:
            p.estimated_region = f"Estimated: {p.locale_country} (via Accept-Language)"
            p.estimate_confidence = 0.45
            p.estimate_method = "Accept-Language locale analysis"

        # Timezone can narrow it down
        if p.timezone_offset is not None:
            tz_region = self._tz_to_region(p.timezone_offset)
            if tz_region:
                if p.estimated_region:
                    p.estimated_region += f" / {tz_region}"
                    p.estimate_confidence = min(0.6, p.estimate_confidence + 0.15)
                else:
                    p.estimated_region = f"Estimated: {tz_region} (via timezone)"
                    p.estimate_confidence = 0.35
                p.estimate_method += " + timezone correlation"

        # If we have a cluster with direct-connection history, use that
        if p.actor_cluster_id:
            cluster = self._actor_clusters.get(
                [k for k, v in self._actor_clusters.items() if v.id == p.actor_cluster_id][0]
                if any(v.id == p.actor_cluster_id for v in self._actor_clusters.values())
                else "",
                None,
            )
            if cluster and cluster.estimated_region:
                p.estimated_region = cluster.estimated_region
                p.estimate_confidence = 0.7
                p.estimate_method = "Historical actor-cluster correlation"

        if not p.estimated_region:
            p.estimated_region = "Unknown — origin masked"
            p.estimate_confidence = 0.0
            p.estimate_method = "No attribution signals available"

    def _tz_to_region(self, offset_minutes: int) -> Optional[str]:
        """Map timezone offset to approximate region."""
        offset_hours = offset_minutes / 60
        tz_map = {
            -8: "US West Coast", -7: "US Mountain", -6: "US Central", -5: "US East Coast",
            -4: "Eastern Americas", -3: "Brazil/Argentina", 0: "UK/West Africa",
            1: "Central Europe", 2: "Eastern Europe", 3: "Middle East/East Africa",
            4: "Gulf States", 5: "Pakistan/Central Asia", 5.5: "India",
            6: "Bangladesh", 7: "Southeast Asia", 8: "China/East Asia",
            9: "Japan/Korea", 10: "Australia East", 12: "New Zealand",
        }
        return tz_map.get(offset_hours)

    def _build_chain(self, p: ConnectionProfile):
        """Build the step-by-step attribution chain."""
        chain = []
        chain.append(f"Exit IP: {p.source_ip}")
        chain.append(f"ASN: {p.asn} ({p.asn_org})")
        chain.append(f"Connection Type: {p.connection_type} (confidence: {p.anonymity_score:.0%})")

        if p.ja3_hash:
            chain.append(f"TLS Fingerprint: {p.ja3_hash[:16]}...")

        if p.actor_cluster_id:
            chain.append(f"Actor Cluster: {p.actor_cluster_id} ({p.linked_sessions} sessions, {len(p.linked_ips)} IPs)")

        if p.geo_locale_mismatch:
            chain.append(f"⚠ Geo-Locale Mismatch: IP={p.geo_ip_country}, Locale={p.locale_country}")

        if p.estimated_region:
            chain.append(f"Estimated Origin: {p.estimated_region} ({p.estimate_confidence:.0%} confidence)")

        p.attribution_chain = chain
        p.overall_confidence = p.estimate_confidence

    def get_actor_clusters(self, min_ips: int = 2) -> list[dict]:
        """Get actor clusters with multiple IPs (likely VPN rotation)."""
        return [
            {
                "id": c.id,
                "ips_count": len(c.ips_seen),
                "sessions": c.sessions,
                "first_seen": c.first_seen,
                "last_seen": c.last_seen,
                "estimated_region": c.estimated_region,
            }
            for c in self._actor_clusters.values()
            if len(c.ips_seen) >= min_ips
        ]


# Global singleton
ip_intelligence = IPIntelligenceEngine()
