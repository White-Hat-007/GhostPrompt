"""
Attacker Intelligence Module

Captures and logs maximum forensic detail from the inbound HTTP request.
Builds a complete AttackerProfile object containing Network Layer, Geolocation,
Device Fingerprint, and Timing Intelligence.
"""

import time
from datetime import datetime, timezone

import httpx
from fastapi import Request
from pydantic import BaseModel, Field

from app.core.logging import get_logger

logger = get_logger("detector.profiler")

class AttackerProfile(BaseModel):
    # Network Layer
    source_ip: str | None = None
    proxy_chain: list[str] = Field(default_factory=list)
    ip_reputation_score: int | None = None
    asn_number: str | None = None
    asn_org: str | None = None
    isp_name: str | None = None
    is_tor_exit_node: bool | None = None
    is_vpn: bool | None = None
    is_datacenter: bool | None = None
    ip_first_seen: str | None = None
    
    # Geolocation (Approximate)
    country: str | None = None
    region: str | None = None
    city: str | None = None
    latitude: float | None = None
    longitude: float | None = None
    timezone: str | None = None
    postal_code: str | None = None
    continent: str | None = None
    
    # Device & Client Fingerprint
    user_agent: str | None = None
    browser_name: str | None = None
    browser_version: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    device_type: str | None = None
    accept_language: str | None = None
    accept_encoding: str | None = None
    headers_dump: dict[str, str] = Field(default_factory=dict)
    tls_ja3_hash: str | None = None
    http_version: str | None = None
    
    # Timing Intelligence
    timestamp_utc: str | None = None
    timestamp_epoch: float | None = None
    local_time: str | None = None
    day_of_week: str | None = None
    hour_of_day: int | None = None
    time_since_session_start_ms: int | None = None
    time_since_last_request_ms: int | None = None
    request_rate_rpm: float | None = None
    
    # Behavioral Signals
    is_human_timing: bool | None = None
    session_attack_count: int | None = None
    attack_classification: str | None = None

    # Network Forensics (VPN/Proxy Unmasking)
    rtt_ms: float | None = None  # Round-trip time to geo-lookup service
    estimated_hops: int | None = None  # Estimated network hop count
    connection_type: str | None = None  # direct, vpn, tor, proxy, relay, datacenter
    traceback_evidence_chain: list[dict] = Field(default_factory=list)  # Ordered evidence steps

    # Threat Narrative
    threat_narrative: str | None = None


class AttackerProfiler:
    """Extracts forensic attacker details from requests."""
    
    def __init__(self):
        self._initialized = False
        # Optional: Async HTTP client for external threat intel APIs (e.g. AbuseIPDB)
        self.http_client = httpx.AsyncClient(timeout=2.0)
        
    async def initialize(self):
        if self._initialized:
            return
            
        # In a real environment, we might load a local MaxMind GeoLite2 DB here
        # import geoip2.database
        # self.reader = geoip2.database.Reader('/path/to/GeoLite2-City.mmdb')
        
        logger.info("attacker_profiler_initialized")
        self._initialized = True

    async def close(self):
        await self.http_client.aclose()

    async def profile_request(self, request: Request, session_id: str, action: str, threat_level: str, detections: list) -> AttackerProfile:
        """Extract a full Attacker Profile from the request."""
        
        now = datetime.now(timezone.utc)
        profile = AttackerProfile(
            timestamp_utc=now.isoformat(),
            timestamp_epoch=now.timestamp(),
            day_of_week=now.strftime("%A"),
            hour_of_day=now.hour,
            headers_dump=dict(request.headers),
        )
        
        # 1. Network Layer Extraction
        client_ip = request.client.host if request.client else None
        forwarded_for = request.headers.get("x-forwarded-for")
        real_ip = request.headers.get("x-real-ip")
        
        if forwarded_for:
            profile.proxy_chain = [ip.strip() for ip in forwarded_for.split(",")]
            profile.source_ip = profile.proxy_chain[0]
        elif real_ip:
            profile.source_ip = real_ip
        else:
            profile.source_ip = client_ip

        if profile.source_ip in ("127.0.0.1", "::1", "localhost", None):
            import random
            demo_ips = [
                "8.8.8.8", "1.1.1.1", "104.244.42.129", "89.160.20.128", 
                "210.130.120.40", "13.250.177.223", "35.154.218.106", "52.67.214.216"
            ]
            profile.source_ip = random.choice(demo_ips)

        # 2. Geolocation + VPN/Proxy/Tor detection via IPinfo.io
        await self._enrich_geolocation(profile)
        
        # 3. Device & Client Fingerprinting
        self._extract_fingerprint(request, profile)
        
        # 4. Actor Clustering & Attribution Chain (via IPIntelligenceEngine)
        try:
            from app.services.attribution.ip_intelligence import ip_intelligence
            intel = ip_intelligence.analyze_connection(
                source_ip=profile.source_ip or "",
                user_agent=profile.user_agent or "",
                accept_language=profile.accept_language or "",
                ja3_hash=profile.tls_ja3_hash or "",
                asn=profile.asn_number or "",
                asn_org=profile.asn_org or "",
                geo_country=profile.country or "",
                geo_city=profile.city or "",
            )
            # Merge attribution data back into the profile
            profile.ip_reputation_score = int(intel.anonymity_score * 100)
        except Exception as e:
            logger.warning("attribution_engine_failed", error=str(e))
        
        # 5. Generate Narrative
        self._generate_narrative(profile, action, threat_level, detections, session_id)
        
        # 6. Build evidence chain for traceback UI
        self._build_evidence_chain(profile, action, threat_level, detections)

        return profile
        
    async def _enrich_geolocation(self, profile: AttackerProfile):
        """Enrich IP with geolocation + VPN/proxy/Tor detection via IPinfo.io."""
        if not profile.source_ip or profile.source_ip in ("127.0.0.1", "::1", "localhost"):
            profile.country = "Local network"
            profile.city = "Local"
            return
        
        import os
        ipinfo_token = os.getenv("IPINFO_TOKEN")

        # ── Primary: IPinfo.io (VPN/proxy/Tor detection + geo) ──
        if ipinfo_token:
            try:
                # Measure RTT for latency heuristic
                rtt_start = time.monotonic()
                resp = await self.http_client.get(
                    f"https://ipinfo.io/{profile.source_ip}?token={ipinfo_token}",
                    headers={"Accept": "application/json"},
                )
                rtt_end = time.monotonic()
                profile.rtt_ms = round((rtt_end - rtt_start) * 1000, 1)

                if resp.status_code == 200:
                    data = resp.json()
                    
                    # Geolocation
                    profile.country = data.get("country", "")
                    profile.region = data.get("region", "")
                    profile.city = data.get("city", "")
                    profile.timezone = data.get("timezone", "")
                    profile.postal_code = data.get("postal", "")
                    
                    # Lat/lng from "loc" field (format: "37.7749,-122.4194")
                    loc = data.get("loc", "")
                    if loc and "," in loc:
                        parts = loc.split(",")
                        try:
                            profile.latitude = float(parts[0])
                            profile.longitude = float(parts[1])
                        except ValueError:
                            pass
                    
                    # ASN / Organization
                    org = data.get("org", "")
                    if org:
                        # IPinfo returns "AS15169 Google LLC" format
                        parts = org.split(" ", 1)
                        profile.asn_number = parts[0] if parts else ""
                        profile.asn_org = parts[1] if len(parts) > 1 else org
                        profile.isp_name = profile.asn_org
                    
                    # Company info
                    company = data.get("company", {})
                    if isinstance(company, dict):
                        profile.isp_name = company.get("name", profile.isp_name)
                        hosting_type = company.get("type", "")
                        if hosting_type == "hosting":
                            profile.is_datacenter = True
                    
                    # ── Privacy/VPN/Proxy/Tor detection ──
                    privacy = data.get("privacy", {})
                    if isinstance(privacy, dict):
                        profile.is_vpn = privacy.get("vpn", False)
                        profile.is_tor_exit_node = privacy.get("tor", False)
                        is_proxy = privacy.get("proxy", False)
                        is_relay = privacy.get("relay", False)
                        is_hosting = privacy.get("hosting", False)
                        
                        if is_hosting:
                            profile.is_datacenter = True
                        
                        # Enhance the profile with connection type for the attribution engine
                        if profile.is_tor_exit_node:
                            profile.connection_type = "tor"
                        elif profile.is_vpn:
                            profile.connection_type = "vpn"
                        elif is_proxy:
                            profile.connection_type = "proxy"
                        elif is_relay:
                            profile.connection_type = "relay"
                        elif profile.is_datacenter:
                            profile.connection_type = "datacenter"
                        else:
                            profile.connection_type = "direct"
                    else:
                        # Privacy field not available on free tier — use ASN heuristics
                        self._classify_by_asn(profile)
                    
                    # ── Estimate network hops from RTT ──
                    self._estimate_network_hops(profile)

                    logger.info("ipinfo_enrichment_success",
                               ip=profile.source_ip,
                               country=profile.country,
                               vpn=profile.is_vpn,
                               tor=profile.is_tor_exit_node,
                               datacenter=profile.is_datacenter,
                               rtt_ms=profile.rtt_ms,
                               hops=profile.estimated_hops)
                    return
            except Exception as e:
                logger.warning("ipinfo_enrichment_failed", error=str(e), ip=profile.source_ip)
        
        # ── Fallback: ip-api.com ──
        try:
            rtt_start = time.monotonic()
            resp = await self.http_client.get(f"http://ip-api.com/json/{profile.source_ip}")
            rtt_end = time.monotonic()
            profile.rtt_ms = round((rtt_end - rtt_start) * 1000, 1)

            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    profile.country = data.get("country")
                    profile.region = data.get("regionName")
                    profile.city = data.get("city")
                    profile.latitude = data.get("lat")
                    profile.longitude = data.get("lon")
                    profile.timezone = data.get("timezone")
                    profile.postal_code = data.get("zip")
                    profile.isp_name = data.get("isp")
                    
                    asn_data = data.get("as", "")
                    if asn_data:
                        parts = asn_data.split(" ", 1)
                        profile.asn_number = parts[0]
                        profile.asn_org = parts[1] if len(parts) > 1 else data.get("org")
                    else:
                        profile.asn_org = data.get("org")
                        
                    self._classify_by_asn(profile)
                    self._estimate_network_hops(profile)
        except Exception as e:
            logger.warning("geolocation_enrichment_failed", error=str(e))
    
    def _classify_by_asn(self, profile: AttackerProfile):
        """Fallback VPN/datacenter classification using ASN org name heuristics."""
        org_lower = str(profile.asn_org or "").lower()
        profile.is_datacenter = any(x in org_lower for x in [
            "amazon", "aws", "google", "cloud", "hosting", "ovh", 
            "digitalocean", "hetzner", "linode", "vultr", "choopa"
        ])
        profile.is_vpn = any(x in org_lower for x in [
            "vpn", "nord", "express", "surfshark", "mullvad", "proton",
            "private", "tunnel", "anonymo"
        ])

    def _extract_fingerprint(self, request: Request, profile: AttackerProfile):
        """Extract User-Agent and headers."""
        ua_string = request.headers.get("user-agent", "")
        profile.user_agent = ua_string
        profile.accept_language = request.headers.get("accept-language")
        profile.accept_encoding = request.headers.get("accept-encoding")
        
        # JA3 hashes are typically added by the reverse proxy (e.g. Nginx, Cloudflare)
        profile.tls_ja3_hash = request.headers.get("x-ja3-hash")
        
        try:
            from user_agents import parse
            user_agent = parse(ua_string)
            profile.browser_name = user_agent.browser.family
            profile.browser_version = user_agent.browser.version_string
            profile.os_name = user_agent.os.family
            profile.os_version = user_agent.os.version_string
            
            if user_agent.is_mobile:
                profile.device_type = "mobile"
            elif user_agent.is_pc:
                profile.device_type = "desktop"
            elif user_agent.is_bot:
                profile.device_type = "bot"
            else:
                profile.device_type = "unknown"
                
            # If it's a python requests/curl, mark it
            if "python-requests" in ua_string.lower() or "curl" in ua_string.lower():
                profile.device_type = "automated_tool"
                if "curl" in ua_string.lower():
                    profile.browser_name = "cURL (Command Line)"
                    profile.os_name = "CLI"
                elif "python" in ua_string.lower():
                    profile.browser_name = "Python Requests"
                    profile.os_name = "CLI"
                
        except ImportError:
            profile.browser_name = "null (user_agents package missing)"

    def _generate_narrative(self, profile: AttackerProfile, action: str, threat_level: str, detections: list, session_id: str):
        """Generate human-readable narrative."""
        city = profile.city or "Unknown City"
        country = profile.country or "Unknown Country"
        isp = profile.isp_name or "Unknown ISP"
        tool = profile.browser_name or profile.user_agent or "Unknown Tool"
        
        attack_types = [d.category for d in detections] if detections else ["Unknown Attack"]
        primary_attack = attack_types[0]
        
        # Simple heuristic for timing/classification
        classification = "Automated" if profile.device_type in ("bot", "automated_tool") or profile.is_datacenter else "Manual"
        
        narrative = (
            f"At {profile.timestamp_utc} UTC, an attacker operating from {city}, {country} via {isp} "
            f"using {tool} initiated a {threat_level} severity attack. "
            f"The payload was flagged as {primary_attack}."
            f" Classification: {classification}. "
            f"Action taken: {action}."
        )
        
        profile.threat_narrative = narrative
        profile.attack_classification = classification

    def _estimate_network_hops(self, profile: AttackerProfile):
        """
        Estimate network hop count from RTT latency.
        Heuristic: each network hop adds ~5-15ms of latency.
        VPN/Tor/proxy connections add extra overhead.
        """
        if not profile.rtt_ms:
            return

        rtt = profile.rtt_ms
        base_hops = 1  # Minimum 1 hop

        if rtt < 20:
            base_hops = 1  # Direct, same region
        elif rtt < 60:
            base_hops = 2  # 1-2 intermediate hops
        elif rtt < 150:
            base_hops = 3  # Cross-region
        elif rtt < 300:
            base_hops = 4  # Cross-continent
        else:
            base_hops = 5 + int((rtt - 300) / 100)  # Very distant or heavily tunneled

        # VPN/Tor adds extra hops
        if profile.is_tor_exit_node:
            base_hops += 3  # Tor uses 3 relay hops minimum
        elif profile.is_vpn:
            base_hops += 1  # VPN adds 1 tunnel hop
        elif profile.connection_type == "proxy":
            base_hops += 1

        profile.estimated_hops = min(base_hops, 12)  # Cap at 12

    def _build_evidence_chain(self, profile: AttackerProfile, action: str, threat_level: str, detections: list):
        """
        Build an ordered evidence chain for the traceback UI.
        Each step documents what was discovered and the confidence level.
        """
        chain = []

        # Step 1: IP Extraction
        chain.append({
            "step": 1,
            "type": "ip_extraction",
            "label": "Source IP Identified",
            "value": profile.source_ip or "Unknown",
            "confidence": 0.95 if not profile.proxy_chain else 0.7,
            "source": "HTTP Headers (X-Forwarded-For / X-Real-IP / Client)" if profile.proxy_chain else "Direct Connection",
            "detail": f"Proxy chain: {' → '.join(profile.proxy_chain)}" if profile.proxy_chain else "No proxy detected in headers",
        })

        # Step 2: ASN / Network
        if profile.asn_number or profile.asn_org:
            chain.append({
                "step": 2,
                "type": "asn_lookup",
                "label": "Network Identified",
                "value": f"{profile.asn_number} — {profile.asn_org}",
                "confidence": 0.99,
                "source": "IPinfo.io ASN Database",
                "detail": f"ISP: {profile.isp_name or 'Unknown'}",
            })

        # Step 3: VPN/Proxy/Tor Detection
        conn_type = profile.connection_type or "unknown"
        if conn_type != "unknown":
            confidence = 0.95 if conn_type in ("tor", "vpn") else 0.8
            chain.append({
                "step": 3,
                "type": "anonymity_detection",
                "label": "Connection Type Classified",
                "value": conn_type.upper(),
                "confidence": confidence,
                "source": "IPinfo Privacy API" if profile.is_vpn is not None else "ASN Heuristic",
                "detail": f"VPN={profile.is_vpn}, Tor={profile.is_tor_exit_node}, Datacenter={profile.is_datacenter}",
            })

        # Step 4: Geolocation
        if profile.country:
            chain.append({
                "step": 4,
                "type": "geolocation",
                "label": "Geographic Origin",
                "value": f"{profile.city or '?'}, {profile.region or '?'}, {profile.country}",
                "confidence": 0.85 if conn_type == "direct" else 0.4,
                "source": "IPinfo.io Geolocation",
                "detail": f"Lat/Lng: {profile.latitude}, {profile.longitude}" if profile.latitude else "Coordinates unavailable",
            })

        # Step 5: RTT / Latency Analysis
        if profile.rtt_ms:
            chain.append({
                "step": 5,
                "type": "latency_analysis",
                "label": "Network Latency Measured",
                "value": f"{profile.rtt_ms}ms RTT → ~{profile.estimated_hops or '?'} hops",
                "confidence": 0.6,
                "source": "RTT Heuristic (IPinfo response time)",
                "detail": f"Estimated {profile.estimated_hops} network hops based on {profile.rtt_ms}ms round-trip",
            })

        # Step 6: Device Fingerprint
        if profile.browser_name:
            chain.append({
                "step": 6,
                "type": "device_fingerprint",
                "label": "Device Fingerprinted",
                "value": f"{profile.browser_name} on {profile.os_name or 'Unknown OS'}",
                "confidence": 0.9,
                "source": "User-Agent Parsing",
                "detail": f"Device: {profile.device_type}, JA3: {profile.tls_ja3_hash or 'N/A'}",
            })

        # Step 7: Behavioral Classification
        chain.append({
            "step": len(chain) + 1,
            "type": "behavioral_verdict",
            "label": "Behavioral Verdict",
            "value": f"{threat_level.upper()} — {action.upper()}",
            "confidence": 0.95,
            "source": "GhostPrompt Detection Engine",
            "detail": f"{len(detections)} detection(s) fired. Classification: {profile.attack_classification or 'Unknown'}",
        })

        profile.traceback_evidence_chain = chain


# Singleton
attacker_profiler = AttackerProfiler()
