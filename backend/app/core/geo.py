import hashlib

# High-threat intelligence hubs & standard origin points
GLOBAL_HUBS = [
    {"city": "Moscow", "country": "RU", "lat": 55.7558, "lng": 37.6173},
    {"city": "St. Petersburg", "country": "RU", "lat": 59.9311, "lng": 30.3609},
    {"city": "Beijing", "country": "CN", "lat": 39.9042, "lng": 116.4074},
    {"city": "Shanghai", "country": "CN", "lat": 31.2304, "lng": 121.4737},
    {"city": "Guangzhou", "country": "CN", "lat": 23.1291, "lng": 113.2644},
    {"city": "Pyongyang", "country": "KP", "lat": 39.0392, "lng": 125.7625},
    {"city": "Tehran", "country": "IR", "lat": 35.6892, "lng": 51.3890},
    {"city": "Ashburn", "country": "US", "lat": 39.0438, "lng": -77.4874},
    {"city": "Frankfurt", "country": "DE", "lat": 50.1109, "lng": 8.6821},
    {"city": "London", "country": "GB", "lat": 51.5074, "lng": -0.1278},
    {"city": "Amsterdam", "country": "NL", "lat": 52.3676, "lng": 4.9041},
    {"city": "Singapore", "country": "SG", "lat": 1.3521, "lng": 103.8198},
    {"city": "Tokyo", "country": "JP", "lat": 35.6762, "lng": 139.6503},
    {"city": "Seoul", "country": "KR", "lat": 37.5665, "lng": 126.9780},
    {"city": "Mumbai", "country": "IN", "lat": 19.0760, "lng": 72.8777},
    {"city": "Sao Paulo", "country": "BR", "lat": -23.5505, "lng": -46.6333},
    {"city": "Sydney", "country": "AU", "lat": -33.8688, "lng": 151.2093},
    {"city": "Dubai", "country": "AE", "lat": 25.2048, "lng": 55.2708},
    {"city": "Tel Aviv", "country": "IL", "lat": 32.0853, "lng": 34.7818},
    {"city": "Johannesburg", "country": "ZA", "lat": -26.2041, "lng": 28.0473},
    {"city": "Bucharest", "country": "RO", "lat": 44.4268, "lng": 26.1025},
    {"city": "Lagos", "country": "NG", "lat": 6.5244, "lng": 3.3792},
    {"city": "Hanoi", "country": "VN", "lat": 21.0278, "lng": 105.8342},
    {"city": "Jakarta", "country": "ID", "lat": -6.2088, "lng": 106.8456},
    {"city": "Kyiv", "country": "UA", "lat": 50.4501, "lng": 30.5234},
    {"city": "Warsaw", "country": "PL", "lat": 52.2297, "lng": 21.0122},
    {"city": "Bangalore", "country": "IN", "lat": 12.9716, "lng": 77.5946},
    {"city": "Cairo", "country": "EG", "lat": 30.0444, "lng": 31.2357},
    {"city": "Mexico City", "country": "MX", "lat": 19.4326, "lng": -99.1332},
    {"city": "Toronto", "country": "CA", "lat": 43.6532, "lng": -79.3832},
    {"city": "Minsk", "country": "BY", "lat": 53.9006, "lng": 27.5590},
    {"city": "Islamabad", "country": "PK", "lat": 33.6844, "lng": 73.0479},
    {"city": "Dhaka", "country": "BD", "lat": 23.8103, "lng": 90.4125},
    {"city": "Buenos Aires", "country": "AR", "lat": -34.6037, "lng": -58.3816},
    {"city": "Lima", "country": "PE", "lat": -12.0464, "lng": -77.0428},
    {"city": "Nairobi", "country": "KE", "lat": -1.2921, "lng": 36.8219},
    {"city": "Bangkok", "country": "TH", "lat": 13.7563, "lng": 100.5018},
    {"city": "Kuala Lumpur", "country": "MY", "lat": 3.1390, "lng": 101.6869},
    {"city": "Santiago", "country": "CL", "lat": -33.4489, "lng": -70.6693},
    {"city": "Bogota", "country": "CO", "lat": 4.7110, "lng": -74.0721},
]


# Realistic user-agent pool mapped to browser/OS combinations
USER_AGENT_POOL = [
    {"browser": "Chrome 126", "os": "Windows 11", "short": "Chrome/Win11"},
    {"browser": "Firefox 127", "os": "Ubuntu 24.04", "short": "Firefox/Linux"},
    {"browser": "Safari 18", "os": "macOS 15", "short": "Safari/macOS"},
    {"browser": "Edge 126", "os": "Windows 10", "short": "Edge/Win10"},
    {"browser": "Chrome 125", "os": "Android 15", "short": "Chrome/Android"},
    {"browser": "curl 8.7", "os": "Linux", "short": "curl/Linux"},
    {"browser": "Python httpx 0.27", "os": "Linux", "short": "httpx/Python"},
    {"browser": "Postman 11", "os": "Windows 11", "short": "Postman/Win11"},
    {"browser": "Chrome 124", "os": "ChromeOS", "short": "Chrome/ChromeOS"},
    {"browser": "Opera 111", "os": "Windows 10", "short": "Opera/Win10"},
    {"browser": "Brave 1.67", "os": "macOS 14", "short": "Brave/macOS"},
    {"browser": "wget 1.24", "os": "Debian", "short": "wget/Debian"},
]


def resolve_geo(seed_val: str, extra_entropy: str = None) -> dict:
    """
    Deterministically map a seed to realistic geo coordinates.
    
    Uses both seed_val AND extra_entropy (e.g. request_id, event_id)
    to spread events across all global hubs instead of clustering
    localhost events into a single location.
    
    Returns lat/lng with realistic city-level jitter so markers
    don't stack perfectly on top of each other.
    """
    if not seed_val:
        return {**GLOBAL_HUBS[0], "browser": USER_AGENT_POOL[0]}

    # Combine seed with extra entropy for better distribution
    combined = str(seed_val)
    if extra_entropy:
        combined = f"{seed_val}:{extra_entropy}"

    digest = hashlib.sha256(combined.encode()).hexdigest()
    idx = int(digest[:8], 16) % len(GLOBAL_HUBS)
    hub = GLOBAL_HUBS[idx]

    # Apply deterministic city-level jitter (±0.5 degrees, ~50km)
    # so markers within the same city don't perfectly overlap
    jitter_lat = ((int(digest[8:12], 16) % 1000) - 500) / 1000 * 0.5
    jitter_lng = ((int(digest[12:16], 16) % 1000) - 500) / 1000 * 0.5

    # Pick a browser from the pool
    browser_idx = int(digest[16:20], 16) % len(USER_AGENT_POOL)
    browser_info = USER_AGENT_POOL[browser_idx]

    # Generate a realistic-looking IP from the hash
    ip_parts = [
        int(digest[20:22], 16),
        int(digest[22:24], 16),
        int(digest[24:26], 16),
        int(digest[26:28], 16),
    ]
    # Avoid private ranges for realism
    if ip_parts[0] in (10, 127, 0):
        ip_parts[0] = 45 + (ip_parts[0] % 200)
    if ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31:
        ip_parts[1] = 32 + (ip_parts[1] % 200)
    if ip_parts[0] == 192 and ip_parts[1] == 168:
        ip_parts[1] = 100 + (ip_parts[1] % 100)

    generated_ip = ".".join(str(p) for p in ip_parts)

    return {
        "city": hub["city"],
        "country": hub["country"],
        "lat": round(hub["lat"] + jitter_lat, 4),
        "lng": round(hub["lng"] + jitter_lng, 4),
        "browser": browser_info,
        "generated_ip": generated_ip,
    }
