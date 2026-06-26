"""
backend/app/intel.py
Gather threat intelligence dari 4 sumber:
  1. AbuseIPDB   — siapa yang report attack ke/dari IP ini
  2. ip-api.com  — koordinat geografis (gratis, no key)
  3. GreyNoise   — apakah attacker adalah targeted threat atau background noise
  4. Censys      — open ports + services yang terexpose di target IP
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import List, Optional, Tuple

import httpx

from .config import Settings
from .models import (
    Attacker, CensysInfo, Coordinates,
    GreyNoiseInfo, ScanResult,
)

logger = logging.getLogger("threat-map.intel")
settings = Settings()

# Approximate country centroids [lat, lon] for map visualization
COUNTRY_CENTROIDS: dict[str, tuple[float, float]] = {
    "AF": (33.93, 67.71), "AL": (41.15, 20.17), "DZ": (28.03, 1.66),
    "AO": (-11.20, 17.87), "AR": (-38.42, -63.62), "AU": (-25.27, 133.78),
    "AT": (47.52, 14.55), "AZ": (40.14, 47.58), "BD": (23.68, 90.36),
    "BE": (50.50, 4.47), "BR": (-14.24, -51.93), "BG": (42.73, 25.49),
    "BY": (53.71, 27.95), "CA": (56.13, -106.35), "CN": (35.86, 104.20),
    "CO": (4.57, -74.30), "HR": (45.10, 15.20), "CZ": (49.82, 15.47),
    "DK": (56.26, 9.50), "EG": (26.82, 30.80), "ET": (9.15, 40.49),
    "FI": (61.92, 25.75), "FR": (46.23, 2.21), "DE": (51.17, 10.45),
    "GH": (7.95, -1.02), "GR": (39.07, 21.82), "GT": (15.78, -90.23),
    "HK": (22.32, 114.17), "HU": (47.16, 19.50), "IN": (20.59, 78.96),
    "ID": (-0.79, 113.92), "IR": (32.43, 53.69), "IQ": (33.22, 43.68),
    "IL": (31.05, 34.85), "IT": (41.87, 12.57), "JP": (36.20, 138.25),
    "KZ": (48.02, 66.92), "KE": (-0.02, 37.91), "KR": (35.91, 127.77),
    "KW": (29.31, 47.48), "LT": (55.17, 23.88), "LV": (56.88, 24.60),
    "LY": (26.34, 17.23), "MY": (4.21, 108.00), "MX": (23.63, -102.55),
    "MA": (31.79, -7.09), "MM": (21.91, 95.96), "NL": (52.13, 5.29),
    "NG": (9.08, 8.68), "NO": (60.47, 8.47), "PK": (30.38, 69.35),
    "PE": (-9.19, -75.02), "PH": (12.88, 121.77), "PL": (51.92, 19.15),
    "PT": (39.40, -8.22), "RO": (45.94, 24.97), "RU": (61.52, 105.32),
    "SA": (23.89, 45.08), "SG": (1.35, 103.82), "ZA": (-30.56, 22.94),
    "ES": (40.46, -3.75), "LK": (7.87, 80.77), "SE": (60.13, 18.64),
    "CH": (46.82, 8.23), "TW": (23.70, 120.96), "TH": (15.87, 100.99),
    "TN": (33.89, 9.54), "TR": (38.96, 35.24), "UA": (48.38, 31.17),
    "GB": (55.38, -3.44), "US": (37.09, -95.71), "UZ": (41.38, 64.59),
    "VN": (14.06, 108.28), "YE": (15.55, 48.52), "ZW": (-19.02, 29.15),
}


# AbuseIPDB category ID → human readable
ABUSE_CATEGORIES = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders",
    4: "DDoS Attack", 5: "FTP Brute-Force", 6: "Ping of Death",
    7: "Phishing", 8: "Fraud VoIP", 9: "Open Proxy",
    10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking",
    16: "SQL Injection", 17: "Spoofing", 18: "Brute Force",
    19: "Bad Web Bot", 20: "Exploited Host", 21: "Web App Attack",
    22: "SSH", 23: "IoT Targeted",
}

# Ports that warrant extra risk points
SENSITIVE_PORTS = {22, 23, 3389, 5900, 445, 139, 3306, 5432, 27017, 6379, 9200, 2375}


# ──────────────────────────────────────────────
# ip-api.com — koordinat (gratis, no key)
# ──────────────────────────────────────────────

async def get_ip_coords(ip: str, client: httpx.AsyncClient) -> Optional[Coordinates]:
    try:
        r = await client.get(
            f"http://ip-api.com/json/{ip}",
            params={"fields": "status,lat,lon,city,country,countryCode,isp"},
            timeout=5.0,
        )
        d = r.json()
        if d.get("status") == "success":
            return Coordinates(
                lat=d["lat"], lon=d["lon"],
                city=d.get("city", ""),
                country=d.get("country", ""),
                country_code=d.get("countryCode", ""),
                isp=d.get("isp", ""),
            )
    except Exception as e:
        logger.debug("ip-api error for %s: %s", ip, e)
    return None


# ──────────────────────────────────────────────
# AbuseIPDB category map (ID → nama)
# ──────────────────────────────────────────────

_ABUSE_CAT: dict[int, str] = {
    1: "DNS Compromise", 2: "DNS Poisoning", 3: "Fraud Orders", 4: "DDoS Attack",
    5: "FTP Brute Force", 6: "Ping of Death", 7: "Phishing", 8: "Fraud VoIP",
    9: "Open Proxy", 10: "Web Spam", 11: "Email Spam", 12: "Blog Spam",
    13: "VPN IP", 14: "Port Scan", 15: "Hacking", 16: "SQL Injection",
    17: "Spoofing", 18: "Brute Force", 19: "Bad Web Bot", 20: "Exploited Host",
    21: "Web App Attack", 22: "SSH Attack", 23: "IoT Targeted",
}


async def _check_ip(ip: str, client: httpx.AsyncClient) -> Optional[dict]:
    """AbuseIPDB /check untuk 1 IP — returns raw API data dict."""
    if not settings.abuseipdb_key:
        return None
    try:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": settings.abuseipdb_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 30, "verbose": ""},
            timeout=8.0,
        )
        if r.status_code == 200:
            return r.json().get("data")
        logger.debug("/check %s → %d", ip, r.status_code)
    except Exception as e:
        logger.debug("/check %s error: %s", ip, e)
    return None


async def batch_check(ips: List[str], client: httpx.AsyncClient, limit: int = 5) -> dict:
    """
    AbuseIPDB /check untuk beberapa IP secara concurrent (max `limit` parallel).
    Returns {ip: check_data_dict}.
    """
    sem = asyncio.Semaphore(limit)

    async def guarded(ip: str):
        async with sem:
            return ip, await _check_ip(ip, client)

    results = await asyncio.gather(*[guarded(ip) for ip in ips])
    return {ip: data for ip, data in results if data}


# ──────────────────────────────────────────────
# ip-api.com — batch geolocate (max 100 IPs)
# ──────────────────────────────────────────────

async def batch_geolocate(ips: List[str], client: httpx.AsyncClient) -> dict:
    """Batch geolocate up to 100 IPs in one request via ip-api.com."""
    if not ips:
        return {}
    try:
        payload = [
            {"query": ip, "fields": "status,lat,lon,city,country,countryCode,isp,query"}
            for ip in ips[:100]
        ]
        r = await client.post(
            "http://ip-api.com/batch",
            json=payload,
            timeout=12.0,
        )
        result: dict = {}
        for item in r.json():
            if item.get("status") == "success":
                result[item["query"]] = Coordinates(
                    lat=item["lat"], lon=item["lon"],
                    city=item.get("city", ""),
                    country=item.get("country", ""),
                    country_code=item.get("countryCode", ""),
                    isp=item.get("isp", ""),
                )
        return result
    except Exception as e:
        logger.error("Batch geolocate error: %s", e)
        return {}


# ──────────────────────────────────────────────
# AbuseIPDB — daftar attacker
# ──────────────────────────────────────────────

async def get_abuseipdb_reports(target_ip: str, client: httpx.AsyncClient) -> List[Attacker]:
    """
    AbuseIPDB /v2/check — reporter IPs are masked for privacy.
    Groups reports by reporterCountryCode (victim countries) and returns one
    Attacker entry per country, with centroid coordinates for the map.
    The scanned IP IS the attacker; these entries are its victims' locations.
    """
    if not settings.abuseipdb_key:
        logger.warning("ABUSEIPDB_KEY tidak di-set")
        return []

    try:
        r = await client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": settings.abuseipdb_key, "Accept": "application/json"},
            params={"ipAddress": target_ip, "maxAgeInDays": 30, "verbose": True},
            timeout=10.0,
        )
        if r.status_code != 200:
            logger.error("AbuseIPDB check error: %d", r.status_code)
            return []

        data = r.json().get("data", {})
        reports = data.get("reports", [])
        abuse_score = data.get("abuseConfidenceScore", 0)

        # Group by reporter country (victim locations)
        country_map: dict[str, dict] = {}
        for rep in reports[:100]:
            cc = rep.get("reporterCountryCode", "")
            cn = rep.get("reporterCountryName", cc)
            if not cc:
                continue
            if cc not in country_map:
                country_map[cc] = {"count": 0, "cats": set(), "name": cn}
            country_map[cc]["count"] += 1
            for c in rep.get("categories", []):
                country_map[cc]["cats"].add(ABUSE_CATEGORIES.get(c, f"Cat-{c}"))

        attackers: List[Attacker] = []
        for cc, info in country_map.items():
            centroid = COUNTRY_CENTROIDS.get(cc)
            coords = Coordinates(
                lat=centroid[0], lon=centroid[1],
                city="", country=info["name"], country_code=cc,
            ) if centroid else None
            attackers.append(Attacker(
                ip=f"Victim-{cc}",
                abuse_score=abuse_score,
                total_reports=info["count"],
                country=info["name"],
                country_code=cc,
                attack_types=sorted(info["cats"]),
                coords=coords,
            ))

        # Sort by report count descending
        attackers.sort(key=lambda a: a.total_reports, reverse=True)
        return attackers

    except Exception as e:
        logger.error("AbuseIPDB error: %s", e)
        return []


# ──────────────────────────────────────────────
# GreyNoise — noise vs targeted threat
# ──────────────────────────────────────────────

async def get_greynoise(ip: str, client: httpx.AsyncClient) -> Optional[GreyNoiseInfo]:
    """
    GreyNoise Community API — gratis, butuh key dari greynoise.io.
    Return None bila key tidak di-set atau IP tidak ada di database GreyNoise.

    Response key fields:
      noise: true  = IP adalah background internet scanner (mass scan)
      noise: false = IP tidak terdeteksi sebagai mass scanner
      riot: true   = IP adalah known benign service (Google, AWS, Cloudflare)
      classification: malicious / benign / unknown
    """
    if not settings.greynoise_key:
        logger.debug("GREYNOISE_KEY tidak di-set — skip")
        return None

    try:
        r = await client.get(
            f"https://api.greynoise.io/v3/community/{ip}",
            headers={"key": settings.greynoise_key},
            timeout=8.0,
        )

        if r.status_code == 404:
            # IP tidak ada di GreyNoise database — belum pernah seen
            return GreyNoiseInfo(seen=False, classification="unknown")

        if r.status_code == 429:
            logger.warning("GreyNoise rate limit hit")
            return None

        if r.status_code != 200:
            logger.error("GreyNoise error: %d", r.status_code)
            return None

        d = r.json()
        return GreyNoiseInfo(
            seen=d.get("noise", False) or d.get("riot", False),
            classification=d.get("classification", "unknown"),
            noise=d.get("noise", False),
            riot=d.get("riot", False),
            name=d.get("name", ""),
            tags=d.get("tags", []),
            cve=d.get("cve", []),
            first_seen=d.get("first_seen", ""),
            last_seen=d.get("last_seen", ""),
            asn=d.get("asn", ""),
            country=d.get("country", ""),
        )
    except Exception as e:
        logger.error("GreyNoise error for %s: %s", ip, e)
        return None


async def enrich_attackers_greynoise(
    attackers: List[Attacker],
    client: httpx.AsyncClient,
) -> List[Attacker]:
    """
    Batch enrich top 20 attacker dengan GreyNoise data.
    Rate limit community API: ~1 req/detik, jadi kita batch dengan delay kecil.
    """
    if not settings.greynoise_key:
        return attackers

    # Enrich top 20 saja supaya tidak kena rate limit
    top = attackers[:20]
    tasks = [get_greynoise(a.ip, client) for a in top]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for i, attacker in enumerate(top):
        if i < len(results) and isinstance(results[i], GreyNoiseInfo):
            attacker.greynoise = results[i]

    return attackers


# ──────────────────────────────────────────────
# Censys — open ports & services
# ──────────────────────────────────────────────

async def get_censys_info(target_ip: str, client: httpx.AsyncClient) -> Optional[CensysInfo]:
    """
    Censys Platform API v3 — daftar gratis di search.censys.io
    Auth: Personal Access Token (Bearer), bukan lagi Basic Auth.
    Endpoint: GET /v3/global/asset/host/{ip}

    Cara dapat token:
      1. Daftar di search.censys.io
      2. Login → klik avatar → Personal Access Tokens
      3. Generate token → copy ke CENSYS_API_TOKEN di .env
    """
    if not settings.censys_api_token:
        logger.debug("CENSYS_API_TOKEN tidak di-set — skip")
        return None

    try:
        r = await client.get(
            f"https://api.platform.censys.io/v3/global/asset/host/{target_ip}",
            headers={
                "Authorization": f"Bearer {settings.censys_api_token}",
                "Accept": "application/json",
            },
            timeout=10.0,
        )

        if r.status_code == 404:
            return CensysInfo()  # IP belum diindex Censys

        if r.status_code == 401:
            logger.error("Censys auth failed — cek CENSYS_API_TOKEN")
            return None

        if r.status_code == 429:
            logger.warning("Censys rate limit hit")
            return None

        if r.status_code != 200:
            logger.error("Censys error: %d %s", r.status_code, r.text[:200])
            return None

        # Censys v3 nests data under result.resource
        d = r.json().get("result", {}).get("resource", {})
        services = d.get("services", [])

        open_ports = sorted([s.get("port") for s in services if s.get("port")])
        service_names = list(set(
            s.get("protocol", s.get("service_name", ""))
            for s in services
            if s.get("protocol") or s.get("service_name")
        ))

        dns = d.get("dns", {})
        hostnames = dns.get("reverse_dns", {}).get("names", [])
        as_info = d.get("autonomous_system", {})

        return CensysInfo(
            open_ports=open_ports,
            services=service_names[:10],
            hostnames=hostnames[:5],
            os=d.get("operating_system", {}).get("product", ""),
            org=as_info.get("name", ""),
            autonomous_system=f"AS{as_info.get('asn', '')} {as_info.get('name', '')}".strip(),
            last_updated=d.get("last_updated_at", ""),
        )

    except Exception as e:
        logger.error("Censys error for %s: %s", target_ip, e)
        return None


# ──────────────────────────────────────────────
# Risk calculator
# ──────────────────────────────────────────────

def _calculate_risk(
    attackers: List[Attacker],
    censys: Optional[CensysInfo],
    greynoise_target: Optional[GreyNoiseInfo],
) -> Tuple[int, int, int]:
    """
    Return (risk_score, targeted_count, scanner_count)

    Risk score 0-100:
    - Jumlah attacker (max 25 poin)
    - Rata-rata abuse score (max 20 poin)
    - Targeted attackers dari GreyNoise (max 25 poin) — lebih berat dari scanner
    - CVE yang aktif di-exploit (max 15 poin)
    - Censys open sensitive ports (max 15 poin)
    """
    score = 0
    targeted_count = 0
    scanner_count = 0

    # Attacker volume
    score += min(len(attackers) * 1, 25)

    # Avg abuse score
    if attackers:
        avg = sum(a.abuse_score for a in attackers) / len(attackers)
        score += int(avg * 0.2)

    # GreyNoise per attacker — bedain targeted vs noise
    for a in attackers:
        gn = a.greynoise
        if not gn:
            continue
        if gn.threat_level == "targeted":
            targeted_count += 1
            score += 3      # Targeted attack lebih berat
        elif gn.threat_level == "scanner":
            scanner_count += 1
            score += 1
        elif gn.riot:
            score -= 2      # Kurangi score kalau ternyata IP benign (false positive)

    score += min(targeted_count * 3, 25)

    # CVE yang aktif di-exploit (dari GreyNoise attacker tags)
    active_cves = set()
    for a in attackers:
        if a.greynoise:
            active_cves.update(a.greynoise.cve)
    score += min(len(active_cves) * 3, 15)

    # Censys exposed sensitive ports
    if censys:
        exposed_sensitive = SENSITIVE_PORTS & set(censys.open_ports)
        score += min(len(exposed_sensitive) * 3, 15)

    # GreyNoise pada target IP sendiri
    if greynoise_target:
        if greynoise_target.classification == "malicious":
            score += 10     # Target IP sendiri flagged malicious (unusual tapi perlu dicatat)

    return max(0, min(score, 100)), targeted_count, scanner_count


# ──────────────────────────────────────────────
# Main scan orchestrator
# ──────────────────────────────────────────────

async def scan_ip(
    target_ip: str,
    include_censys: bool = True,
    include_greynoise: bool = True,
) -> ScanResult:
    """
    Full parallel scan:
      1. AbuseIPDB reports (attacker list)
      2. ip-api koordinat target
      3. Censys open ports/services
      4. GreyNoise untuk target IP itu sendiri
      → lalu parallel enrich tiap attacker dengan koordinat + GreyNoise
    """
    async with httpx.AsyncClient() as client:
        tasks = [
            get_abuseipdb_reports(target_ip, client),
            get_ip_coords(target_ip, client),
        ]
        if include_censys:
            tasks.append(get_censys_info(target_ip, client))
        if include_greynoise:
            tasks.append(get_greynoise(target_ip, client))

        results = await asyncio.gather(*tasks, return_exceptions=True)

    # Unpack results
    idx = 0
    attackers: List[Attacker] = results[idx] if not isinstance(results[idx], Exception) else []
    idx += 1
    target_coords: Optional[Coordinates] = results[idx] if not isinstance(results[idx], Exception) else None
    idx += 1
    censys: Optional[CensysInfo] = None
    if include_censys:
        censys = results[idx] if not isinstance(results[idx], Exception) else None
        idx += 1
    greynoise_target: Optional[GreyNoiseInfo] = None
    if include_greynoise:
        greynoise_target = results[idx] if not isinstance(results[idx], Exception) else None

    # Attacker coords sudah diisi dari country centroids — skip ip-api lookup
    # Skip GreyNoise per-attacker karena IP adalah synthetic "Victim-CC"

    # Hitung risk score
    risk, targeted_count, scanner_count = _calculate_risk(attackers, censys, greynoise_target)

    # Build summary
    active_cves: set = set()
    for a in attackers:
        if a.greynoise:
            active_cves.update(a.greynoise.cve)

    parts = [f"IP {target_ip}: {len(attackers)} reported attackers, risk {risk}/100."]
    if targeted_count:
        parts.append(f"{targeted_count} targeted (non-noise) attackers detected.")
    if scanner_count:
        parts.append(f"{scanner_count} known internet scanners.")
    if active_cves:
        parts.append(f"Active exploits: {', '.join(list(active_cves)[:3])}.")
    if censys and censys.open_ports:
        exposed = SENSITIVE_PORTS & set(censys.open_ports)
        if exposed:
            parts.append(f"Sensitive ports exposed: {', '.join(str(p) for p in sorted(exposed))}.")

    return ScanResult(
        target_ip=target_ip,
        target_coords=target_coords,
        risk_score=risk,
        total_attackers=len(attackers),
        targeted_count=targeted_count,
        scanner_count=scanner_count,
        attackers=attackers,
        censys=censys,
        greynoise_target=greynoise_target,
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        summary=" ".join(parts),
    )


# ──────────────────────────────────────────────
# Defender mode — siapa yang menyerang server kita
# ──────────────────────────────────────────────

async def _get_ipsum_threats(client: httpx.AsyncClient, limit: int = 60) -> List[dict]:
    """
    Fetch IP malicious terverifikasi dari ipsum (stamparm/GitHub).
    Gratis, no API key. Aggregasi dari 10+ threat intel sources.
    Format: "IP\\tSCORE" — score = jumlah source yang mem-blacklist IP ini (max ~10).
    """
    try:
        r = await client.get(
            "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt",
            timeout=15.0,
            headers={"User-Agent": "ThreatMap/1.0"},
        )
        if r.status_code != 200:
            logger.error("ipsum fetch error: %d", r.status_code)
            return []

        entries: List[tuple] = []
        for line in r.text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) >= 2:
                try:
                    entries.append((parts[0], int(parts[1])))
                except ValueError:
                    pass

        # Sort by score DESC → ambil top `limit` paling berbahaya
        entries.sort(key=lambda x: x[1], reverse=True)
        top = entries[:limit]

        logger.info("ipsum: %d total IPs, using top %d (score≥%d)", len(entries), len(top), top[-1][1] if top else 0)
        return [{"ip": ip, "score": score} for ip, score in top]
    except Exception as e:
        logger.error("ipsum error: %s", e)
        return []


async def scan_defender(target_ip: str) -> ScanResult:
    """
    Defender mode scan:
      1. Geolocate target IP (server kita)
      2. Fetch AbuseIPDB blacklist — top 60 IP paling berbahaya saat ini
      3. Batch geolocate semua attacker
      4. Return ScanResult — attacker list sebagai incoming threats ke target
    """
    async with httpx.AsyncClient() as client:
        ipsum_raw, target_coords = await asyncio.gather(
            _get_ipsum_threats(client, limit=60),
            get_ip_coords(target_ip, client),
            return_exceptions=True,
        )

    if isinstance(ipsum_raw, Exception):
        ipsum_raw = []
    if isinstance(target_coords, Exception):
        target_coords = None

    if not ipsum_raw:
        return ScanResult(
            target_ip=target_ip,
            target_coords=target_coords,
            risk_score=0,
            total_attackers=0,
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            summary="No threat data available. ipsum feed unreachable.",
        )

    # ipsum format: {ip, score} — score 1-10 (jumlah blacklist sources)
    # Map score ke abuse_score 0-100
    detail_map: dict = {
        e["ip"]: {
            "score":         min(e["score"] * 10, 100),
            "total_reports": 0,
            "last_reported": "",
            "usage_type":    "Known Threat",
            "isp":           "",
            "country_code":  "",
        }
        for e in ipsum_raw
    }

    ips = list(detail_map.keys())

    # AbuseIPDB /check untuk top 10 (dapatkan totalReports + abuse score)
    top10 = ips[:10]
    async with httpx.AsyncClient() as client:
        geo_map, check_map = await asyncio.gather(
            batch_geolocate(ips, client),
            batch_check(top10, client, limit=5),
        )

    # Merge /check data ke detail_map
    for ip, chk in check_map.items():
        dm = detail_map.get(ip, {})
        if chk.get("abuseConfidenceScore"):
            dm["score"] = chk["abuseConfidenceScore"]
        if chk.get("totalReports"):
            dm["total_reports"] = chk["totalReports"]
        if chk.get("lastReportedAt"):
            dm["last_reported"] = chk["lastReportedAt"]
        if not dm["isp"] and chk.get("isp"):
            dm["isp"] = chk["isp"]
        # Merge AbuseIPDB report categories
        cats: list[str] = []
        for rep in (chk.get("reports") or []):
            for cid in rep.get("categories", []):
                name = _ABUSE_CAT.get(cid)
                if name and name not in cats:
                    cats.append(name)
        if cats:
            dm["categories"] = cats

    attackers: List[Attacker] = []
    for ip in ips:
        d      = detail_map[ip]
        coords = geo_map.get(ip)
        if not coords:
            continue

        attack_types = d.get("categories") or [d.get("usage_type", "Known Threat")]

        attackers.append(Attacker(
            ip=ip,
            abuse_score=d["score"],
            total_reports=d["total_reports"],
            last_reported=d["last_reported"],
            usage_type=d["usage_type"],
            country=coords.country,
            country_code=coords.country_code or d.get("country_code", ""),
            isp=d["isp"] or coords.isp,
            coords=coords,
            attack_types=attack_types,
        ))

    targeted = len(attackers)   # semua Feodo = confirmed C2 server, semuanya critical
    scanners  = 0
    risk      = min(75 + len(attackers) // 4, 99)

    # Increase cache TTL for defender scan to 4 hours (Feodo updates every 5 min tapi limit API kita)

    return ScanResult(
        target_ip=target_ip,
        target_coords=target_coords,
        risk_score=risk,
        total_attackers=len(attackers),
        targeted_count=targeted,
        scanner_count=scanners,
        attackers=attackers,
        scan_timestamp=datetime.now(timezone.utc).isoformat(),
        summary=(
            f"Defender scan for {target_ip}: {len(attackers)} known malicious IPs detected "
            f"(ipsum — aggregated from 10+ threat intel feeds). Risk {risk}/100."
        ),
    )
