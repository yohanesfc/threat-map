"""backend/app/models.py"""
from __future__ import annotations
from typing import List, Optional
from pydantic import BaseModel


class Coordinates(BaseModel):
    lat: float
    lon: float
    city: str = ""
    country: str = ""
    country_code: str = ""
    isp: str = ""


class GreyNoiseInfo(BaseModel):
    """
    Data dari GreyNoise Community API.
    Memberitahu apakah IP adalah background internet noise atau targeted threat.
    """
    seen: bool = False
    classification: str = "unknown"     # benign / malicious / unknown
    noise: bool = False                 # True = mass internet scanner (bukan targeted)
    riot: bool = False                  # True = known benign (Google, Cloudflare, dll)
    name: str = ""                      # nama botnet/scanner jika dikenal
    tags: List[str] = []               # ["Mirai", "Port Scanner", "SSH Brute Force"]
    cve: List[str] = []                # CVE yang sedang di-exploit oleh IP ini
    first_seen: str = ""
    last_seen: str = ""
    asn: str = ""
    country: str = ""

    @property
    def threat_level(self) -> str:
        """Derived threat level untuk display"""
        if self.riot:
            return "benign"
        if not self.seen:
            return "unknown"
        if self.classification == "malicious" and not self.noise:
            return "targeted"           # Paling berbahaya — targeted attack
        if self.classification == "malicious" and self.noise:
            return "scanner"            # Botnet/mass scanner
        return "noise"                  # Background noise, tidak perlu panik


class CensysInfo(BaseModel):
    """
    Data dari Censys Search API.
    Open ports + services + TLS certs yang terexpose.
    """
    open_ports: List[int] = []
    services: List[str] = []           # ["HTTP", "HTTPS", "SSH", "RDP"]
    hostnames: List[str] = []
    os: str = ""
    org: str = ""
    autonomous_system: str = ""
    last_updated: str = ""


class Attacker(BaseModel):
    ip: str
    abuse_score: int = 0               # 0-100 dari AbuseIPDB
    total_reports: int = 0
    last_reported: str = ""
    usage_type: str = ""
    isp: str = ""
    country: str = ""
    country_code: str = ""
    coords: Optional[Coordinates] = None
    attack_types: List[str] = []       # dari AbuseIPDB categories
    greynoise: Optional[GreyNoiseInfo] = None  # enrichment GreyNoise per attacker


class ScanResult(BaseModel):
    target_ip: str
    target_coords: Optional[Coordinates] = None
    risk_score: int = 0                # 0-100
    total_attackers: int = 0
    targeted_count: int = 0            # attacker yang bukan noise (lebih berbahaya)
    scanner_count: int = 0             # known mass scanner
    attackers: List[Attacker] = []
    censys: Optional[CensysInfo] = None
    greynoise_target: Optional[GreyNoiseInfo] = None  # GreyNoise data untuk target IP itu sendiri
    scan_timestamp: str = ""
    summary: str = ""


class ScanRequest(BaseModel):
    ip: str
    include_censys: bool = True
    include_greynoise: bool = True
