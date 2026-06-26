"""
backend/app/main.py — Threat Map API
WebSocket push real-time scan progress ke frontend.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator

from .config import Settings
from .intel import scan_ip, scan_defender
from .models import ScanRequest, ScanResult

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("threat-map")
settings = Settings()

# In-memory scan cache (last 20 scans)
_scan_cache: dict[str, ScanResult] = {}


def _validate_ip(ip: str) -> str:
    ip = ip.strip()
    try:
        parsed = ipaddress.ip_address(ip)
        if parsed.is_private:
            raise HTTPException(400, "Private IP addresses cannot be scanned")
        if parsed.is_loopback:
            raise HTTPException(400, "Loopback addresses cannot be scanned")
        return str(parsed)
    except ValueError:
        raise HTTPException(400, f"Invalid IP address: {ip}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Threat Map API starting")
    yield
    logger.info("Threat Map API shutdown")


app = FastAPI(
    title="Threat Map API",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

Instrumentator().instrument(app).expose(app)


@app.get("/health")
async def health():
    return {
        "service": "threat-map-api",
        "status": "ok",
        "sources": {
            "abuseipdb": "configured" if settings.abuseipdb_key else "NOT SET",
            "greynoise": "configured" if settings.greynoise_key else "NOT SET",
            "censys": "configured" if settings.censys_api_token else "NOT SET",
            "ip_api": "always available (no key required)",
        }
    }


@app.post("/api/scan")
async def scan(req: ScanRequest):
    """
    Satu-kali scan, return hasil lengkap.
    Untuk real-time progress, pakai WebSocket /ws/scan.
    """
    ip = _validate_ip(req.ip)

    # Cache check (5 menit)
    if ip in _scan_cache:
        cached = _scan_cache[ip]
        ts = datetime.fromisoformat(cached.scan_timestamp)
        age = (datetime.now(timezone.utc) - ts).seconds
        if age < 300:
            logger.info("Cache hit for %s (age=%ds)", ip, age)
            return cached

    result = await scan_ip(ip, req.include_censys, req.include_greynoise)
    _scan_cache[ip] = result

    # Keep cache small
    if len(_scan_cache) > 20:
        oldest = next(iter(_scan_cache))
        del _scan_cache[oldest]

    return result


@app.websocket("/ws/scan")
async def ws_scan(websocket: WebSocket):
    """
    WebSocket endpoint — push progress real-time ke frontend.
    Flow:
      client → {"ip": "1.2.3.4", "include_censys": true, "include_greynoise": true}
      server → {"type": "progress", "step": "abuseipdb", "message": "..."}
      server → {"type": "progress", "step": "greynoise", "message": "..."}
      server → {"type": "progress", "step": "censys", "message": "..."}
      server → {"type": "progress", "step": "coords", "message": "..."}
      server → {"type": "result", "data": {...ScanResult...}}
      server → {"type": "done"}
    """
    await websocket.accept()
    logger.info("WebSocket connected: %s", websocket.client)

    try:
        while True:
            raw = await websocket.receive_text()
            try:
                payload = json.loads(raw)
            except json.JSONDecodeError:
                await websocket.send_json({"type": "error", "message": "Invalid JSON"})
                continue

            ip_raw = payload.get("ip", "").strip()
            include_censys = payload.get("include_censys", True)
            include_greynoise = payload.get("include_greynoise", True)

            # Validate
            try:
                ip = _validate_ip(ip_raw)
            except HTTPException as e:
                await websocket.send_json({"type": "error", "message": e.detail})
                continue

            # Progress steps
            await websocket.send_json({
                "type": "progress",
                "step": "abuseipdb",
                "message": f"Querying AbuseIPDB for attack reports on {ip}...",
            })
            await asyncio.sleep(0.1)

            if include_greynoise:
                await websocket.send_json({
                    "type": "progress",
                    "step": "greynoise",
                    "message": f"Checking GreyNoise — is {ip} targeted or just background noise?",
                })
                await asyncio.sleep(0.1)

            if include_censys:
                await websocket.send_json({
                    "type": "progress",
                    "step": "censys",
                    "message": f"Scanning exposed services on {ip} via Censys...",
                })
                await asyncio.sleep(0.1)

            await websocket.send_json({
                "type": "progress",
                "step": "coords",
                "message": "Geolocating attackers...",
            })

            # Run scan
            try:
                result = await scan_ip(ip, include_censys, include_greynoise)
                _scan_cache[ip] = result

                await websocket.send_json({
                    "type": "result",
                    "data": result.model_dump(),
                })
                await websocket.send_json({"type": "done"})
                logger.info(
                    "Scan done: %s | attackers=%d targeted=%d risk=%d",
                    ip, result.total_attackers, result.targeted_count, result.risk_score,
                )

            except Exception as e:
                logger.error("Scan error for %s: %s", ip, e)
                await websocket.send_json({
                    "type": "error",
                    "message": f"Scan failed: {str(e)[:200]}",
                })

    except WebSocketDisconnect:
        logger.info("WebSocket disconnected: %s", websocket.client)


@app.post("/api/scan-defender")
async def scan_defender_endpoint(req: ScanRequest):
    """
    Defender mode: scan your own server IP.
    Returns current AbuseIPDB blacklist (top malicious IPs globally) as incoming threats.
    """
    ip = _validate_ip(req.ip)

    cache_key = f"def:{ip}"
    if cache_key in _scan_cache:
        cached = _scan_cache[cache_key]
        ts  = datetime.fromisoformat(cached.scan_timestamp)
        age = (datetime.now(timezone.utc) - ts).seconds
        if age < 14400:  # 4 jam — Feodo Tracker bebas diakses tapi hemat request
            logger.info("Defender cache hit for %s (age=%ds)", ip, age)
            return cached

    result = await scan_defender(ip)
    _scan_cache[cache_key] = result

    if len(_scan_cache) > 20:
        oldest = next(iter(_scan_cache))
        del _scan_cache[oldest]

    logger.info("Defender scan done: %s | threats=%d risk=%d", ip, result.total_attackers, result.risk_score)
    return result


@app.get("/api/history")
async def history():
    """List IP yang pernah di-scan (dari cache)"""
    return [
        {
            "ip": ip,
            "risk_score": r.risk_score,
            "total_attackers": r.total_attackers,
            "scan_timestamp": r.scan_timestamp,
        }
        for ip, r in _scan_cache.items()
    ]


if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=settings.port, reload=True)
