# Threat Map

Real-time IP threat intelligence visualizer — scan IP mencurigakan dan lihat negara-negara korban di peta dunia interaktif.

**Live:** https://threat.yohanesfc.web.id

---

## Stack

| Layer | Tech |
|---|---|
| Frontend | Next.js 14 (App Router), React, Tailwind CSS, D3.js |
| Backend | FastAPI (Python), WebSocket, Prometheus metrics |
| Container | Docker Compose, ARM64 |
| Proxy | Caddy + Cloudflare |

## Konsep

Masukkan IP mencurigakan (misal IP yang muncul di log fail2ban/SSH) untuk investigasi:

- **AbuseIPDB** menunjukkan berapa negara yang melaporkan IP ini sebagai penyerang
- **GreyNoise** mengklasifikasikan: `targeted` (serangan terarah), `scanner` (mass botnet), `noise` (background), `benign`
- **Censys** menampilkan port terbuka dan layanan yang berjalan di IP tersebut
- **Peta D3** menggambar arc animasi dari IP target → negara korban
- **Risk score** 0–100 berdasarkan jumlah korban, kualitas ancaman, dan port sensitif yang terbuka

## Fitur

- Scan via WebSocket — progress real-time step by step
- **Victim Countries** — grup laporan AbuseIPDB by negara reporter, dengan koordinat centroid di peta
- **GreyNoise classification** — targeted / scanner / noise / benign untuk target IP
- **Censys open ports & services** — via Platform API v3 (`result.resource.*`)
- **Risk score** 0–100 dengan breakdown: attacker volume, abuse score, targeted count, CVE aktif, sensitive ports
- **Scan cache** 5 menit — tidak re-query untuk IP yang sama
- **History** — 20 IP terakhir dari in-memory cache (`GET /api/history`)

## Port

| Service | Port | Keterangan |
|---|---|---|
| Backend API | `8090` | REST + WebSocket |
| Frontend | `3001` | Next.js (PORT=3001, HOSTNAME=0.0.0.0) |

## Struktur

```
threat-map/
├── backend/
│   ├── app/
│   │   ├── main.py      # FastAPI app, WebSocket /ws/scan, REST /api/scan
│   │   ├── intel.py     # AbuseIPDB (country grouping), GreyNoise, Censys, country centroids
│   │   ├── models.py    # Pydantic models (ScanResult, Attacker, CensysInfo)
│   │   └── config.py    # Settings via env vars
│   ├── requirements.txt
│   └── Dockerfile
├── frontend/
│   ├── src/
│   │   ├── app/
│   │   │   └── page.tsx        # Main UI — IP input, sidebar, stats, victim list
│   │   ├── components/
│   │   │   └── ThreatMap.tsx   # D3 world map — arc dari target IP → victim countries
│   │   └── lib/
│   │       └── useScan.ts      # WebSocket hook (status, progress, result)
│   └── Dockerfile              # ARG NEXT_PUBLIC_* di builder stage (bukan runtime)
├── docker-compose.yml          # build.args untuk NEXT_PUBLIC_* vars
├── .env                        # API keys (TIDAK di-commit)
└── caddy-addition.txt          # Config Caddy standalone subdomain
```

## Environment Variables

Salin `.env.example` ke `.env` lalu isi:

```env
ABUSEIPDB_KEY=       # abuseipdb.com → My Account → API
GREYNOISE_KEY=       # greynoise.io → Account → API Key (Community gratis)
CENSYS_API_TOKEN=    # search.censys.io → avatar → Personal Access Tokens
```

`ip-api.com` tidak butuh key (gratis, 45 req/menit).

## Deploy

```bash
# Pertama kali
cd /home/ubuntu/threat-map
docker compose up -d --build

# Update code (WAJIB --build, bukan hanya up -d)
# NEXT_PUBLIC_* baked saat build time — perlu rebuild jika URL berubah
docker compose build && docker compose up -d

# Lihat log
docker compose logs -f threat-map-api
docker compose logs -f threat-map-frontend

# Verify NEXT_PUBLIC_* terbake benar
docker exec threat-map-frontend grep -r "threat.yohanesfc.web.id" /app/.next/static | head -1
```

## API Endpoints

| Method | Path | Keterangan |
|---|---|---|
| `GET` | `/health` | Health check + status API keys |
| `POST` | `/api/scan` | One-shot scan, return `ScanResult` |
| `GET` | `/api/history` | 20 IP terakhir dari in-memory cache |
| `WS` | `/ws/scan` | Real-time scan dengan progress events |

### WebSocket Flow

```
client  →  {"ip": "1.2.3.4", "include_censys": true, "include_greynoise": true}
server  →  {"type": "progress", "step": "abuseipdb",  "message": "..."}
server  →  {"type": "progress", "step": "greynoise",  "message": "..."}
server  →  {"type": "progress", "step": "censys",     "message": "..."}
server  →  {"type": "progress", "step": "coords",     "message": "..."}
server  →  {"type": "result",   "data": { ...ScanResult... }}
server  →  {"type": "done"}
```

## Caddy Config

Subdomain `threat.yohanesfc.web.id` dikonfigurasi di `~/n8n/Caddyfile`:

```
/ws/*     → 172.17.0.1:8090  (WebSocket, dengan Upgrade/Connection headers)
/api/*    → 172.17.0.1:8090  (REST)
/health   → 172.17.0.1:8090
/metrics  → 172.17.0.1:8090
default   → 172.17.0.1:3001  (Next.js frontend)
```

> **UFW wajib:** `ufw allow 3001/tcp && ufw allow 8090/tcp` — tanpa ini Caddy tidak bisa reach 172.17.0.1.

## Catatan Teknis

### AbuseIPDB — reporter IP tidak tersedia
AbuseIPDB `/v2/check` tidak mengembalikan `reporterIp` (dimasking untuk privasi). Data yang tersedia adalah `reporterCountryCode`. `intel.py` mengelompokkan laporan per negara dan menggunakan koordinat centroid dari `COUNTRY_CENTROIDS` dict untuk visualisasi peta.

### Censys Platform API v3
Response nested di `result.resource.*` (bukan `result.*` langsung). Field nama service menggunakan `protocol`, bukan `service_name`.

### NEXT_PUBLIC_* di Docker
`NEXT_PUBLIC_*` di-bake saat `npm run build` (build time), bukan runtime. `Dockerfile` menggunakan `ARG` + `ENV` di builder stage, dan `docker-compose.yml` menggunakan `build.args` (bukan hanya `environment:`).

## Risk Score

| Score | Label | Kondisi |
|---|---|---|
| 70–100 | CRITICAL | Banyak victim / targeted attacker / sensitive ports exposed |
| 40–69 | HIGH | Scanner aktif / abuse score sedang |
| 20–39 | MEDIUM | Background noise |
| 0–19 | LOW | Tidak ada ancaman signifikan |
