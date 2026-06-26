'use client'
import { useCallback, useRef, useState } from 'react'

export type ScanStatus = 'idle' | 'connecting' | 'scanning' | 'done' | 'error'

export interface GreyNoiseInfo {
  seen: boolean
  classification: string        // benign / malicious / unknown
  noise: boolean                // true = mass scanner
  riot: boolean                 // true = known benign (Google, Cloudflare)
  name: string                  // botnet name jika dikenal
  tags: string[]
  cve: string[]
  first_seen: string
  last_seen: string
  asn: string
  country: string
  threat_level: string          // targeted / scanner / noise / benign / unknown
}

export interface Attacker {
  ip: string
  abuse_score: number
  total_reports: number
  last_reported: string
  usage_type: string
  country: string
  country_code: string
  isp: string
  attack_types: string[]
  coords?: { lat: number; lon: number; city: string; country: string }
  greynoise?: GreyNoiseInfo
}

export interface CensysInfo {
  open_ports: number[]
  services: string[]
  hostnames: string[]
  os: string
  org: string
  autonomous_system: string
  last_updated: string
}

export interface ScanResult {
  target_ip: string
  target_coords?: { lat: number; lon: number; city: string; country: string }
  risk_score: number
  total_attackers: number
  targeted_count: number        // attacker yang bukan noise
  scanner_count: number         // known mass scanner
  attackers: Attacker[]
  censys?: CensysInfo
  greynoise_target?: GreyNoiseInfo  // GreyNoise data untuk target IP itu sendiri
  scan_timestamp: string
  summary: string
}

export interface ProgressEvent {
  step: string
  message: string
}

export function useScan() {
  const ws = useRef<WebSocket | null>(null)
  const [status, setStatus] = useState<ScanStatus>('idle')
  const [progress, setProgress] = useState<ProgressEvent | null>(null)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [error, setError] = useState<string>('')

  const scan = useCallback((
    ip: string,
    includeCensys: boolean = true,
    includeGreynoise: boolean = true,
  ) => {
    if (ws.current) ws.current.close()

    setStatus('connecting')
    setResult(null)
    setError('')
    setProgress(null)

    const wsUrl = `${process.env.NEXT_PUBLIC_WS_URL}/ws/scan`
    const socket = new WebSocket(wsUrl)
    ws.current = socket

    socket.onopen = () => {
      setStatus('scanning')
      socket.send(JSON.stringify({
        ip,
        include_censys: includeCensys,
        include_greynoise: includeGreynoise,
      }))
    }

    socket.onmessage = (event) => {
      const msg = JSON.parse(event.data)
      if (msg.type === 'progress') {
        setProgress({ step: msg.step, message: msg.message })
      } else if (msg.type === 'result') {
        setResult(msg.data)
      } else if (msg.type === 'done') {
        setStatus('done')
      } else if (msg.type === 'error') {
        setError(msg.message)
        setStatus('error')
      }
    }

    socket.onerror = () => {
      setError('Cannot connect to threat-map API. Is the backend running?')
      setStatus('error')
    }

    socket.onclose = () => {
      if (status === 'scanning') setStatus('idle')
    }
  }, [])

  const reset = useCallback(() => {
    ws.current?.close()
    setStatus('idle')
    setResult(null)
    setError('')
    setProgress(null)
  }, [])

  return { scan, reset, status, progress, result, error }
}

// ── Defender mode — scan your own server IP ───────────────────────────────────

export function useDefenderScan() {
  const [status, setStatus]   = useState<ScanStatus>('idle')
  const [result, setResult]   = useState<ScanResult | null>(null)
  const [error, setError]     = useState<string>('')

  const scan = useCallback(async (ip: string) => {
    setStatus('scanning')
    setResult(null)
    setError('')

    try {
      const r = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL}/api/scan-defender`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ ip, include_censys: false, include_greynoise: false }),
        },
      )
      if (!r.ok) {
        const err = await r.json().catch(() => ({}))
        setError(err.detail ?? `Server error ${r.status}`)
        setStatus('error')
        return
      }
      const data: ScanResult = await r.json()
      setResult(data)
      setStatus('done')
    } catch {
      setError('Cannot connect to threat-map API.')
      setStatus('error')
    }
  }, [])

  const reset = useCallback(() => {
    setStatus('idle')
    setResult(null)
    setError('')
  }, [])

  return { scan, reset, status, result, error }
}
