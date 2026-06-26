'use client'
import { useState } from 'react'
import { Shield, Search, AlertTriangle, Wifi, Globe, Lock, RefreshCw, Terminal, Crosshair, Server } from 'lucide-react'
import dynamic from 'next/dynamic'
import { useScan, useDefenderScan, type Attacker } from '@/lib/useScan'

// Dynamic import ThreatMap (D3 needs browser)
const ThreatMap = dynamic(() => import('@/components/ThreatMap'), { ssr: false })

function RiskBadge({ score }: { score: number }) {
  const label = score >= 70 ? 'CRITICAL' : score >= 40 ? 'HIGH' : score >= 20 ? 'MEDIUM' : 'LOW'
  const color = score >= 70 ? 'text-radar-danger border-radar-danger' :
    score >= 40 ? 'text-radar-warn border-radar-warn' :
      score >= 20 ? 'text-yellow-400 border-yellow-400' : 'text-radar-safe border-radar-safe'
  return (
    <span className={`border px-2 py-0.5 text-xs font-mono font-bold rounded ${color}`}>
      {label}
    </span>
  )
}

// Shorten overly long official country names
const SHORT_NAME: Record<string, string> = {
  'United States of America': 'United States',
  'United Kingdom of Great Britain and Northern Ireland': 'United Kingdom',
  'Russian Federation': 'Russia',
  'Republic of Korea': 'South Korea',
  "Democratic People's Republic of Korea": 'North Korea',
  'Iran, Islamic Republic of': 'Iran',
  'Syrian Arab Republic': 'Syria',
  'Venezuela, Bolivarian Republic of': 'Venezuela',
  'Taiwan, Province of China': 'Taiwan',
  'Viet Nam': 'Vietnam',
  'Congo, Democratic Republic of the': 'DR Congo',
  'Tanzania, United Republic of': 'Tanzania',
  'Bolivia, Plurinational State of': 'Bolivia',
  'Moldova, Republic of': 'Moldova',
  'Macedonia, the Former Yugoslav Republic of': 'North Macedonia',
}

function shortName(country: string): string {
  return SHORT_NAME[country] ?? country
}

// Abbreviate known verbose attack type names
const SHORT_TYPE: Record<string, string> = {
  'Bad Web Bot': 'Web Bot',
  'Brute Force': 'Brute-Force',
  'SQL Injection': 'SQLi',
  'Web App Attack': 'Web Attack',
  'Exploited Host': 'Exploited',
  'Open Proxy': 'Proxy',
  'Email Spam': 'Email Spam',
  'DDoS Attack': 'DDoS',
  'Port Scan': 'Port Scan',
  'DNS Compromise': 'DNS Comp.',
  'DNS Poisoning': 'DNS Poison',
  'Fraud Orders': 'Fraud',
  'Ping of Death': 'Ping DoD',
  'Fraud VoIP': 'VoIP Fraud',
  'Web Spam': 'Web Spam',
  'Blog Spam': 'Blog Spam',
  'IoT Targeted': 'IoT Target',
}

function shortType(t: string): string {
  return SHORT_TYPE[t] ?? t
}

function formatAge(ts: string): string {
  if (!ts) return ''
  const h = Math.floor((Date.now() - new Date(ts).getTime()) / 3_600_000)
  if (h < 1) return '<1h'
  if (h < 24) return `${h}h`
  return `${Math.floor(h / 24)}d`
}

function AttackerRow({ a, index }: { a: Attacker; index: number }) {
  const color = a.abuse_score >= 70 ? '#ff2d55' : a.abuse_score >= 40 ? '#ff9500' : '#00d4ff'
  const gnLevel = a.greynoise?.threat_level
  const gnColor = gnLevel === 'targeted' ? '#ff2d55' :
    gnLevel === 'scanner' ? '#ff9500' :
    gnLevel === 'benign' ? '#30d158' : '#8ba3c4'
  const gnLabel = gnLevel === 'targeted' ? 'TARGET' :
    gnLevel === 'scanner' ? 'SCAN' :
    gnLevel === 'benign' ? 'BENIGN' : null

  const displayTypes = a.attack_types.slice(0, 2).map(shortType)
  const extraCount = a.attack_types.length - 2

  return (
    <div className="flex items-center gap-2 py-2 border-b border-radar-border/50 hover:bg-radar-border/20 px-2 rounded transition-colors">
      <span className="text-radar-text font-mono text-xs w-4 text-right shrink-0">{index + 1}</span>

      {/* Country code badge */}
      <span
        className="font-mono text-xs font-bold px-1.5 py-0.5 rounded shrink-0"
        style={{ background: `${color}18`, color, border: `1px solid ${color}40`, minWidth: '30px', textAlign: 'center' }}
      >
        {a.country_code}
      </span>

      {/* Country info */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-white font-medium truncate">{shortName(a.country)}</span>
          {gnLabel && (
            <span
              className="font-mono shrink-0 px-1 rounded border"
              style={{ borderColor: gnColor, color: gnColor, fontSize: '8px' }}
            >
              {gnLabel}
            </span>
          )}
        </div>

        {displayTypes.length > 0 && (
          <div className="flex items-center gap-1 mt-0.5">
            <span className="text-xs truncate" style={{ color, opacity: 0.85 }}>
              {displayTypes.join(' · ')}
            </span>
            {extraCount > 0 && (
              <span className="text-xs shrink-0 font-mono" style={{ color: '#4a6070' }}>
                +{extraCount}
              </span>
            )}
          </div>
        )}

        {a.greynoise?.name && (
          <div className="text-xs truncate mt-0.5" style={{ color: gnColor, opacity: 0.8 }}>
            {a.greynoise.name}
          </div>
        )}

        {/* ISP — shown when populated (defender mode) */}
        {a.isp && !a.greynoise?.name && (
          <div className="text-xs truncate mt-0.5 font-mono" style={{ color: '#4a6070' }}>
            {a.isp}
          </div>
        )}
      </div>

      {/* Score + age */}
      <div className="text-right shrink-0">
        <div className="font-mono text-xs font-bold" style={{ color }}>{a.abuse_score}</div>
        <div className="text-xs text-radar-text">
          {a.total_reports > 0 ? `${a.total_reports}r` : ''}
          {a.last_reported && a.total_reports > 0 ? ' · ' : ''}
          {formatAge(a.last_reported)}
        </div>
      </div>
    </div>
  )
}

type TabMode = 'attacker' | 'defender'

export default function Page() {
  const [tab, setTab]               = useState<TabMode>('attacker')
  const [ip, setIp]                 = useState('')
  const [includeCensys, setIncludeCensys]       = useState(true)
  const [includeGreynoise, setIncludeGreynoise] = useState(true)

  const attacker = useScan()
  const defender = useDefenderScan()

  const active    = tab === 'attacker' ? attacker : defender
  const result    = active.result
  const error     = active.error
  const isScanning = active.status === 'scanning' || active.status === 'connecting'
  const progress  = 'progress' in active ? active.progress : null

  const handleScan = () => {
    if (!ip.trim()) return
    if (tab === 'attacker') attacker.scan(ip.trim(), includeCensys, includeGreynoise)
    else defender.scan(ip.trim())
  }

  const handleReset = () => {
    if (tab === 'attacker') attacker.reset()
    else defender.reset()
  }

  return (
    <div className="min-h-screen bg-radar-bg flex flex-col" style={{ fontFamily: 'Inter, system-ui' }}>

      {/* Header */}
      <header className="border-b border-radar-border px-6 py-3 flex items-center justify-between shrink-0">
        <div className="flex items-center gap-3">
          <Shield className="text-radar-accent" size={20} />
          <span className="font-mono text-sm font-medium text-white tracking-wider">THREAT MAP</span>
          <span className="text-radar-border">·</span>
          <span className="text-radar-text text-sm">IP Threat Intelligence</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-1.5 h-1.5 rounded-full bg-radar-safe animate-pulse" />
          <span className="text-radar-text text-xs font-mono">LIVE</span>
        </div>
      </header>

      {/* Main layout */}
      <div className="flex flex-1 overflow-hidden">

        {/* Left panel */}
        <aside className="w-80 border-r border-radar-border flex flex-col shrink-0 overflow-hidden">

          {/* Tab switcher */}
          <div className="grid grid-cols-2 border-b border-radar-border">
            <button
              onClick={() => setTab('attacker')}
              className="flex items-center justify-center gap-2 py-3 text-xs font-mono transition-colors"
              style={{
                background: tab === 'attacker' ? '#00d4ff10' : 'transparent',
                color: tab === 'attacker' ? '#00d4ff' : '#4a6070',
                borderBottom: tab === 'attacker' ? '2px solid #00d4ff' : '2px solid transparent',
              }}
            >
              <Crosshair size={12} />
              Attacker Intel
            </button>
            <button
              onClick={() => setTab('defender')}
              className="flex items-center justify-center gap-2 py-3 text-xs font-mono transition-colors"
              style={{
                background: tab === 'defender' ? '#30d15810' : 'transparent',
                color: tab === 'defender' ? '#30d158' : '#4a6070',
                borderBottom: tab === 'defender' ? '2px solid #30d158' : '2px solid transparent',
              }}
            >
              <Server size={12} />
              Defender View
            </button>
          </div>

          {/* IP Input */}
          <div className="p-4 border-b border-radar-border">
            <label className="text-xs text-radar-text font-mono uppercase tracking-wider block mb-2">
              {tab === 'defender' ? 'Your Server IP' : 'Target IP Address'}
            </label>
            <div className="flex gap-2">
              <input
                type="text"
                value={ip}
                onChange={e => setIp(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleScan()}
                placeholder={tab === 'defender' ? 'e.g. your.server.ip' : 'e.g. 203.0.113.10'}
                className="flex-1 bg-radar-panel border border-radar-border rounded px-3 py-2 text-sm font-mono text-white placeholder-radar-text/40 focus:outline-none focus:border-radar-accent transition-colors"
              />
              <button
                onClick={isScanning ? handleReset : handleScan}
                disabled={!ip.trim() && !isScanning}
                className="px-3 py-2 rounded border transition-all text-sm font-mono"
                style={{
                  background: isScanning ? 'transparent' : '#00d4ff15',
                  borderColor: isScanning ? '#ff2d55' : '#00d4ff',
                  color: isScanning ? '#ff2d55' : '#00d4ff',
                }}
              >
                {isScanning ? <RefreshCw size={16} className="animate-spin" /> : <Search size={16} />}
              </button>
            </div>

            {tab === 'attacker' && (
              <div className="flex gap-3 mt-3">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={includeGreynoise}
                    onChange={e => setIncludeGreynoise(e.target.checked)}
                    className="accent-radar-accent" />
                  <span className="text-xs text-radar-text">GreyNoise</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={includeCensys}
                    onChange={e => setIncludeCensys(e.target.checked)}
                    className="accent-radar-accent" />
                  <span className="text-xs text-radar-text">Censys</span>
                </label>
              </div>
            )}
            {tab === 'defender' && (
              <p className="text-xs text-radar-text mt-2 opacity-60">
                Shows live global threats that may target your server
              </p>
            )}
          </div>

          {/* Progress */}
          {isScanning && progress && (
            <div className="px-4 py-3 border-b border-radar-border">
              <div className="flex items-center gap-2 text-radar-accent text-xs font-mono">
                <Terminal size={12} />
                <span>{progress.message}</span>
              </div>
            </div>
          )}

          {/* Error */}
          {active.status === 'error' && (
            <div className="px-4 py-3 border-b border-radar-border">
              <div className="text-radar-danger text-xs font-mono flex items-start gap-2">
                <AlertTriangle size={12} className="shrink-0 mt-0.5" />
                {error}
              </div>
            </div>
          )}

          {/* Risk Score */}
          {result && (
            <div className="p-4 border-b border-radar-border">
              <div className="flex items-center justify-between mb-3">
                <span className="text-xs text-radar-text font-mono uppercase tracking-wider">Risk Score</span>
                <RiskBadge score={result.risk_score} />
              </div>
              <div className="flex items-end gap-3">
                <span
                  className="text-5xl font-bold font-mono leading-none"
                  style={{
                    color: result.risk_score >= 70 ? '#ff2d55' :
                      result.risk_score >= 40 ? '#ff9500' : '#30d158'
                  }}
                >
                  {result.risk_score}
                </span>
                <span className="text-radar-text text-lg mb-1">/100</span>
              </div>
              <div className="mt-3 h-1.5 bg-radar-border rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full transition-all duration-1000"
                  style={{
                    width: `${result.risk_score}%`,
                    background: result.risk_score >= 70 ? '#ff2d55' :
                      result.risk_score >= 40 ? '#ff9500' : '#30d158'
                  }}
                />
              </div>
              <p className="text-xs text-radar-text mt-2 leading-relaxed">{result.summary}</p>
            </div>
          )}

          {/* Stats */}
          {result && (
            <div className="grid grid-cols-2 gap-px bg-radar-border border-b border-radar-border">
              {(tab === 'defender'
                ? [
                    { label: 'Active Threats', value: result.total_attackers, icon: <Globe size={12} /> },
                    { label: 'Critical', value: result.targeted_count, icon: <AlertTriangle size={12} />, danger: result.targeted_count > 0 },
                    { label: 'Scanners', value: result.scanner_count, icon: <Wifi size={12} /> },
                    { label: 'Risk Score', value: result.risk_score, icon: <Lock size={12} />, danger: result.risk_score >= 70 },
                  ]
                : [
                    { label: 'Reporters', value: result.total_attackers, icon: <Globe size={12} /> },
                    { label: 'Targeted', value: result.targeted_count, icon: <AlertTriangle size={12} />, danger: result.targeted_count > 0 },
                    { label: 'Scanners', value: result.scanner_count, icon: <Wifi size={12} /> },
                    { label: 'Open Ports', value: result.censys?.open_ports?.length ?? '—', icon: <Lock size={12} /> },
                  ]
              ).map(s => (
                <div key={s.label} className="bg-radar-panel p-3">
                  <div className="flex items-center gap-1.5 text-radar-text mb-1">
                    {s.icon}
                    <span className="text-xs">{s.label}</span>
                  </div>
                  <div className={`font-mono font-medium text-sm ${(s as any).danger ? 'text-radar-danger' : 'text-white'}`}>
                    {String(s.value)}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* GreyNoise — target IP classification */}
          {result?.greynoise_target && (
            <div className="p-4 border-b border-radar-border">
              <div className="text-xs text-radar-text font-mono uppercase tracking-wider mb-2">GreyNoise — Target IP</div>
              <div className="flex items-center gap-2 mb-2">
                <span className="text-xs font-mono px-2 py-0.5 rounded border"
                  style={{
                    borderColor: result.greynoise_target.riot ? '#30d158' :
                      result.greynoise_target.classification === 'malicious' ? '#ff2d55' : '#8ba3c4',
                    color: result.greynoise_target.riot ? '#30d158' :
                      result.greynoise_target.classification === 'malicious' ? '#ff2d55' : '#8ba3c4',
                  }}>
                  {result.greynoise_target.riot ? 'KNOWN BENIGN' :
                    result.greynoise_target.classification.toUpperCase()}
                </span>
                {result.greynoise_target.noise && (
                  <span className="text-xs text-radar-text">(background noise)</span>
                )}
              </div>
              {result.greynoise_target.name && (
                <div className="text-xs text-radar-warn font-mono">{result.greynoise_target.name}</div>
              )}
              {result.greynoise_target.tags.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-2">
                  {result.greynoise_target.tags.slice(0, 4).map(t => (
                    <span key={t} className="text-xs px-1.5 py-0.5 rounded bg-radar-border text-radar-text">{t}</span>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Censys — open ports */}
          {result?.censys && result.censys.open_ports.length > 0 && (
            <div className="p-4 border-b border-radar-border">
              <div className="text-xs text-radar-text font-mono uppercase tracking-wider mb-2">
                Censys — Exposed Services
              </div>
              {result.censys.services.length > 0 && (
                <div className="flex flex-wrap gap-1 mb-3">
                  {result.censys.services.map(s => (
                    <span key={s} className="text-xs px-1.5 py-0.5 rounded bg-radar-border/50 text-radar-accent font-mono">{s}</span>
                  ))}
                </div>
              )}
              <div className="flex flex-wrap gap-1">
                {result.censys.open_ports.slice(0, 20).map(p => {
                  const sensitive = [22, 23, 3389, 5900, 445, 3306, 5432, 27017, 6379, 9200, 2375].includes(p)
                  return (
                    <span key={p} className="font-mono text-xs px-1.5 py-0.5 rounded border"
                      style={{
                        borderColor: sensitive ? '#ff2d55' : '#0d2545',
                        color: sensitive ? '#ff2d55' : '#8ba3c4',
                        background: sensitive ? '#ff2d5510' : 'transparent',
                      }}>
                      {p}
                    </span>
                  )
                })}
              </div>
              {result.censys.org && (
                <div className="text-xs text-radar-text mt-2 font-mono truncate">{result.censys.autonomous_system}</div>
              )}
            </div>
          )}

          {/* Attacker list */}
          {result && result.attackers.length > 0 && (
            <div className="flex-1 overflow-y-auto">
              <div className="px-4 py-2 border-b border-radar-border sticky top-0 bg-radar-panel">
                <span className="text-xs text-radar-text font-mono uppercase tracking-wider">
                  {tab === 'defender' ? `Incoming Threats (${result.total_attackers})` : `Reporting Countries (${result.total_attackers})`}
                </span>
              </div>
              <div className="px-2 py-1">
                {result.attackers.slice(0, 30).map((a, i) => (
                  <AttackerRow key={a.ip} a={a} index={i} />
                ))}
              </div>
            </div>
          )}

          {/* Empty state */}
          {active.status === 'idle' && !result && (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center">
              <Shield className="text-radar-border mb-4" size={40} />
              <p className="text-radar-text text-sm">
                {tab === 'defender'
                  ? 'Enter your server IP to see global threats targeting your infrastructure'
                  : 'Enter a suspicious IP address to scan for threat intelligence'}
              </p>
            </div>
          )}
        </aside>

        {/* Map area */}
        <main className="flex-1 relative bg-radar-bg overflow-hidden">
          <ThreatMap result={result} scanning={isScanning} arcDirection={tab === 'defender' ? 'inward' : 'outward'} />

          {/* Overlay stats */}
          {result && (
            <div className="absolute top-4 right-4 flex flex-col gap-2">
              <div className="bg-radar-panel/90 border border-radar-border rounded px-3 py-2 backdrop-blur-sm">
                <div className="text-xs text-radar-text font-mono">Target</div>
                <div className="font-mono text-white text-sm font-medium">{result.target_ip}</div>
                {result.target_coords && (
                  <div className="text-xs text-radar-text">{result.target_coords.city}, {result.target_coords.country}</div>
                )}
              </div>
              {result.total_attackers > 0 && (
                <div className="bg-radar-danger/10 border border-radar-danger/30 rounded px-3 py-2">
                  <div className="text-xs text-radar-danger font-mono">
                    {tab === 'defender' ? 'Incoming Threats' : 'Active Threats'}
                  </div>
                  <div className="font-mono text-radar-danger text-2xl font-bold">{result.total_attackers}</div>
                </div>
              )}
            </div>
          )}
        </main>
      </div>
    </div>
  )
}
