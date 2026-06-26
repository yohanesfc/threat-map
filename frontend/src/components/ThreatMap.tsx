'use client'
import { useEffect, useRef } from 'react'
import * as d3 from 'd3'
import { geoNaturalEarth1, geoPath, geoGraticule } from 'd3-geo'
import type { ScanResult } from '@/lib/useScan'

interface Props {
  result: ScanResult | null
  scanning: boolean
  arcDirection?: 'outward' | 'inward'
}

const WORLD_URL = 'https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json'
const W = 900
const H = 480

// ── SVG SMIL helpers ──────────────────────────────────────────────────────────

function svgEl(tag: string, attrs: Record<string, string>): Element {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag)
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v)
  return el
}

function addAnim(parent: Element, attrs: Record<string, string>): Element {
  const el = svgEl('animate', attrs)
  parent.appendChild(el)
  return el
}

function addAnimMotion(parent: Element, pathId: string, attrs: Record<string, string>) {
  const el = svgEl('animateMotion', attrs)
  const mp = svgEl('mpath', {})
  mp.setAttributeNS('http://www.w3.org/1999/xlink', 'href', `#${pathId}`)
  mp.setAttribute('href', `#${pathId}`)
  el.appendChild(mp)
  parent.appendChild(el)
}

function arcLen(x1: number, y1: number, cx: number, cy: number, x2: number, y2: number): number {
  let len = 0, px = x1, py = y1
  for (let i = 1; i <= 28; i++) {
    const t = i / 28
    const x = (1 - t) ** 2 * x1 + 2 * (1 - t) * t * cx + t ** 2 * x2
    const y = (1 - t) ** 2 * y1 + 2 * (1 - t) * t * cy + t ** 2 * y2
    len += Math.hypot(x - px, y - py)
    px = x; py = y
  }
  return Math.ceil(len) + 10
}

// ── Component ─────────────────────────────────────────────────────────────────

const BW = 28   // zoom button width
const BH = 28   // zoom button height
const BX = 14   // left margin inside SVG

export default function ThreatMap({ result, scanning, arcDirection = 'outward' }: Props) {
  const svgRef  = useRef<SVGSVGElement>(null)
  const zoomRef = useRef<d3.ZoomBehavior<SVGSVGElement, unknown> | null>(null)

  // ── Build base map (once) ────────────────────────────────────────────────────
  useEffect(() => {
    if (!svgRef.current) return
    const svg = d3.select(svgRef.current)
    svg.selectAll('*').remove()

    const projection = geoNaturalEarth1().scale(W / 6.5).translate([W / 2, H / 2])
    const pathFn     = geoPath().projection(projection)
    const graticule  = geoGraticule()

    // ── Defs ──────────────────────────────────────────────────────────────────
    const defs = svg.append('defs')

    const glow = defs.append('filter').attr('id', 'arc-glow')
      .attr('x', '-60%').attr('y', '-60%').attr('width', '220%').attr('height', '220%')
    glow.append('feGaussianBlur').attr('stdDeviation', '2.5').attr('result', 'blur')
    const fm1 = glow.append('feMerge')
    fm1.append('feMergeNode').attr('in', 'blur')
    fm1.append('feMergeNode').attr('in', 'SourceGraphic')

    const sg = defs.append('filter').attr('id', 'dot-glow')
      .attr('x', '-120%').attr('y', '-120%').attr('width', '340%').attr('height', '340%')
    sg.append('feGaussianBlur').attr('stdDeviation', '5').attr('result', 'blur')
    const fm2 = sg.append('feMerge')
    fm2.append('feMergeNode').attr('in', 'blur')
    fm2.append('feMergeNode').attr('in', 'SourceGraphic')

    const bg = defs.append('radialGradient').attr('id', 'ocean-bg')
      .attr('cx', '50%').attr('cy', '48%').attr('r', '68%')
    bg.append('stop').attr('offset', '0%').attr('stop-color', '#0c1f3a')
    bg.append('stop').attr('offset', '100%').attr('stop-color', '#020a18')

    const vig = defs.append('radialGradient').attr('id', 'vignette')
      .attr('cx', '50%').attr('cy', '50%').attr('r', '70%')
    vig.append('stop').attr('offset', '40%').attr('stop-color', '#000').attr('stop-opacity', '0')
    vig.append('stop').attr('offset', '100%').attr('stop-color', '#000').attr('stop-opacity', '0.7')

    // ── Map root group (this is what zoom transforms) ─────────────────────────
    const mapGroup = svg.append('g').attr('class', 'map-root')

    mapGroup.append('rect').attr('width', W).attr('height', H).attr('fill', 'url(#ocean-bg)')

    mapGroup.append('path').datum(graticule()).attr('d', pathFn)
      .attr('fill', 'none').attr('stroke', '#0b1e35').attr('stroke-width', 0.25)

    mapGroup.append('path').datum(geoGraticule().step([30, 30])()).attr('d', pathFn)
      .attr('fill', 'none').attr('stroke', '#112640').attr('stroke-width', 0.45)

    fetch(WORLD_URL)
      .then(r => r.json())
      .then(world => {
        const { feature, mesh } = require('topojson-client')
        const countries        = feature(world, world.objects.countries)
        const internalBorders  = mesh(world, world.objects.countries, (a: any, b: any) => a !== b)
        const coastlines       = mesh(world, world.objects.countries, (a: any, b: any) => a === b)

        mapGroup.append('g').attr('class', 'countries')
          .selectAll('path').data((countries as any).features).join('path')
          .attr('d', pathFn as any).attr('fill', '#0e2348').attr('stroke', 'none')

        mapGroup.append('path').datum(internalBorders).attr('d', pathFn as any)
          .attr('fill', 'none').attr('stroke', '#1a3860').attr('stroke-width', 0.3)

        mapGroup.append('path').datum(coastlines).attr('d', pathFn as any)
          .attr('fill', 'none').attr('stroke', '#254d80').attr('stroke-width', 0.55)

        mapGroup.append('g').attr('class', 'arcs')

        if (result?.target_coords) drawArcs(mapGroup, projection, result, arcDirection)
      })

    // ── Vignette overlay — stays fixed (not inside map-root) ─────────────────
    svg.append('rect').attr('width', W).attr('height', H)
      .attr('fill', 'url(#vignette)').attr('pointer-events', 'none')

    // ── D3 zoom ───────────────────────────────────────────────────────────────
    const zoom = d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([1, 8])
      .translateExtent([[-W * 0.5, -H * 0.5], [W * 1.5, H * 1.5]])
      .on('zoom', (event) => {
        mapGroup.attr('transform', event.transform.toString())
      })

    svg.call(zoom)
    zoomRef.current = zoom

    // ── Zoom controls — SVG-native, fixed at bottom-left ──────────────────────
    // Positioned OUTSIDE map-root so they stay fixed during pan/zoom
    const zoomBtns = [
      { label: '+',  y: H - 14 - BH * 3 - 12, action: () => d3.select(svgRef.current!).transition().duration(250).call(zoom.scaleBy, 1.6) },
      { label: '⊙', y: H - 14 - BH * 2 - 6,  action: () => d3.select(svgRef.current!).transition().duration(380).call(zoom.transform, d3.zoomIdentity) },
      { label: '−',  y: H - 14 - BH,           action: () => d3.select(svgRef.current!).transition().duration(250).call(zoom.scaleBy, 1 / 1.6) },
    ]

    const ctrl = svg.append('g').attr('class', 'zoom-ctrl').attr('pointer-events', 'all')

    zoomBtns.forEach(({ label, y, action }) => {
      const btn = ctrl.append('g').attr('cursor', 'pointer').attr('transform', `translate(${BX},${y})`)

      btn.append('rect')
        .attr('width', BW).attr('height', BH).attr('rx', 5)
        .attr('fill', 'rgba(10,26,50,0.82)').attr('stroke', '#1e3d6e')
        .attr('stroke-width', 1)

      btn.append('text')
        .attr('x', BW / 2).attr('y', BH / 2 + 5)
        .attr('text-anchor', 'middle')
        .attr('font-size', label === '⊙' ? '12' : '16')
        .attr('font-weight', 'bold').attr('font-family', 'monospace')
        .attr('fill', '#7a96b8').attr('pointer-events', 'none')
        .text(label)

      btn.on('click', (e: MouseEvent) => { e.stopPropagation(); action() })
        .on('mouseenter', function () {
          d3.select(this).select('rect').attr('stroke', '#00d4ff').attr('fill', 'rgba(0,212,255,0.10)')
          d3.select(this).select('text').attr('fill', '#00d4ff')
        })
        .on('mouseleave', function () {
          d3.select(this).select('rect').attr('stroke', '#1e3d6e').attr('fill', 'rgba(10,26,50,0.82)')
          d3.select(this).select('text').attr('fill', '#7a96b8')
        })
    })
  }, [])

  // ── Redraw arcs on new result ─────────────────────────────────────────────────
  useEffect(() => {
    if (!svgRef.current || !result?.target_coords) return
    const svg        = d3.select(svgRef.current)
    const mapGroup   = svg.select<SVGGElement>('.map-root')
    const projection = geoNaturalEarth1().scale(W / 6.5).translate([W / 2, H / 2])
    drawArcs(mapGroup, projection, result, arcDirection)
  }, [result])

  return (
    <div className="relative w-full h-full">
      <svg
        ref={svgRef}
        className="w-full h-full cursor-grab active:cursor-grabbing"
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="xMidYMid meet"
      />

      {scanning && (
        <div
          className="absolute inset-0 flex items-center justify-center"
          style={{ background: 'rgba(2,10,24,0.55)', backdropFilter: 'blur(3px)' }}
        >
          <div className="flex flex-col items-center gap-4">
            <div
              className="w-14 h-14 rounded-full border-2 border-t-transparent animate-spin"
              style={{ borderColor: '#00d4ff', borderTopColor: 'transparent', filter: 'drop-shadow(0 0 10px #00d4ff88)' }}
            />
            <span className="text-xs font-mono tracking-[0.35em] uppercase" style={{ color: '#00d4ff' }}>
              Scanning
            </span>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Color by threat level ─────────────────────────────────────────────────────

function riskColor(a: { abuse_score: number; greynoise?: { threat_level?: string } | null }): string {
  const lvl = a.greynoise?.threat_level
  if (lvl === 'targeted') return '#ff2d55'
  if (lvl === 'scanner')  return '#ff9500'
  if (lvl === 'benign')   return '#30d158'
  if (lvl === 'noise')    return '#4a6070'
  if (a.abuse_score >= 70) return '#ff2d55'
  if (a.abuse_score >= 40) return '#ff9500'
  return '#00d4ff'
}

// ── Draw looping arcs ─────────────────────────────────────────────────────────

function drawArcs(
  container: d3.Selection<SVGGElement, unknown, null, undefined>,
  projection: d3.GeoProjection,
  result: ScanResult,
  direction: 'outward' | 'inward' = 'outward',
) {
  container.selectAll('.arc-group').remove()
  const g = container.append('g').attr('class', 'arc-group')

  const target = result.target_coords!
  const [tx, ty] = projection([target.lon, target.lat]) ?? [0, 0]

  const victims     = result.attackers.filter(a => a.coords)
  const ARC_DUR_MS  = 2000
  const STAGGER_MS  = 260
  const SPREAD_MS   = Math.max(victims.length * STAGGER_MS, 3000)

  victims.forEach((victim, i) => {
    if (!victim.coords) return
    const [vx, vy] = projection([victim.coords.lon, victim.coords.lat]) ?? [0, 0]
    const color = riskColor(victim)

    const midX = (tx + vx) / 2
    const midY = Math.min(ty, vy) - Math.abs(vx - tx) * 0.38 - 15
    // outward: attacker → victim countries | inward: victim countries → attacker
    const [sx, sy, ex, ey] = direction === 'inward'
      ? [vx, vy, tx, ty]
      : [tx, ty, vx, vy]
    const d   = `M${sx},${sy} Q${midX},${midY} ${ex},${ey}`
    const len = arcLen(sx, sy, midX, midY, ex, ey)

    const arcId = `arc${i}`
    const dur   = `${(ARC_DUR_MS / 1000).toFixed(2)}s`
    const begin = `${((i * STAGGER_MS) % SPREAD_MS / 1000).toFixed(2)}s`

    // Arc line
    const arcEl = g.append('path')
      .attr('id', arcId).attr('d', d).attr('fill', 'none')
      .attr('stroke', color).attr('stroke-width', 1.6).attr('stroke-linecap', 'round')
      .attr('stroke-dasharray', String(len)).attr('stroke-dashoffset', String(len))
      .attr('filter', 'url(#arc-glow)').node()!

    addAnim(arcEl, { attributeName: 'stroke-dashoffset', from: String(len), to: '0', dur, begin, repeatCount: 'indefinite', calcMode: 'linear' })
    addAnim(arcEl, { attributeName: 'opacity', values: '0;0.95;0.85;0', keyTimes: '0;0.05;0.78;1', dur, begin, repeatCount: 'indefinite' })

    // Origin dot (attacker)
    const origEl = g.append('circle').attr('cx', tx).attr('cy', ty).attr('r', 2)
      .attr('fill', color).attr('filter', 'url(#arc-glow)').node()!
    addAnim(origEl, { attributeName: 'opacity', values: '0;1;0.9;0', keyTimes: '0;0.06;0.76;1', dur, begin, repeatCount: 'indefinite' })

    // Victim dot + label
    const victimEl = g.append('circle').attr('cx', vx).attr('cy', vy).attr('r', 3)
      .attr('fill', color).attr('filter', 'url(#arc-glow)').node()!
    addAnim(victimEl, { attributeName: 'opacity', values: '0;1;0.9;0', keyTimes: '0;0.06;0.76;1', dur, begin, repeatCount: 'indefinite' })
    addAnim(victimEl, { attributeName: 'r', values: '1;3.5;2.5;1', keyTimes: '0;0.08;0.75;1', dur, begin, repeatCount: 'indefinite' })

    const labelEl = g.append('text')
      .attr('x', vx).attr('y', vy - 7).attr('text-anchor', 'middle')
      .attr('font-size', '8').attr('font-family', 'monospace').attr('font-weight', '600')
      .attr('letter-spacing', '0.05em').attr('fill', color)
      .attr('stroke', '#020a18').attr('stroke-width', '2.5').attr('paint-order', 'stroke')
      .attr('pointer-events', 'none')
      .text(victim.country.length > 14 ? victim.country.slice(0, 13) + '…' : victim.country)
      .node()!
    addAnim(labelEl, { attributeName: 'opacity', values: '0;1;0.9;0', keyTimes: '0;0.06;0.76;1', dur, begin, repeatCount: 'indefinite' })

    // Comet
    const cometEl = g.append('circle').attr('r', 3).attr('fill', '#ffffff')
      .attr('opacity', 0).attr('filter', 'url(#arc-glow)').node()!
    addAnimMotion(cometEl, arcId, { dur, begin, repeatCount: 'indefinite', calcMode: 'linear' })
    addAnim(cometEl, { attributeName: 'opacity', values: '0;0;1;1;0', keyTimes: '0;0.04;0.09;0.84;1', dur, begin, repeatCount: 'indefinite' })
    addAnim(cometEl, { attributeName: 'r', values: '1;3.5;2.5;1', keyTimes: '0;0.12;0.82;1', dur, begin, repeatCount: 'indefinite' })
  })

  // Target: pulsing rings
  for (let i = 0; i < 3; i++) {
    const ringEl = g.append('circle').attr('cx', tx).attr('cy', ty).attr('r', 6)
      .attr('fill', 'none').attr('stroke', '#ff2d55').attr('stroke-width', 1.4 - i * 0.35).node()!
    addAnim(ringEl, { attributeName: 'r', values: `5;${20 + i * 9}`, dur: '2.6s', begin: `${i * 0.65}s`, repeatCount: 'indefinite', calcMode: 'spline', keySplines: '0.2 0.8 0.6 1', keyTimes: '0;1' })
    addAnim(ringEl, { attributeName: 'opacity', values: '0.85;0', dur: '2.6s', begin: `${i * 0.65}s`, repeatCount: 'indefinite', calcMode: 'spline', keySplines: '0.3 0 0.7 1', keyTimes: '0;1' })
  }

  // Target: halo + core
  g.append('circle').attr('cx', tx).attr('cy', ty).attr('r', 12)
    .attr('fill', '#ff2d55').attr('opacity', 0.18).attr('filter', 'url(#dot-glow)')
  g.append('circle').attr('cx', tx).attr('cy', ty).attr('r', 5)
    .attr('fill', '#ff2d55').attr('stroke', '#ffffff').attr('stroke-width', 1.5).attr('filter', 'url(#dot-glow)')
  g.append('circle').attr('cx', tx).attr('cy', ty).attr('r', 2)
    .attr('fill', '#ffffff').attr('opacity', 0.95)
}
