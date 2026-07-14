import { useState, useEffect, useRef } from "react"
import type { DetectionResult } from "./types"

/* ─── Design tokens ──────────────────────────────────────────────────────────
   Palette: off-white base, neutral greys, three verdict colours (muted, not neon)
   Type: System sans for UI, monospace only for domain string
   No dark panels. No glows. No gradients. No sweep animations.
   Signature element: the verdict row — a left-coloured border card that uses
   colour with restraint, only on the status strip, nowhere else.
──────────────────────────────────────────────────────────────────────────── */
const CSS = `
  .pg {
    --white:   #ffffff;
    --bg:      #f7f7f6;
    --border:  #e4e3e0;
    --border2: #d0cfcc;
    --ink:     #1a1a1a;
    --ink2:    #4a4a4a;
    --ink3:    #7a7a7a;
    --mono:    ui-monospace, "SF Mono", "Cascadia Code", Consolas, monospace;
    --sans:    "Segoe UI", system-ui, -apple-system, sans-serif;

    --c-clean:   #1a7a3c;
    --c-warn:    #92580a;
    --c-phish:   #b91c1c;
    --bg-clean:  #f0faf4;
    --bg-warn:   #fef9ef;
    --bg-phish:  #fef2f2;
    --strip-clean:  #22c55e;
    --strip-warn:   #f59e0b;
    --strip-phish:  #ef4444;

    width: 360px;
    background: var(--bg);
    color: var(--ink);
    font-family: var(--sans);
    font-size: 13px;
    -webkit-font-smoothing: antialiased;
  }
  .pg * { box-sizing: border-box; margin: 0; padding: 0; }

  /* header */
  .pg-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 12px 14px;
    background: var(--white);
    border-bottom: 1px solid var(--border);
  }
  .pg-wordmark {
    display: flex; align-items: center; gap: 7px;
    font-size: 12px; font-weight: 700; letter-spacing: .06em;
    color: var(--ink);
  }
  .pg-badge {
    font-size: 9px; font-weight: 600; letter-spacing: .05em;
    color: var(--ink3); border: 1px solid var(--border2);
    padding: 2px 5px; border-radius: 3px;
  }
  .pg-settings {
    background: none; border: none; cursor: pointer; padding: 4px;
    border-radius: 5px; color: var(--ink3); display: inline-flex;
    transition: background .12s;
  }
  .pg-settings:hover { background: var(--border); color: var(--ink2); }

  /* verdict card */
  .pg-verdict {
    margin: 12px 12px 0;
    background: var(--white);
    border: 1px solid var(--border);
    border-radius: 8px;
    overflow: hidden;
  }
  .pg-verdict-strip {
    height: 4px; width: 100%;
  }
  .pg-verdict-body {
    padding: 14px;
  }
  .pg-domain {
    font-family: var(--mono); font-size: 12px; color: var(--ink2);
    margin-bottom: 10px;
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .pg-verdict-row {
    display: flex; align-items: center; justify-content: space-between; gap: 8px;
  }
  .pg-verdict-left {
    display: flex; align-items: center; gap: 9px;
  }
  .pg-verdict-label {
    font-size: 17px; font-weight: 700; letter-spacing: -.01em;
  }
  .pg-verdict-sub {
    font-size: 11.5px; color: var(--ink3); margin-top: 2px;
  }
  .pg-score {
    font-family: var(--mono); font-size: 22px; font-weight: 600;
    font-variant-numeric: tabular-nums; line-height: 1;
  }
  .pg-score sup { font-size: 11px; opacity: .6; }

  /* risk bar */
  .pg-bar-wrap {
    margin-top: 12px;
  }
  .pg-bar-track {
    height: 6px; background: var(--border); border-radius: 99px; overflow: hidden;
  }
  .pg-bar-fill {
    height: 100%; border-radius: 99px;
    transition: width .6s cubic-bezier(.16,1,.3,1);
  }
  .pg-bar-labels {
    display: flex; justify-content: space-between;
    margin-top: 5px; font-size: 10px; color: var(--ink3);
  }

  /* source chip */
  .pg-source {
    display: inline-flex; align-items: center; gap: 6px;
    margin-top: 12px; padding: 5px 9px;
    background: var(--bg); border: 1px solid var(--border);
    border-radius: 5px; font-size: 11px; color: var(--ink3);
  }
  .pg-source strong { color: var(--ink2); font-weight: 600; }

  /* leave page button */
  .pg-leave {
    display: block; width: 100%; margin-top: 12px;
    padding: 10px; border-radius: 6px;
    background: var(--c-phish); color: #fff;
    border: none; cursor: pointer;
    font-family: var(--sans); font-size: 13px; font-weight: 600;
    text-align: center; letter-spacing: .01em;
    transition: opacity .12s;
  }
  .pg-leave:hover { opacity: .88; }

  /* caution note */
  .pg-caution-note {
    margin-top: 12px; padding: 10px 12px;
    background: var(--bg-warn); border: 1px solid #f0d080;
    border-radius: 6px; font-size: 12px; line-height: 1.5;
    color: var(--c-warn);
  }

  /* signals section */
  .pg-signals {
    margin: 10px 12px 0;
  }
  .pg-signals-title {
    font-size: 10px; font-weight: 700; letter-spacing: .07em;
    text-transform: uppercase; color: var(--ink3);
    margin-bottom: 8px;
  }
  .pg-signal-card {
    background: var(--white); border: 1px solid var(--border);
    border-radius: 7px; padding: 10px 12px; margin-bottom: 6px;
  }
  .pg-signal-top {
    display: flex; align-items: center; justify-content: space-between; gap: 8px;
    margin-bottom: 4px;
  }
  .pg-signal-name {
    font-size: 12.5px; font-weight: 600; color: var(--ink);
    overflow: hidden; text-overflow: ellipsis; white-space: nowrap;
  }
  .pg-signal-tag {
    flex-shrink: 0; font-size: 9px; font-weight: 600; letter-spacing: .04em;
    text-transform: uppercase; color: var(--ink3);
    background: var(--bg); border: 1px solid var(--border);
    padding: 2px 5px; border-radius: 3px;
  }
  .pg-signal-desc {
    font-size: 12px; line-height: 1.45; color: var(--ink2);
    margin-bottom: 7px;
  }
  .pg-signal-bar-row {
    display: flex; align-items: center; gap: 8px;
  }
  .pg-signal-bar-track {
    flex: 1; height: 3px; background: var(--border); border-radius: 99px; overflow: hidden;
  }
  .pg-signal-bar-fill {
    height: 100%; border-radius: 99px;
  }
  .pg-signal-weight {
    font-family: var(--mono); font-size: 9.5px; color: var(--ink3);
    font-variant-numeric: tabular-nums;
  }

  /* footer */
  .pg-footer {
    display: flex; align-items: center; justify-content: space-between;
    margin: 10px 12px 12px;
    padding-top: 10px; border-top: 1px solid var(--border);
  }
  .pg-private {
    display: flex; align-items: center; gap: 5px;
    font-size: 10.5px; font-weight: 600; color: #166534;
  }
  .pg-ms {
    font-family: var(--mono); font-size: 10px; color: var(--ink3);
  }

  /* empty & loading */
  .pg-empty {
    padding: 32px 20px 28px; text-align: center;
  }
  .pg-empty-icon {
    display: inline-flex; padding: 14px;
    background: var(--white); border: 1px solid var(--border);
    border-radius: 12px; margin-bottom: 14px;
  }
  .pg-empty h2 {
    font-size: 15px; font-weight: 700; margin-bottom: 7px;
  }
  .pg-empty p {
    font-size: 12.5px; line-height: 1.5; color: var(--ink3);
    margin-bottom: 18px;
  }
  .pg-scan-btn {
    padding: 9px 20px; background: var(--ink); color: #fff;
    border: none; border-radius: 6px; cursor: pointer;
    font-family: var(--sans); font-size: 13px; font-weight: 600;
    transition: opacity .12s;
  }
  .pg-scan-btn:hover { opacity: .85; }

  .pg-skeleton {
    background: var(--border); border-radius: 4px;
    animation: pg-pulse 1.4s ease-in-out infinite;
  }
  @keyframes pg-pulse {
    0%, 100% { opacity: 1; } 50% { opacity: .45; }
  }
  @keyframes pg-fade {
    from { opacity: 0; transform: translateY(4px); }
    to   { opacity: 1; transform: none; }
  }
  .pg-fade { animation: pg-fade .3s ease both; }
`

// ── Feature name → plain English ──────────────────────────────────────────
const FEATURE_LABELS: Record<string, { name: string; tag: string }> = {
  URLLength:                  { name: "URL is unusually long",               tag: "Length" },
  DomainLength:               { name: "Domain name is unusually long",        tag: "Length" },
  IsDomainIP:                 { name: "Domain is a raw IP address",           tag: "Structure" },
  URLSimilarityIndex:         { name: "URL resembles a known brand name",     tag: "Spoofing" },
  CharContinuationRate:       { name: "Unusual character patterns in URL",    tag: "Structure" },
  TLDLegitimateProb:          { name: "Top-level domain has low trust score", tag: "Domain" },
  URLCharProb:                { name: "Unusual mix of characters in URL",     tag: "Structure" },
  NoOfSubDomain:              { name: "Excessive number of subdomains",       tag: "Structure" },
  HasObfuscation:             { name: "URL contains encoded characters",      tag: "Obfuscation" },
  NoOfObfuscatedChar:         { name: "Several encoded characters found",     tag: "Obfuscation" },
  ObfuscationRatio:           { name: "High proportion of encoded characters",tag: "Obfuscation" },
  NoOfLettersInURL:           { name: "Unusually few letters in URL",         tag: "Structure" },
  LetterRatioInURL:           { name: "Low letter-to-character ratio",        tag: "Structure" },
  NoOfDegitsInURL:            { name: "Unusually many digits in URL",         tag: "Structure" },
  DegitRatioInURL:            { name: "High digit-to-character ratio",        tag: "Structure" },
  NoOfEqualsInURL:            { name: "Many equals signs in URL",             tag: "Parameters" },
  NoOfQMarkInURL:             { name: "Multiple question marks in URL",       tag: "Parameters" },
  NoOfAmpersandInURL:         { name: "Many query parameters chained",        tag: "Parameters" },
  NoOfOtherSpecialCharsInURL: { name: "High density of special characters",   tag: "Structure" },
  SpacialCharRatioInURL:      { name: "Unusual special character ratio",      tag: "Structure" },
  IsHTTPS:                    { name: "Site does not use HTTPS",              tag: "Security" },
  Reputation:                 { name: "Listed as a trusted site",             tag: "Allowlist" },
}

function labelFor(raw: string): { name: string; tag: string } {
  return FEATURE_LABELS[raw] ?? { name: raw, tag: "Signal" }
}

// ── Verdict config ────────────────────────────────────────────────────────
type VKey = "CLEAN" | "SUSPICIOUS" | "PHISHING"

function verdictFor(score: number): VKey {
  if (score < 0.5)  return "CLEAN"
  if (score <= 0.85) return "SUSPICIOUS"
  return "PHISHING"
}

const VERDICT_CONFIG = {
  CLEAN: {
    label: "Safe",
    sub: "No threats detected on this page",
    color: "var(--c-clean)",
    strip: "var(--strip-clean)",
    bg: "var(--bg-clean)",
  },
  SUSPICIOUS: {
    label: "Suspicious",
    sub: "Proceed carefully on this page",
    color: "var(--c-warn)",
    strip: "var(--strip-warn)",
    bg: "var(--bg-warn)",
  },
  PHISHING: {
    label: "Phishing detected",
    sub: "This page is likely fraudulent",
    color: "var(--c-phish)",
    strip: "var(--strip-phish)",
    bg: "var(--bg-phish)",
  },
}

// ── SVG icons (no emojis, no external deps) ───────────────────────────────
const Icons = {
  shield: (color: string, size = 18) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
      <path d="M9 12l2 2 4-4"/>
    </svg>
  ),
  warning: (color: string, size = 18) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.3 3.6 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.6a2 2 0 0 0-3.4 0z"/>
      <path d="M12 9v4"/><path d="M12 17h.01"/>
    </svg>
  ),
  block: (color: string, size = 18) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10"/>
      <path d="M4.9 4.9l14.2 14.2"/>
    </svg>
  ),
  scan: (color: string, size = 22) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2"/>
      <path d="M3 12h18"/>
    </svg>
  ),
  cpu: (color: string, size = 13) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="6" y="6" width="12" height="12" rx="2"/>
      <path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2"/>
    </svg>
  ),
  list: (color: string, size = 13) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01"/>
    </svg>
  ),
  lock: (color: string, size = 12) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="4" y="11" width="16" height="9" rx="2"/>
      <path d="M8 11V7a4 4 0 0 1 8 0v4"/>
    </svg>
  ),
  gear: (color: string, size = 16) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke={color} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3"/>
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z"/>
    </svg>
  ),
  arrowLeft: (color: string, size = 14) => (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none"
      stroke={color} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M19 12H5"/><path d="M12 19l-7-7 7-7"/>
    </svg>
  ),
}

// ── Header ────────────────────────────────────────────────────────────────
function Header({ onSettings }: { onSettings: () => void }) {
  return (
    <div className="pg-header">
      <div className="pg-wordmark">
        {Icons.shield("#1a7a3c", 16)}
        <span>PHISHGUARD</span>
        <span className="pg-badge">ON-DEVICE</span>
      </div>
      <button className="pg-settings" onClick={onSettings} title="Settings">
        {Icons.gear("#7a7a7a", 16)}
      </button>
    </div>
  )
}

// ── Main popup ────────────────────────────────────────────────────────────
export default function Popup() {
  const [result, setResult]     = useState<DetectionResult | null>(null)
  const [loading, setLoading]   = useState(true)
  const [barPct, setBarPct]     = useState(0)
  const [displayScore, setDisplayScore] = useState(0)
  const rafRef = useRef<number | null>(null)

  useEffect(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id
      if (!tabId) { setLoading(false); return }
      chrome.storage.local.get(`result_${tabId}`, (data) => {
        const res = data[`result_${tabId}`] as DetectionResult | undefined
        if (res) {
          setResult(res)
          const target = res.prediction.score * 100
          const start  = performance.now()
          const dur    = 600
          const tick   = (now: number) => {
            const p = Math.min(1, (now - start) / dur)
            const e = 1 - Math.pow(1 - p, 3)
            setBarPct(target * e)
            setDisplayScore(target * e)
            if (p < 1) rafRef.current = requestAnimationFrame(tick)
          }
          rafRef.current = requestAnimationFrame(tick)
        }
        setLoading(false)
      })
    })
    return () => { if (rafRef.current) cancelAnimationFrame(rafRef.current) }
  }, [])

  const openSettings = () => chrome.runtime.openOptionsPage()
  const reloadTab    = () => chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const id = tabs[0]?.id
    if (id) { chrome.tabs.reload(id); window.close() }
  })
  const leavePage = () => chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const id = tabs[0]?.id
    if (id) { chrome.tabs.goBack(id); window.close() }
  })

  // ── Loading state ──────────────────────────────────────────────────────
  if (loading) {
    return (
      <div className="pg">
        <style dangerouslySetInnerHTML={{ __html: CSS }} />
        <Header onSettings={openSettings} />
        <div style={{ padding: "12px 12px 0" }}>
          <div className="pg-verdict">
            <div className="pg-skeleton" style={{ height: 4 }} />
            <div style={{ padding: 14 }}>
              <div className="pg-skeleton" style={{ height: 12, width: 160, marginBottom: 12 }} />
              <div className="pg-skeleton" style={{ height: 20, width: 100, marginBottom: 10 }} />
              <div className="pg-skeleton" style={{ height: 6, borderRadius: 99 }} />
            </div>
          </div>
        </div>
        <div style={{ padding: "10px 12px 12px", display: "flex", flexDirection: "column", gap: 6 }}>
          {[0, 1, 2].map(i => (
            <div key={i} className="pg-skeleton" style={{ height: 70, borderRadius: 7 }} />
          ))}
        </div>
      </div>
    )
  }

  // ── Empty state ────────────────────────────────────────────────────────
  if (!result) {
    return (
      <div className="pg">
        <style dangerouslySetInnerHTML={{ __html: CSS }} />
        <Header onSettings={openSettings} />
        <div className="pg-empty">
          <div className="pg-empty-icon">
            {Icons.scan("#7a7a7a", 24)}
          </div>
          <h2>Nothing scanned yet</h2>
          <p>Open any website and this extension checks it on your device. No data is sent anywhere.</p>
          <button className="pg-scan-btn" onClick={reloadTab}>Scan this page</button>
        </div>
      </div>
    )
  }

  // ── Result state ───────────────────────────────────────────────────────
  const score      = result.prediction.score
  const vkey       = verdictFor(score)
  const vc         = VERDICT_CONFIG[vkey]
  const isReputation = result.prediction.source === "OVERRIDE"
  const mlSignals  = (result.explanations ?? []).filter(e => e.category !== "Reputation")
  const repSignals = (result.explanations ?? []).filter(e => e.category === "Reputation")
  const maxImp     = Math.max(0.0001, ...(isReputation ? repSignals : mlSignals).map(s => s.importance || 0))

  let host = result.url
  try { host = new URL(result.url).hostname.replace(/^www\./, "") } catch {}

  const VIcon = vkey === "CLEAN"
    ? Icons.shield(vc.color, 20)
    : vkey === "SUSPICIOUS"
    ? Icons.warning(vc.color, 20)
    : Icons.block(vc.color, 20)

  const sourceLabel = isReputation ? "Trusted-sites list" : "On-device model"
  const SourceIcon  = isReputation ? Icons.list("#7a7a7a", 13) : Icons.cpu("#7a7a7a", 13)

  const signals = isReputation ? repSignals : mlSignals

  return (
    <div className="pg">
      <style dangerouslySetInnerHTML={{ __html: CSS }} />
      <Header onSettings={openSettings} />

      {/* Verdict card */}
      <div className="pg-verdict pg-fade" style={{ margin: "12px 12px 0" }}>
        <div className="pg-verdict-strip" style={{ background: vc.strip }} />
        <div className="pg-verdict-body" style={{ background: vc.bg }}>

          {/* Domain */}
          <div className="pg-domain" title={host}>{host}</div>

          {/* Verdict row */}
          <div className="pg-verdict-row">
            <div className="pg-verdict-left">
              {VIcon}
              <div>
                <div className="pg-verdict-label" style={{ color: vc.color }}>{vc.label}</div>
                <div className="pg-verdict-sub">{vc.sub}</div>
              </div>
            </div>
            <div className="pg-score" style={{ color: vc.color }}>
              {Math.round(displayScore)}<sup>%</sup>
            </div>
          </div>

          {/* Risk bar */}
          <div className="pg-bar-wrap">
            <div className="pg-bar-track">
              <div className="pg-bar-fill" style={{ width: `${barPct}%`, background: vc.strip }} />
            </div>
            <div className="pg-bar-labels">
              <span>Safe</span>
              <span>50 · Caution</span>
              <span>85 · Phishing</span>
            </div>
          </div>

          {/* Source chip */}
          <div className="pg-source">
            {SourceIcon}
            <span>Checked by <strong>{sourceLabel}</strong></span>
          </div>

          {/* Leave page — phishing only */}
          {vkey === "PHISHING" && (
            <button className="pg-leave" onClick={leavePage}>
              Leave this page
            </button>
          )}

          {/* Caution note — suspicious only */}
          {vkey === "SUSPICIOUS" && (
            <div className="pg-caution-note">
              This page shows some warning signs. Check the address bar carefully before entering any personal information.
            </div>
          )}
        </div>
      </div>

      {/* Signals */}
      {signals.length > 0 && (
        <div className="pg-signals">
          <div className="pg-signals-title">
            {isReputation ? "Why it is trusted" : "What raised concern"}
          </div>

          {signals.map((s, i) => {
            const { name, tag } = labelFor(s.feature)
            const pct = Math.round(((s.importance || 0) / maxImp) * 100)
            return (
              <div key={i} className="pg-signal-card pg-fade"
                style={{ animationDelay: `${i * 50}ms` }}>
                <div className="pg-signal-top">
                  <span className="pg-signal-name">{name}</span>
                  <span className="pg-signal-tag">{tag}</span>
                </div>
                <p className="pg-signal-desc">{s.description}</p>
                <div className="pg-signal-bar-row">
                  <div className="pg-signal-bar-track">
                    <div className="pg-signal-bar-fill"
                      style={{ width: `${pct}%`, background: vc.strip, opacity: .8 }} />
                  </div>
                  <span className="pg-signal-weight">{(s.importance || 0).toFixed(3)}</span>
                </div>
              </div>
            )
          })}

          {!isReputation && (
            <p style={{ fontSize: 10.5, color: "var(--ink3)", lineHeight: 1.45,
              margin: "2px 2px 0", paddingBottom: 2 }}>
              Bar length shows each signal's weight in the model, not the direction of risk for this specific page.
            </p>
          )}
        </div>
      )}

      {/* Footer */}
      <div className="pg-footer">
        <div className="pg-private">
          {Icons.lock("#166534", 12)}
          <span>Runs entirely on your device</span>
        </div>
        <span className="pg-ms">{result.processingTimeMs.toLocaleString()}ms</span>
      </div>
    </div>
  )
}