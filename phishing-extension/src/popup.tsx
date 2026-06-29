import { useState, useEffect, useRef } from "react"
import type { DetectionResult } from "./types"

/* ────────────────────────────────────────────────────────────────────────
   PhishGuard popup — a security "detector readout".
   Signature element: a dark instrument-panel hero showing the DOMAIN being
   judged, the verdict, and a scanning risk meter glowing in the verdict
   colour, plus the decision source (reputation allowlist vs on-device model).
   ──────────────────────────────────────────────────────────────────────── */

const TOKENS = `
  .pg-root {
    --paper: #faf9f7;
    --surface: #ffffff;
    --panel: #0d1014;
    --panel-2: #161b22;
    --panel-line: #232a33;
    --line: #ecebe8;
    --ink: #16181d;
    --muted: #6b7280;
    --panel-ink: #e9ecf1;
    --panel-muted: #828b99;
    --font-mono: ui-monospace, "SF Mono", "JetBrains Mono", "Cascadia Code", Consolas, "Liberation Mono", monospace;
    --font-sans: "Segoe UI", system-ui, -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
    width: 372px;
    background: var(--paper);
    color: var(--ink);
    font-family: var(--font-sans);
    -webkit-font-smoothing: antialiased;
  }
  .pg-root * { box-sizing: border-box; }

  .pg-iconbtn {
    background: transparent; border: none; cursor: pointer;
    color: var(--panel-muted); padding: 6px; border-radius: 7px;
    display: inline-flex; align-items: center; justify-content: center;
    transition: background .15s ease, color .15s ease;
  }
  .pg-iconbtn:hover { background: rgba(255,255,255,.07); color: var(--panel-ink); }
  .pg-iconbtn:focus-visible { outline: 2px solid var(--vc); outline-offset: 2px; }

  .pg-btn {
    font-family: var(--font-sans); font-size: 13px; font-weight: 600;
    padding: 9px 16px; border-radius: 8px; border: none; cursor: pointer;
    background: var(--ink); color: #fff;
    transition: transform .12s ease, opacity .15s ease;
  }
  .pg-btn:hover { opacity: .9; }
  .pg-btn:active { transform: translateY(1px); }
  .pg-btn:focus-visible { outline: 2px solid var(--ink); outline-offset: 2px; }

  .pg-signal { transition: background .15s ease, border-color .15s ease; }
  .pg-signal:hover { background: #fbfbfa; border-color: #e2e1dd; }

  @keyframes pg-fade-up { from { opacity: 0; transform: translateY(6px); } to { opacity: 1; transform: none; } }
  @keyframes pg-sweep { from { transform: translateX(-100%); } to { transform: translateX(220%); } }
  @keyframes pg-pulse { 0%,100% { opacity: .55; } 50% { opacity: .28; } }
  @keyframes pg-dot { 0%,100% { opacity: 1; } 50% { opacity: .35; } }
`

const fmt = (n: number) => n.toLocaleString("en-US")

type Verdict = {
  key: "CLEAN" | "SUSPICIOUS" | "PHISHING"
  title: string
  glow: string   // on dark hero
  ink: string    // on light body
  wash: string   // faint tint
}

function verdictFor(score: number): Verdict {
  if (score < 0.5)
    return { key: "CLEAN", title: "Safe to use", glow: "#2fd27a", ink: "#15803d", wash: "rgba(47,210,122,.12)" }
  if (score <= 0.85)
    return { key: "SUSPICIOUS", title: "Be cautious", glow: "#fbbf24", ink: "#b45309", wash: "rgba(251,191,36,.13)" }
  return { key: "PHISHING", title: "Likely phishing", glow: "#ff5c57", ink: "#dc2626", wash: "rgba(255,92,87,.13)" }
}

/* ── inline icons (sized to their text) ───────────────────────────────── */
const I = {
  shieldCheck: (c: string, s = 16) => (
    <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="M9 12l2 2 4-4" />
    </svg>
  ),
  alert: (c: string, s = 16) => (
    <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M10.3 3.6 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.6a2 2 0 0 0-3.4 0z" /><path d="M12 9v4" /><path d="M12 17h.01" />
    </svg>
  ),
  skull: (c: string, s = 16) => (
    <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="9" cy="12" r="1" /><circle cx="15" cy="12" r="1" />
      <path d="M8 20v-2a2 2 0 0 1-2-2 9 9 0 1 1 12 0 2 2 0 0 1-2 2v2" /><path d="M10 20h4" />
    </svg>
  ),
  badge: (c: string, s = 13) => (
    <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 2 4 5v6c0 5 8 9 8 9s8-4 8-9V5l-8-3z" /><path d="M9 12l2 2 4-4" />
    </svg>
  ),
  cpu: (c: string, s = 13) => (
    <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="6" y="6" width="12" height="12" rx="2" /><path d="M9 2v2M15 2v2M9 20v2M15 20v2M2 9h2M2 15h2M20 9h2M20 15h2" />
    </svg>
  ),
  gear: (c: string, s = 17) => (
    <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="3" />
      <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 1 1-2.83 2.83l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 1 1-4 0v-.09a1.65 1.65 0 0 0-1-1.51 1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 1 1-2.83-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 1 1 0-4h.09a1.65 1.65 0 0 0 1.51-1 1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 1 1 2.83-2.83l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 1 1 4 0v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 1 1 2.83 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 1 1 0 4h-.09a1.65 1.65 0 0 0-1.51 1z" />
    </svg>
  ),
  lock: (c: string, s = 12) => (
    <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="4" y="11" width="16" height="9" rx="2" /><path d="M8 11V7a4 4 0 0 1 8 0v4" />
    </svg>
  ),
  scan: (c: string, s = 22) => (
    <svg width={s} height={s} viewBox="0 0 24 24" fill="none" stroke={c} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 7V5a2 2 0 0 1 2-2h2M17 3h2a2 2 0 0 1 2 2v2M21 17v2a2 2 0 0 1-2 2h-2M7 21H5a2 2 0 0 1-2-2v-2" /><path d="M3 12h18" />
    </svg>
  ),
}

export default function Popup() {
  const [result, setResult] = useState<DetectionResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [meter, setMeter] = useState(0)        // 0..100 animated
  const [shownScore, setShownScore] = useState(0)
  const raf = useRef<number | null>(null)

  useEffect(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id
      if (!tabId) { setLoading(false); return }
      chrome.storage.local.get(`result_${tabId}`, (data) => {
        const res = data[`result_${tabId}`] as DetectionResult | undefined
        if (res) {
          setResult(res)
          const target = res.prediction.score * 100
          const start = performance.now()
          const dur = 750
          const tick = (t: number) => {
            const p = Math.min(1, (t - start) / dur)
            const e = 1 - Math.pow(1 - p, 3) // easeOutCubic
            setMeter(target * e)
            setShownScore(target * e)
            if (p < 1) raf.current = requestAnimationFrame(tick)
          }
          raf.current = requestAnimationFrame(tick)
        }
        setLoading(false)
      })
    })
    return () => { if (raf.current) cancelAnimationFrame(raf.current) }
  }, [])

  const openOptions = () => chrome.runtime.openOptionsPage()
  const reloadTab = () => chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const id = tabs[0]?.id
    if (id) { chrome.tabs.reload(id); window.close() }
  })

  /* ── loading ──────────────────────────────────────────────────────── */
  if (loading) {
    return (
      <div className="pg-root" style={{ "--vc": "#2fd27a" } as React.CSSProperties}>
        <style dangerouslySetInnerHTML={{ __html: TOKENS }} />
        <div style={{ background: "var(--panel)", padding: "18px 18px 24px" }}>
          <Brand onOptions={openOptions} />
          <div style={{ height: 14, width: 150, marginTop: 18, background: "var(--panel-2)", borderRadius: 4, animation: "pg-pulse 1.4s infinite" }} />
          <div style={{ height: 30, width: 200, marginTop: 14, background: "var(--panel-2)", borderRadius: 6, animation: "pg-pulse 1.4s infinite" }} />
          <div style={{ height: 8, marginTop: 18, background: "var(--panel-2)", borderRadius: 99, animation: "pg-pulse 1.4s infinite" }} />
        </div>
        <div style={{ padding: 16, display: "flex", flexDirection: "column", gap: 10 }}>
          {[0, 1, 2].map(i => <div key={i} style={{ height: 46, background: "#efeeec", borderRadius: 9, animation: "pg-pulse 1.4s infinite" }} />)}
        </div>
      </div>
    )
  }

  /* ── empty ────────────────────────────────────────────────────────── */
  if (!result) {
    return (
      <div className="pg-root" style={{ "--vc": "#2fd27a" } as React.CSSProperties}>
        <style dangerouslySetInnerHTML={{ __html: TOKENS }} />
        <div style={{ background: "var(--panel)", padding: "18px 18px 22px" }}>
          <Brand onOptions={openOptions} />
        </div>
        <div style={{ padding: "32px 24px 26px", textAlign: "center" }}>
          <div style={{ display: "inline-flex", padding: 14, borderRadius: 14, background: "#f0efec", marginBottom: 14 }}>
            {I.scan("#6b7280", 24)}
          </div>
          <h2 style={{ margin: 0, fontSize: 16, fontWeight: 700, letterSpacing: "-.01em" }}>Nothing scanned yet</h2>
          <p style={{ margin: "8px 0 18px", fontSize: 13, lineHeight: 1.5, color: "var(--muted)" }}>
            Open a website and PhishGuard will check it on your device. Reload this tab to scan it now.
          </p>
          <button className="pg-btn" onClick={reloadTab}>Scan this page</button>
        </div>
      </div>
    )
  }

  /* ── result ───────────────────────────────────────────────────────── */
  const score = result.prediction.score
  const v = verdictFor(score)
  const VIcon = v.key === "CLEAN" ? I.shieldCheck : v.key === "SUSPICIOUS" ? I.alert : I.skull

  let host = result.url
  try { host = new URL(result.url).hostname.replace(/^www\./, "") } catch {}

  const explanations = result.explanations ?? []
  const isReputation = explanations.some(e => e.category === "Reputation") || result.prediction.source === "OVERRIDE"
  const mlSignals = explanations.filter(e => e.category !== "Reputation")
  const maxImp = Math.max(0.0001, ...mlSignals.map(s => s.importance || 0))

  const sourceLabel = isReputation ? "Trusted-sites list" : "On-device model"
  const SourceIcon = isReputation ? I.badge : I.cpu

  const prettyCat = (c: string) =>
    !c || c === "UNKNOWN" ? "Signal" : c.split("_").map(w => w[0] + w.slice(1).toLowerCase()).join(" ")

  return (
    <div className="pg-root" style={{ "--vc": v.glow } as React.CSSProperties}>
      <style dangerouslySetInnerHTML={{ __html: TOKENS }} />

      {/* ── HERO: detector readout panel (signature element) ─────────── */}
      <div style={{ background: "var(--panel)", padding: "18px 18px 22px", position: "relative", overflow: "hidden" }}>
        <Brand onOptions={openOptions} />

        {/* domain under inspection */}
        <div style={{ marginTop: 18, display: "flex", alignItems: "center", gap: 8 }}>
          <span style={{ width: 7, height: 7, borderRadius: 99, background: v.glow, boxShadow: `0 0 8px ${v.glow}`, flexShrink: 0 }} />
          <span title={host} style={{
            fontFamily: "var(--font-mono)", fontSize: 14, fontWeight: 500, color: "var(--panel-ink)",
            letterSpacing: "-.01em", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap"
          }}>{host}</span>
        </div>

        {/* verdict + score */}
        <div style={{ marginTop: 12, display: "flex", alignItems: "flex-end", justifyContent: "space-between", animation: "pg-fade-up .4s ease both" }}>
          <div style={{ display: "flex", alignItems: "center", gap: 9 }}>
            {VIcon(v.glow, 22)}
            <span style={{ fontSize: 19, fontWeight: 700, letterSpacing: "-.02em", color: "#fff" }}>{v.title}</span>
          </div>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 26, fontWeight: 600, color: v.glow, lineHeight: 1, fontVariantNumeric: "tabular-nums" }}>
            {shownScore.toFixed(0)}<span style={{ fontSize: 14, opacity: .7 }}>%</span>
          </span>
        </div>

        {/* scanning risk meter */}
        <div style={{ marginTop: 16 }}>
          <div style={{ position: "relative", height: 8, borderRadius: 99, background: "#1c222b", overflow: "hidden" }}>
            <div style={{
              position: "absolute", inset: 0, width: `${meter}%`, borderRadius: 99,
              background: v.glow, boxShadow: `0 0 10px ${v.glow}aa`,
              transition: "width .05s linear"
            }}>
              {/* sweeping sheen */}
              <span style={{ position: "absolute", top: 0, bottom: 0, width: 40, background: "linear-gradient(90deg,transparent,rgba(255,255,255,.55),transparent)", animation: "pg-sweep 1.6s ease-in-out 1" }} />
            </div>
            {/* threshold ticks at 50 / 85 */}
            <span style={{ position: "absolute", top: -2, bottom: -2, left: "50%", width: 1, background: "var(--panel-line)" }} />
            <span style={{ position: "absolute", top: -2, bottom: -2, left: "85%", width: 1, background: "var(--panel-line)" }} />
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", marginTop: 7, fontSize: 10, fontWeight: 500, color: "var(--panel-muted)", fontFamily: "var(--font-mono)" }}>
            <span style={{ color: v.key === "CLEAN" ? v.glow : undefined }}>safe</span>
            <span style={{ color: v.key === "SUSPICIOUS" ? v.glow : undefined }}>50 · caution</span>
            <span style={{ color: v.key === "PHISHING" ? v.glow : undefined }}>85 · phishing</span>
          </div>
        </div>

        {/* decision source chip */}
        <div style={{
          marginTop: 16, display: "inline-flex", alignItems: "center", gap: 7,
          padding: "5px 10px", borderRadius: 7, background: "var(--panel-2)", border: "1px solid var(--panel-line)"
        }}>
          {SourceIcon(v.glow, 13)}
          <span style={{ fontSize: 11, color: "var(--panel-muted)" }}>Decided by</span>
          <span style={{ fontFamily: "var(--font-mono)", fontSize: 11, fontWeight: 600, color: "var(--panel-ink)" }}>{sourceLabel}</span>
        </div>
      </div>

      {/* ── BODY: reasoning ──────────────────────────────────────────── */}
      <div style={{ padding: "16px 16px 0" }}>
        <h3 style={{ margin: "0 0 11px", fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: ".06em", color: "var(--muted)" }}>
          {isReputation ? "Why it's trusted" : "What the model weighed"}
        </h3>

        {isReputation ? (
          <div style={{ display: "flex", gap: 11, padding: 13, borderRadius: 10, background: v.wash, border: `1px solid ${v.ink}22`, animation: "pg-fade-up .45s ease both" }}>
            <div style={{ flexShrink: 0, marginTop: 1 }}>{I.badge(v.ink, 16)}</div>
            <p style={{ margin: 0, fontSize: 12.5, lineHeight: 1.5, color: "#3f4148" }}>
              <strong style={{ fontFamily: "var(--font-mono)", color: "var(--ink)" }}>{host}</strong> is on PhishGuard's
              bundled list of well-known, popular websites, so it was cleared without sending anything to the model.
            </p>
          </div>
        ) : mlSignals.length > 0 ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {mlSignals.map((s, i) => {
              const pct = Math.round(((s.importance || 0) / maxImp) * 100)
              return (
                <div key={i} className="pg-signal" style={{
                  padding: "10px 12px", borderRadius: 10, background: "var(--surface)", border: "1px solid var(--line)",
                  animation: `pg-fade-up .4s ease both`, animationDelay: `${i * 55}ms`
                }}>
                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: 8 }}>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 12, fontWeight: 600, color: "var(--ink)", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{s.feature}</span>
                    <span style={{ flexShrink: 0, fontSize: 9, fontWeight: 600, letterSpacing: ".03em", textTransform: "uppercase", color: "var(--muted)", background: "#f4f3f1", padding: "2px 6px", borderRadius: 5 }}>{prettyCat(s.category)}</span>
                  </div>
                  <p style={{ margin: "5px 0 8px", fontSize: 12, lineHeight: 1.4, color: "#54565d" }}>{s.description}</p>
                  {/* importance weight bar — honest signal strength, no misleading arrows */}
                  <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                    <div style={{ flex: 1, height: 4, borderRadius: 99, background: "#edece9" }}>
                      <div style={{ height: "100%", width: `${pct}%`, borderRadius: 99, background: v.ink, opacity: .85 }} />
                    </div>
                    <span style={{ fontFamily: "var(--font-mono)", fontSize: 9.5, color: "var(--muted)", fontVariantNumeric: "tabular-nums" }}>{(s.importance || 0).toFixed(3)}</span>
                  </div>
                </div>
              )
            })}
            <p style={{ margin: "2px 2px 0", fontSize: 10.5, lineHeight: 1.4, color: "var(--muted)" }}>
              Bars show each signal's overall weight in the model — not its direction for this site.
            </p>
          </div>
        ) : (
          <div style={{ padding: 13, borderRadius: 10, border: "1px dashed var(--line)", textAlign: "center", fontSize: 12, color: "var(--muted)" }}>
            No notable signals stood out.
          </div>
        )}
      </div>

      {/* ── FOOTER ───────────────────────────────────────────────────── */}
      <div style={{ margin: "16px 16px 14px", paddingTop: 12, borderTop: "1px solid var(--line)", display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ display: "inline-flex" }}>{I.lock("#15803d", 12)}</span>
          <span style={{ fontSize: 10.5, fontWeight: 600, color: "#15803d" }}>Runs 100% on your device</span>
        </div>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 10, color: "var(--muted)" }}>
          {fmt(result.processingTimeMs)}ms
        </span>
      </div>
    </div>
  )
}

/* ── brand row (lives inside the dark hero) ───────────────────────────── */
function Brand({ onOptions }: { onOptions: () => void }) {
  return (
    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <span style={{ display: "inline-flex" }}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="#2fd27a" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="M9 12l2 2 4-4" />
          </svg>
        </span>
        <span style={{ fontFamily: "var(--font-mono)", fontSize: 13, fontWeight: 700, letterSpacing: ".08em", color: "#fff" }}>PHISHGUARD</span>
        <span style={{ fontSize: 8.5, fontWeight: 600, letterSpacing: ".06em", color: "var(--panel-muted)", border: "1px solid var(--panel-line)", padding: "2px 5px", borderRadius: 4 }}>LOCAL AI</span>
      </div>
      <button className="pg-iconbtn" onClick={onOptions} title="Settings">{I.gear("currentColor", 17)}</button>
    </div>
  )
}
