import { useState, useEffect } from "react"
import type { DetectionResult } from "./types"

export default function Popup() {
  const [result, setResult] = useState<DetectionResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [animatedWidth, setAnimatedWidth] = useState(0)

  useEffect(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id
      if (tabId) {
        chrome.storage.local.get(`result_${tabId}`, (data) => {
          if (data[`result_${tabId}`]) {
            const res = data[`result_${tabId}`]
            setResult(res)
            // Trigger animation after setting result
            setTimeout(() => {
              setAnimatedWidth(res.prediction.score * 100)
            }, 100)
          }
          setLoading(false)
        })
      } else {
        setLoading(false)
      }
    })
  }, [])

  // Action to open extension options
  const openOptions = () => {
    chrome.runtime.openOptionsPage()
  }

  // Action to request manual re-analysis by reloading current tab
  const reloadTab = () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id
      if (tabId) {
        chrome.tabs.reload(tabId)
        window.close() // Close popup
      }
    })
  }

  // Styles
  const fontStack = '"Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, sans-serif'
  
  if (loading) {
    return (
      <div style={{
        width: 360,
        padding: 24,
        boxSizing: "border-box",
        fontFamily: fontStack,
        backgroundColor: "#fafaf9",
        display: "flex",
        flexDirection: "column",
        gap: 16
      }}>
        {/* Loading skeleton */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
          <div style={{ width: 100, height: 20, backgroundColor: "#e4e4e7", borderRadius: 4, animation: "pulse 1.5s infinite ease-in-out" }} />
          <div style={{ width: 24, height: 24, backgroundColor: "#e4e4e7", borderRadius: "50%", animation: "pulse 1.5s infinite ease-in-out" }} />
        </div>
        <div style={{ height: 60, backgroundColor: "#e4e4e7", borderRadius: 8, animation: "pulse 1.5s infinite ease-in-out" }} />
        <div style={{ height: 16, backgroundColor: "#e4e4e7", borderRadius: 4, animation: "pulse 1.5s infinite ease-in-out" }} />
        <div style={{ height: 120, backgroundColor: "#e4e4e7", borderRadius: 8, animation: "pulse 1.5s infinite ease-in-out" }} />
        <style dangerouslySetInnerHTML={{ __html: `
          @keyframes pulse {
            0% { opacity: 0.6; }
            50% { opacity: 0.3; }
            100% { opacity: 0.6; }
          }
        `}} />
      </div>
    )
  }

  if (!result) {
    return (
      <div style={{
        width: 360,
        padding: 24,
        boxSizing: "border-box",
        fontFamily: fontStack,
        backgroundColor: "#fafaf9",
        color: "#18181b",
        textAlign: "center"
      }}>
        <div style={{ display: "flex", justifyContent: "center", marginBottom: 12 }}>
          <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="#71717a" strokeWidth="1.5">
            <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
          </svg>
        </div>
        <h2 style={{ fontSize: 18, fontWeight: 600, margin: "0 0 8px 0" }}>No Analysis Available</h2>
        <p style={{ fontSize: 13, color: "#52525b", lineHeight: 1.5, margin: "0 0 16px 0" }}>
          Navigate to a webpage or reload the current tab to analyze it for phishing indicators.
        </p>
        <button
          onClick={reloadTab}
          style={{
            padding: "8px 16px",
            backgroundColor: "#18181b",
            color: "#ffffff",
            border: "none",
            borderRadius: 6,
            fontSize: 13,
            fontWeight: 500,
            cursor: "pointer",
            outline: "none",
            transition: "background-color 0.2s"
          }}
        >
          Analyze Page
        </button>
      </div>
    )
  }

  const { score } = result.prediction
  const riskPercent = (score * 100).toFixed(1)

  // 3-Tier Verdict System
  let verdict: "CLEAN" | "SUSPICIOUS" | "PHISHING"
  let verdictColor: string
  let verdictBg: string
  let verdictBorder: string
  let verdictTitle: string
  let verdictIcon: JSX.Element

  if (score < 0.50) {
    verdict = "CLEAN"
    verdictColor = "#047857" // emerald-700
    verdictBg = "#ecfdf5"    // emerald-50
    verdictBorder = "#10b981" // emerald-500
    verdictTitle = "Safe Website"
    verdictIcon = (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={verdictColor} strokeWidth="2.5">
        <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z" />
      </svg>
    )
  } else if (score <= 0.85) {
    verdict = "SUSPICIOUS"
    verdictColor = "#b45309" // amber-700
    verdictBg = "#fffbeb"    // amber-50
    verdictBorder = "#f59e0b" // amber-500
    verdictTitle = "Suspicious Activity"
    verdictIcon = (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={verdictColor} strokeWidth="2.5">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z" />
      </svg>
    )
  } else {
    verdict = "PHISHING"
    verdictColor = "#b91c1c" // red-700
    verdictBg = "#fef2f2"    // red-50
    verdictBorder = "#ef4444" // red-500
    verdictTitle = "Phishing Site Blocked"
    verdictIcon = (
      <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke={verdictColor} strokeWidth="2.5">
        <path strokeLinecap="round" strokeLinejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
    )
  }

  // Format category name for badge
  const formatCategory = (cat: string) => {
    if (!cat || cat === "UNKNOWN") return "General"
    return cat.split("_").map(word => word.charAt(0) + word.slice(1).toLowerCase()).join(" ")
  }

  return (
    <div style={{
      width: 360,
      padding: 20,
      boxSizing: "border-box",
      fontFamily: fontStack,
      backgroundColor: "#fafaf9", // Warm off-white
      color: "#18181b",
      display: "flex",
      flexDirection: "column",
      gap: 16
    }}>
      {/* Top Header */}
      <div style={{
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center"
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
          <span style={{ fontSize: 16, fontWeight: 700, letterSpacing: "-0.025em" }}>PHISHGUARD</span>
          <span style={{
            fontSize: 9,
            fontWeight: 600,
            backgroundColor: "#e4e4e7",
            color: "#52525b",
            padding: "2px 6px",
            borderRadius: 4,
            textTransform: "uppercase"
          }}>v1.0 Local AI</span>
        </div>
        <button
          onClick={openOptions}
          style={{
            background: "none",
            border: "none",
            cursor: "pointer",
            color: "#71717a",
            padding: 4,
            borderRadius: 4,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            transition: "background-color 0.2s"
          }}
          title="Settings"
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9.594 3.94c.09-.542.56-.94 1.11-.94h2.593c.55 0 1.02.398 1.11.94l.213 1.281c.063.374.313.686.645.87.074.04.147.083.22.127.324.196.72.257 1.075.124l1.217-.456a1.125 1.125 0 011.37.49l1.296 2.247a1.125 1.125 0 01-.26 1.43l-1.003.828c-.293.241-.438.613-.43.992a7.723 7.723 0 010 .255c-.008.378.137.75.43.991l1.004.827c.424.35.534.954.26 1.43l-1.298 2.247a1.125 1.125 0 01-1.369.491l-1.217-.456c-.355-.133-.75-.072-1.076.124a6.47 6.47 0 01-.22.128c-.331.183-.581.495-.644.869l-.213 1.281c-.09.543-.56.94-1.11.94h-2.594c-.55 0-1.019-.398-1.11-.94l-.213-1.281c-.062-.374-.312-.686-.644-.87a6.52 6.52 0 01-.22-.127c-.325-.196-.72-.257-1.076-.124l-1.217.456a1.125 1.125 0 01-1.369-.49l-1.297-2.247a1.125 1.125 0 01.26-1.43l1.004-.827c.292-.24.437-.613.43-.991a6.936 6.936 0 010-.255c.007-.38-.138-.751-.43-.992l-1.004-.827a1.125 1.125 0 01-.26-1.43l1.297-2.247a1.125 1.125 0 011.37-.491l1.216.456c.356.133.751.072 1.076-.124.072-.044.146-.086.22-.128.332-.183.582-.495.644-.869l.214-1.28z" />
            <circle cx="12" cy="12" r="3" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </button>
      </div>

      {/* Main Alert Card */}
      <div style={{
        padding: 16,
        borderRadius: 10,
        backgroundColor: verdictBg,
        border: `1px solid ${verdictBorder}`,
        display: "flex",
        flexDirection: "column",
        gap: 8,
        boxShadow: "0 1px 3px rgba(0,0,0,0.02)"
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          {verdictIcon}
          <span style={{
            fontSize: 14,
            fontWeight: 700,
            color: verdictColor,
            textTransform: "uppercase",
            letterSpacing: "0.025em"
          }}>{verdictTitle}</span>
        </div>
        
        {/* Score & Verdict Text */}
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
          <span style={{ fontSize: 12, color: "#52525b" }}>Risk Assessment</span>
          <span style={{
            fontSize: 24,
            fontWeight: 800,
            color: verdictColor,
            fontVariantNumeric: "tabular-nums"
          }}>{riskPercent}%</span>
        </div>
      </div>

      {/* Signature Element: Risk Gauge */}
      <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
        <div style={{ position: "relative", height: 8, backgroundColor: "#e4e4e7", borderRadius: 4, overflow: "hidden" }}>
          <div style={{
            position: "absolute",
            top: 0,
            left: 0,
            height: "100%",
            width: `${animatedWidth}%`,
            backgroundColor: verdictColor,
            borderRadius: 4,
            transition: "width 0.8s cubic-bezier(0.16, 1, 0.3, 1)"
          }} />
        </div>
        {/* Threshold Markers */}
        <div style={{ display: "flex", justifyContent: "space-between", fontSize: 10, color: "#71717a", fontWeight: 500 }}>
          <span>Clean</span>
          <span style={{ color: score >= 0.50 && score <= 0.85 ? verdictColor : "#71717a" }}>Suspicious (50%)</span>
          <span style={{ color: score > 0.85 ? verdictColor : "#71717a" }}>Phishing (85%)</span>
        </div>
      </div>

      {/* Why This Decision (SHAP Explanations) */}
      <div style={{ display: "flex", flexDirection: "column", gap: 10, marginTop: 4 }}>
        <h3 style={{ fontSize: 12, fontWeight: 700, textTransform: "uppercase", letterSpacing: "0.05em", color: "#52525b", margin: 0 }}>
          Key Risk Indicators (SHAP)
        </h3>

        {result.explanations && result.explanations.length > 0 ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
            {result.explanations.map((exp, i) => {
              // Decide direction
              // 1. If it's IsHTTPS and value is 0 (unencrypted) it increases risk.
              // 2. If it's DomainTitleMatchScore and <= 0.5 it increases risk.
              // 3. For others, positive values generally indicate a phishing feature.
              // Let's inspect description direction
              const isPhishRisk = exp.description.toLowerCase().includes("increases") || 
                                  exp.description.toLowerCase().includes("suspicious") || 
                                  exp.description.toLowerCase().includes("missing") ||
                                  (exp.feature === "IsHTTPS" && exp.value === 0) ||
                                  (exp.feature === "DomainTitleMatchScore" && exp.value <= 0.5);
              
              const iconColor = isPhishRisk ? "#ef4444" : "#10b981"
              const cardBorderColor = isPhishRisk ? "rgba(239, 68, 68, 0.1)" : "rgba(16, 185, 129, 0.1)"
              
              return (
                <div key={i} style={{
                  padding: 10,
                  borderRadius: 8,
                  backgroundColor: "#ffffff",
                  border: `1px solid ${cardBorderColor}`,
                  boxShadow: "0 1px 2px rgba(0,0,0,0.01)",
                  display: "flex",
                  alignItems: "flex-start",
                  gap: 8
                }}>
                  {/* Directional Icon */}
                  <div style={{ marginTop: 2 }}>
                    {isPhishRisk ? (
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={iconColor} strokeWidth="3">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 4.5v15m0-15l7.5 7.5m-7.5-7.5L4.5 12" />
                      </svg>
                    ) : (
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke={iconColor} strokeWidth="3">
                        <path strokeLinecap="round" strokeLinejoin="round" d="M12 19.5v-15m0 15l7.5-7.5m-7.5 7.5l-7.5-7.5" />
                      </svg>
                    )}
                  </div>
                  
                  {/* Feature Content */}
                  <div style={{ display: "flex", flexDirection: "column", gap: 3 }}>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <span style={{ fontSize: 11, fontWeight: 700, color: "#18181b" }}>{exp.feature}</span>
                      <span style={{
                        fontSize: 9,
                        fontWeight: 600,
                        backgroundColor: "#f4f4f5",
                        color: "#71717a",
                        padding: "1px 4px",
                        borderRadius: 3
                      }}>
                        {formatCategory(exp.category)}
                      </span>
                    </div>
                    <span style={{ fontSize: 12, color: "#52525b", lineHeight: 1.4 }}>{exp.description}</span>
                  </div>
                </div>
              )
            })}
          </div>
        ) : (
          <div style={{
            padding: 12,
            borderRadius: 8,
            border: "1px dashed #e4e4e7",
            textAlign: "center",
            fontSize: 12,
            color: "#71717a"
          }}>
            No significant risk indicators identified.
          </div>
        )}
      </div>

      {/* Footer */}
      <div style={{
        marginTop: 4,
        paddingTop: 12,
        borderTop: "1px solid #e4e4e7",
        display: "flex",
        justifyContent: "space-between",
        alignItems: "center"
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 4 }}>
          <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="2.5">
            <path strokeLinecap="round" strokeLinejoin="round" d="M9 12.75L11.25 15 15 9.75M21 12c0 1.268-.63 2.39-1.593 3.068a3.745 3.745 0 01-1.043 3.296 3.745 3.745 0 01-3.296 1.043A3.745 3.745 0 0112 21c-1.268 0-2.39-.63-3.068-1.593a3.746 3.746 0 01-3.296-1.043 3.745 3.745 0 01-1.043-3.296A3.745 3.745 0 013 12c0-1.268.63-2.39 1.593-3.068a3.745 3.745 0 011.043-3.296 3.746 3.746 0 013.296-1.043A3.746 3.746 0 0112 3c1.268 0 2.39.63 3.068 1.593a3.746 3.746 0 013.296 1.043 3.746 3.746 0 011.043 3.296A3.745 3.745 0 0121 12z" />
          </svg>
          <span style={{ fontSize: 10, fontWeight: 600, color: "#047857" }}>100% On-Device AI</span>
        </div>
        
        <span style={{
          fontSize: 10,
          color: "#71717a",
          fontFamily: "Consolas, Monaco, monospace"
        }}>
          {result.processingTimeMs}ms
        </span>
      </div>
    </div>
  )
}
