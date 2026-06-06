import { useState, useEffect } from "react"
import type { DetectionResult } from "./types"

export default function Popup() {
  const [result, setResult] = useState<DetectionResult | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id
      if (tabId) {
        chrome.storage.local.get(`result_${tabId}`, (data) => {
          if (data[`result_${tabId}`]) {
            setResult(data[`result_${tabId}`])
          }
          setLoading(false)
        })
      } else {
        setLoading(false)
      }
    })
  }, [])

  if (loading) {
    return <div style={{ padding: 16, width: 320 }}>Loading analysis...</div>
  }

  if (!result) {
    return (
      <div style={{ padding: 16, width: 320, fontFamily: "sans-serif" }}>
        <h2>PhishGuard AI</h2>
        <p>No analysis available for this page yet. Try refreshing.</p>
      </div>
    )
  }

  const { isPhishing, score } = result.prediction
  const riskPercent = (score * 100).toFixed(1)
  
  const isHighRisk = isPhishing
  const bgColor = isHighRisk ? "#fee2e2" : "#dcfce7"
  const borderColor = isHighRisk ? "#ef4444" : "#22c55e"
  const textColor = isHighRisk ? "#b91c1c" : "#15803d"

  return (
    <div style={{ padding: 16, width: 320, fontFamily: "sans-serif" }}>
      <h2 style={{ margin: "0 0 16px" }}>PhishGuard AI</h2>
      
      <div style={{
        padding: 16, 
        borderRadius: 8, 
        backgroundColor: bgColor,
        border: `1px solid ${borderColor}`
      }}>
        <h3 style={{ margin: "0 0 8px", color: textColor }}>
          {isHighRisk ? "⚠️ High Risk - Phishing Detected" : "✅ Safe / Legitimate"}
        </h3>
        <p style={{ margin: 0, fontWeight: "bold" }}>
          Risk Score: {riskPercent}%
        </p>
      </div>

      {result.explanations && result.explanations.length > 0 && (
        <div style={{ marginTop: 16 }}>
          <h4 style={{ margin: "0 0 8px" }}>Why this decision? (SHAP)</h4>
          <ul style={{ margin: 0, paddingLeft: 20, fontSize: 13, color: "#444" }}>
            {result.explanations.map((exp, i) => (
              <li key={i} style={{ marginBottom: 4 }}>
                <strong>{exp.feature}</strong>: {exp.description} 
              </li>
            ))}
          </ul>
        </div>
      )}

      <p style={{ fontSize: 11, color: "#888", marginTop: 20, textAlign: "center" }}>
        Model runs 100% locally. Processed in {result.processingTimeMs}ms.
      </p>
    </div>
  )
}
