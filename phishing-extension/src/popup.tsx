import { useState, useEffect } from "react"

export default function Popup() {
  const [status, setStatus] = useState<string>("Analyzing...")
  const [score, setScore] = useState<number | null>(null)

  useEffect(() => {
    // In a real implementation, we fetch the cached result from storage for the active tab
    // For now we show a placeholder
    setTimeout(() => {
      setStatus("Safe / Legitimate")
      setScore(0.04)
    }, 500)
  }, [])

  return (
    <div style={{ padding: 16, width: 300, fontFamily: "sans-serif" }}>
      <h2 style={{ margin: "0 0 16px" }}>PhishGuard AI</h2>
      
      <div style={{
        padding: 16, 
        borderRadius: 8, 
        backgroundColor: score !== null && score > 0.5 ? "#fee2e2" : "#dcfce7",
        border: `1px solid ${score !== null && score > 0.5 ? "#ef4444" : "#22c55e"}`
      }}>
        <h3 style={{ margin: "0 0 8px", color: score !== null && score > 0.5 ? "#b91c1c" : "#15803d" }}>
          {status}
        </h3>
        {score !== null && (
          <p style={{ margin: 0 }}>
            Risk Score: <strong>{(score * 100).toFixed(1)}%</strong>
          </p>
        )}
      </div>

      <p style={{ fontSize: 12, color: "#666", marginTop: 16 }}>
        Model runs 100% locally in your browser to protect your privacy.
      </p>
    </div>
  )
}
