import { useState, useEffect } from "react";
import { Storage } from "@plasmohq/storage";

const storage = new Storage();

export default function Options() {
  const [threshold, setThreshold] = useState<number>(0.5);
  const [gsbKey, setGsbKey] = useState<string>("");
  const [useGsb, setUseGsb] = useState<boolean>(true);

  useEffect(() => {
    storage.get("riskThreshold").then((val) => {
      if (val) setThreshold(Number(val));
    });
    storage.get("gsbKey").then((val) => {
      if (val) setGsbKey(val as string);
    });
    storage.get("useGsbFallback").then((val) => {
      if (val !== undefined) setUseGsb(val as boolean);
    });
  }, []);

  const saveOptions = async () => {
    await storage.set("riskThreshold", threshold);
    await storage.set("gsbKey", gsbKey);
    await storage.set("useGsbFallback", useGsb);
    alert("Settings saved!");
  };

  return (
    <div style={{ padding: 40, maxWidth: 600, margin: "0 auto", fontFamily: "sans-serif" }}>
      <h1>PhishGuard Settings</h1>

      <div style={{ marginBottom: 24, padding: 20, border: "1px solid #ccc", borderRadius: 8 }}>
        <h2>Detection Sensitivity</h2>
        <p style={{ color: "#666" }}>
          Adjust the risk score threshold (0.0 to 1.0) above which a page is flagged as phishing. 
          Current: {threshold}
        </p>
        <input 
          type="range" 
          min="0.1" 
          max="0.9" 
          step="0.05" 
          value={threshold} 
          onChange={(e) => setThreshold(Number(e.target.value))} 
          style={{ width: "100%" }}
        />
      </div>

      <div style={{ marginBottom: 24, padding: 20, border: "1px solid #ccc", borderRadius: 8 }}>
        <h2>Defense-in-Depth (Google Safe Browsing)</h2>
        <p style={{ color: "#666" }}>
          For borderline cases (e.g. risk score between 40% and 70%), PhishGuard can query the Google Safe Browsing API as a fallback.
        </p>
        
        <div style={{ marginBottom: 12 }}>
          <label style={{ display: "flex", alignItems: "center", cursor: "pointer" }}>
            <input 
              type="checkbox" 
              checked={useGsb} 
              onChange={(e) => setUseGsb(e.target.checked)} 
              style={{ marginRight: 8 }}
            />
            Enable GSB Fallback
          </label>
        </div>

        {useGsb && (
          <div>
            <label style={{ display: "block", marginBottom: 4 }}>GSB API Key:</label>
            <input 
              type="password" 
              value={gsbKey} 
              onChange={(e) => setGsbKey(e.target.value)} 
              placeholder="AIzaSy..."
              style={{ width: "100%", padding: 8, boxSizing: "border-box" }}
            />
          </div>
        )}
      </div>

      <button 
        onClick={saveOptions}
        style={{ 
          padding: "10px 20px", 
          backgroundColor: "#2563eb", 
          color: "white", 
          border: "none", 
          borderRadius: 4,
          cursor: "pointer",
          fontSize: 16
        }}
      >
        Save Settings
      </button>
    </div>
  );
}
