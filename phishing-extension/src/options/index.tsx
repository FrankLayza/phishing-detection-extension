import { useState, useEffect } from "react";
import { Storage } from "@plasmohq/storage";

const storage = new Storage();

export default function Options() {
  const [gsbKey, setGsbKey] = useState<string>("");
  const [useGsb, setUseGsb] = useState<boolean>(true);
  const [showToast, setShowToast] = useState<boolean>(false);
  const [showPassword, setShowPassword] = useState<boolean>(false);

  useEffect(() => {
    storage.get("gsbKey").then((val) => {
      if (val) setGsbKey(val as string);
    });
    storage.get("useGsbFallback").then((val) => {
      if (val !== undefined) setUseGsb(val as unknown as boolean);
    });
  }, []);

  const saveOptions = async () => {
    await storage.set("gsbKey", gsbKey);
    await storage.set("useGsbFallback", useGsb);
    
    // Show success toast
    setShowToast(true);
    setTimeout(() => {
      setShowToast(false);
    }, 3000);
  };

  const fontStack = '"Segoe UI", -apple-system, BlinkMacSystemFont, Roboto, sans-serif';

  return (
    <div style={{
      minHeight: "100vh",
      backgroundColor: "#fafaf9",
      padding: "60px 20px",
      boxSizing: "border-box",
      fontFamily: fontStack,
      color: "#18181b"
    }}>
      <div style={{
        maxWidth: 600,
        margin: "0 auto",
        display: "flex",
        flexDirection: "column",
        gap: 24
      }}>
        {/* Header Block */}
        <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
            <span style={{ fontSize: 24, fontWeight: 800, letterSpacing: "-0.03em" }}>PHISHGUARD</span>
            <span style={{
              fontSize: 11,
              fontWeight: 600,
              backgroundColor: "#18181b",
              color: "#ffffff",
              padding: "2px 8px",
              borderRadius: 6
            }}>Control Panel</span>
          </div>
          <p style={{ margin: 0, fontSize: 14, color: "#71717a" }}>
            Configure local machine learning inference variables and fallback services.
          </p>
        </div>

        {/* Fallback Services Card */}
        <div style={{
          backgroundColor: "#ffffff",
          borderRadius: 12,
          border: "1px solid #e4e4e7",
          padding: 24,
          boxShadow: "0 1px 3px rgba(0,0,0,0.02)",
          display: "flex",
          flexDirection: "column",
          gap: 20
        }}>
          <div>
            <h2 style={{ margin: "0 0 4px 0", fontSize: 16, fontWeight: 700 }}>Defense in Depth</h2>
            <p style={{ margin: 0, fontSize: 13, color: "#71717a", lineHeight: 1.5 }}>
              For scores near the boundary between clean and suspicious, query Google Safe Browsing as an external verification layer.
            </p>
          </div>

          <div style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            paddingTop: 12,
            borderTop: "1px solid #f4f4f5"
          }}>
            <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
              <span style={{ fontSize: 14, fontWeight: 600 }}>Enable GSB Fallback</span>
              <span style={{ fontSize: 12, color: "#a1a1aa" }}>Queries safe-browsing API on borderline cases</span>
            </div>
            
            {/* Custom Toggle Switch */}
            <label style={{
              position: "relative",
              display: "inline-block",
              width: 44,
              height: 24,
              cursor: "pointer"
            }}>
              <input 
                type="checkbox" 
                checked={useGsb} 
                onChange={(e) => setUseGsb(e.target.checked)} 
                style={{ opacity: 0, width: 0, height: 0 }}
              />
              <span style={{
                position: "absolute",
                top: 0, left: 0, right: 0, bottom: 0,
                backgroundColor: useGsb ? "#10b981" : "#e4e4e7",
                borderRadius: 24,
                transition: "background-color 0.2s cubic-bezier(0.4, 0, 0.2, 1)",
                display: "flex",
                alignItems: "center"
              }}>
                <span style={{
                  height: 18,
                  width: 18,
                  left: useGsb ? 22 : 4,
                  bottom: 3,
                  position: "absolute",
                  backgroundColor: "#ffffff",
                  borderRadius: "50%",
                  transition: "left 0.2s cubic-bezier(0.4, 0, 0.2, 1)",
                  boxShadow: "0 1px 2px rgba(0, 0, 0, 0.1)"
                }} />
              </span>
            </label>
          </div>

          {useGsb && (
            <div style={{
              display: "flex",
              flexDirection: "column",
              gap: 8,
              paddingTop: 16,
              borderTop: "1px solid #f4f4f5"
            }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline" }}>
                <label style={{ fontSize: 13, fontWeight: 600, color: "#3f3f46" }}>Google Safe Browsing API Key</label>
                <span style={{
                  fontSize: 10,
                  fontWeight: 600,
                  color: gsbKey ? "#047857" : "#b91c1c",
                  backgroundColor: gsbKey ? "#ecfdf5" : "#fef2f2",
                  padding: "2px 6px",
                  borderRadius: 4
                }}>
                  {gsbKey ? "Configured" : "Missing Key"}
                </span>
              </div>
              
              <div style={{ position: "relative" }}>
                <input 
                  type={showPassword ? "text" : "password"} 
                  value={gsbKey} 
                  onChange={(e) => setGsbKey(e.target.value)} 
                  placeholder="AIzaSy..."
                  style={{
                    width: "100%",
                    padding: "10px 40px 10px 12px",
                    boxSizing: "border-box",
                    borderRadius: 6,
                    border: "1px solid #e4e4e7",
                    fontSize: 13,
                    fontFamily: "Consolas, Monaco, monospace",
                    backgroundColor: "#fafaf9",
                    outline: "none",
                    transition: "border-color 0.2s"
                  }}
                />
                
                {/* Password Visibility Button */}
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  style={{
                    position: "absolute",
                    right: 8,
                    top: "50%",
                    transform: "translateY(-50%)",
                    background: "none",
                    border: "none",
                    cursor: "pointer",
                    color: "#71717a",
                    padding: 4,
                    display: "flex",
                    alignItems: "center"
                  }}
                >
                  {showPassword ? (
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M3.98 8.223A10.477 10.477 0 001.934 12C3.226 16.338 7.244 19.5 12 19.5c.993 0 1.953-.138 2.863-.395M6.228 6.228A10.45 10.45 0 0112 4.5c4.756 0 8.773 3.162 10.065 7.498a10.523 10.523 0 01-4.293 5.774M6.228 6.228L3 3m3.228 3.228l3.65 3.65m7.824 7.824L21 21m-3.228-3.228l-3.65-3.65m0 0a3 3 0 10-4.243-4.243m4.242 4.242L9.88 9.88" />
                    </svg>
                  ) : (
                    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <path strokeLinecap="round" strokeLinejoin="round" d="M2.036 12.322a1.012 1.012 0 010-.639C3.423 7.51 7.36 4.5 12 4.5c4.638 0 8.573 3.007 9.963 7.178.07.207.07.431 0 .639C20.577 16.49 16.64 19.5 12 19.5c-4.638 0-8.573-3.007-9.963-7.178z" />
                      <circle cx="12" cy="12" r="3" />
                    </svg>
                  )}
                </button>
              </div>
              <span style={{ fontSize: 11, color: "#a1a1aa", lineHeight: 1.4 }}>
                Requires a Google Cloud Platform account with the Google Safe Browsing API enabled.
              </span>
            </div>
          )}
        </div>

        {/* Action Buttons */}
        <div style={{ display: "flex", justifyContent: "flex-end" }}>
          <button 
            onClick={saveOptions}
            style={{ 
              padding: "10px 24px", 
              backgroundColor: "#18181b", 
              color: "#ffffff", 
              border: "none", 
              borderRadius: 6,
              cursor: "pointer",
              fontSize: 14,
              fontWeight: 600,
              boxShadow: "0 1px 2px rgba(0,0,0,0.05)",
              transition: "background-color 0.2s"
            }}
          >
            Save Settings
          </button>
        </div>
      </div>

      {/* Success Toast */}
      <div style={{
        position: "fixed",
        bottom: 24,
        right: 24,
        backgroundColor: "#18181b",
        color: "#ffffff",
        padding: "12px 20px",
        borderRadius: 8,
        fontSize: 13,
        fontWeight: 500,
        boxShadow: "0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1)",
        display: "flex",
        alignItems: "center",
        gap: 8,
        transform: showToast ? "translateY(0)" : "translateY(100px)",
        opacity: showToast ? 1 : 0,
        transition: "transform 0.3s cubic-bezier(0.16, 1, 0.3, 1), opacity 0.3s ease",
        pointerEvents: showToast ? "auto" : "none",
        zIndex: 9999
      }}>
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#10b981" strokeWidth="3">
          <path strokeLinecap="round" strokeLinejoin="round" d="M4.5 12.75l6 6 9-13.5" />
        </svg>
        Settings saved successfully!
      </div>
    </div>
  );
}
