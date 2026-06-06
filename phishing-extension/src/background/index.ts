import { MLRunner } from "../ml/onnx-runner";
import { ShapApproximator } from "../ml/shap-approximator";
import { urlCache } from "../utils/cache";
import type { FeatureVector, DetectionResult } from "../types";

const mlRunner = new MLRunner();
const shapApproximator = new ShapApproximator();

// Initialize models
Promise.all([mlRunner.init(), shapApproximator.init()]).catch(console.error);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "ANALYZE_PAGE") {
    (async () => {
      try {
        const { features, url } = message.payload;
        
        // 1. Check cache
        const cached = urlCache.get(url);
        if (cached) {
          sendResponse({ success: true, result: cached });
          return;
        }
        
        // 2. Run ML Model
        const startTime = Date.now();
        let mlPrediction = await mlRunner.predict(features);
        
        // 3. Google Safe Browsing API Fallback for borderline cases
        const storage = await chrome.storage.local.get(["riskThreshold", "useGsbFallback", "gsbKey"]);
        const threshold = storage.riskThreshold || 0.5;
        const useGsb = storage.useGsbFallback !== false;
        
        // If it's borderline (e.g., within 0.15 of threshold) and GSB is enabled
        if (useGsb && storage.gsbKey && Math.abs(mlPrediction.score - threshold) < 0.15) {
          try {
            const apiResp = await fetch(`https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${storage.gsbKey}`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({
                client: { clientId: "phishguard", clientVersion: "1.0.0" },
                threatInfo: {
                  threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                  platformTypes: ["ANY_PLATFORM"],
                  threatEntryTypes: ["URL"],
                  threatEntries: [{ url }]
                }
              })
            });
            const apiData = await apiResp.json();
            if (apiData.matches && apiData.matches.length > 0) {
              // Override ML prediction if GSB flags it
              mlPrediction.isPhishing = true;
              mlPrediction.score = 0.99;
            }
          } catch (apiErr) {
            console.error("GSB API Error:", apiErr);
          }
        }
        
        // 4. Generate Explanations
        const explanations = await shapApproximator.getExplanations(features);
        
        const result: DetectionResult = {
          url,
          timestamp: Date.now(),
          prediction: {
            ...mlPrediction,
            source: 'ML'
          },
          explanations,
          processingTimeMs: Date.now() - startTime
        };

        // Save to cache
        urlCache.set(url, result);
        
        // Save to storage for the popup UI
        const tabId = sender.tab?.id;
        if (tabId) {
          await chrome.storage.local.set({ [`result_${tabId}`]: result });
        }

        // Update badge
        if (result.prediction.isPhishing) {
          chrome.action.setBadgeText({ text: "!", tabId });
          chrome.action.setBadgeBackgroundColor({ color: "#FF0000", tabId });
        } else {
          chrome.action.setBadgeText({ text: "✓", tabId });
          chrome.action.setBadgeBackgroundColor({ color: "#00FF00", tabId });
        }

        sendResponse({ success: true, result });
      } catch (e) {
        console.error("Analysis failed:", e);
        sendResponse({ success: false, error: String(e) });
      }
    })();
    return true;
  }
});

// Clean up storage when tabs are closed
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.local.remove(`result_${tabId}`);
});
