import { MLRunner } from "../ml/onnx-runner";
import type { FeatureVector, DetectionResult } from "../types";

const mlRunner = new MLRunner();

// Initialize model as soon as background worker starts
mlRunner.init().catch(console.error);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "ANALYZE_PAGE") {
    (async () => {
      try {
        const { features, url } = message.payload;
        
        // 1. Run ML Model
        const mlPrediction = await mlRunner.predict(features);
        
        // 2. We can add Google Safe Browsing API check here 
        // For borderline cases, just like test_url.py!
        let finalVerdict = mlPrediction;
        
        const result: DetectionResult = {
          url,
          timestamp: Date.now(),
          prediction: {
            ...finalVerdict,
            source: 'ML'
          },
          explanations: [], // Can be hydrated by SHAP mapping
          processingTimeMs: 0
        };

        // If high risk, we can show a warning badge or block
        if (result.prediction.isPhishing) {
          chrome.action.setBadgeText({ text: "!", tabId: sender.tab?.id });
          chrome.action.setBadgeBackgroundColor({ color: "#FF0000", tabId: sender.tab?.id });
        } else {
          chrome.action.setBadgeText({ text: "✓", tabId: sender.tab?.id });
          chrome.action.setBadgeBackgroundColor({ color: "#00FF00", tabId: sender.tab?.id });
        }

        sendResponse({ success: true, result });
      } catch (e) {
        console.error("Analysis failed:", e);
        sendResponse({ success: false, error: String(e) });
      }
    })();
    return true; // Indicates async response
  }
});
