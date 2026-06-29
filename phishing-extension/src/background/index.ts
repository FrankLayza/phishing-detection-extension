import { MLRunner } from "../ml/rf-inference";
import { ShapApproximator } from "../ml/shap-approximator";
import { urlCache } from "../utils/cache";
import type { FeatureVector, DetectionResult } from "../types";

const mlRunner = new MLRunner();
const shapApproximator = new ShapApproximator();

// ---------------------------------------------------------------------------
// Reputation allowlist (top-sites). URL-only ML cannot distinguish a popular
// legitimate bare domain (google.com) from phishing on a reputable TLD, because
// the signal isn't in the URL string. We therefore short-circuit known-popular
// registrable domains to CLEAN and let the ML model handle unknown domains and
// typosquats. The list is bundled on-device, so this stays privacy-preserving.
// ---------------------------------------------------------------------------
let allowlist: Set<string> | null = null;

async function initAllowlist() {
  if (allowlist) return;
  try {
    const resp = await fetch(chrome.runtime.getURL("assets/top_domains.json"));
    allowlist = new Set<string>(await resp.json());
    console.log(`PhishGuard: Reputation allowlist loaded (${allowlist.size} domains)`);
  } catch (e) {
    console.error("PhishGuard: failed to load allowlist", e);
    allowlist = new Set();
  }
}

/** True if the URL's registrable domain (eTLD+1) is a known-popular site. */
function isAllowlisted(url: string): boolean {
  if (!allowlist || allowlist.size === 0) return false;
  let host: string;
  try {
    host = new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return false;
  }
  const labels = host.split(".");
  // Test the last 2 and last 3 labels against the PSL-derived allowlist
  // (covers bbc.co.uk via "bbc.co.uk", google.com via "google.com").
  for (let take = 2; take <= 3 && take <= labels.length; take++) {
    if (allowlist.has(labels.slice(-take).join("."))) return true;
  }
  return false;
}

// Initialize models + allowlist
Promise.all([mlRunner.init(), shapApproximator.init(), initAllowlist()]).catch(console.error);

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

        const startTime = Date.now();

        // 2. Reputation fast-path: known-popular domain → CLEAN (skip ML)
        await initAllowlist();
        if (isAllowlisted(url)) {
          const repResult: DetectionResult = {
            url,
            timestamp: Date.now(),
            prediction: { isPhishing: false, score: 0.05, source: 'OVERRIDE' },
            explanations: [{
              feature: "Reputation",
              value: 1,
              importance: 1,
              description: "Recognized as a well-known, popular website (reputation allowlist)",
              category: "Reputation",
            }],
            processingTimeMs: Date.now() - startTime,
          };
          urlCache.set(url, repResult);
          const repTabId = sender.tab?.id;
          if (repTabId) {
            await chrome.storage.local.set({ [`result_${repTabId}`]: repResult });
            chrome.action.setBadgeText({ text: "✓", tabId: repTabId });
            chrome.action.setBadgeBackgroundColor({ color: "#00FF00", tabId: repTabId });
          }
          sendResponse({ success: true, result: repResult });
          return;
        }

        // 3. Run ML Model (unknown domain)
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
