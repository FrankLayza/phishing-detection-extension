import { MLRunner } from "../ml/rf-inference";
import { ShapApproximator } from "../ml/shap-approximator";
import { reputation } from "../ml/reputation";
import { urlCache } from "../utils/cache";
import type { DetectionResult } from "../types";

const mlRunner = new MLRunner();
const shapApproximator = new ShapApproximator();

// Initialize models + reputation adapters
Promise.all([mlRunner.init(), shapApproximator.init(), reputation.init()]).catch(console.error);

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  // Only trust messages from this extension's own content scripts, popup, or
  // options page. Without this check any web page could post a forged
  // ANALYZE_PAGE with hand-picked features and read back the verdict, turning
  // the detector into an oracle for tuning evasive URLs.
  if (sender.id !== chrome.runtime.id) return false;

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

        // 2. Reputation check — hard allowlist first, advisory platform correction
        //    feeds the model below. See src/ml/reputation.ts for the seam.
        const rep = await reputation.evaluate(url, features);

        if (rep.kind === "allowlisted") {
          const repResult: DetectionResult = {
            url,
            timestamp: Date.now(),
            prediction: { isPhishing: false, score: 0.05, source: 'OVERRIDE' },
            explanations: rep.signals,
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

        // 3. Run ML Model (unknown domain). The model always sees the raw
        //    features first. For platform-hosted URLs whose raw score is below
        //    the PHISHING cut (0.90, the calibrated hard-red line) the advisory
        //    reputation adapter neutralises TLDLegitimateProb and we re-score —
        //    so a borderline page that is clean on every other signal drops to
        //    CLEAN. A HARD verdict (>= 0.90 on the raw vector) is immune to the
        //    correction: platform membership may soften a borderline, never a
        //    red alarm. See src/ml/reputation.ts for the seam.
        //
        //    The correction is ALSO withheld when the subdomain impersonates a
        //    brand (rep.impersonation set): the neutralisation would remove the
        //    clone's only phishing signal (the low-trust TLD). See the guard in
        //    reputation.ts.
        let mlPrediction = await mlRunner.predict(features);
        const correctionApplied =
          rep.kind === "platform" &&
          !rep.impersonation &&
          mlPrediction.score < 0.9;
        const usedFeatures = correctionApplied ? rep.features : features;
        if (correctionApplied) {
          mlPrediction = await mlRunner.predict(rep.features);
        }
        
        // 3b. Google Safe Browsing API Fallback for borderline cases
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
        
        // 4. Generate Explanations. Only when the platform correction actually ran
        //    does the popup get the "TLD trust neutralised" signal; a hard
        //    verdict that was immune to the correction shows plain ML signals.
        //    A withheld brand-impersonation correction is the one exception:
        //    the guard's signal must show because it is WHY the page kept its
        //    full risk score.
        const shapExplanations = await shapApproximator.getExplanations(usedFeatures);
        const explanations = correctionApplied || rep.impersonation
          ? [...rep.signals, ...shapExplanations]
          : shapExplanations;
        
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

// Discard the stored verdict the moment a tab navigates away.
//
// The entry is keyed by tab ID alone, so without this it outlives the page it
// describes: navigating google.com -> paypa1-security.gq in the same tab left
// the old CLEAN verdict in place, and the popup rendered "Safe - google.com"
// over a phishing URL. The popup now also compares result.url to the live tab
// URL, but that is the second line of defence -- stale state should not survive
// the navigation that invalidated it.
//
// Fires on committed navigation only (url changes on the loading tab), so a
// same-page anchor jump does not needlessly discard a valid verdict.
chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.url) {
    chrome.storage.local.remove(`result_${tabId}`);
    // Drop the badge too, or the previous page's ✓/! stays on the icon while
    // the new page is unscanned.
    chrome.action.setBadgeText({ text: "", tabId });
  }
});
