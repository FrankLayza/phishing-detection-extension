import { extractPageFeatures } from "./content/feature-extractor";

console.log("PhishGuard: Content script injected, analyzing page...");

const url = window.location.href;
const html = document.documentElement.outerHTML;

// 1. Extract DOM and URL features
const features = extractPageFeatures(url, html);

// 2. Send features to background worker for ML inference
chrome.runtime.sendMessage({
  action: "ANALYZE_PAGE",
  payload: { url, features }
}, (response) => {
  if (response?.success) {
    console.log("PhishGuard Analysis Complete:", response.result);
    
    // If it's phishing, we can optionally inject an interstitial warning here!
    if (response.result.prediction.isPhishing) {
      console.warn("🚨 PHISHGUARD ALERT: This page has been flagged as highly suspicious!");
    }
  } else {
    console.error("PhishGuard Analysis Failed:", response?.error);
  }
});
