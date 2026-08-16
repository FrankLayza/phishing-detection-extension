import { extractPageFeatures } from "./content/feature-extractor";

console.log("PhishGuard: Content script injected, analyzing page...");

const url = window.location.href;
const html = document.documentElement.outerHTML;

// 1. Extract the 21 lexical URL features
const features = extractPageFeatures(url, html);

// 2. Send features to background worker for ML inference
chrome.runtime.sendMessage({
  action: "ANALYZE_PAGE",
  payload: { url, features }
}, (response) => {
  if (response?.success) {
    console.log("PhishGuard Analysis Complete:", response.result);
    
    if (response.result.prediction.verdict === "PHISHING") {
      console.warn("PHISHGUARD ALERT: This page has been classified as phishing.");
    } else if (response.result.prediction.verdict === "SUSPICIOUS") {
      console.warn("PhishGuard caution: this page has suspicious URL signals.");
    }
  } else {
    console.error("PhishGuard Analysis Failed:", response?.error);
  }
});
