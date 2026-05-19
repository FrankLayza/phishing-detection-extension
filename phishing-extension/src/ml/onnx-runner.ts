import * as ort from "onnxruntime-web";
import type { FeatureVector } from "../types";

// Explicitly set WASM path if needed by Plasmo, though usually auto-resolved
ort.env.wasm.wasmPaths = "/assets/";

export class MLRunner {
  private session: ort.InferenceSession | null = null;
  private scaler: { min: number[]; scale: number[] } | null = null;

  async init() {
    if (this.session) return;
    
    // We will place the model and scaler JSON in the assets directory
    const modelUrl = chrome.runtime.getURL("assets/phishing_model.onnx");
    this.session = await ort.InferenceSession.create(modelUrl, {
      executionProviders: ["wasm"]
    });

    // In a full implementation, we load the MinMaxScaler params here
    // For now we'll do a basic pass-through or mock scaler
    try {
      const scalerUrl = chrome.runtime.getURL("assets/scaler.json");
      const resp = await fetch(scalerUrl);
      this.scaler = await resp.json();
    } catch (e) {
      console.warn("Could not load scaler, using raw features");
    }
  }

  async predict(features: FeatureVector): Promise<{ isPhishing: boolean, score: number }> {
    await this.init();

    // Map object to 44-element array in exact same order as python training
    const featureKeys: (keyof FeatureVector)[] = [
      "URLLength", "DomainLength", "IsDomainIP", "URLSimilarityIndex", 
      "CharContinuationRate", "TLDLegitimateProb", "URLCharProb", "NoOfSubDomain", 
      "HasObfuscation", "NoOfObfuscatedChar", "ObfuscationRatio", "NoOfLettersInURL", 
      "LetterRatioInURL", "NoOfDegitsInURL", "DegitRatioInURL", "NoOfEqualsInURL", 
      "NoOfQMarkInURL", "NoOfAmpersandInURL", "NoOfOtherSpecialCharsInURL", 
      "SpacialCharRatioInURL", "IsHTTPS", "DomainAgeBucket", "HasTitle", 
      "DomainTitleMatchScore", "URLTitleMatchScore", "HasFavicon", "Robots", 
      "IsResponsive", "NoOfURLRedirect", "NoOfSelfRedirect", "HasDescription", 
      "LineOfCode", "LargestLineLength", "NoOfPopup", "NoOfiFrame", 
      "HasExternalFormSubmit", "HasSocialNet", "HasSubmitButton", "HasHiddenFields", 
      "HasPasswordField", "Bank", "Pay", "Crypto", "HasCopyrightInfo"
    ];

    const rawArray = featureKeys.map(k => features[k] || 0);
    
    // Scale features if scaler is loaded
    const scaledArray = this.scaler 
      ? rawArray.map((val, i) => (val - this.scaler!.min[i]) * this.scaler!.scale[i])
      : rawArray;

    const tensor = new ort.Tensor("float32", new Float32Array(scaledArray), [1, 44]);
    const feeds = { float_input: tensor };

    const results = await this.session!.run(feeds);
    
    // Scikit-learn random forest usually outputs 'output_label' and 'output_probability'
    // Depending on ZipMap setting. If zipmap=False, output is usually an array of probs
    const probs = results[this.session!.outputNames[1]].data as Float32Array;
    
    // probs is usually [prob_safe, prob_phishing]
    const phishingProb = probs.length > 1 ? probs[1] : probs[0];
    
    return {
      isPhishing: phishingProb >= 0.5,
      score: phishingProb
    };
  }
}
