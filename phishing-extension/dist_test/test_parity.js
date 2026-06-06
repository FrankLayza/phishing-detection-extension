var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(
  // If the importer is in node compatibility mode or this is not an ESM
  // file that has been converted to a CommonJS file using a Babel-
  // compatible transform (i.e. "__esModule" has not been set), then set
  // "default" to the CommonJS "module.exports" for node compatibility.
  isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target,
  mod
));

// src/ml/onnx-runner.ts
function isLeaf(node) {
  return "v" in node;
}
function predictTree(tree, features) {
  if (isLeaf(tree)) {
    return tree.v;
  }
  if (features[tree.f] <= tree.t) {
    return predictTree(tree.l, features);
  }
  return predictTree(tree.r, features);
}
var MLRunner = class {
  model = null;
  async init() {
    if (this.model)
      return;
    const modelUrl = chrome.runtime.getURL("assets/phishing_model.json");
    const resp = await fetch(modelUrl);
    this.model = await resp.json();
    console.log(`PhishGuard: Model loaded (${this.model.n_estimators} trees, ${this.model.n_features} features)`);
  }
  async predict(features) {
    await this.init();
    const model = this.model;
    const rawArray = model.feature_names.map(
      (name) => features[name] ?? 0
    );
    const scaledArray = rawArray.map(
      (val, i) => val * model.scaler.scale[i] + model.scaler.min[i]
    );
    const probs = new Array(model.classes.length).fill(0);
    for (const tree of model.trees) {
      const leafProbs = predictTree(tree, scaledArray);
      for (let c = 0; c < probs.length; c++) {
        probs[c] += leafProbs[c];
      }
    }
    for (let c = 0; c < probs.length; c++) {
      probs[c] /= model.n_estimators;
    }
    const phishingProb = probs.length > 1 ? probs[1] : probs[0];
    return {
      isPhishing: phishingProb >= 0.5,
      score: phishingProb
    };
  }
};

// src/ml/test_parity.ts
var fs = __toESM(require("fs"));
var path = __toESM(require("path"));
global.chrome = {
  runtime: {
    getURL: (p) => p
  }
};
global.fetch = async (url) => {
  const filePath = path.resolve(__dirname, "../../assets/phishing_model.json");
  const data = fs.readFileSync(filePath, "utf-8");
  return {
    json: async () => JSON.parse(data)
  };
};
var ALL_FEATURES = [
  "URLLength",
  "DomainLength",
  "IsDomainIP",
  "URLSimilarityIndex",
  "CharContinuationRate",
  "TLDLegitimateProb",
  "URLCharProb",
  "NoOfSubDomain",
  "HasObfuscation",
  "NoOfObfuscatedChar",
  "ObfuscationRatio",
  "NoOfLettersInURL",
  "LetterRatioInURL",
  "NoOfDegitsInURL",
  "DegitRatioInURL",
  "NoOfEqualsInURL",
  "NoOfQMarkInURL",
  "NoOfAmpersandInURL",
  "NoOfOtherSpecialCharsInURL",
  "SpacialCharRatioInURL",
  "IsHTTPS",
  "DomainAgeBucket",
  "HasTitle",
  "DomainTitleMatchScore",
  "URLTitleMatchScore",
  "HasFavicon",
  "Robots",
  "IsResponsive",
  "NoOfURLRedirect",
  "NoOfSelfRedirect",
  "HasDescription",
  "LineOfCode",
  "LargestLineLength",
  "NoOfPopup",
  "NoOfiFrame",
  "HasExternalFormSubmit",
  "HasSocialNet",
  "HasSubmitButton",
  "HasHiddenFields",
  "HasPasswordField",
  "Bank",
  "Pay",
  "Crypto",
  "HasCopyrightInfo"
];
var testCases = [
  {
    url: "https://google.com",
    rawVector: [18, 10, 0, 0, 0.6470588235294118, 0.95, 0.042222222222222223, 0, 0, 0, 0, 14, 0.7777777777777778, 0, 0, 0, 0, 0, 1, 0.05555555555555555, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 0, 149, 15340, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 1],
    expectedPythonScore: 0.421694
  },
  {
    url: "https://github.com",
    rawVector: [18, 10, 0, 0.16666666666666663, 0.6470588235294118, 0.95, 0.03555555555555555, 0, 0, 0, 0, 14, 0.7777777777777778, 0, 0, 0, 0, 0, 1, 0.05555555555555555, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1428, 160903, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 1],
    expectedPythonScore: 0.290706
  },
  {
    url: "https://secure-paypal-login.tk/verify",
    rawVector: [37, 22, 0, 0.3157894736842105, 0.6666666666666666, 0.1, 0.04081081081081083, 0, 0, 0, 0, 30, 0.8108108108108109, 0, 0, 0, 0, 0, 1, 0.02702702702702703, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    expectedPythonScore: 0.679265
  }
];
function zipFeatures(raw) {
  const features = {};
  for (let i = 0; i < ALL_FEATURES.length; i++) {
    features[ALL_FEATURES[i]] = raw[i];
  }
  return features;
}
async function runTests() {
  const runner = new MLRunner();
  let allPassed = true;
  console.log("==========================================================================");
  console.log("  TYPESCRIPT MLRUNNER PARITY VALIDATION");
  console.log("==========================================================================");
  for (const tc of testCases) {
    const featureVector = zipFeatures(tc.rawVector);
    const result = await runner.predict(featureVector);
    const tsScore = result.score;
    const diff = Math.abs(tsScore - tc.expectedPythonScore);
    const passed = diff <= 0.01;
    console.log(`
URL: ${tc.url}`);
    console.log(`  Raw vector length: ${tc.rawVector.length}`);
    console.log(`  Python ML score:   ${tc.expectedPythonScore.toFixed(6)}`);
    console.log(`  TS MLRunner score: ${tsScore.toFixed(6)}`);
    console.log(`  Difference:        ${diff.toFixed(6)}`);
    console.log(`  Status:            ${passed ? "\u2713 PASS" : "\u2717 FAIL"}`);
    if (!passed) {
      allPassed = false;
    }
  }
  console.log("\n==========================================================================");
  if (allPassed) {
    console.log("  OVERALL STATUS: \u2713 PASS (All TypeScript scores match Python within 0.01)");
  } else {
    console.log("  OVERALL STATUS: \u2717 FAIL (Prediction mismatch detected)");
    process.exit(1);
  }
  console.log("==========================================================================");
}
runTests().catch((err) => {
  console.error("Test execution failed:", err);
  process.exit(1);
});
