"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const onnx_runner_1 = require("./onnx-runner");
const fs = require("fs");
const path = require("path");
// Mock Chrome runtime and fetch APIs for Node.js environment
global.chrome = {
    runtime: {
        getURL: (p) => p
    }
};
global.fetch = async (url) => {
    // Model file is located at phishing-extension/assets/phishing_model.json
    // We resolve relative to this script's directory
    const filePath = path.resolve(__dirname, "../../assets/phishing_model.json");
    const data = fs.readFileSync(filePath, "utf-8");
    return {
        json: async () => JSON.parse(data)
    };
};
const ALL_FEATURES = [
    'URLLength', 'DomainLength', 'IsDomainIP', 'URLSimilarityIndex', 'CharContinuationRate',
    'TLDLegitimateProb', 'URLCharProb', 'NoOfSubDomain', 'HasObfuscation', 'NoOfObfuscatedChar',
    'ObfuscationRatio', 'NoOfLettersInURL', 'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL',
    'NoOfEqualsInURL', 'NoOfQMarkInURL', 'NoOfAmpersandInURL', 'NoOfOtherSpecialCharsInURL',
    'SpacialCharRatioInURL', 'IsHTTPS', 'DomainAgeBucket', 'HasTitle', 'DomainTitleMatchScore',
    'URLTitleMatchScore', 'HasFavicon', 'Robots', 'IsResponsive', 'NoOfURLRedirect', 'NoOfSelfRedirect',
    'HasDescription', 'LineOfCode', 'LargestLineLength', 'NoOfPopup', 'NoOfiFrame',
    'HasExternalFormSubmit', 'HasSocialNet', 'HasSubmitButton', 'HasHiddenFields',
    'HasPasswordField', 'Bank', 'Pay', 'Crypto', 'HasCopyrightInfo'
];
const testCases = [
    {
        url: "https://google.com",
        rawVector: [18.0, 10.0, 0.0, 0.0, 0.6470588235294118, 0.95, 0.042222222222222223, 0.0, 0.0, 0.0, 0.0, 14.0, 0.7777777777777778, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.05555555555555555, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 149.0, 15340.0, 0.0, 0.0, 0.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0],
        expectedPythonScore: 0.421694
    },
    {
        url: "https://github.com",
        rawVector: [18.0, 10.0, 0.0, 0.16666666666666663, 0.6470588235294118, 0.95, 0.03555555555555555, 0.0, 0.0, 0.0, 0.0, 14.0, 0.7777777777777778, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.05555555555555555, 1.0, 0.0, 1.0, 1.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 1.0, 1428.0, 160903.0, 0.0, 0.0, 0.0, 1.0, 1.0, 1.0, 0.0, 0.0, 0.0, 0.0, 1.0],
        expectedPythonScore: 0.290706
    },
    {
        url: "https://secure-paypal-login.tk/verify",
        rawVector: [37.0, 22.0, 0.0, 0.3157894736842105, 0.6666666666666666, 0.1, 0.04081081081081083, 0.0, 0.0, 0.0, 0.0, 30.0, 0.8108108108108109, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.02702702702702703, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
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
    const runner = new onnx_runner_1.MLRunner();
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
        console.log(`\nURL: ${tc.url}`);
        console.log(`  Raw vector length: ${tc.rawVector.length}`);
        console.log(`  Python ML score:   ${tc.expectedPythonScore.toFixed(6)}`);
        console.log(`  TS MLRunner score: ${tsScore.toFixed(6)}`);
        console.log(`  Difference:        ${diff.toFixed(6)}`);
        console.log(`  Status:            ${passed ? "✓ PASS" : "✗ FAIL"}`);
        if (!passed) {
            allPassed = false;
        }
    }
    console.log("\n==========================================================================");
    if (allPassed) {
        console.log("  OVERALL STATUS: ✓ PASS (All TypeScript scores match Python within 0.01)");
    }
    else {
        console.log("  OVERALL STATUS: ✗ FAIL (Prediction mismatch detected)");
        process.exit(1);
    }
    console.log("==========================================================================");
}
runTests().catch(err => {
    console.error("Test execution failed:", err);
    process.exit(1);
});
