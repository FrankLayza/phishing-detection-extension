# PhishGuard: Client-Side Phishing Detection

PhishGuard is an in-browser phishing detection system implemented as a Chromium Manifest V3 extension. All feature extraction and model inference execute entirely on-device, ensuring zero browsing telemetry leaves the client.

The detection engine combines a 21-feature lexical URL extractor, an in-browser Random Forest classifier (evaluated via a pure-TypeScript inference runtime), and a heuristic reputation layer to minimize false positives on high-traffic domains while detecting brand spoofing on deployment platforms.

---

## Performance & Evaluation

Evaluated against the held-out validation set and 4,000 previously unseen legitimate domains (Cisco Umbrella Top 1M):

| Metric | Result | Target / Standard |
|---|---|---|
| Held-Out Classification Accuracy | **91.58%** | Baseline benchmark |
| Phishing Detection Rate (Recall) | **88.80%** | Malicious URLs flagged |
| False Positive Rate (Blocking Alarm $\ge 0.90$) | **0.80%** | Critical threshold |
| Caution Advisory Rate ($0.50 \le \text{Score} < 0.90$) | **9.40%** | Non-blocking warning |
| Train / Serve Feature Agreement | **20,160 / 20,160** | 100% Python $\leftrightarrow$ TypeScript parity |

---

## Detection Architecture

```
Incoming URL
    │
    ▼
Content Script (21 Lexical Features Extracted)
    │
    ▼
Service Worker
    ├──► Reputation Layer (src/ml/reputation.ts)
    │      ├── High-trust domain list (short-circuit to CLEAN)
    │      └── Platform & brand impersonation check
    │
    └──► Random Forest Classifier (src/ml/rf-inference.ts)
           └── Decision scoring (20-tree ensemble)
                   │
                   ▼
     Combined Output Classification
       - CLEAN:      Score < 0.50
       - SUSPICIOUS: 0.50 <= Score < 0.90 (Advisory caution)
       - PHISHING:   Score >= 0.90 (Blocking alert)
```

---

## Setup & Installation

### 1. Browser Extension (TypeScript / Plasmo)

**Prerequisites:** Node.js 18+ and `pnpm`.

```bash
cd phishing-extension
pnpm install
pnpm build
```

**Load into Chromium:**
1. Navigate to `chrome://extensions`.
2. Toggle **Developer mode** (top-right).
3. Click **Load unpacked** and select `phishing-extension/build/chrome-mv3-prod`.

### 2. Python Environment (ML Pipeline & Verification)

**Prerequisites:** Python 3.11.

```bash
# 1. Create a virtual environment
python -m venv venv

# 2. Activate environment
# On Windows (PowerShell):
.\venv\Scripts\Activate.ps1
# On Windows (CMD):
.\venv\Scripts\activate.bat
# On Linux / macOS:
source venv/bin/activate

# 3. Install pinned dependencies
pip install -r requirements.txt
```

---

## Verification & Testing

Ensure feature extractors and validation scripts operate consistently:

```bash
# 1. Verify train-serve parity (Python vs TypeScript feature extraction)
node ml-pipeline/gen_parity_features.mjs && python ml-pipeline/check_parity.py

# 2. Evaluate false alarm rate on unseen legitimate domains
python ml-pipeline/validate_unknown_legit.py

# 3. Inspect individual feature attribution for false positives
python ml-pipeline/diagnose_fpr.py

# 4. Run CLI test evaluation through the shipped pipeline
node ml-pipeline/demo_supervisor.mjs "https://paypal.vercel.app"
```

---

## Project Structure

```
phishing-detector/
├── phishing-extension/               # Browser extension workspace (Plasmo + React)
│   ├── assets/                       # Serialized model and domain lists
│   ├── src/content/                  # Lexical feature extraction (client serve side)
│   ├── src/ml/                       # RF inference engine, reputation checks, parsing
│   └── src/popup.tsx                 # Extension verdict UI
├── ml-pipeline/                      # Model training, verification, and analysis
│   ├── features/lexical_extractor.py # Feature extraction (training side)
│   ├── train.py                      # Training corpus creation and model fitting
│   ├── check_parity.py               # Feature agreement test suite
│   ├── validate_unknown_legit.py     # Independent validation on unseen domains
│   └── demo_supervisor.mjs           # Standalone verification runner
├── requirements.txt                  # Pinned Python dependencies
└── README.md                         # Technical documentation
```

---

## Technical Constraints & Boundaries

- **Feature Space:** Detection relies solely on lexical URL features without executing dynamic network crawls, preserving client privacy.
- **Top-Level Domain Bias:** Domain endings heavily correlated with abuse (e.g. `.app`, which contains a disproportionate volume of phishing URLs in public datasets) contribute to the residual 9.4% advisory rate on unfamiliar domains.
- **Brand Lexicon:** Brand impersonation guards track ten predefined high-risk targets (financial and tech platforms) on hosting providers.
- **Resource Footprint:** Serialized model payload is ~19.6 MB JSON, requiring ~1 second initialization time upon service worker activation.
