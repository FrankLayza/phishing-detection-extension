# PhishGuard

A Chrome extension that detects phishing pages **on your own device**. No browsing data
ever leaves the browser.

A Random Forest is trained in Python, exported to a compact JSON format, and scored by a
pure-TypeScript engine inside the extension. A reputation layer sits on top of the model to
suppress false alarms on legitimate sites and to stop phishing clones hosted on free
platforms from being cleared.

> Final-year research project. The authoritative numbers live in
> [`SOURCE_OF_TRUTH.md`](SOURCE_OF_TRUTH.md) — this README summarises, it does not decide.

---

## How well does it work?

Measured on the exact model the extension loads, against 4,000 real legitimate websites the
model has never seen (Cisco top-1m, ranks below the training cut):

| | |
|---|---|
| Legitimate sites given a caution flag | **9.4%** |
| Legitimate sites given a blocking red alarm | **0.8%** |
| Phishing pages caught | **88.8%** |
| Held-out accuracy | **91.58%** |
| Python↔TypeScript feature agreement | **20,160 / 20,160 values** |

Only the red band blocks or alarms; the middle band is advisory. The residual false-alarm
rate is dominated by legitimate sites on domain endings that are genuinely phishing-heavy
(`.app` carries roughly 6,400 phishing samples against 200 legitimate ones), which a URL
string alone cannot separate — see [`SOURCE_OF_TRUTH.md`](SOURCE_OF_TRUTH.md) §3a.

## Install and run

```bash
# 1. Get the code and build the extension
git clone https://github.com/FrankLayza/phishing-detection-extension.git
cd phishing-detection-extension/phishing-extension
pnpm install
pnpm build          # postbuild copies the model into build/chrome-mv3-prod/assets/

# 2. Load it in Chrome
#    chrome://extensions -> enable Developer mode -> Load unpacked
#    -> select phishing-extension/build/chrome-mv3-prod
```

The 19.6 MB model is committed as an ordinary git file — no Git LFS, so a plain `git clone`
gives you a working extension.

Click the toolbar icon on any page to see the verdict, the risk score, and the signals
behind it.

For the Python side:

```bash
pip install -r requirements.txt
```

Datasets are not committed. `ml-pipeline/` expects `datasets/phiusiil.csv` (PhiUSIIL
phishing URL dataset) and `datasets/top-1m.csv` (Cisco Umbrella top sites).

## Try it

Verify any of these with the CLI, which runs the same code path as the extension:

```bash
node ml-pipeline/demo_supervisor.mjs "https://paypal.vercel.app"
```

| URL | Expected |
|---|---|
| `https://www.google.com` | CLEAN — known site, model skipped |
| `https://gtbank.com` | CLEAN — model's own verdict |
| `https://my-portfolio.vercel.app` | CLEAN — legitimate page on a free host |
| `https://microsoft.github.io` | CLEAN — the org's own project page |
| `https://paypal.vercel.app` | **SUSPICIOUS** — brand name on a deploy-anywhere host |
| `https://microsoft-verify-login.netlify.app` | **SUSPICIOUS** — brand impersonation |
| `https://paypa1-login.vercel.app/confirm` | **PHISHING** — typo-squat, blocking red |

Full set with scores and reasoning: [`SUPERVISOR_DEMO.md`](SUPERVISOR_DEMO.md).

## How it works

```
page load
   │
   ▼
content script ──► 21 features from the URL string ──► service worker
                                                          │
                          ┌───────────────────────────────┤
                          │                               │
                   reputation layer                  Random Forest
                   (src/ml/reputation.ts)         (src/ml/rf-inference.ts)
                          │                               │
   known popular domain ──┘ short-circuit to CLEAN         │
   hosting platform ─────► neutralise domain-ending trust ─┤
   brand in subdomain ───► withhold that discount ─────────┤
                                                          ▼
                                            CLEAN <0.50 · SUSPICIOUS <0.90 · PHISHING ≥0.90
```

Only the optional Google Safe Browsing fallback ever touches the network, and only for
borderline scores when the user supplies their own API key.

Detail: [`architecture.md`](architecture.md).

## Layout

```
phishing-extension/          Chrome MV3 extension (Plasmo + React)
  src/content/               feature extractor — the serve side of train/serve parity
  src/ml/                    inference, reputation, brand vocabulary, domain parsing
  src/popup.tsx              verdict UI
  assets/                    committed model + trusted-domains list

ml-pipeline/                 training and validation
  train.py                   builds the corpus, trains, evaluates
  features/lexical_extractor.py   the train side of parity
  check_parity.py            proves both extractors agree
  validate_unknown_legit.py  the acceptance metric
  diagnose_fpr.py            which feature drives the false alarms
  demo_supervisor.mjs        score URLs through the shipped pipeline
```

## Documentation

| File | What it's for |
|---|---|
| [`SOURCE_OF_TRUTH.md`](SOURCE_OF_TRUTH.md) | **Authoritative numbers.** Every metric, with provenance. |
| [`architecture.md`](architecture.md) | Components, data flow, and the invariants that keep it correct. |
| [`SUPERVISOR_DEMO.md`](SUPERVISOR_DEMO.md) | 10-minute demo script with expected scores. |
| [`CONTEXT.md`](CONTEXT.md) | Domain vocabulary. |
| [`handoff.md`](handoff.md) | Current state and open decisions. |
| [`memory.md`](memory.md) | Traps this project has already hit. **Read before trusting a green check.** |
| [`IMPLEMENTATION_NOTE.md`](IMPLEMENTATION_NOTE.md) | Dated changelog of every change and why. |

## Verifying it yourself

```bash
# Do the Python and TypeScript extractors agree? (they must, or the model is
# scored on features it was never trained on)
node ml-pipeline/gen_parity_features.mjs && python ml-pipeline/check_parity.py

# What is the false-alarm rate on the model that actually ships?
python ml-pipeline/validate_unknown_legit.py

# Which feature is responsible for it?
python ml-pipeline/diagnose_fpr.py
```

## Two things to know before changing anything

1. **`assets/phishing_model.json` is authoritative and does not reproduce from a retrain.**
   The URL-normalisation fix landed after it was trained, so retraining yields a different
   forest that is measurably worse. Never replace it silently —
   [`SOURCE_OF_TRUTH.md`](SOURCE_OF_TRUTH.md) §3.
2. **A script that scores URLs must bundle the real extractor from `src/`.** Four scripts
   that kept their own inlined copy drifted and produced wrong answers people acted on;
   they were deleted. `demo_supervisor.mjs`, `score_shipped.mjs` and
   `gen_parity_features.mjs` do it correctly.

## Limitations

Stated plainly, because they are measured rather than guessed:

- **9.4% of unfamiliar legitimate sites get a caution flag.** Above the 10% target only
  narrowly, and the cause is an information limit rather than a fixable defect. Two
  interventions were tried and rejected on measurement.
- **Ten brands are tracked** for impersonation. `instagram` is not among them.
- **Brand squats on ordinary domains** rely on the model alone.
- **The brand guard withholds a discount; it never adds risk.** A clone the model scores
  below 0.50 on its own still reads CLEAN.
- **~20 MB model, ~1 second cold start** each time Chrome wakes the worker.

## License

Academic project. No license granted for redistribution.
