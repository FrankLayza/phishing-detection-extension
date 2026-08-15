# Supervisor Demo Guide

How to show PhishGuard to a supervisor in ~10 minutes, with the exact URLs and
commands, and the train/serve parity evidence.

## What this is

PhishGuard is a Chrome extension that detects phishing pages **on-device** — a
Random Forest trained in `ml-pipeline/` is exported to a browser-bundleable JSON
and scored locally; no URL ever leaves the device. Reputation (domain allowlist,
hosting-platform correction, brand-impersonation guard) sits on top of the model.

## The 3 pillars to demonstrate

1. **Accuracy** — 91.58% / FPR 5.87% on held-out data; calibrated verdict bands.
2. **Train/serve parity** — the Python training extractor and the shipped TS
   extractor are byte-identical (0 mismatches across 20,160 values).
3. **On-device privacy + the brand-impersonation guard** — the reputation layer
   that stops platform-hosted clones from being cleared.

---

## 1. Live browser demo (~4 min)

```bash
cd phishing-extension
pnpm build
```

Then:

1. Open `chrome://extensions`
2. Enable **Developer mode** (top-right toggle)
3. Click **Load unpacked** and select `phishing-extension/build/chrome-mv3-prod`
4. Visit the URLs in the table below — the popup shows verdict, risk score, and
   explanation signals.

### Test URLs

| URL | Expected | Why |
|---|---|---|
| `https://www.google.com` | **CLEAN** (0.05) | Known domain — reputation allowlist short-circuits the model |
| `https://gtbank.com` | **CLEAN** (0.199) | Real domain — model's own verdict, no reputation help |
| `https://apple-relay.cloudflare.com` | **CLEAN** (0.05) | Allowlisted CDN infrastructure (legit brand token in subdomain) |
| `https://my-portfolio.vercel.app` | **CLEAN** (0.269) | Legit project page — platform correction (was the top false positive) |
| `https://microsoft.github.io` | **CLEAN** (0.221) | The org's own project page — subdomain IS the brand, normal correction |
| `https://microsoft-verify-login.netlify.app` | **SUSPICIOUS** (0.828) | Brand impersonation — guard withholds the correction (was wrongly CLEAN) |
| `https://secure-paypal-verify.vercel.app/account/login` | **SUSPICIOUS** (0.897) | Brand impersonation — guard withholds the correction |
| `https://paypa1-login.vercel.app/confirm` | **PHISHING** (0.925) | Typo-squat clone — hard red, immune to any correction |
| `https://microsoft-verify-login.phishcorp.co` | **SUSPICIOUS** (0.596) | Non-platform brand squat — model only, known honest gap |

> **Honest gaps to mention if asked:** `instagram` is not in the brand list, so
> `instagram-login-clone-delta.vercel.app` stays CLEAN; and brand squats on
> arbitrary non-platform domains rely on the model alone. Both are documented in
> `SOURCE_OF_TRUTH.md` as corpus-level follow-ups.

## 2. CLI demo — same pipeline, no browser (~2 min)

```bash
node ml-pipeline/demo_supervisor.mjs
# or with your own URLs:
node ml-pipeline/demo_supervisor.mjs "https://secure-paypal-verify.vercel.app/account" "https://gtbank.com"
```

This bundles the **real shipped extractor**, loads the **committed model JSON**
from `build/`, and runs the **same reputation logic** as the extension, so its
output matches what the popup shows.

## 3. Train/serve parity proof (~2 min)

The model is trained in Python but scored in the browser in TypeScript. The
parity gate proves the two extractors are identical:

```bash
node ml-pipeline/gen_parity_features.mjs   # writes parity_ts.json (960 URLs)
python ml-pipeline/check_parity.py
```

Expected output:

```
  URLs compared:      960
  Values compared:    20160
  Mismatches:         0
  Python errors:      0
  VERDICT: PARITY OK — every feature value identical across all URLs.
```

---

## Key numbers (source of truth: `SOURCE_OF_TRUTH.md`)

| Metric | Value |
|---|---|
| Accuracy (held-out) | 91.58% |
| Precision / Recall / F1 | 93.28% / 88.80% / 90.98% |
| In-corpus False Positive Rate | 5.87% |
| 5-fold CV | 91.43% |
| Unknown-legit ML-tier FPR (sampled top-1m, n=4000) | 15.4% |
| Unknown-legit **hard red alarms** | 0.7–0.8% |
| Model size | 19.4 MB browser bundle |

Verdict bands (calibrated): **CLEAN < 0.50** · **SUSPICIOUS 0.50–0.90** ·
**PHISHING ≥ 0.90**. Only PHISHING is a blocking, alarming verdict.

## Known follow-ups (if the supervisor digs)

- **Unknown-legit FPR still above the <10% target** (15.4% ML-tier) — residual
  path-digit gap and long hyphenated domains.
- **Train/serve model drift documented:** a retrain on current code yields
  90.65% / FPR 6.64% (not 91.58% / 5.87%) because the root-slash strip landed
  after the shipped model was trained. The committed model is authoritative and
  intentionally kept — see the warning in `SOURCE_OF_TRUTH.md` §3.
- Model size (19.4 MB), `shap_mapping.json` staleness, dead code in `train.py`.

## Do NOT use for the demo

- `ml-pipeline/test_url.py` — loads the divergent retrain pkl, old 0.50/0.85
  bands, no reputation layer. Drifted; superseded by `demo_supervisor.mjs`.
- `diagnose_url.mjs` — inlined drift of the extractor at the repo root.
