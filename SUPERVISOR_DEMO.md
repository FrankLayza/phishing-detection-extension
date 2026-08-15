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

Verified Aug 15, 2026 against the shipped build. Reproduce any row with
`node ml-pipeline/demo_supervisor.mjs "<url>"`.

| URL | Expected | Why |
|---|---|---|
| `https://www.google.com` | **CLEAN** (0.050) | Known domain — reputation allowlist short-circuits the model |
| `https://gtbank.com` | **CLEAN** (0.199) | Real domain — model's own verdict, no reputation help |
| `https://apple-relay.cloudflare.com` | **CLEAN** (0.050) | Allowlisted CDN infrastructure (legit brand token in subdomain) |
| `https://my-portfolio.vercel.app` | **CLEAN** (0.269) | Legit project page — platform correction (was the top false positive) |
| `https://microsoft.github.io` | **CLEAN** (0.221) | Org's own page on an *identity-bound* platform — exemption applies |
| `https://microsoft-verify-login.netlify.app` | **SUSPICIOUS** (0.828) | Brand impersonation — guard withholds the correction |
| `https://microsoft-verify-login.railway.app` | **SUSPICIOUS** (0.837) | Same, on a platform that is itself in the top-30k list — the allowlist no longer speaks for its tenants |
| `https://paypal.vercel.app` | **SUSPICIOUS** (0.866) | Bare brand label on a deploy-anywhere platform — claimable by anyone, so no exemption |
| `https://secure-paypal-verify.vercel.app/account/login` | **SUSPICIOUS** (0.897) | Brand impersonation — guard withholds the correction |
| `https://paypa1-login.vercel.app/confirm` | **PHISHING** (0.925) | Typo-squat clone — hard red, immune to any correction |
| `https://paple-login.vercel.app/signin` | **SUSPICIOUS** (0.821) | Transposition squat scoring *exactly* at the typo threshold |
| `https://microsoft-verify-login.phishcorp.co` | **SUSPICIOUS** (0.596) | Non-platform brand squat — model only, known honest gap |
| `https://paypal-verify-login.neocities.org` | **CLEAN** (0.124) | **Known gap, show it deliberately** — see below |

> **The one row that stays CLEAN, and why it is the honest answer.** The guard fires
> on `paypal-verify-login.neocities.org` and withholds the correction — but a
> withheld correction only removes a discount, it never adds risk. `.org` carries
> high suffix trust, so the model's own raw score is 0.124 and nothing overrides it.
> This follows directly from *advisory authority* (`CONTEXT.md`): reputation removes
> false reasons to flag, it never invents reasons. Making impersonation positive
> evidence would catch this row at the cost of flagging legitimate brand-adjacent
> projects on free hosts (`apple-music-clone.vercel.app`). That trade was considered
> and deliberately not taken.

> **Other honest gaps if asked:** only 10 brands are tracked, so `instagram` is not
> matched; brand squats on arbitrary non-platform domains rely on the model alone;
> and `URLSimilarityIndex` — the model's own brand feature — carries just 0.0036
> importance, which is *why* the reputation layer exists rather than a model fix.

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

| Metric | Value | Measured on |
|---|---|---|
| Accuracy (held-out) | 91.58% | committed model |
| Precision / Recall / F1 | 93.28% / 88.80% / 90.98% | committed model |
| In-corpus False Positive Rate | 5.87% | committed model |
| 5-fold CV | 91.43% | committed model |
| Unknown-legit ML-tier FPR (sampled top-1m, n=4000) | ~15–16% | ⚠️ `random_forest.pkl`, **not** the shipped model |
| Unknown-legit pipeline FPR (what users experience) | ~9.9% | ⚠️ same caveat |
| Unknown-legit **hard red alarms** | 0.7–0.8% | ⚠️ same caveat |
| Model size | 19.6 MiB browser bundle | — |

> ⚠️ **Be precise about the FPR provenance if asked.** `validate_unknown_legit.py:83`
> loads `models/random_forest.pkl` (846k–865k nodes depending on the run), while the
> extension loads `assets/phishing_model.json` (806,620 nodes). They are different
> forests, so the unknown-legit FPR figures describe a model that is not shipped.
> Re-measuring those populations through `demo_supervisor.mjs` (which uses the
> committed model and the real TS extractor) is a known follow-up. The in-corpus
> figures above are the committed model's own.

Verdict bands (calibrated): **CLEAN < 0.50** · **SUSPICIOUS 0.50–0.90** ·
**PHISHING ≥ 0.90**. Only PHISHING is a blocking, alarming verdict.

## Known follow-ups (if the supervisor digs)

- **Unknown-legit FPR still above the <10% target** (~16% ML-tier). Root cause
  diagnosed: `DomainLength` is the model's **#2 feature** (0.1238 importance) and
  encodes suffix structure as risk, so mechanically longer regional domains
  (`gtbank.com.ng`) are penalised. Removing the length features was tested and
  nearly doubled FPR (18.1% → 34.7%), so the fix is corpus-level, not feature-level.
- **Training is not currently reproducible.** Three seeded runs of `train.py`
  produced three different forests (806,620 / 846,454 / 864,614 nodes). In-corpus
  metrics are stable to ~0.02 pt, but the claim of byte-identical reproducibility in
  `SOURCE_OF_TRUTH.md` no longer holds. Must be fixed before any corpus experiment,
  or an FPR change cannot be told apart from run-to-run noise.
- **Train/serve model drift documented:** a retrain on current code yields ~90.6% /
  FPR ~6.6% (not 91.58% / 5.87%) because the root-slash strip landed after the
  shipped model was trained. The committed model is authoritative and intentionally
  kept — see the warning in `SOURCE_OF_TRUTH.md` §3.
- `shap_mapping.json` staleness, ~1 s MV3 cold start, and dead code in `train.py`.

## Do NOT use for the demo

- `ml-pipeline/test_url.py` — loads the divergent retrain pkl, old 0.50/0.85
  bands, no reputation layer. Drifted; superseded by `demo_supervisor.mjs`.
- `diagnose_url.mjs` — inlined drift of the extractor at the repo root.
