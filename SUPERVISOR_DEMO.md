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
| Unknown-legit ML-tier FPR (sampled top-1m, n=4000) | **15.4%** | shipped model |
| Unknown-legit pipeline FPR (what users experience) | **9.4%** | shipped model |
| Unknown-legit **hard red alarms** (>= 0.90) | **0.8%** | shipped model |
| Unknown-legit ML-tier FPR (curated regional, n=144) | 21.5% | shipped model |
| Model size | 19.6 MiB browser bundle | — |

> **All FPR figures are measured on the artifact the extension loads.**
> `validate_unknown_legit.py` defaults to `assets/phishing_model.json` (806,620 nodes)
> as of Aug 15, 2026; it previously read `models/random_forest.pkl`, which is whatever
> `train.py` last produced. If asked, the honest framing is that the published numbers
> were correct but the harness had drifted, so it was re-pointed and re-verified. Pass
> `--model pkl` to score a retrain instead — the current one is about a point worse
> (sampled 16.5% ML / 10.2% pipeline), which is why the committed model is kept.

Verdict bands (calibrated): **CLEAN < 0.50** · **SUSPICIOUS 0.50–0.90** ·
**PHISHING ≥ 0.90**. Only PHISHING is a blocking, alarming verdict.

## Known follow-ups (if the supervisor digs)

- **Unknown-legit FPR still above the <10% target** (15.4% ML-tier, 9.4% pipeline).
  Root cause measured, not assumed: of the legitimate sites the model flags, the
  distinguishing feature is `TLDLegitimateProb` at **+1.59 sd** — they sit on
  suffixes that are genuinely phishing-heavy (`.app` 0.095, `.co` 0.182,
  `.xyz` 0.292). `DomainLength`, blamed for this in earlier drafts, measures
  **−0.03 sd** and is not involved; that retraction is worth mentioning, because it
  came from confusing feature *importance* with *error attribution*.
  Reproduce with `python ml-pipeline/diagnose_fpr.py`.
- **The obvious fixes are both closed by measurement.** Removing the length features
  nearly doubled FPR (18.1% → 34.7%). Oversampling legitimate sites on low-trust
  suffixes bought 0.6pt of FPR for 0.8pt of recall and left the model still worse
  than the one shipping — rejected, full ablation in `SOURCE_OF_TRUTH.md` §3a. What
  remains is an information ceiling: `.app` really is 6,368 phishing rows against
  200 legitimate, and a URL string alone cannot separate the honest minority.
- **Training is reproducible** — verified Aug 15, 2026 by two consecutive runs of
  `train.py` producing identical forests (864,614 nodes) and identical metrics
  (90.64% / FPR 6.62% / CV 0.9038). A retrain takes ~5 min, so corpus experiments give
  directly interpretable before/after comparisons. Determinism holds per environment;
  pin library versions when comparing.
- **Train/serve model drift documented:** a retrain on current code yields ~90.6% /
  FPR ~6.6% (not 91.58% / 5.87%) because the root-slash strip landed after the
  shipped model was trained. The committed model is authoritative and intentionally
  kept — see the warning in `SOURCE_OF_TRUTH.md` §3.
- `shap_mapping.json` staleness, ~1 s MV3 cold start, and dead code in `train.py`.

## Do NOT use for the demo

These drifted scripts were **deleted** on Aug 15, 2026 rather than left as traps.
Recoverable from git history if ever needed:

- `ml-pipeline/test_url.py` — loaded the divergent retrain pkl with old 0.50/0.85 bands
  and no reputation layer.
- `diagnose_url.mjs`, `simulate_extension.mjs` — each carried its own inlined copy of the
  extractor, which drifted from the real one and gave different answers for the same URL.
- `cross_validate_ts.mjs` (+ `cross_validation_data.json`, `gen_cross_validation.py`) —
  a 6-URL inference smoke test that printed a stale feature-count message for a
  21-feature model.

**Use `ml-pipeline/demo_supervisor.mjs` for everything.** It is the only script that
bundles the real extractor from `src/` and loads the committed model, so it cannot drift
away from what the extension does.
