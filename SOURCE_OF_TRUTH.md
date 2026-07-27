# PhishGuard — Source of Truth (v4)

> Authoritative reference for the PhishGuard model & extension as of **July 27, 2026**.
> Supersedes `PhishGuard_PRD.md` wherever they conflict (the PRD is kept as a dated
> dissertation artifact but contains stale claims — see §6).

## 1. What PhishGuard is
A privacy-preserving Chrome/Chromium extension that classifies URLs as **CLEAN /
SUSPICIOUS / PHISHING** in real time, entirely **on-device**. A Random Forest is
trained in Python on the PhiUSIIL dataset (phishing class) and the Cisco Umbrella
top-1M list (legitimate class), exported to compact JSON, and run by a pure-TypeScript
inference engine in the extension. Google Safe Browsing is an optional fallback for
borderline scores only.

## 2. The model (v4, compact lexical-only)
- **Features: 21 lexical (URL-string) features only.** DOM/content features were
  dropped (see §4). Canonical order lives in `ml-pipeline/features/feature_config.py`
  (`ALL_FEATURES`) — the single source of feature order consumed by training **and**
  export. The TS extractor must emit the same names; inference maps by name.
- **Algorithm:** `RandomForestClassifier(n_estimators=100, max_depth=20,
  min_samples_split=5, min_samples_leaf=4, max_features='log2',
  class_weight='balanced')`.
  - Previous config (n_estimators=300, max_depth=None) produced a 175.8 MB JSON export
    and ~50 ms Python inference. max_depth=None allows trees to grow to depth ~35–45
    on 200k samples. Capping at 20 with min_samples_leaf=4 reduces the export to
    19.4 MB with <1% accuracy cost.
- **Verdict tiers:** CLEAN `< 0.50`, SUSPICIOUS `0.50–0.85`, PHISHING `≥ 0.85`
- **Scaler:** sklearn `MinMaxScaler`. The browser applies the **real sklearn formula
  `scaled = raw * scale_ + min_`** (NOT `clip(x/data_max)` — that PRD claim is wrong
  for the shipped model, whose `min_` has negative values). `rf-inference.ts` already
  does this correctly.

## 3. Measured performance (real, verifiable)
Held-out 20% test set (42,189 samples: 22,000 legit + 20,189 phish), from `models/evaluation_results.json`:

| Metric | Value |
|---|---|
| Accuracy | 94.02% |
| Precision | 95.14% |
| Recall | 92.21% |
| F1 | 93.65% |
| False Positive Rate | 4.32% |
| False Negative Rate | 7.79% |
| 5-fold CV accuracy | 93.85% (±0.11%) |

**Confusion matrix:** TN=21,049 | FP=951 | FN=1,572 | TP=18,617

**Real-world spot validation** (`validate_realworld.py`, 20 curated URLs):
- Overall: 19/20 correct (95.0%)
- Safe URLs: 9/10 — one FP: `amazon.com/dp/B08N5WRWNW` (long product path)
- Phishing URLs: 10/10 — all correctly flagged with p ≥ 0.66

**Model size:** `phishing-extension/assets/phishing_model.json` = **19,863 KB (19.4 MB)**
(down from 175.8 MB with the previous 300-tree, unbounded-depth config)

**Inference latency** (`benchmark_inference.py`, 1000 single-URL runs):
| Path | Mean | Median | P95 |
|---|---|---|---|
| Python sklearn (pkl) | 60 ms | 50 ms | 116 ms |
| JSON tree-traversal (browser) | **1.15 ms** | **0.98 ms** | **1.9 ms** |

> The browser-path JSON traversal is what matters for the extension: **~1 ms median**.
> Python sklearn latency is expected higher overhead for a Python process with 100 trees.

**Python↔TypeScript inference parity:** Verified on 6 test URLs via `cross_validate_ts.mjs`.
All 6 passed within a 0.01 probability tolerance (max observed delta ~0.007).
Note: this is a small smoke-test sample. Do not cite as "100% parity, 0.000000 divergence"
— the accurate claim is "6 of 6 test URLs matched within a 0.01 tolerance."

## 4. Why content features were dropped (the false-positive root cause)
Live testing showed google.com → 91.8% PHISHING. Root cause = **train/serve skew**:
- The old model's #1 feature `LineOfCode` (importance 0.16) was trained on a
  near-degenerate distribution but received real, large, **unscaled** values from the
  live DOM. Out-of-range inputs routed legitimate pages into garbage leaves.
- `DomainTitleMatchScore` / `URLTitleMatchScore` were trained on a **0–100** scale but
  the TS extractor emitted **0/1**, destroying the strongest legitimacy signal.

Lexical (URL-string) features have **exact train/serve parity** — `lexical_extractor.py`
and `feature-extractor.ts` are byte-identical ports (same BRANDS, TLD_SCORES,
Levenshtein, char-frequency tables). The lexical-only model cannot suffer this skew.

## 5. Dataset
- **Phishing class:** `datasets/phiusiil.csv` — 100,945 phishing URLs (raw label 0).
- **Legitimate class:** Cisco Umbrella top-1M domains (`datasets/top-1m.csv`) —
  110,000 domains, structure-augmented (~27% path, ~45% subdomain) to match the
  phishing class distribution so URL structure carries no class signal.
- **Labels (post-inversion):** 1 = phishing, 0 = legitimate.
- **Lexical features self-extracted** by `features/lexical_extractor.py` for ALL URLs
  (both classes) using the same code path as inference — no pipeline-origin bias.
- `datasets/All.csv`, `datasets/Phishing.csv` — a different/older feature schema.
  **Not used** by the current pipeline.
- `IsHTTPS` is neutralised to 1.0 during training (modern phishing also uses HTTPS,
  so the signal is spurious and was causing bias).

## 6. Corrections to PhishGuard_PRD.md (do not trust these PRD claims)
| PRD claim | Reality |
|---|---|
| LineOfCode/HasSocialNet have **0 importance** | LineOfCode was the **#1** feature (0.16) — the FP driver |
| Scaler: all `data_min_=0`, use `clip(x/DATA_MAX)` | Shipped `min_` has negative values; correct formula is `x*scale_+min_` |
| Title-match features are 0–1 | Dataset/scaler prove **0–100** |
| Accuracy 97.89%, FPR 0.62% | Unverified; measured v4 = 94.02% / 4.32% FPR |
| 44 features | v4 uses **21** (lexical-only) |
| Dataset ~235k | Phishing: 100,945 PhiUSIIL; Legit: 110,000 Cisco top-1M |
| Model is "lightweight" | JSON export = 19.4 MB (down from 175.8 MB) |
| "100% parity, 0.000000 divergence" | 6/6 URLs within 0.01 tolerance; max delta ~0.007 |

## 7. Pipeline commands
```
python ml-pipeline/train.py                                          # retrain → models/*.pkl + metrics
python ml-pipeline/export_model_json.py                              # → phishing-extension/assets/phishing_model.json
python ml-pipeline/gen_cross_validation.py && node cross_validate_ts.mjs   # parity check
python ml-pipeline/benchmark_inference.py                            # latency benchmark (sklearn + JSON)
python ml-pipeline/validate_realworld.py                             # spot-check on 20 curated URLs
cd phishing-extension && pnpm build                                  # → build/chrome-mv3-prod
```

## 8. Known follow-ups (not blockers)
- **Model size (19.4 MB):** Still large for a browser bundle. Further reduction:
  reduce to 50 trees + max_depth=15 (~3 MB), or switch to XGBoost JSON (10–50× smaller
  than RF for equivalent accuracy). Investigate before finalising the dissertation's
  "lightweight" claim.
- **amazon.com FP:** Long product paths (e.g. `/dp/B08N5WRWNW`) are flagged as phishing.
  Root cause: `NoOfSubDomain` (importance 0.256) and `DomainLength` (0.158) interact
  poorly with long paths from short brand domains. Mitigation: brand-list augmentation
  or path-depth normalisation in the feature extractor.
- **Parity sample size:** Only 6 URLs in `cross_validate_ts.mjs`. Expand to ≥50 before
  making strong parity claims in the dissertation.
- **SHAP explanations** in `shap-approximator.ts` are still global-importance lookups
  with mostly static text. Functional but not true per-prediction SHAP.
