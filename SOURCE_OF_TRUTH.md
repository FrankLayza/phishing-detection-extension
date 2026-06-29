# PhishGuard — Source of Truth (v3)

> Authoritative reference for the PhishGuard model & extension as of **June 29, 2026**.
> Supersedes `PhishGuard_PRD.md` wherever they conflict (the PRD is kept as a dated
> dissertation artifact but contains stale claims — see §6).

## 1. What PhishGuard is
A privacy-preserving Chrome/Chromium extension that classifies URLs as **CLEAN /
SUSPICIOUS / PHISHING** in real time, entirely **on-device**. A Random Forest is
trained in Python on the PhiUSIIL dataset, exported to compact JSON, and run by a
pure-TypeScript inference engine in the extension. Google Safe Browsing is an
optional fallback for borderline scores only. AI/ML-based, multi-signal, explainable.

## 2. The model (v3, lexical-only)
- **Features: 21 lexical (URL-string) features only.** DOM/content features were
  dropped (see §4). Canonical order lives in `ml-pipeline/features/feature_config.py`
  (`ALL_FEATURES`) — the single source of feature order consumed by training **and**
  export. The TS extractor must emit the same names; inference maps by name.
- **Algorithm:** `RandomForestClassifier(n_estimators=100, max_depth=20,
  min_samples_split=5, min_samples_leaf=2, max_features='sqrt',
  class_weight='balanced')`.
- **Verdict tiers:** CLEAN `< 0.50`, SUSPICIOUS `0.50–0.85`, PHISHING `≥ 0.85`.
- **Scaler:** sklearn `MinMaxScaler`. The browser applies the **real sklearn formula
  `scaled = raw * scale_ + min_`** (NOT `clip(x/data_max)` — that PRD claim is wrong
  for the shipped model, whose `min_` has negative values). `rf-inference.ts` already
  does this correctly.

## 3. Measured performance (real, verifiable)
Held-out 20% test set (~47k samples), from `models/evaluation_results.json`:

| Metric | Value |
|---|---|
| Accuracy | 95.46% |
| Precision | 97.13% |
| Recall | 92.10% |
| F1 | 94.55% |
| False Positive Rate | 2.04% |
| 10-fold CV accuracy | 95.39% (±0.21%) |

These replace the PRD's unverified 97.89% (the only saved eval there was a 20-sample
test with a false positive). **Python↔TypeScript inference parity: exact (diff
0.000000 to 6 decimals)** via `cross_validate_ts.mjs`.

## 4. Why content features were dropped (the false-positive root cause)
Live testing showed google.com → 91.8% PHISHING. Root cause = **train/serve skew**:
- The old model's #1 feature `LineOfCode` (importance 0.16) was trained on a
  near-degenerate distribution but received real, large, **unscaled** values from the
  live DOM (`LargestLineLength` ranged 22..13,980,000 in the dataset). Out-of-range
  inputs routed legitimate pages into garbage leaves.
- `DomainTitleMatchScore` / `URLTitleMatchScore` were trained on a **0–100** scale but
  the TS extractor emitted **0/1**, destroying the strongest legitimacy signal.

Lexical (URL-string) features have **perfect train/serve parity** — `lexical_extractor.py`
and `feature-extractor.ts` are byte-identical ports (same BRANDS, TLD_SCORES,
Levenshtein, char-frequency tables). So the lexical-only model cannot suffer this skew.

## 5. Dataset
- `datasets/phiusiil.csv` — **235,795 rows, 56 cols.** Labels: PhiUSIIL encodes
  **1 = legitimate, 0 = phishing**; training **inverts** so 1 = phishing. Balance:
  134,850 legit / 100,945 phishing.
- `datasets/All.csv`, `datasets/Phishing.csv` — a different/older feature schema
  (`Querylength,domain_token_count,…`). **Not used** by the current pipeline.
- Bias mitigation in training: `augment_legitimate_urls()` adds realistic
  paths/subdomains to legit URLs (PhiUSIIL legit URLs otherwise lack paths). `IsHTTPS`
  neutralized to 1.0 (constant in dataset → ~0 importance). Content-zero augmentation
  is now a no-op (no content features).

## 6. Corrections to PhishGuard_PRD.md (do not trust these PRD claims)
| PRD claim | Reality |
|---|---|
| LineOfCode/HasSocialNet have **0 importance** | LineOfCode was the **#1** feature (0.16) — the FP driver |
| Scaler: all `data_min_=0`, use `clip(x/DATA_MAX)` | Shipped `min_` has negative values; correct formula is `x*scale_+min_` |
| Title-match features are 0–1 | Dataset/scaler prove **0–100** |
| Accuracy 97.89%, FPR 0.62% | Unverified; measured v3 = 95.46% / 2.04% FPR |
| 44 features | v3 uses **21** (lexical-only) |
| Dataset ~235k | ✅ correct (235,795) |

## 7. Pipeline commands
```
python ml-pipeline/train.py              # retrain → models/*.pkl + metrics
python ml-pipeline/export_model_json.py  # → phishing-extension/assets/phishing_model.json
python ml-pipeline/gen_cross_validation.py && node cross_validate_ts.mjs   # parity check
cd phishing-extension && pnpm build      # → build/chrome-mv3-prod (load unpacked in Chrome)
```

## 8. Known follow-ups (not blockers)
- **SHAP explanations** in `shap-approximator.ts` are still global-importance lookups
  with mostly static text, and `popup.tsx` infers the risk arrow via string matching.
  Functional but not true per-prediction SHAP — worth refactoring to value-conditional
  explanations with an explicit `isPhishRisk` flag.
- Lexical-only trades some page-content signal for robustness. Safe binary DOM signals
  (e.g. `HasPasswordField`) could be re-added later **only** if extracted identically at
  train and serve time.
