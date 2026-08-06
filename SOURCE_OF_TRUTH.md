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
| Accuracy | 92.82% |
| Precision | 94.66% |
| Recall | 90.07% |
| F1 | 92.31% |
| False Positive Rate | 4.66% |
| False Negative Rate | 9.93% |
| 5-fold CV accuracy | *not persisted — see note* |

**Confusion matrix:** TN=20,974 | FP=1,026 | FN=2,005 | TP=18,184

> These are the **post-corpus-fix** numbers (model retrained Aug 5, 2026). The previous
> v4 figures (94.02% / 95.14% / 92.21%, FP=951) came from the pre-fix model whose
> legitimate class carried the URL-structure artifact — they are superseded, not
> comparable. Accuracy fell 1.2 points while real-world unknown-legit FPR fell by two
> thirds; see §3a. Regenerate with `python ml-pipeline/train.py`.
>
> **5-fold CV:** `train.py` computes it but only `print()`s it — no artifact backs it.
> The old "93.85% (±0.11%)" was a pre-fix stdout figure and has been removed rather
> than restated. Do not cite a CV number until it is persisted to
> `models/evaluation_results.json`.

### 3a. Unknown-legitimate FPR — the metric that actually gates the product
Held-out accuracy measures the corpus, not the goal. The legitimate class is partly
synthesized, so in-corpus accuracy stays high while genuinely unseen legitimate sites
fail. Measured by `validate_unknown_legit.py` → `models/unknown_legit_validation.json`:

| Set | n | ML-tier FPR | Full-pipeline FPR |
|---|---|---|---|
| Curated regional (banks, fintech, SMB) | 144 | **18.1%** | 13.2% |
| Sampled top-1m, rank ≥120k | 4,000 | **19.1%** | 8.1% |

Roughly **1 in 5 unknown legitimate sites is flagged by the ML tier**, against a <10%
target. Phishing detection is not the weak side (90.1% held-out recall, 10/10 on the
real-world phishing spot set) — false positives on legitimate sites are. Residual
failures concentrate in long hyphenated domains (`oakwood-dental-clinic.com`), rare in
both training classes. The allowlist cannot close this: gtbank.com is rank ~380k,
flutterwave.com ~687k; covering them needs ~700k entries (~10 MB) vs the current
30k/456 KB. **Verdict thresholds have never been calibrated against FPR** — the
documented sweep (0.60 → 11.8%/13.7% FPR at 86.2% recall; 0.65 → 11.8%/11.8% at 82.4%)
is a pending product decision, not applied.

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

**Python↔TypeScript EXTRACTOR parity (the one that matters):** the browser's
`feature-extractor.ts` must produce the same 21 feature values the model was trained on.
Validated over **960 stratified URLs / 20,160 values** by `check_parity.py` → **0 mismatches**.
Previously the TS extractor's hardcoded 14-entry TLD dict diverged from Python's `tldextract`
on country/compound TLDs and IP hosts (~10% of URLs, the `DomainLength`/`NoOfSubDomain`
train/serve skew). Fixed Aug 2026 by a 1:1 `tldextract` port in TS
(`src/ml/tldextract.ts` + generated `src/ml/psl-trie.ts`). Regenerate the PSL data with
`python ml-pipeline/gen_psl_trie.py` whenever the Python PSL updates, and re-run:
`node ml-pipeline/gen_parity_features.mjs && python ml-pipeline/check_parity.py`.

**SHAP (exact TreeExplainer, 500 seeded held-out samples)** — `models/shap_values.json`,
generated by `ml-pipeline/gen_shap_table.py`. Top 5 by mean|SHAP|:

| Feature | mean\|SHAP\| | value↔SHAP corr | Direction |
|---|---|---|---|
| TLDLegitimateProb | 0.0789 | −0.85 | lower TLD trust → phishing |
| NoOfSubDomain | 0.0758 | **−0.84** | **fewer** subdomains → phishing |
| DegitRatioInURL | 0.0515 | +0.73 | more digits → phishing |
| DomainLength | 0.0491 | +0.14 | mixed / context-dependent |
| CharContinuationRate | 0.0489 | +0.72 | more repetition → phishing |

> Regenerated Aug 6, 2026 against the post-corpus-fix model. The earlier table
> (`NoOfSubDomain` #1 at 0.1770) was computed on the pre-fix model and is superseded.
>
> **`NoOfSubDomain` still runs OPPOSITE to the phishing literature.** The corpus fix
> demoted it in *permutation* importance (#1 → #5, 0.256 → 0.091) but did **not** correct
> its SHAP direction: r moved from −0.75 to **−0.84**, marginally stronger. Any claim that
> the inverted-direction artifact is "gone" is wrong — only its magnitude shrank.
> Do not cite the high-subdomain-count→phishing story for this model.
> `URLSimilarityIndex` (r = −0.43, was −0.64) is likewise a consequence of the ≥0.6
> typosquat threshold, not evidence that brand-similar URLs are safe.
>
> **`IsHTTPS` is constant** in the sample: mean|SHAP| = 0.000000, contributing nothing.
> Four more features (`ObfuscationRatio`, `NoOfObfuscatedChar`, `HasObfuscation`,
> `IsDomainIP`) sit below 4e-5 — effectively inert. The model runs on ~11 live features,
> not 21. Note this before presenting the 21-feature set as all load-bearing.
>
> Use `mean_abs_shap` for magnitude and `value_shap_corr` for direction — **not** signed
> mean SHAP, which only reflects the sample's class mix.


## 4. Why content features were dropped (the false-positive root cause)
Live testing showed google.com → 91.8% PHISHING. Root cause = **train/serve skew**:
- The old model's #1 feature `LineOfCode` (importance 0.16) was trained on a
  near-degenerate distribution but received real, large, **unscaled** values from the
  live DOM. Out-of-range inputs routed legitimate pages into garbage leaves.
- `DomainTitleMatchScore` / `URLTitleMatchScore` were trained on a **0–100** scale but
  the TS extractor emitted **0/1**, destroying the strongest legitimacy signal.

Lexical (URL-string) features have **exact train/serve parity** — `lexical_extractor.py`
and `feature-extractor.ts` are byte-identical ports (same BRANDS, TLD_SCORES, Levenshtein,
char-frequency tables, and — since Aug 2026 — the same Public-Suffix-List domain parsing via
`src/ml/tldextract.ts`, a 1:1 port of Python's `tldextract`). Validated at 0 mismatches over
960 URLs by `check_parity.py`. The lexical-only model cannot suffer this skew.

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
python ml-pipeline/gen_shap_table.py                                 # → models/shap_values.json (SHAP + directions)
python ml-pipeline/generate_shap_plots.py                            # → models/shap_*.png (figures only)
cd phishing-extension && pnpm build                                  # → build/chrome-mv3-prod
```

> `gen_shap_table.py` is the citable artifact (writes JSON); `generate_shap_plots.py`
> only produces PNGs and prints to stdout. Both re-extract features from the full
> dataset first, so each takes ~6 min.

## 8. Known follow-ups (not blockers)
- **Model size (19.4 MB):** Still large for a browser bundle. Further reduction:
  reduce to 50 trees + max_depth=15 (~3 MB), or switch to XGBoost JSON (10–50× smaller
  than RF for equivalent accuracy). Investigate before finalising the dissertation's
  "lightweight" claim.
- **amazon.com FP:** Long product paths (e.g. `/dp/B08N5WRWNW`) are flagged as phishing.
  Root cause: `NoOfSubDomain` (importance 0.256) and `DomainLength` (0.158) interact
  poorly with long paths from short brand domains. Mitigation: brand-list augmentation
  or path-depth normalisation in the feature extractor.
- **Parity sample size:** `cross_validate_ts.mjs` (inference smoke test) still uses 6 URLs.
  Extractor parity is now validated at 960 URLs via `check_parity.py` — cite that, not the
  6-URL script, for train/serve claims.
- **SHAP explanations** in `shap-approximator.ts` are still global-importance lookups
  with mostly static text. Functional but not true per-prediction SHAP.
- **`shap_mapping.json` is stale and incomplete (extension-facing bug).** It holds only
  **12** features with importances from an *older* model (`NoOfSubDomain` 0.3076 vs the
  current 0.2559) and is **missing `DomainLength`** — the #2 feature — and `URLLength`,
  so the popup can never cite either. `shap-approximator.ts:23,33` also still branches on
  `DomainTitleMatchScore`, a v3 content feature dropped in v4. Regenerate from the 21
  current features before the next build.
- **Dead code in `train.py`:** `augment_legitimate_urls()` and `inject_popular_legit()`
  are defined but never called — `build_legit_urls_from_top_sites()` does the structure
  augmentation inline. Harmless, but they read as active pipeline stages.
- **`cross_validate_ts.mjs` prints stale text:** hardcodes "All 44 scaled values match"
  (model has 21) and still frames itself as diagnosing the scaler bug fixed in 0537be5,
  printing "SCALER BUG IDENTIFIED" and "fix the scaler formula and ship it" on success.
