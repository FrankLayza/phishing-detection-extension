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
- **Verdict tiers:** CLEAN `< 0.50`, SUSPICIOUS `0.50–0.90`, PHISHING `≥ 0.90`
  (calibrated Aug 9, 2026 — see §3a; the PHISHING cut was `0.85` before)
- **Scaler:** sklearn `MinMaxScaler`. The browser applies the **real sklearn formula
  `scaled = raw * scale_ + min_`** (NOT `clip(x/data_max)` — that PRD claim is wrong
  for the shipped model, whose `min_` has negative values). `rf-inference.ts` already
  does this correctly.

## 3. Measured performance (real, verifiable)
Held-out 20% test set (42,189 samples: 22,000 legit + 20,189 phish), from `models/evaluation_results.json`:

| Metric | Value |
|---|---|
| Accuracy | 91.58% |
| Precision | 93.28% |
| Recall | 88.80% |
| F1 | 90.98% |
| False Positive Rate | 5.87% |
| False Negative Rate | 11.20% |
| 5-fold CV accuracy | 91.43% (±0.15%) |

**Confusion matrix:** TN=20,708 | FP=1,292 | FN=2,261 | TP=17,928

> These are the **query/digit-leak-fix** numbers (retrained Aug 9, 2026, later session).
> The data-derived-TLD figures (92.97% / 95.21% / 89.84%, FP=913) are superseded.
>
> **Accuracy fell ~1.4 points and that is the intended result, not a regression.** The
> synthesised legitimate class contained no query strings and no path digits, so `?`, `=`
> and digits were perfect phishing tells *inside the corpus*. Held-out accuracy was partly
> measuring that leak. Closing it lowers the in-corpus number while cutting the
> false-positive rate on real unseen sites by a quarter (§3a). Quote both together; do not
> cite the old 92.97% as if it were comparable.
>
> **5-fold CV is now persisted** (Aug 9, 2026). `train.py` computed it every run but
> only `print()`ed it, which is why this section previously said "do not cite a CV
> number". It now writes `models/cv_results.json` (mean, std, per-fold), so 92.84%
> (±0.33%, 2σ) is artifact-backed. The old "93.85% (±0.11%)" remains superseded — it
> was a pre-corpus-fix stdout figure.
>
> Training is fully seeded (`random_state=42` on the split, SMOTE and the forest).
> Verified by re-running: identical metrics, identical forest (691,570 nodes, matching
> thresholds) and a **byte-identical** `phishing_model.json`. Only `random_forest.pkl`
> changes hash between runs, from joblib serialization metadata rather than model
> content — so don't treat a `.pkl` hash difference as a changed model.

### 3a. Unknown-legitimate FPR — the metric that actually gates the product
Held-out accuracy measures the corpus, not the goal. The legitimate class is partly
synthesized, so in-corpus accuracy stays high while genuinely unseen legitimate sites
fail. Measured by `validate_unknown_legit.py` → `models/unknown_legit_validation.json`:

| Set | n | ML-tier FPR | Full-pipeline FPR | Hard red alarms |
|---|---|---|---|---|
| Curated regional (banks, fintech, SMB) | 144 | 21.5% | 16.7% | **0.7%** |
| Sampled top-1m, rank ≥120k | 4,000 | **15.4%** | 9.5% | **0.8%** |

> Measured Aug 9, 2026 (later session) on the query/digit-leak-fix model. The measured
> pre-change baseline was **20.8%** on both populations. Cite the **sampled** row as the
> headline: n=4,000 has statistical power, n=144 does not, and the curated set is
> 100/144 `.com` so it moves on composition rather than on real effects.
>
> An older SOT figure of 18.1% curated **could not be reproduced** (the unmodified model
> measured 20.8%); `models/` is untracked so the earlier JSON is unrecoverable. Baseline
> is 20.8%; cite nothing older.

**The root cause was a corpus leak, found by asking the model.** After two principled
feature fixes failed to move this number, per-instance SHAP on the 36 curated false
positives named the reason: every worst offender was a query URL
(`takealot.com/search?q=account&page=2`, 0.984). The synthesised legitimate class
contained `?` in **0.0%** of URLs against phishing's 6.4%, `=` in 0.0% against 5.8%, and
path digits in 0.0% against 13.8% — so punctuation and digits were perfect phishing tells
in training, and every real site with a search box, pagination or a dated article tripped
them. Fixed in `train.py` (`_synth_query()` + digit injection, calibrated to the phishing
rates). Sampled FPR 20.8% → **15.4%** for 1.1 points of recall.

**Verdict bands are now calibrated** (`models/threshold_sweep.json`, from
`sweep_thresholds.py`). The CLEAN cut governs recall, so it stays at 0.50 — raising it to
0.65 would cost 8.7 points of phishing caught (88.8% → 80.1%) to buy FPR that the middle
tier handles more safely. The **PHISHING** cut moved 0.85 → **0.90**, halving hard red
alarms on unknown-legit sites (1.8% → 0.8%) while still calling 46.9% of real phishing
red. Most residual FPR is now the amber "be cautious" tier, which does not block
navigation — that distinction matters more to users than the headline FPR.

Still above the <10% ML-tier target. Remaining drivers: the residual path-digit gap (7.4%
legit vs 13.8% phishing) and long hyphenated domains (`oakwood-dental-clinic.com`), rare
in both classes. The allowlist cannot close it: gtbank.com is rank ~380k, flutterwave.com
~687k; covering them needs ~700k entries (~10 MB) vs the current 30k/456 KB.

**A rejected variant, recorded so it is not retried.** Making the legit class mostly
bare-domain improved curated FPR (21.5% → 14.6%) but made sampled FPR slightly *worse*
(15.4% → 15.8%) while costing 4.3 points of recall (88.8% → 84.5%). The curated gain was a
composition artifact. Full ablation table in IMPLEMENTATION_NOTE.md.

**Do not describe the Aug 7 "recover FPR via TLDLegitimateProb" hypothesis as confirmed;
it was falsified by measurement.** The TLD table is retained on correctness grounds
(1,172 suffixes scored on evidence vs 14 plus a coin flip), not because it improved this
metric.

**Real-world spot validation** (`validate_realworld.py`, 20 curated URLs):
- Overall: 19/20 correct (95.0%)
- Safe URLs: 9/10 — one FP: `amazon.com/dp/B08N5WRWNW` (ASIN token `B08N5WRWNW`
  raises `DegitRatioInURL` and caps-continuation). **ML-tier only:** `amazon.com` is in
  the 30k allowlist and short-circuits to CLEAN before the ML tier runs, so the shipped
  extension is unaffected. Confirmed by reading the tier order, not assumed.
- Phishing URLs: 10/10 — all correctly flagged with p ≥ 0.66

**Model size:** `phishing-extension/assets/phishing_model.json` = **17,183 KB (16.8 MB)**
(down from 175.8 MB with the previous 300-tree, unbounded-depth config; 19.4 MB → 16.8 MB
at this retrain, since data-derived TLD values split more cleanly than a 0.50 default)

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
`gen_parity_features.mjs` now rebuilds its own esbuild bundle on every run — before
Aug 9 it read a hand-built `__parity_bundle.mjs`, so a stale bundle could report
PARITY OK against extractor code that was never compiled. Do not reintroduce a
manual prebuild step.

**`TLDLegitimateProb` is a generated table, not a formula** (Aug 9, 2026). The same
14-entry dict also *supplied* this feature's value, defaulting every unlisted suffix
to a flat 0.50 — 22% of curated legit sites, and also `.app` (6,368 phishing rows vs
200 legit), `.xyz` and `.top`, which the dict scored as neutral as `.org`. Replaced by
`ml-pipeline/gen_tld_rates.py`, which estimates a per-suffix legit rate with
hierarchical shrinkage toward the parent suffix (`edu.ng` → `ng` → global prior) and
emits **both** consumers from one computation: `features/tld_rates.json` for Python and
generated `src/ml/tld-rates.ts` for the browser. All arithmetic happens at generation
time, so runtime is a pure lookup in both languages and parity is exact by construction.
Regenerate with `python ml-pipeline/gen_tld_rates.py`, then re-run the parity harness,
`train.py`, `export_model_json.py` and `gen_shap_mapping.py` — the feature's values
change, so the model **must** be retrained.

Two properties of that estimator are load-bearing and easy to get wrong:

* **Evidence population ≠ training corpus.** Rates are estimated from a wider legit
  slice (deeper top-1m ranks) than the 52/48-balanced training corpus, and that slice
  is held **disjoint from both the held-out test split and the sampled-validation
  band** so neither metric is compromised. Estimating from the balanced corpus instead
  put `.com` at 0.585, since a corpus balanced for training is the wrong sample from
  which to estimate a reputation prior.
* **Shrinkage M = 100, chosen by sweep against the FPR metric, not by taste.** No
  dataset can estimate `com.ng`: all of top-1m holds 34 such domains against PhiUSIIL's
  59 phishing rows. Maximum likelihood reads 0.14 there and flagged 8/8 curated
  `com.ng` sites. M = 100 keeps sparse regional suffixes near-neutral (`com.ng` 0.477)
  while high-volume hostile ones keep full signal (`.app` 0.095, `.top` 0.030,
  `.xyz` 0.292, `.tk` 0.147). At M = 300 `.tk` washes out to 0.345.

**SHAP (exact TreeExplainer, 500 seeded held-out samples)** — `models/shap_values.json`,
generated by `ml-pipeline/gen_shap_table.py`. Top 5 by mean|SHAP|:

| Feature | mean\|SHAP\| | value↔SHAP corr | Direction |
|---|---|---|---|
| TLDLegitimateProb | 0.1191 | −0.93 | lower TLD trust → phishing |
| NoOfSubDomain | 0.0714 | **−0.84** | **fewer** subdomains → phishing |
| DegitRatioInURL | 0.0476 | +0.71 | more digits → phishing |
| DomainLength | 0.0468 | +0.32 | longer domain → phishing |
| CharContinuationRate | 0.0415 | +0.70 | more repetition → phishing |

> Regenerated Aug 9, 2026 against the data-derived-TLD model. The Aug 6 table
> (`TLDLegitimateProb` at 0.0789, `DomainLength` r = +0.14) was computed before
> that change and is superseded; the Aug 4 table (`NoOfSubDomain` #1 at 0.1770)
> predates the corpus fix. `TLDLegitimateProb` **increased** its dominance when
> the hardcoded dict was replaced (0.0789 → 0.1191, r −0.85 → −0.93): with 1,172
> suffixes scored on evidence instead of 14 plus a 0.50 default, the feature
> now carries real information across the whole corpus rather than for 14 TLDs.
> One model decision in four traces to this single feature — a concentration
> worth stating as a limitation, not a strength.
>
> **`DomainLength` is now the regional false-positive driver.** Its correlation
> strengthened +0.14 → +0.32, and with the TLD feature neutral for `com.ng`
> (0.477) it is what still flags `gtbank.com.ng` at 0.678. Compound suffixes are
> mechanically longer than `.com`, so the feature encodes suffix structure as
> risk. This is the next FPR item and is **not** fixed by the TLD work.
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
