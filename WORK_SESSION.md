# WORK_SESSION.md

> Session doc for the PhishGuard project. Treat the repo as source of truth; this file summarises state as observed (August 5, 2026).

## Project Summary

**PhishGuard** is a privacy-preserving Chrome/Chromium extension that classifies URLs as
CLEAN / SUSPICIOUS / PHISHING in real time, on-device. A Random Forest is trained in Python
on PhiUSIIL phishing URLs + a Cisco Umbrella top-sites legitimate class, exported to compact
JSON, and run by a pure-TypeScript inference engine in the extension. Google Safe Browsing is
an optional fallback for borderline scores only. The primary success metric is **minimizing
false positives on legitimate, previously-unseen websites**.

Current model: v4, 21 lexical (URL-string) features only, `RandomForest(n_estimators=100,
depth=20, ...)`. Content/DOM features were dropped because they caused train/serve skew
(google.com scored 91.8% PHISHING).

## Current State

Grounded, working baseline (models regenerated Aug 5 12:48, assets re-exported):

- **Model:** `models/random_forest.pkl` (61 MB), scaler, `feature_importance.json`,
  `evaluation_results.json`, `shap_values.json`.
- **Assets:** `phishing-extension/assets/phishing_model.json` (19.4 MB, 21-feature),
  `shap_mapping.json` (21/21 features, regenerated), `top_domains.json` allowlist (30k).
- **Docs:** `SOURCE_OF_TRUTH.md` (authoritative, v4), `IMPLEMENTATION_NOTE.md`.
- **Corpus fix applied:** legit class now draws from BOTH top-sites (55k) and small/obscure
  real sites (55k PhiUSIIL legit domains), with URL structure distribution-matched to the
  phishing class (`measure_structure` / `build_legit_urls` in `train.py`). This cut real-world
  unknown-legit FPR from 60.4% → 18.1% (curated) and 26.7% → 19.1% (sampled).
- **Brand/SHAP fixes:** `shap_mapping.json` regenerated to 21/21; `shap-approximator.ts`
  dead v3 branch (`DomainTitleMatchScore`) removed.

## Recent Work

Most recent activity (Aug 5), from newest to oldest, all **uncommitted / untracked**:

- **Extractor parity fix** (this session) — see Current Objective. New files:
  `phishing-extension/src/ml/tldextract.ts`, `phishing-extension/src/ml/psl-trie.ts`
  (generated), `ml-pipeline/gen_psl_trie.py`; modified `feature-extractor.ts`,
  `ml-pipeline/check_parity.py`. Parity now 0 mismatches / 20,160 values.
- `ml-pipeline/check_parity.py` (19:36) — NEW parity harness. Compares Python
  `lexical_extractor.py` against the REAL shipped `feature-extractor.ts` (via esbuild bundle)
  over 960 URLs. Was authored before this session but had not been run; first run exposed the
  skew above, subsequent runs are green.
- `ml-pipeline/gen_parity_features.mjs` (13:53) + `ml-pipeline/__parity_bundle.mjs` (13:54) —
  build the TS extractor for parity; writes `parity_ts.json` (960 URLs, 0 errors).
- `parity_urls.json` (13:53, 960 URLs) / `parity_ts.json` (13:54).
- `IMPLEMENTATION_NOTE.md` (13:26) — the "Fixed the false-positive root cause: corpus
  structure bias" entry (Aug 5). Up-to-date and consistent with code.
- `simulate_extension.mjs` (12:44) — end-to-end sim; unknown-legit corpus expanded 4 → 12.
- `ml-pipeline/validate_unknown_legit.py` (12:39) — acceptance metric (unknown-legit FPR).
- `ml-pipeline/gen_shap_mapping.py` (12:41) — drift-proof, converts feature_importance.json
  → shap_mapping.json.
- `ml-pipeline/train.py` + `features/feature_config.py` (12:36 / 13:16) — corpus-structure
  fix, benign vocabulary synthesis, 21 features retained (comment corrected; 12-feature subset
  rejected as worse on every axis).

## Current Objective

**Restore / verify Python ↔ TypeScript **extractor** parity on a statistically meaningful
sample.** The shipping model is trained on `lexical_extractor.py` features but scored in the
browser on `feature-extractor.ts`. `SOURCE_OF_TRUTH.md` claims the two are "byte-identical
ports", previously tested on only 6 URLs. `check_parity.py` was authored this session to test
that claim properly.

### ✅ RESOLVED this session — extractor parity is now green

The parity harness exposed a **real train/serve skew** (195 mismatches / 20,160 values on the
first run) and it has been **fixed and verified**:

- **Before:** 195 mismatches — `DomainLength` (10.0% of URLs) and `NoOfSubDomain` (9.8%)
  diverged because Python used `tldextract` (full Public Suffix List) while the TS extractor
  used a 14-entry hardcoded TLD dict. Divergences clustered on country/compound TLDs
  (`.com.ng`, `.com.au`, `ac.in` …) and IP hosts.
- **Fix:**
  - `phishing-extension/src/ml/tldextract.ts` (new) — 1:1 port of tldextract's algorithm
    (longest-match PSL trie with wildcard/exception rules, RFC 3492 punycode decode, IP
    handling) plus `rawHost` / `rawPath` that mirror `lenient_netloc` / `urlparse().path`
    (no WHATWG percent-decoding / punycode conversion).
  - `phishing-extension/src/ml/psl-trie.ts` (generated) — the 6,933 public rules from the
    tldextract **runtime cache** (what training actually used; the bundled snapshot differs
    by ~350 rules), via `ml-pipeline/gen_psl_trie.py`.
  - `feature-extractor.ts` — domain/subdomain/TLD decomposition, letter/digit counting and
    path-based brand similarity now Unicode-aware and derived from the raw URL string.
  - `ml-pipeline/check_parity.py` — stdout now UTF-8 (was crashing on unicode URLs).
- **Verified:**
  - `check_parity.py` on 960 URLs / 20,160 values → **PARITY OK, 0 mismatches**.
  - 4,580 randomized hostname parses (981 curated + 3,599 fuzz, incl. IDN, wildcard/exception
    rules, trailing dots, IPs) → all identical to Python.
  - Scoring the 960 URLs under TS vs Python features → **0 verdict changes, max delta 0.0000**
    (previously 21 URLs flipped clean→flagged, incl. 3 curated FPs: `lagostechhub.com.ng`,
    `greenfield-academy.edu.ng`, `westside-physio.com.au`).
  - `npx tsc --noEmit` clean; `pnpm build` (plasmo chrome-mv3) succeeds.
  - No retrain needed: the model was trained on Python features and the browser now produces
    identical values.

No other code fix has been applied.

**Measured FP impact of the divergence (this session):** scoring the same 960 URLs
with Python features (train-time) vs shipped TS features (browser) flips **21 URLs from
clean → flagged** — i.e. the skew itself *creates* false positives in the browser for
legit sites on undicted country/compound TLDs (`.com.au` ×5, `.ng` ×3, `.gov.my`,
`.com.tr`, `.ac.in`, `.arpa` ×6 …), max delta 0.39 (`middlesbrough.gov.uk` 0.473→0.780).
Three of those are already in the curated unknown-legit FP list (`lagostechhub.com.ng`,
`greenfield-academy.edu.ng`, `westside-physio.com.au`), so fixing parity directly lowers
the curated FPR. It does **not** however address the dominant remaining FP driver — long
hyphenated domains under-supported in *both* training classes (`.co.uk`/`.com` parse
identically, so parity is irrelevant to them). Parity fix is necessary but not sufficient
to reach the <10% FPR target.

**Post-fix status:** the above 21 skew-created FPs are eliminated (0 verdict changes, max
delta 0.0000 on the same 960 URLs). The 18–19% unknown-legit FPR that remains is the
distributional/coverage problem (long hyphenated domains + uncalibrated thresholds), not
extractor skew.

## Outstanding TODOs

Priority order:

1. **[HIGH] Decide the verdict threshold** — the IMPLEMENTATION_NOTE's open item: unknown-legit
   FPR is 18–19% vs the <10% target; a threshold sweep (0.60/0.65 vs current 0.50) is presented
   but a product decision was not yet applied. Weigh the phishing-recall trade-off.
2. **[MED] Extension import / naming** — `feature_extractor.py` import `tldextract` vs TS; verify
   `top_domains.json` (allowlist) is still the shipped 30k and that the extension build matches
   assets after any retrain.
3. **[MED] Notes/审计 hygiene** — SOT §8 follow-ups: model size (19.4 MB) for a "lightweight"
   claim (XGBoost or fewer trees); `cross_validate_ts.mjs` stale text ("All 44 scaled values
   match", "SCALER BUG IDENTIFIED"); `simulate_extension.mjs` inlined extractor has drift;
   dead `augment_virtual`/`inject_popular_legit` in `train.py`; `.gitignore` names a docx file
   that doesn't match the actual(`PROJECT_COMPLETE_CORRECTED` vs the tracked `REPORT_*` docx).
4. **[LOW] Dissertation reconcile of SOT claims** — any doc numbers must cite artifacts
   (`models/evaluation_results.json`, `parity_results.json`, ...). SHAP in the popup remains
   global-importance approximation, not per-prediction SHAP (known, SOT §8).

**Done this session (was #1):** extractor parity fix (see Current Objective) — verified 0
mismatches / 20,160 values, 0 score impact.

## Risks / Technical Debt

- **PSL drift between Python and the browser**: the TS trie is a frozen snapshot of
  tldextract's runtime cache. If the Python PSL updates (cache expiry / package upgrade),
  `check_parity.py` will fail → regenerate with `python ml-pipeline/gen_psl_trie.py` and re-run
  the parity harness. This is now an enforced gate, not a silent risk.
- **Model size** 19.4 MB asset is large for a browser bundle; dissertation "lightweight" claim is
  at risk on delivery.
- **Small/obscure-class legit support**: unknown-legit FPR 18–19% remains above the <10% target;
  failures concentrated in long hyphenated domains rare in both training classes.
- **Docs/asset drift risk:** `shap_mapping.json` was just regenerated and must stay driven by
  `gen_shap_mapping.py`, not hand-edited. Same now applies to `psl-trie.ts` / `gen_psl_trie.py`.
- **Known minor residuals** (documented, not skew): `rawHost` uses strict dotted-quad IPv4 for
  IP detection (abbreviated `inet_aton` forms like `127.1` diverge); userinfo URLs (`user@host`)
  are parsed by raw host not netloc prefix. Both ~nonexistent in real traffic/datasets.
- Uncommitted work: none of the Aug 5 work is committed; a wrong late edit could be lost or
  mix debug files (parity JSON, 60 MB pkl) into a commit (see `.gitignore`).

## Recommended Next Step

**Extractor parity is now fixed and verified (0 mismatches / 20,160 values).** The highest-value
remaining work is the **verdict-threshold decision**: unknown-legit FPR is 18–19% vs the <10%
target. A sweep is already documented in IMPLEMENTATION_NOTE.md (0.60 → 11.8%/13.7% FPR at 86.2%
recall; 0.65 → 11.8%/11.8% at 82.4%). Apply the chosen threshold (CLEAN/SUSPICIOUS boundary in
`rf-inference.ts` + popup), then re-measure with `validate_unknown_legit.py`.

Optional after that (product decision): augment the legit class with long hyphenated domains to
improve model support for the residual FP population.

Ongoing hygiene (cheap, when time permits): retire the stale text in `cross_validate_ts.mjs`,
fix the drifted inlined extractor in `simulate_extension.mjs`/`diagnose_url.mjs`, and align the
`.gitignore` docx entry with the actual filenames.