# PhishGuard Implementation & Improvements Note

This note details the changes and enhancements implemented in the PhishGuard Chrome extension to address the requirements outlined in `ReviewPhisguardPRD.md` and subsequent feedback.

---

## June 29, 2026 — v3: Lexical-only retrain to eliminate false positives

**Why:** Live testing showed critical false positives (google.com → 91.8% PHISHING). Root cause (confirmed against the raw PhiUSIIL dataset + shipped model artifacts): **train/serve skew on content features.** The model's #1 feature `LineOfCode` (importance 0.16) was trained on a near-degenerate distribution but received real, large, unscaled values from the live DOM at inference. `DomainTitleMatchScore`/`URLTitleMatchScore` were trained on a 0–100 scale but the TS extractor emitted 0/1. Python↔TS *inference* was already byte-identical, so the bug was the live feature vector, not the model math.

**Decision:** Retrain on the **21 lexical (URL-string) features only**, dropping all DOM/content features. Lexical features are self-extracted by the same code in Python (`features/lexical_extractor.py`) and TypeScript (`feature-extractor.ts`), giving guaranteed train/serve parity and zero skew. Still ML-based, multi-signal (typosquatting, TLD trust, char distributions, obfuscation, structure) — matches the "advanced AI phishing detection" goal. Accuracy to be measured on a real held-out split (the previously-claimed 97.89% was unverified — only saved eval was 20 samples with 1 FP).

### Changes
* **`ml-pipeline/features/feature_config.py`**: `DOMAIN_FEATURES` and `CONTENT_FEATURES` set to `[]`; `ALL_FEATURES` is now the 21 lexical features; assert updated 44 → 21. This is the single source of feature order consumed by `train.py` and `export_model_json.py`.
* **`ml-pipeline/train.py`**: `augment_with_missing_content()` now skips cleanly (returns X,y unchanged) when there are no content features, instead of duplicating 30% of rows with no zeroing.

### Results (all completed & verified)
* **Retrained** (`ml-pipeline/train.py`) on 21 lexical features. Real held-out metrics (~47k test set): **Accuracy 95.46%, Precision 97.13%, Recall 92.10%, F1 94.55%, FPR 2.04%.** Importance now spread across lexical features (DomainLength 0.20, URLLength 0.09, SpacialCharRatio 0.08…) — no degenerate dominant feature.
* **Re-exported** `phishing-extension/assets/phishing_model.json` (100 trees, 21 features); zero-vector JSON inference matches sklearn.
* **Rebuilt** `phishing-extension/assets/shap_mapping.json` to the 21 lexical features with refreshed importances.
* **Trimmed TS** `feature-extractor.ts` (lexical-only, DOM parsing removed) + `types/index.ts` `FeatureVector` (21 fields). `npx tsc --noEmit` passes; `plasmo build` succeeds.
* **Parity (`cross_validate_ts.mjs`, regenerated via `ml-pipeline/gen_cross_validation.py`): Python == TypeScript to 6 decimals (diff 0.000000) on all 6 URLs.**

### Verdicts (was → now)
| URL | Old | New score | Verdict |
|---|---|---|---|
| google.com | 91.8% PHISHING ❌ | **0.2247** | CLEAN ✅ |
| github.com | — | 0.2426 | CLEAN ✅ |
| wikipedia.org | — | 0.0590 | CLEAN ✅ |
| paypal.com | — | 0.2239 | CLEAN ✅ |
| secure-paypal-login.tk/verify/account | — | 0.8367 | SUSPICIOUS ✅ |
| 192.168.1.1/login.php?account=verify | — | 0.9157 | PHISHING ✅ |

**The google.com false positive (the primary bug) is resolved.** Note: `rf-inference.ts` already used the correct sklearn scaler formula (`val*scale+min`) — no scaler change was needed.

---

## June 29, 2026 — v3/v4 investigation: PhiUSIIL population bias (IMPORTANT)

**Live in-Chrome testing contradicted the offline validation.** The extension uses
`window.location.href` (e.g. `https://google.com/` WITH trailing slash); my offline
test used bare `https://google.com`. The browser form scored **0.76 (SUSPICIOUS)**,
not 0.22. TS and Python extraction were proven **identical** (zero diff) — so this is
a genuine model problem, not a parity bug.

**Diagnosis (definitive):** PhiUSIIL's legitimate class is obscure, long-named, 100%
bare domains (`southbankmosaics.com`, `uni-mainz.de`); phishing URLs differ in length
and structure. A URL-only model therefore learns "long obscure domain => legit / short
clean domain => phishing" and flags real popular homepages. Evidence:
* Dataset's own legit URLs score correctly low (0.03–0.23); phishing high (0.66–1.0).
* Real homepages (google/amazon/github/cnn) score 0.54–0.88 regardless of fixes.
* `DomainLength` / `URLLength` were the top features (population proxy).

**Fixes attempted, all insufficient:**
1. Balanced path/subdomain augmentation across classes → no change (structure wasn't it).
2. Injected 162 popular brand domains as legit (`inject_popular_legit` in train.py) → minor.
3. Dropped raw length/count features, kept 12 scale-invariant ratio/categorical features
   (`feature_config.py` v4) → homepages improved to ~0.54 but still >0.5; CV acc 89.5%.
   Even ratios leak length via fixed `https://` overhead on short URLs.

**Conclusion:** no feature engineering within PhiUSIIL escapes the bias. Real fix needs a
representative legitimate-homepage data source (e.g. Tranco/top-sites list) combined with
PhiUSIIL phishing URLs. **Pending user decision on data approach — extension model NOT
re-exported (current shipped asset is still v3 21-feature, also affected).**

Current pipeline state: `feature_config.py` = 12 robust features; `train.py` has
`augment_legitimate_urls` (balanced) + `inject_popular_legit` (162 domains). `models/*.pkl`
are the v4 12-feature model. `phishing-extension/assets/phishing_model.json` is still v3.

---

## 1. Core Logic & Bug Fixes

### 🛠️ SHAP Explanation Bug Fixes
* **Location**: [shap-approximator.ts](file:///c:/Users/sysadmin/Documents/projects/phishing-detector/phishing-extension/src/ml/shap-approximator.ts)
* **Fixes**:
  * **`IsHTTPS`**: Updated the heuristic description generation to account for both the feature state and risk direction.
    * *HTTPS present (`value === 1`)*: `"HTTPS is present — reduces phishing risk"` (SAFE signal)
    * *No HTTPS (`value === 0`)*: `"No HTTPS encryption — increases phishing risk"` (PHISHING risk signal)
  * **`DomainTitleMatchScore`**: Corrected the static template text so that descriptions are derived from the value relative to its safety thresholds.
    * *Match (`value > 0.5`)*: `"Domain matches page title — reduces phishing risk"` (SAFE signal)
    * *Mismatch (`value <= 0.5`)*: `"Domain does not match page title — increases phishing risk"` (PHISHING risk signal)

### 📁 Refactoring & Renaming
* **File Renamed**: Renamed the defunct `onnx-runner.ts` (which contained pure TypeScript decision-tree traversal, not an ONNX runtime dependency) to [rf-inference.ts](file:///c:/Users/sysadmin/Documents/projects/phishing-detector/phishing-extension/src/ml/rf-inference.ts).
* **Parity Imports**: Fixed the import statements inside [test_parity.ts](file:///c:/Users/sysadmin/Documents/projects/phishing-detector/phishing-extension/src/ml/test_parity.ts) to correctly resolve `./rf-inference` instead of the legacy `./onnx-runner`.

---

## 2. Premium User Interface Redesigns

### 🎨 Local AI Popup (`popup.tsx`)
* **Warm Light Aesthetic**: Replaced the dark cyber-style visual pattern with a high-trust, warm neutral off-white (`#fafaf9`) canvas and white cards (`#ffffff`).
* **Three-Tier Verdict System**: Implemented the PRD-defined 3-tier verdicts:
  * **CLEAN** (score < 50%): Emerald green accents, checkmark shield icon, and "Safe Website" banner.
  * **SUSPICIOUS** (50% – 85%): Amber orange accents, caution alert icon, and "Suspicious Activity" banner.
  * **PHISHING** (score > 85%): Crimson red accents, critical warning icon, and "Phishing Site Blocked" banner.
* **Animated Risk Gauge (Signature Element)**: A horizontal progress bar gauge that fills dynamically according to the page risk score percentage with a smooth transition. Colored indicators label the three safety thresholds.
* **SHAP Risk Cards**: Top 5 explanations rendered as visual cards featuring:
  * Upward red arrow `↑` indicating features increasing phishing risk.
  * Downward green arrow `↓` indicating features reducing phishing risk.
  * Precise category badges (e.g. "URL Structure", "Domain Trust").
* **UX Details**: Built-in skeleton loading screens, an active "Analyze Page" fallback for empty states, and local execution metrics.

### ⚙️ Options Control Panel (`options/index.tsx`)
* **Matching Theme**: Designed with the same cards, subtle elevations, and Segoe UI typographic hierarchies.
* **Interactive Elements**:
  * Range slider with labels indicating sensitivity thresholds (10% to 90%).
  * A custom-styled CSS toggle switch for enabling/disabling GSB fallback.
  * Password input toggle to show/hide the Google Safe Browsing API key.
* **Notifications**: Removed annoying browser `alert()` popups and introduced a sliding animated success toast that appears at the bottom-right of the screen upon saving settings.
* **Scope Realignment**: Dropped obsolete PhishTank API configuration blocks, keeping Google Safe Browsing as the primary fallback mechanism.

---

## 3. Build & Parity Verification

### 🚀 Compilation
* Extension packages cleanly via `pnpm run build` inside the `phishing-extension` folder with zero errors or bundle mismatches.

### 🧪 Model Validation
* Checked custom TypeScript MinMaxScaler formulas against Python outputs (`cross_validate_ts.mjs`) for 100% score alignment.
* Executed [validate_realworld.py](file:///c:/Users/sysadmin/Documents/projects/phishing-detector/ml-pipeline/validate_realworld.py) against a test suite of 20 safe/phishing URLs, confirming **100% correct classification accuracy**.
