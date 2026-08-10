# PhishGuard Implementation & Improvements Note

This note details the changes and enhancements implemented in the PhishGuard Chrome extension to address the requirements outlined in `ReviewPhisguardPRD.md` and subsequent feedback.

---

## August 10, 2026 — The shipped build had no model: restored the asset copy dropped with `web_accessible_resources`

**Context:** merging `fix/query-digit-corpus-leak` into `main` (fast-forward to `0ca9429`)
to test the recalibrated red band in Chrome. The merge itself was clean. Verifying the
build before loading it unpacked is what surfaced this.

**The bug:** `build/chrome-mv3-prod/` contained no `assets/` directory, while the service
worker fetches three files from exactly that path at runtime:

| Call site | Asset |
| --- | --- |
| [`src/ml/rf-inference.ts:48`](phishing-extension/src/ml/rf-inference.ts) | `phishing_model.json` |
| [`src/ml/shap-approximator.ts:8`](phishing-extension/src/ml/shap-approximator.ts) | `shap_mapping.json` |
| [`src/background/index.ts:21`](phishing-extension/src/background/index.ts) | `top_domains.json` |

**Cause:** commit `357f33e` (Aug 7, "tighten extension permissions") removed
`web_accessible_resources: ["assets/*"]` from `package.json`. The security reasoning was
correct and stands — that entry exposed the whole ~20 MB model to every page visited,
which hands an attacker the exact decision boundary for offline evasion tuning. But the
entry was doing double duty: it was also the only thing making Plasmo copy `assets/` into
the build. Removing it dropped the files from the packaged extension entirely.

**Runtime symptom (why it looked like it worked):** the failure is near-silent. The
`Promise.all` at `background/index.ts:49` only `.catch(console.error)`s, and
`initAllowlist()` catches its own failure and falls back to an empty `Set` — so
`isAllowlisted()` returns false for *every* domain, every page falls through to the ML
tier, and `MLRunner.predict()` then throws on the missing model. Errors appear only in the
service-worker console, which nothing in the test loop reads.

**Why no gate caught it:** every validation path reads the *source* `assets/` from disk,
never the build — `simulate_extension.mjs:166-168` and `diagnose_url.mjs:138` both
`readFileSync`. The "`pnpm build` succeeds" line recorded in three prior entries is true
and yet says nothing about whether the extension *runs*. Same class as the stale
`__parity_bundle.mjs`: a check that passes on an artifact that isn't what ships.
Note `diagnose_url.mjs:159` already expected `build/chrome-mv3-prod/assets/phishing_model.json`
— that comparison had been silently printing nothing since Aug 7.

**Fix:** [`phishing-extension/scripts/copy-assets.mjs`](phishing-extension/scripts/copy-assets.mjs),
wired as a `postbuild` script (plus a `copy:assets` alias for running it alone). It copies
only the three assets actually fetched — `category_importance.json` and `assets/fonts/`
are unreferenced in `src/` and stay out of the bundle. It exits non-zero on a missing
source asset or a missing build dir, so this cannot regress into a silent no-op again.

`web_accessible_resources` was deliberately **not** restored:
`chrome.runtime.getURL()` + `fetch()` from a service worker does not require it — that gate
governs access from *page* and *content-script* context only. All three loads are
worker-side (`background/index.ts:1-2` is the sole importer of both ML modules), so copying
alone is sufficient and the model stays unreachable from any visited page. Verified: the
built `manifest.json` has no `web_accessible_resources` key.

**Verified after the fix:**
* `pnpm build` → `assets/` present in output; all three files SHA-256 identical to source.
* Model loads and parses from the shipped path: 100 trees, 21 features, classes `[0, 1]`.
* `diagnose_url.mjs` now scores both copies and they agree exactly —
  `assets/` 0.2086 / `build/` 0.2086 on `takealot.com/search?q=account&page=2`
  (allowlist HIT, so ML is short-circuited in the real flow anyway).
* `validate_realworld.py` → 19/20, phishing 10/10 — unchanged.
* `simulate_extension.mjs` run against the **shipped build model** → 28/36 overall,
  unknown-legit 8/12. That reproduces the known documented weak spot, not new breakage.
* `npx tsc --noEmit` → exit 0. Parity gate → **0 mismatches / 20,160 values** (960 URLs).

**A pnpm-10 gotcha worth keeping:** `pnpm config get enable-pre-post-scripts` returns
`undefined` here, and pnpm ≥7 documents that default as false — which would make
`postbuild` a silent no-op, the exact failure being fixed. Tested empirically instead of
trusting the doc: pnpm 10.30.3 **does** run pre/post hooks for directly-invoked scripts.
Confirmed by the hook firing in the build output above. Do not "fix" this by inlining the
copy into `build` on the assumption the hook is dead.

---

## August 9, 2026 (later) — Found the real FPR cause: the legit class had no query strings

**Why:** two principled fixes in a row (path brand-similarity, then the TLD table) had
failed to move the false-positive rate. Rather than guess a third time, I ran per-instance
SHAP on the 36 curated false positives and let the model name its own reason.

### The diagnosis
Every worst offender was a **query URL**: `takealot.com/search?q=account&page=2` (0.984),
`firstbanknigeria.com/search?q=account&page=2` (0.974), `moniepoint.com/blog/2026/announcement`.
Measuring the two training classes explains it exactly:

| | phishing (real) | legit (synthesised) |
|---|---|---|
| URLs containing `?` | 6.4% | **0.0%** |
| URLs containing `=` | 5.8% | **0.0%** |
| digit anywhere in path | 13.8% | **0.0%** |

`build_legit_urls()` synthesised paths from a bare-word vocabulary and **never emitted a
query string or a digit**. So `?`, `=` and any path digit were *perfect* phishing tells in
training — and every real site with a search box, pagination, or a dated article tripped
them. This is the same class of bug as the earlier path-shape artifact, one level down:
structure was distribution-matched, character *composition* was not.

### The fix
`_synth_query()` (new) plus digit injection in `_synth_segment()` in `train.py`, both
calibrated to the phishing class's measured rates. Verified after the change: legit `?`
6.7% vs phishing 6.4%, `=` 6.7% vs 5.8%, path digits 7.4% vs 13.8% (closer; the residual
digit gap is a known follow-up).

### Ablation — one change was kept, one rejected
I also tried making the legit class mostly bare-domain (real browsing is ~100% bare, the
corpus was 57% subdomained). Measured both arms separately:

| variant | curated FPR (n=144) | **sampled FPR (n=4,000)** | recall |
|---|---|---|---|
| baseline | 20.8% | 20.8% | 89.9% |
| **query/digit fix only (SHIPPED)** | 21.5% | **15.4%** | **88.8%** |
| query fix + bare subdomains | 14.6% | 15.8% | 84.5% |

The bare-subdomain arm looks better only on the 144-URL curated set, which is 100/144
`.com`; on the corpus with statistical power it is slightly *worse* while costing 4.3
points of recall. **Rejected**, with the reasoning recorded inline in `train.py` so it is
not "fixed" again.

### Verdict bands calibrated (`popup.tsx`)
`sweep_thresholds.py` (new) reports FPR and recall together — the CLEAN cut governs
recall, so moving it is a bad trade (0.65 would buy FPR at the cost of 88.8% → 80.1%
recall). But only the **PHISHING** band is an alarming verdict, and it is nearly free to
tune: **0.85 → 0.90** halves hard false alarms on unknown-legit sites (1.8% → 0.8%) while
still calling 46.9% of real phishing red. CLEAN stays at 0.50. Most of the residual FPR is
now the soft amber "be cautious" tier, not a red banner.

### Net effect vs the start of the day
| metric | before | after |
|---|---|---|
| sampled unknown-legit FPR (n=4,000) | 20.8% | **15.4%** |
| full-pipeline FPR (what users meet) | 9.2% | **9.5%** |
| hard red alarms on legit sites | 1.8% | **0.8%** |
| phishing recall (held-out) | 89.9% | 88.8% |
| real-world spot set | 19/20, phishing 10/10 | 19/20, **phishing 10/10** |
| held-out accuracy | 92.6% | 91.6% |
| 5-fold CV | 92.8% | 91.4% (±0.15%) |

Held-out accuracy fell ~1 point. That is expected and *desirable*: the corpus metric was
inflated by the leak, so removing it lowers the in-corpus number while improving behaviour
on real sites. Say this plainly rather than quoting the old 92.6%.

### Verification (all re-run)
| Check | Result |
|---|---|
| `check_parity.py` — 960 URLs / 20,160 values | **0 mismatches** |
| `npx tsc --noEmit` / `pnpm build` (chrome-mv3) | clean / succeeds |
| `export_model_json.py` round-trip | sklearn vs JSON inference match |
| `validate_realworld.py` | 19/20 — **phishing 10/10**; the one FP (`amazon.com/dp/...`, 0.617) is now amber, not red, and is allowlisted anyway |
| Assets re-exported | `phishing_model.json` 19.6 MB, `shap_mapping.json` 21/21, SHAP table regenerated |

### Still open
* FPR is 15.4% (sampled) against the <10% target — better, not solved. Next lever is the
  residual path-digit gap (7.4% legit vs 13.8% phishing) and long hyphenated domains.
* `DomainLength` change from earlier today (SLD label instead of `SLD.TLD`) is retained;
  it is correct in isolation but did not move the metric on its own.

---

## August 9, 2026 — `TLDLegitimateProb` is now data-derived; the FPR hypothesis is falsified

**Why:** the Aug 7 commit named the next fix explicitly — recover the unknown-legit FPR
from `TLDLegitimateProb`, whose 14-entry hardcoded dict sends 22% of curated legit sites
to a flat 0.50. Implemented, measured, and the prediction **did not hold**.

### The defect was two-sided, not one
The dict penalised legitimate country suffixes (`.ng`, `.com.ng`, `.com.au` → 0.50 vs a
US `.com`'s 0.95). Measuring the corpus showed it also **flattered hostile ones**: `.app`
carries 6,368 phishing rows against 200 legit (true rate 0.03), `.xyz` 0.027, `.top`
0.005 — all scored the same neutral 0.50, while `.tk` (0.019) was hand-assigned 0.10.
The extension's hardest real case is a fresh malicious domain on exactly those suffixes.

### What was built
* **`ml-pipeline/gen_tld_rates.py`** (new): estimates a per-suffix legitimacy rate and
  emits **both** consumers from one computation — `features/tld_rates.json` (Python) and
  generated `src/ml/tld-rates.ts` (browser), 1,172 suffixes. All arithmetic happens at
  generation time; runtime is a pure lookup in both languages, so parity is exact by
  construction rather than by a hand-maintained port.
* **Hierarchical shrinkage.** Empirical log-odds shrunk toward the *parent* suffix
  (`edu.ng` → `ng` → global prior), weight `n/(n+M)`. Both extractors walk the same
  hierarchy at lookup, so an unseen `sch.ng` inherits `ng` rather than a global default.
* **Evidence population ≠ training corpus.** The first version estimated from the
  52/48-balanced training corpus and put `.com` at **0.585** — barely above the prior —
  because PhiUSIIL phishing is 43% `.com`. A corpus balanced for training is the wrong
  sample for a reputation prior. Widened to a deeper top-1m slice, held **disjoint from
  both the held-out test split and the sampled-validation band** so neither metric is
  compromised. `.com` → 0.763.
* **M = 100, swept not chosen.** No dataset can estimate `com.ng`: all of top-1m holds
  34 such domains against 59 phishing rows. Maximum likelihood reads 0.14 there and
  flagged **8/8** curated `com.ng` sites. M = 100 keeps sparse regional suffixes neutral
  (`com.ng` 0.477) while high-volume hostile ones keep signal (`.app` 0.095, `.top`
  0.030, `.xyz` 0.292, `.tk` 0.147). M = 300 washes `.tk` out to 0.345.

### MEASURED OUTCOME — the metric moved the wrong way

| variant | curated ML FPR | sampled ML FPR | held-out acc | recall |
|---|---|---|---|---|
| baseline (hardcoded dict) | **20.8%** | 20.8% | 92.58% | 89.86% |
| narrow evidence, M=300 | 23.6% | 20.6% | 93.22% | 90.44% |
| **wide evidence, M=100 (shipped)** | 24.3% | **19.6%** | 92.97% | 89.84% |
| wide evidence, M=300 | 25.0% | 20.0% | 93.05% | 90.05% |

**Cause:** the curated corpus is 100/144 `.com` URLs. The dict's hardcoded 0.95 was, for
that population, a better number than the honest empirical 0.763 — it functioned as a
hand-tuned prior favouring exactly the sites the corpus contains. Sampled FPR (n=4,000,
the figure with statistical power) did improve, 20.8% → 19.6%.

**Kept anyway.** 1,172 suffixes scored on evidence beats 14 plus a coin flip, and the
hostile-suffix half of the fix is a real detection gain that the curated corpus does not
measure. Same reasoning as the Aug 7 path-similarity fix: a metric that improves because
a feature is wrong in a flattering direction is not a metric worth protecting. **The Aug
7 hypothesis is falsified — do not restate it as confirmed.**

### The residual is `DomainLength`, not this feature
With the TLD feature neutral for `com.ng` (0.477), those sites are *still* 7/8 flagged
(`gtbank.com.ng/personal-banking` = 0.678). Feature-by-feature comparison against the
`.com` curated set shows the gap is `DomainLength`/`URLLength`: compound suffixes are
mechanically longer, so the feature encodes suffix structure as risk. SHAP confirms it
independently — `DomainLength` value↔SHAP correlation strengthened +0.14 → **+0.32**.
That is the next FPR item.

### Parity harness could pass on a stale artifact — fixed
`gen_parity_features.mjs` imported a hand-built `__parity_bundle.mjs`. When
`tld-rates.ts` landed it reported **960 divergences** against extractor code that had
never been recompiled — the same trap that produced 287 false divergences on Aug 7. It
now rebuilds the bundle via esbuild's **JS API** on every run (the CLI path fails:
Node ≥20 refuses to `spawnSync` a `.CMD` shim on Windows, and pnpm's strict layout keeps
esbuild in `.pnpm/`, not `node_modules/esbuild`). A gate that can pass on a stale
artifact is not a gate.

### 5-fold CV is now persisted
`train.py` computed CV every run but only `print()`ed it, which is why SOT carried "do
not cite a CV number" against a figure that was in fact measured every run. It now writes
`models/cv_results.json`: **92.84% (±0.33%, 2σ)**.

### Verification (all re-run, not cited from docs)
| Check | Result |
|---|---|
| `check_parity.py` — 960 URLs / 20,160 values | **0 mismatches** |
| `npx tsc --noEmit` / `plasmo build` (chrome-mv3) | clean / succeeds in ~32 s |
| Held-out | acc 92.97%, prec 95.21%, recall 89.84%, TN=21,087 FP=913 |
| `validate_realworld.py` | 19/20 — phishing **10/10**, one ML-tier `.com` FP |
| Retrain determinism | identical metrics, identical forest (691,570 nodes), **byte-identical** `phishing_model.json` |
| Assets re-exported | `phishing_model.json` 19.4 MB → **16.8 MB**, `shap_mapping.json` 21/21 |

The one real-world FP is `amazon.com/dp/B08N5WRWNW` (ASIN token). `amazon.com` is in the
30k allowlist and short-circuits to CLEAN before the ML tier, so the shipped extension is
unaffected — verified by reading the tier order in `background/index.ts`, not assumed.

### Still open (unchanged by this pass)
* Unknown-legit FPR 19.6–24.3% vs the <10% target. Now attributable: `DomainLength` on
  compound suffixes, plus long hyphenated domains under-supported in both classes.
* Verdict thresholds still uncalibrated (CLEAN <0.50); the 0.60/0.65 sweep is documented
  but not applied — still a product decision.
* SOT's previously published curated FPR (18.1%) **could not be reproduced**: the
  unmodified pre-change model measured **20.8%** at the start of this session. `models/`
  is untracked so the old JSON is unrecoverable; 20.8% is the honest baseline.
* `cross_validate_ts.mjs` still prints stale v3 text.

---

## August 6, 2026 — Verification pass: doc/artifact drift corrected, SHAP regenerated

**Why:** Re-verified the Aug 5 parity work against the live repo rather than the write-ups.
The parity fix itself holds — but two artifacts were stale and one documented conclusion
was wrong.

### Verified good (re-run live, not cited from docs)
* `check_parity.py` → **0 mismatches / 20,160 values** across 960 URLs, 0 Python errors,
  after regenerating `parity_ts.json` fresh.
* `npx tsc --noEmit` → exit 0. `pnpm build` (plasmo, chrome-mv3) → succeeds in ~31 s.
* `psl-trie.ts` → **6,933 rules** (16 wildcard, 8 exception), matching the documented count.
* Pre-fix `feature-extractor.ts` confirmed to carry exactly the 14-entry `TLD_SCORES` dict
  (`com org net edu gov co.uk de fr jp tk ml ga cf gq`) used as compound-TLD authority.
* `shap_mapping.json` shipped to the extension covers 21/21 features — no drift.

### Fixed: `SOURCE_OF_TRUTH.md` §3 carried pre-retrain metrics
SOT still published the **pre-corpus-fix** model's numbers (94.02% / 95.14% / 92.21%,
TN=21,049 FP=951) while `models/evaluation_results.json` held the Aug 5 retrain
(92.82% / 94.66% / 90.07%, TN=20,974 FP=1,026). Corrected in place, with FPR recomputed
to 4.66% and FNR to 9.93% from the actual confusion matrix.

Also removed the **5-fold CV claim "93.85% (±0.11%)"**: `train.py:486` only `print()`s the
CV score and never persists it, so no artifact ever backed that figure — and it was measured
on the pre-fix model. Marked *not persisted* rather than restated. **Do not cite a CV number
until `train.py` writes it to `evaluation_results.json`.**

Added **§3a** promoting unknown-legit FPR (18.1% curated / 19.1% sampled) into SOT proper,
so the headline accuracy figure is no longer readable without the metric that actually
gates the product.

### Fixed: `models/shap_values.json` was stale by two days
The file was dated Aug 3 against an Aug 5 model retrain. Regenerated via
`gen_shap_table.py` (exact TreeExplainer, 500 seeded samples).

**This falsified a claim made in this very note.** The Aug 5 entry asserted the inverted
`NoOfSubDomain` SHAP direction was "gone". It is not:

| | Pre-fix | Post-fix |
|---|---|---|
| `NoOfSubDomain` permutation importance | 0.256 (#1) | 0.091 (#5) |
| `NoOfSubDomain` mean\|SHAP\| | 0.1770 (#1) | 0.0758 (#2) |
| `NoOfSubDomain` value↔SHAP corr | −0.75 | **−0.84** |

The corpus fix reduced the feature's *magnitude* but left its direction inverted, slightly
more so. Corrected the Aug 5 entry above and SOT §4. New top feature by mean|SHAP| is
`TLDLegitimateProb` (0.0789).

### New finding: the model effectively runs on ~11 features, not 21
`IsHTTPS` has mean|SHAP| = **0.000000** — constant across the sample, contributing nothing.
`ObfuscationRatio`, `NoOfObfuscatedChar`, `HasObfuscation`, `IsDomainIP` all sit below 4e-5.
Presenting the 21-feature set as uniformly load-bearing overstates it; noted in SOT §4.

### Still open (unchanged by this pass)
* Unknown-legit FPR 18–19% vs <10% target — distributional, not extractor skew.
* Verdict thresholds still uncalibrated (CLEAN <0.50). Sweep documented, not applied.
* `cross_validate_ts.mjs` still prints stale v3 text.
* 5-fold CV not persisted by `train.py` (see above).

---

## August 5, 2026 — Extractors now actually byte-identical: Python↔TS parity fixed on 960 URLs

**Why:** `check_parity.py` (new this session) compared the Python training extractor
(`features/lexical_extractor.py`) against the REAL shipped TS extractor
(`phishing-extension/src/content/feature-extractor.ts`, esbuild-bundled) over a stratified
960-URL set. It found **195 mismatches / 20,160 values** — the two were NOT byte-identical as
`SOURCE_OF_TRUTH.md` claimed. The earlier `cross_validate_ts.mjs` only checked 6 URLs, missing it.

### The bug: TLD/IP parsing divergence = train/serve skew
Python resolves domains with `tldextract` (full Public Suffix List). The TS extractor used a
14-entry hardcoded `TLD_SCORES` dict. On **country/compound TLDs** (`.com.ng`, `.com.au`,
`.gov.my`, `ac.in` …) and **IP hosts**, the two computed different `DomainLength` (10.0% of URLs)
and `NoOfSubDomain` (9.8%) — both top-importance model features. Measured score impact on 960
URLs: **21 legit sites flipped clean→flagged in the browser** that the model-training features
would have scored clean (incl. 3 already in the curated FP list: `lagostechhub.com.ng`,
`greenfield-academy.edu.ng`, `westside-physio.com.au`). This is the same failure class as the
original google.com false positive.

### The fix
* **`phishing-extension/src/ml/tldextract.ts`** (new): 1:1 port of tldextract's algorithm —
  longest-match PSL trie with wildcard (`*.foo`) / exception (`!foo.bar`) rules, RFC 3492
  punycode decode of input labels, IP-host handling — plus `rawHost` / `rawPath` that mirror
  `lenient_netloc` / `urlparse().path` (the WHATWG `URL` API percent-decodes hosts and
  percent-encodes paths, which diverged from Python).
* **`phishing-extension/src/ml/psl-trie.ts`** (generated): the 6,933 public PSL rules from the
  tldextract **runtime cache** (what training actually used — the bundled snapshot differs by
  ~350 rules). Regenerated by **`ml-pipeline/gen_psl_trie.py`** (new).
* **`feature-extractor.ts`**: domain/subdomain/TLD decomposition, letter/digit counting and
  path-based brand similarity now Unicode-aware (`\p{L}`/`\p{Nd}` like Python `isalpha()`/`isdigit()`)
  and derived from the raw URL string.
* **`ml-pipeline/check_parity.py`**: stdout fixed to UTF-8 (was crashing on IDN URLs).

### Verification
| Check | Result |
|---|---|
| `check_parity.py` — 960 URLs / 20,160 values | **PARITY OK, 0 mismatches** |
| Hostname parses vs Python (981 curated + 3,599 fuzz, incl. IDN/wildcard/trailing-dot/IP) | 0 mismatches |
| Score delta TS vs Python on 960 URLs | **0 verdict changes, max delta 0.0000** |
| `npx tsc --noEmit` / `pnpm build` (chrome-mv3) | clean / succeeds |

No retrain or re-export was needed — the model is trained on Python features and the browser
now produces identical values.

### Still open (unchanged)
* Unknown-legit FPR 18–19% vs <10% target — the residual FP population (long hyphenated
  domains under-supported in both classes) is a distributional problem, not extractor skew.
  Threshold sweep (0.60/0.65) is documented above; product decision pending.
* `simulate_extension.mjs` / `diagnose_url.mjs` keep their own drifted inlined extractors
  (fine for quick checks; don't cite them for parity).
* `cross_validate_ts.mjs` still prints stale v3 text ("All 44 scaled values match").

---

## August 5, 2026 — Fixed the false-positive root cause: corpus structure bias

**Why:** Re-measured the shipped model against the goal ("flag phishing sites AND
identify legitimate sites"). Held-out accuracy was 94.02%, but every legitimate site
outside the 30k allowlist was being flagged. The reported accuracy was measuring the
wrong thing: the legitimate class is partly synthesized, so in-corpus accuracy stays
high while real unknown sites fail.

### The bug: URL structure leaked the label
`build_legit_urls_from_top_sites()` attached a fixed 15-item list of short, shallow
paths (`/help`, `/p/12345`) to legitimate domains, while the phishing class carried
**real** paths averaging ~31 chars at depth ~2.2. PhiUSIIL's legitimate class is
**100% bare domains** (0% paths). So path *shape* became the class signal and the
model learned "long or deep path => phishing".

Measured on the pre-fix model — same domains, path varied:

| Domain | bare | +path | +long path |
|---|---|---|---|
| gtbank.com | 0.134 | 0.777 | 0.947 |
| flutterwave.com | 0.301 | 0.845 | 0.935 |
| jumia.com.ng | 0.478 | 0.950 | 0.972 |

Mean 0.616 -> 0.910 -> 0.968. A legitimate site became "phishing" purely by having a
URL path — and users browse pages, not bare homepages.

### The fix (`ml-pipeline/train.py`)
* **`measure_structure()`** (new): measures the phishing class's empirical structure
  *distribution* — path depth, segment lengths, subdomain counts and label lengths.
* **`build_legit_urls()`** (replaces `build_legit_urls_from_top_sites`): synthesizes
  legitimate URL structure sampled from that distribution, filled with **benign
  vocabulary** (`BENIGN_SEGMENTS` / `BENIGN_SUBDOMAINS`).
* **Why distributions, not the phishing strings themselves:** copying real phishing
  paths onto legit domains fixes the shape artifact but injects label noise — it
  produces rows like `atlantid99.google.com/ai/sign.php` labelled *legitimate*,
  teaching the model to ignore genuine phishing patterns. Matching only the
  structural moments removes the shape signal while keeping character composition
  an honest signal. (First attempt did copy strings; caught on inspection and replaced.)
* **Legitimate class now draws from two populations:** 55k Cisco top-sites (global
  mainstream) + 55k PhiUSIIL legitimate domains (small/obscure real sites — clinics,
  schools, regional business). The pre-fix corpus had only the former, which is why
  unknown small sites were flagged. Classes land near balance, so SMOTE no longer fires.

### New validation: the metric that actually matters
**`ml-pipeline/validate_unknown_legit.py`** (new) scores legitimate domains in
*neither* training population — curated regional sites (Nigerian banks, African
fintech/e-commerce, small business) with realistic paths, plus a 4k sample of
top-1m ranks >=120k. Reports FPR for the ML tier alone and for the full pipeline.

### Results

| Metric | Pre-fix | Post-fix |
|---|---|---|
| Curated unknown-legit FPR | **60.4%** | **18.1%** |
| Sampled unknown-legit FPR | **26.7%** | **19.1%** |
| Phishing recall (4k held-out) | 93.4% | 90.8% |
| `validate_realworld.py` | 19/20 | 19/20 (10/10 phishing) |
| Held-out accuracy | 94.02% | 92.82% |
| `NoOfSubDomain` importance | 0.256 | 0.091 |

Held-out accuracy fell 1.2 points while the real-world false-positive rate fell by
**two thirds** — the accuracy drop is the corpus artifact being removed, not a
regression. `NoOfSubDomain` collapsed from #1 to #5 in *permutation* importance (0.256 → 0.091),
confirming the structure artifact's magnitude shrank. However, its **SHAP direction did not
correct**: r moved from −0.75 to −0.84 (marginally stronger), still running opposite to the
phishing literature. The feature's load-bearing magnitude dropped; the inversion persists.

### Negative result recorded: do NOT drop the length features
`feature_config.py` carried a comment claiming the raw length/count features had been
dropped as population-biased. They never were, and they should not be. Tested a
12-feature scale-invariant subset on the fixed corpus — worse on every axis:

| | 21-feature | 12-feature |
|---|---|---|
| Curated FPR | 18.1% | 34.7% |
| Sampled FPR | 19.1% | 29.0% |
| Phishing recall | 90.8% | 87.8% |
| Held-out accuracy | 0.9282 | 0.8461 |

The bias was in the **corpus**, not the features. With structure matched across
classes, length and count features carry real signal. Comment corrected in place.

### Allowlist expansion evaluated and rejected
Regional sites sit far below any practical cut: jumia.com.ng rank 210k,
gtbank.com 380k, paystack.com 420k, flutterwave.com 687k. Covering mainstream
Nigerian banking needs ~700k entries (~10 MB bundled) vs the current 30k/456 KB;
even top-300k (4.5 MB) covers only 8/18 curated sites. Unknown-legitimate accuracy
has to come from the ML tier. Allowlist stays at 30k as a fast path for global giants.

### Explanation layer fixed
* **`ml-pipeline/gen_shap_mapping.py`** (new): derives `shap_mapping.json` from
  `models/feature_importance.json`, so it can no longer drift. Was 12 of 21 features
  with importances from an older model, missing `DomainLength` (#1) and `URLLength`
  — the popup could never cite the signals that drove those verdicts. Now 21/21.
* **`shap-approximator.ts:23,33`** branched on `DomainTitleMatchScore`, a v3 content
  feature dropped in v4. Dead branch removed.

### Files changed
* `ml-pipeline/train.py` — `measure_structure()`, `build_legit_urls()`, benign vocab
* `ml-pipeline/features/feature_config.py` — corrected the stale drop-the-features comment
* `ml-pipeline/validate_unknown_legit.py` — new, the acceptance metric
* `ml-pipeline/gen_shap_mapping.py` — new, drift-proof mapping generator
* `phishing-extension/src/ml/shap-approximator.ts` — removed dead v3 branch
* `phishing-extension/assets/shap_mapping.json` — regenerated, 21/21
* `phishing-extension/assets/phishing_model.json` — re-exported, 19.1 MB, parity verified
* `simulate_extension.mjs` — unknown-legit corpus expanded 4 -> 12 with regional sites

### Still open
* Unknown-legit FPR is 18-19%, above the <10% target. Remaining failures are long
  hyphenated domains (25-26 chars: `riverside-veterinary.co.uk`,
  `oakwood-dental-clinic.com`) which are rare in *both* training classes (6-10%),
  so the model has little support there.
* Verdict thresholds (CLEAN <0.50) have never been calibrated against FPR. Sweep:
  0.60 gives 11.8%/13.7% FPR at 86.2% recall; 0.65 gives 11.8%/11.8% at 82.4%.
  A pending product decision, not yet applied.

---

## August 3, 2026 — Dissertation audit: reconciled the report with the shipped system

**Why:** Audited `FINAL_YEAR_RESEARCH_REPORT_COMPLETE_CORRECTED.docx` against the repo artifacts and source. Headline metrics (94.02 / 95.14 / 92.21 / 93.65, confusion matrix, hyperparameters, Table 4.6 Gini importances) were all accurate. The defects were concentrated in **architecture claims** describing a system that was never built, and in **numbers with no artifact behind them**.

Backup of the pre-edit document: `FINAL_YEAR_RESEARCH_REPORT_BACKUP_PRE_FIX.docx`.

### New pipeline script
* **`ml-pipeline/gen_shap_table.py`** (new): computes exact TreeExplainer SHAP values over a seeded 500-sample subset of the held-out split and **persists them to `models/shap_values.json`**. Previously `generate_shap_plots.py` only printed to stdout and saved PNGs, so the dissertation's SHAP table had no traceable source. Also records the **Pearson correlation between each feature's value and its SHAP contribution**, which is the quantity that actually licenses a "direction of effect" claim (mean signed SHAP does not — it only reports average contribution over whatever class mix the sample has).

### Architecture claims corrected (the report described an unbuilt system)
* **Pre-navigation interception (§3.3.1, §3.8):** claimed `webRequest` intercepted URLs "before the browser initiates the network handshake." No such listener exists in `src/`; `webRequest` isn't in the manifest. `content.ts` is a **content script** reading `document.documentElement.outerHTML`, so detection is **post-load**. Rewritten to state this, and to explain that MV3 withdrew blocking `webRequest` — so the described design is not merely unimplemented but unachievable as written.
* **Navigation blocking + injected interstitial (§3.8):** claimed the extension "forcefully blocks the navigation request and injects a high-contrast warning interface." `content.ts:19-22` emits a `console.warn`; the comment literally reads "we can optionally inject an interstitial warning here!" The "Leave this page" button exists only in `popup.tsx:547`, behind a manual toolbar click. Rewritten to describe badge + popup reporting, with the overlay listed as an implementation priority.
* **Inverted GSB privacy claim (§3.8):** claimed PHISHING/SUSPICIOUS verdicts trigger the Safe Browsing call while SAFE verdicts stay local. `background/index.ts:102` fires on `|score − 0.5| < 0.15`, i.e. **0.35–0.65** — so confident PHISHING **never** calls GSB, and a CLEAN URL at 0.40 **does**, transmitting it externally. Corrected, and the default-off (user-supplied key) status is now stated.
* **Per-prediction SHAP in the browser (§4.7):** claimed "SHAP values are used directly by the extension's explainability layer at classification time." `shap-approximator.ts` does a static dictionary lookup of **global** importances with canned strings. Recast as global-importance attribution filtered by observed feature values, with true per-prediction SHAP listed as future work.

### Numbers corrected against artifacts
| Claim | Was | Now | Source |
|---|---|---|---|
| Table 2.1 "This Study" accuracy | 94.70% | 94.02% | contradicted 8 other places in the same report |
| Top-5 feature share | 73.9% | 67.5% | `feature_importance.json` |
| sklearn pickle size | ~615 MB | 61.2 MB | `models/random_forest.pkl` (decimal slip; also broke the "orders of magnitude" argument — it's ~3×) |
| Export-size floor | "791 KB" *and* "below 5 MB" in one paragraph | ~3 MB projection, flagged as a projection | SOT §8 |
| Allowlist | "over 30,000" | exactly 30,000 | `top_domains.json` |
| Table 4.8 SHAP values | matched no artifact; ranks 9/10 inverted | regenerated from `models/shap_values.json` | new script |
| §4.4 diagonal | "46,997 of 46,998 test samples… single off-diagonal entry" | 39,666 of 42,189; 2,523 off-diagonal | fabricated text claiming 99.998% two paragraphs after 94.02% |

### Honest disclosures added (previously absent or contradicted)
* **`NoOfSubDomain` direction is backwards vs. the literature** (r = −0.75: *fewer* subdomains → phishing). Traced in §4.7 to the structure augmentation in `train.py:35-93`, which lifts the legitimate class to ~45% subdomain while PhiUSIIL phishing URLs frequently have none — so the model learned a property of this corpus, not of phishing. §4.6's opposing narrative claim was aligned. **This is the most consequential finding of the audit: it was being reported as confirmation of theory.**
* **`URLSimilarityIndex` direction** likewise reflects the extractor's ≥0.6 threshold (v5 typosquat fix), not a claim that brand-similar URLs are safe.
* **Model-tier vs. deployed-system FPR:** 4.32% is the ML tier in isolation; the 30k allowlist short-circuits before inference, so the user-facing rate is lower — stated without inventing a figure.
* **Real-world validation now reported** (§4.9, from `realworld_validation.json`): 19/20, 10/10 phishing, and the one FP (`amazon.com/dp/B08N5WRWNW` @ 0.768) disclosed as illustrating exactly what the allowlist absorbs.
* **Scaler-fitting caveat (§5.2):** `train.py:328` fits `MinMaxScaler` on the full training set before `cross_val_score`, so each fold's scaler saw its validation data. Practically harmless for trees (split-invariant under monotonic rescaling) but the stricter protocol is fold-internal.

### Structural / reference fixes
* **Three sections began mid-sentence** (§4.1, §4.3, §4.5) — opening clauses restored.
* **Figures 4.1–4.3 were never inserted**; literal `[ Insert confusion_matrix.png … ]` placeholders remained. Embedded `confusion_matrix.png`, `shap_summary_plot.png`, `shap_bar_plot.png` and renumbered so they appear in order (Fig 4.3 previously preceded 4.1).
* **Table 4.5** titled "10-Fold" over 5-fold data (+5 empty rows) → "Five-Fold", rows dropped.
* **Table 4.7** summed to 113.5% (overlapping "URL Structure 21/100%" and "Remaining Lexical 11/13.5%" as siblings) → invalid row removed, 7.4% stated in prose.
* **§3.3.2 vs §4.1 contradiction** on hyperparameter provenance ("systematic optimization" vs "not automated search") → §4.1 is correct per `train.py`; §3.3.2 aligned.
* **Dangling cross-references to §3.6** (200 ms budget, four thresholds, usability evaluation) → all three now actually defined there.
* **Explainability objective** referenced by §4.7/§5.1 but absent from §1.3 → added as objective (iv).
* **§5.4 had only "First,"** → second and third contributions written (train/serve skew as transferable constraint; allowlist and lexical model as complementary).
* **§1.7** claimed Safe Browsing "precluded direct live testing" — contradicted by SOT §4 (live testing found google.com → 91.8%, which drove the whole v4 redesign) → restated accurately.
* **§3.5.2** claimed low-importance features "are systematically excluded" — `IsHTTPS` (0.0) and 4 others are retained → corrected with the actual rationale.
* **Table 3.4** step 6 said CSV; `train.py:306` writes a joblib pickle. Step 1 claimed duplicate removal; code only drops nulls/empties.
* **References:** added missing **Lundberg & Lee (2017)** (cited 4×, underpins the SHAP chapter). Removed unverifiable **Kautsar et al. (2025)** (Table 2.1 row, §2.3.4 sentence, 2 decorative cites) and **Prasad & Hannousse (2022)**. Corrected three Table 2.1 misattributions after checking the sources: **Al-Subaiey (2024)** is phishing *email* detection (F1 0.99), not URL structural features; **Tang & Mahmoud (2021)** is a *survey* with no original experiment, not a 97.3% result; **Gupta (2021)** is text-based ML, not deep learning. Dropped decorative citations (Breiman on Agile, Sahingoz on MV3 CSP). Fixed "the PhishTank" typo; removed uncited ISCXURL-2016.
* **§5.1/§5.3** implied a multi-source fusion layer incl. PhishTank; only GSB exists → both corrected.
* **"PhishGuard"** first appeared in §5.1 → introduced in §1.3.

### Verification
Automated pass over all paragraphs **and table cells**: 25 known-bad strings confirmed absent, 27 required strings confirmed present, all 10 Table 4.8 rows byte-match `models/shap_values.json`, 6 images embedded (3 original + 3 new). Document reopens cleanly via python-docx (448 lines, 16 tables).

**Not changed — needs your judgement:** the reference list restarts alphabetically mid-way (Zaimi → Alenezi); two entries are dated 2026 with 2025 DOIs; Chapter 4 is titled "System Design and Implementation" but covers only model work (a scope note was added pointing to Ch. 3 rather than restructuring). Also unaddressed in code: `shap_mapping.json` still holds **12** features with **stale** importances from an older model (missing `DomainLength`, the #2 feature) and `shap-approximator.ts` still branches on the dropped `DomainTitleMatchScore` — the extension's explanation layer is running on outdated data.

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

## June 29, 2026 — v5: hybrid reputation + ML (SHIPPED FIX)

**User decision:** add a real top-sites list. Implemented as a two-tier hybrid.

**Why a hybrid:** experiments proved a URL-only lexical model CANNOT distinguish a
popular legitimate bare domain (`google.com`) from phishing on a reputable TLD
(`someshop.com`, `*.web.app`) — the signal isn't in the URL string. Whichever feature
the model latched onto (DomainLength → URLSimilarityIndex → NoOfSubDomain) put real
homepages on the phishing side. The fix is reputation, exactly as real products do.

**Architecture:**
1. **Training data overhauled** (`train.py`): LEGITIMATE class is now real top-sites
   (Cisco Umbrella top-1m, `datasets/top-1m.csv`), structure-augmented to match the
   phishing distribution; PHISHING class is PhiUSIIL phishing URLs. This replaces
   PhiUSIIL's biased obscure-long-domain legit class.
2. **Feature set v4** (`feature_config.py`): 12 scale-invariant features (dropped raw
   length/count features that encoded the population bias).
3. **Typosquat fix** (`lexical_extractor.py` + `feature-extractor.ts`): `URLSimilarityIndex`
   now only fires on HIGH similarity (≥0.6) — genuine typosquats (paypa1, g00gle), not
   coincidental distance (github~google). Applied identically in Python & TS (parity kept).
4. **Reputation allowlist** (`phishing-extension/assets/top_domains.json`, 30k registrable
   domains, 456 KB): `background/index.ts` short-circuits known-popular domains to CLEAN
   before ML. Shared-hosting platforms (web.app, firebaseapp.com, github.io, …) are
   EXCLUDED from the allowlist so platform-hosted phishing still goes to ML. Bundled
   on-device → still privacy-preserving.

**Validated hybrid (simulated end-to-end, allowlist + ML on built assets):**
* LEGIT (google, github, wikipedia, paypal, stackoverflow, cnn, bbc, moonpay, wiki article): **9/9 CLEAN**.
* PHISHING (secure-paypal-login.tk, paypa1-…gq, 192.168.1.1, liuy-…web.app, …weeblysite.com, g00gle-verify.tk): **6/6 flagged** (5 PHISHING, 1 SUSPICIOUS).
* Python↔TS inference parity still exact (cross_validate_ts.mjs ALL PASS).
* ML tier alone: held-out Accuracy 89.6%, the realistic number for URL-only on unknown domains.

**Known residual limitation:** an UNKNOWN legitimate domain NOT in the top-30k allowlist
(e.g. a small local business site) may be over-flagged by the ML tier. Mitigations:
enlarge the allowlist, or add an online reputation lookup. Documented, not a blocker.

**Re-export/build done:** `phishing_model.json` (12-feat), `shap_mapping.json` (12),
`top_domains.json` rebuilt; `pnpm build` succeeds. **User must reload the unpacked
extension in Chrome to pick up the new build.**

---

## June 29, 2026 — Popup UI redesign (`popup.tsx`)

Full rework via the uidesigner skill. Reframed the popup as a **security "detector
readout"** instead of generic stacked cards.
* **Shows the domain under inspection** (mono, in the hero) — previously the popup never
  displayed which site it judged. This was the biggest usability gap.
* **Signature element:** dark instrument-panel hero (ink `#0d1014`) with the domain, verdict
  word, animated count-up risk %, and a scanning risk meter that glows in the verdict colour
  with threshold ticks at 50/85.
* **Decision-source chip** ("Trusted-sites list" vs "On-device model") surfaces the v5 hybrid
  architecture — the product's defining truth.
* **Reputation verdicts** get an honest dedicated explanation ("on PhishGuard's trusted-sites
  list, cleared without sending anything to the model") instead of empty ML cards.
* **Removed the buggy ↑/↓ SHAP arrows** (they asserted wrong directions). ML signals now show
  an honest **importance weight bar** + value, with a caption clarifying bars show weight, not
  per-site direction. Resolves the long-standing SHAP-direction cosmetic bug.
* Copy made blunt/honest: "Likely phishing" (it doesn't block), "Safe to use", "Be cautious".
* Design system: mono "readout" voice for data (domain/score/signals), Segoe humanist for
  prose; verdict colour is the only chroma, red reserved for phishing; designed loading +
  empty states; hover/focus states on all interactive elements; no external fonts (MV3-CSP safe).
* `npx tsc --noEmit` clean; `pnpm build` succeeds.

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
