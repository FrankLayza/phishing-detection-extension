# PhishGuard — Memory

Hard-won facts and traps. Read this **before** validating anything or trusting a
green check. Everything here cost a real debugging session; several entries exist
because a check passed while the product was broken.

Companion docs: `architecture.md` (structure) · `handoff.md` (current state) ·
`SOURCE_OF_TRUTH.md` (numbers) · `CONTEXT.md` (vocabulary).

**Status legend:** ✅ verified current (Aug 15, 2026) · ⚠️ still open · 🔒 fixed, kept
here so the failure mode isn't reintroduced.

---

## 0. The meta-lesson

**Every validation surface in this repo has been green while the product was broken
at least once.** Five separate times the harness measured something *adjacent* to
what ships. When you validate, ask what exactly is under test — the source or the
build, the bundle or a stale copy, the corpus URL shape or the browser's.

The one check that has never lied is loading the extension in Chrome and clicking
the icon. Several bugs were only ever caught that way.

## 1. The four harness lies 🔒

1. **The parity gate can pass on a stale bundle.** `check_parity.py` compares
   against an esbuild bundle of the TS extractor; it passed twice against a
   `__parity_bundle.mjs` that predated the edits under test. Always run
   `gen_parity_features.mjs` (esbuild **JS API**, not the CLI) first.
2. **Validation read source, not build.** The shipped extension had no model for
   three days while every check stayed green, because the harnesses read `src/` and
   `assets/` while `build/chrome-mv3-prod/` lacked the copied model. The `postbuild`
   asset copy is what puts the model on disk. Verify the built artifact.
3. **Browser URL shape ≠ corpus URL shape.** Harnesses build `'https://' + domain`;
   Chrome sends `https://domain/`. That slash was worth +26 points of FPR (see §2).
   Score URLs in browser form. Use `score_shipped.mjs` or `demo_supervisor.mjs`;
   **never** `diagnose_url.mjs` (drifted inlined extractor, gives a third answer).
4. **A verdict outlived its page.** `result_<tabId>` was only cleared on tab
   *close*, so navigating showed "Safe · google.com" over a live phishing URL —
   complete with green shield. Fixed in two layers (popup URL equality +
   `tabs.onUpdated` eviction); both are load-bearing. Corollary: any manual
   click-through spot-check from before Aug 10, 2026 proved nothing, because it
   could not distinguish a fresh verdict from a stale one.

### …make that five ⚠️

5. **The headline FPR measures a model that isn't shipped.** Discovered Aug 15, 2026.
   `validate_unknown_legit.py:83` loads `models/random_forest.pkl`; the extension
   loads `assets/phishing_model.json`. Different forests — 864,614 nodes versus
   806,620. Every unknown-legit FPR figure in the docs therefore describes a model
   nobody runs. Exactly the same trap as `test_url.py`, which was already flagged for
   it; nobody noticed it also applied to the project's primary acceptance metric.
   The same harness also uses `PHISH_MIN = 0.85` against a shipped red band of 0.90,
   and builds URLs with no root slash — so it is wrong on three axes at once.

## 1a. Reproducibility: verified, and a cautionary tale ✅

**Training IS deterministic in a fixed environment.** Two consecutive runs of
`train.py` on identical code produced identical forests (864,614 nodes) and identical
metrics (90.64% accuracy, FPR 6.62%, 5-fold CV 0.9038 ± 0.0025). Environment: Python
3.11.9, scikit-learn 1.3.0, numpy 1.24.3 — the repo `venv` and system Python carry the
same versions, and both `tldextract` caches hold the same PSL snapshot.

**The cautionary part, and the reason this entry exists.** Non-determinism was briefly
*asserted* here on the strength of three differing node counts — 806,620 (shipped),
846,454 (Aug 14), 864,614 (Aug 15) — and the docs were updated to say training was
broken. The inference was wrong. Three counts from three unknown tree states are not
evidence of randomness; the controlled test is **two runs on identical code**, which
had not been done. Running it took five minutes and reversed the conclusion.

The lesson generalises past this repo: **differing artefacts prove the inputs differed,
not that the process is random.** Identify what varied before blaming the process, and
prefer one controlled comparison over three uncontrolled ones.

Residual unknown, recorded honestly: the Aug 14 figure of 846,454 cannot be reproduced
from the committed tree — the only training-relevant change since is a comment — so it
was most likely measured against uncommitted working-tree state. Cite **864,614** as
the current retrain baseline. Determinism holds *per environment*, so pin interpreter
and library versions when comparing runs and re-baseline after any dependency bump.

Still true and unaffected: the *shipped* 806,620-node model does not reproduce from
current code, because the root-slash strip landed after it was trained (§6).

## 2. The root slash — and a correction ✅

**Corrected Aug 15, 2026 by direct measurement of `datasets/phiusiil.csv`.**

| Class | n | root-slash |
|---|---|---|
| Legitimate (`label == 1`) | 134,850 | **0** (0.00%) |
| Phishing (`label == 0`) | 100,945 | **31,744** (31.45%) |

`label == 1` is **legitimate** — confirmed by `gen_tld_rates.py:130`, which builds
its legit domain list from `label == 1`, and by inspection (label 1:
`southbankmosaics.com`, `uni-mainz.de`; label 0: `f0519141.xsph.ru`,
`shprakserf.gq`).

So **the root slash is a phishing-class token**, and the browser puts one on every
homepage — which is exactly why every homepage scored as phishing
(`google.com` 0.207 → 0.880, `gtbank.com` 0.199 → 0.892; 39.0% of 1,500 unknown-legit
homepages flagged vs 12.6% bare). Fixed Aug 10 (`38e820d`) by stripping a lone root
slash in both extractors rather than retraining.

> 🔒 **Two code comments used to state this backwards** — `feature-extractor.ts` and
> `lexical_extractor.py:52-72` both claimed "legitimate rows are 31.4% root-slash while
> phishing rows are 0.0%". Under that inverted premise the observed symptom is
> impossible: a legit-leaning token cannot push homepages *toward* phishing. Both were
> corrected in `69d7373` with the measurement inline. Kept here because the inversion
> survived in code for five days while the correct number sat in
> `SOURCE_OF_TRUTH.md` — a rationale nobody re-derives is a rationale that can rot.

Consequence to keep in mind: because the strip changes 31.4% of *phishing* rows, it
is **not** a training no-op — which is why the committed model no longer reproduces
from current code (§6).

## 3. The metric that actually gates the product ⚠️

**Judge PhishGuard by unknown-legitimate FPR, not held-out accuracy.** Held-out
accuracy is inflated because the legitimate training class is partly synthesized:
in-corpus accuracy sits ~91–93% while real unknown sites get flagged. Measure with
`validate_unknown_legit.py` (curated n=144, sampled n=4,000 — cite the sampled
figure, it has the statistical power).

Acceptance target: ML-tier FPR <10% on both populations, recall >90%. Currently
~16% sampled ML-tier / ~9.9% pipeline — **still above target**, and note both figures
come from the harness described in §1 item 5, i.e. measured on `random_forest.pkl`
rather than the shipped model.

**The allowlist cannot solve this. Do not retry that path.** Regional sites sit far
below any practical cut: `jumia.com.ng` rank 210k, `gtbank.com` 380k,
`paystack.com` 420k, `flutterwave.com` 687k. Mainstream Nigerian banking needs
~700k entries (~10 MB) against today's 30k/456 KB; top-300k (4.5 MB) still covers
only 8/18 curated sites. Unknown-legit accuracy must come from the ML tier.

## 4. Feature-level findings

- **`DomainLength` is the prime suspect** for the residual FPR. Compound suffixes
  are mechanically longer than `.com`, so the feature encodes suffix structure as
  risk. With TLD trust neutral for `com.ng` (0.477), those sites are still 7/8
  flagged (`gtbank.com.ng/personal-banking` = 0.678). SHAP agrees: value↔SHAP
  correlation strengthened +0.14 → **+0.32**.
- **Two feature fixes aimed at FPR both made the metric worse, and both were kept.**
  (a) `URLSimilarityIndex` path leak — `/apply` scored 0.80 against "apple"; fixed by
  gating on typo *pattern*; curated FPR 18.1% → 20.8%, because the buggy feature
  fired on 75% of legit curated URLs and the forest had fit it as a crutch.
  (b) `TLDLegitimateProb`'s 14-entry hand dict → 1,172 data-derived rates; curated
  20.8% → 24.3% (sampled improved 20.8% → 19.6%), because the curated corpus is
  100/144 `.com` and the hardcoded 0.95 flattered exactly that population (honest
  empirical rate 0.763). **Precedent worth following:** a feature that calls a
  dental clinic's `/apply` page Apple impersonation is indefensible regardless of
  what removing it does to a corpus metric. Say so plainly in the dissertation.
- **Don't estimate a reputation prior from the training corpus.** It's balanced
  ~52/48 for SMOTE, which put `.com` at 0.585 ("uninformative"). Use a wider
  evidence population held disjoint from both the test split and the validation
  band. And no dataset can estimate `com.ng` (34 domains in all of top-1m vs 59
  phishing rows) — shrinkage must report neutral rather than fabricate 0.14.
- **Brand-in-subdomain is not separable lexically.** Teaching the extractor to score
  brand tokens in compound subdomains collapsed `URLSimilarityIndex` to 0.0037
  importance at FPR 6.54%, because legit CDN rows (`apple-relay.cloudflare.com`)
  legitimately carry brand tokens. That is why the guard lives in `reputation.ts`.
- **`URLSimilarityIndex` is inert in the shipped model too** — 0.0036 importance,
  dead last of 21 features (measured Aug 15, 2026). The model contributes essentially
  nothing to brand-impersonation detection; the reputation layer does all of it. Treat
  this as evidence *for* the architecture, and quote it if anyone asks why the guard
  isn't "just a feature".
- **`DomainLength` is the #2 feature** at 0.1238 importance, behind only
  `TLDLegitimateProb` (0.2967). The FPR diagnosis is confirmed by the model's own
  importances, not just by SHAP.
- **The pattern that predicts success on this metric:** every *corpus*-level
  intervention has worked (path structure 60.4% → 18.1%; query/digit composition
  20.8% → 15.4% sampled) and every *feature*-level one has failed (path brand gate,
  data-derived TLD table, dropping length features). Aim new attempts at the corpus.

## 5. Dead ends — do not re-investigate

- **Leakage.** Tested and rejected. Ungrouped split; 20.3% of test phishing URLs
  share a host with training, but recall is 89.72% seen vs 90.16% unseen (inflation
  −0.09 pt). Switch to `GroupShuffleSplit` for viva defensibility, not for metrics.
- **PhiUSIIL's own CSV is contaminated, but this project is immune.** Its
  `URLSimilarityIndex` column is 100.0 for 100% of legitimate rows and classifies the
  whole dataset at 99.67% alone. PhishGuard re-extracts from raw URL strings, which
  is why it reports ~91–93% where papers claim 99.9%. **Its number is the honest
  one — frame that as a contribution.**
- **The allowlist as an FPR fix** — see §3.
- **Dead code that looks dangerous but isn't:** `augment_legitimate_urls` and
  `inject_popular_legit` in `train.py` are never called. The latter *would* cause
  real leakage if wired in. Delete rather than enable.

## 6. The committed model is authoritative ⚠️

`assets/phishing_model.json` (~19.6 MiB, 20,586,218 bytes) does **not** byte-reproduce
from current code. A retrain yields a different forest (846,454 nodes vs the
committed 806,620) and ~0.8 pt worse FPR (90.65% / 6.64% vs the documented 91.58% /
5.87%), because the root-slash strip landed after the model was trained (§2).

**Never silently replace it.** Any retrain is a reviewed decision and must be
re-exported explicitly via `export_model_json.py`. Verified Aug 15: the file in
`assets/` is md5-identical to the one in `build/chrome-mv3-prod/assets/`.

## 7. Performance: cold start, not inference ⚠️

The "~1 ms inference" figure is real but measures only warm steady-state traversal.
Measured on the actual load path:

| Metric | Measured |
|---|---|
| `JSON.parse` of the model | **942 ms** |
| total cold start | **1,048 ms** |
| heap after parse | **80 MB** |
| internal nodes / leaves | 384,081 / 384,181 |

**Why it recurs:** MV3 kills the service worker after ~30 s idle. `MLRunner.init()`
guards on `this.model`, but that's worker memory — when the worker dies the guard
resets and the full parse happens again. Same root cause makes `utils/cache.ts`
nearly useless: an in-memory `Map` with a 1-hour TTL that dies with the worker, so
the TTL is largely fictional (it also never evicts and keys on full URL rather than
registrable domain).

Report **both** numbers in the dissertation (~1 ms warm / ~1,050 ms cold). Fixes in
ROI order: binary typed-array model format (384k nodes × ~16 B ≈ 6 MB, parse drops
to tens of ms), persist to `chrome.storage.session`, shrink the forest (depth 20 on
21 features is over-capacity — sweep 20–50 trees × depth 8–16).

## 8. Security posture

- 🔒 **Model no longer world-readable.** `web_accessible_resources: ["assets/*"]`
  against `<all_urls>` used to expose the entire model to every website (offline
  evasion against the exact decision boundary). Absent from `package.json` as of
  Aug 15; the worker's `chrome.runtime.getURL` doesn't need it.
- 🔒 **Verdicts no longer forgeable.** `background/index.ts:18` now rejects messages
  where `sender.id !== chrome.runtime.id`. Without it any page could post a crafted
  `ANALYZE_PAGE` and read the verdict back, turning the detector into a tuning
  oracle.
- ⚠️ **GSB fallback is aimed at the wrong band.** It fires on
  `|score − threshold| < 0.15`, i.e. [0.35, 0.65], but 13 curated legit URLs score
  ≥0.85. The band where help is needed isn't the band being checked.
- ⚠️ **Fail-open everywhere, with only `console.error`.** A broken model yields an
  unprotected browser and no user-visible signal.

## 9. Verified correct — do not re-audit

`rf-inference.ts` tree traversal (`<=` → left), soft-voting aggregation (sums
per-tree class fractions / `n_estimators`), and the `val * scale_ + min_` scaler all
match sklearn exactly. The parity gate independently confirms 0 mismatches across
20,160 values.

## 10. Project conventions

- **Append a dated entry to `IMPLEMENTATION_NOTE.md` at every point of
  implementation or integration** — as work happens, not at the end. The author is
  working under context limits and needs a durable record that survives sessions.
- `SOURCE_OF_TRUTH.md` owns all numbers; don't restate metrics elsewhere, link to it.
- Generated files are never hand-edited: `psl-trie.ts`, `tld-rates.ts`,
  `phishing_model.json`, `shap_mapping.json`.
- **Verdict-affecting changes are deliberate reviewed decisions**, not drive-by
  fixes. This is why the findings in `handoff.md` §3 were reported rather than
  patched.
- Known stale tooling: `test_url.py` (divergent pkl, old 0.50/0.85 bands, no
  reputation layer), `diagnose_url.mjs` (drifted inlined extractor),
  `cross_validate_ts.mjs` (prints "All 44 scaled values match" for a 21-feature
  model). Don't use them for evidence.
