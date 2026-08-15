# PhishGuard — Handoff

**As of:** August 15, 2026 · branch `main` · working tree clean.

Read `architecture.md` for structure, `memory.md` for traps, `SOURCE_OF_TRUTH.md`
for numbers. This file is the transient layer: what just landed, what's open, and
what to pick up. It supersedes the state section of `WORK_SESSION.md`, which is
stale (Aug 5).

---

## 0. Status: the guard is fixed and the build is demo-ready

All seven review findings are **fixed and verified**. The extension has been rebuilt
(`pnpm build`), all 3 assets copied, and the shipped model md5 is unchanged
(`c39d40f…`, 806,620 nodes) — the timing retrain did not leak into it.

| Check | Result |
|---|---|
| `tsc --noEmit` | clean |
| Parity gate | **0 mismatches / 20,160 values** |
| 12 demo rows in `SUPERVISOR_DEMO.md` | all reproduce |
| Previously-cleared attack URLs | **6 of 8 now flagged** (was 0 of 8) |
| 10 legit platform tenants | all CLEAN 0.181–0.299, no regression |
| Reported unknown-legit FPR | unchanged (harness doesn't model the platform adapter) |

**Next planned step is Step 0: fix training reproducibility** (see §3, finding A).
That is a prerequisite for any corpus experiment aimed at the FPR.

## 1. What landed

```
<pending> fix: close three holes in the brand-impersonation guard
ebd0314   docs: add architecture/handoff/memory as the cross-session pickup point
eb3e2b3   feat: brand-impersonation guard for platform-hosted clones
7f77ebc   chore: ignore demo-generated bundles and dissertation scratch files
```

`eb3e2b3` introduced the reputation seam (`src/ml/reputation.ts`), the shared brand
vocabulary (`src/ml/brands.ts`), the brand-impersonation guard, a `popup.tsx` fix for
dropped Reputation-category signals, and `demo_supervisor.mjs` / `SUPERVISOR_DEMO.md`.

The follow-up commit closes the three verdict-level holes review found in it, plus
four housekeeping items. Details in `IMPLEMENTATION_NOTE.md`.

## 2. Fixed findings (was §3, kept for reference)

| # | Was | Now |
|---|---|---|
| 1 | Hard allowlist cleared platform tenants — `microsoft-verify-login.railway.app` → CLEAN 0.05 | Allowlist skipped for tenants (`isTenant`); → SUSPICIOUS 0.837 |
| 2 | Bare-brand-label exemption granted on all 18 platforms — `paypal.vercel.app` → CLEAN 0.232 | Limited to `IDENTITY_BOUND_PLATFORMS`; → SUSPICIOUS 0.866 |
| 3 | `sim > 0.6` excluded exact-threshold squats — `paple-login.vercel.app` → CLEAN 0.253 | `>=`; → SUSPICIOUS 0.821 |
| 4 | `feature-extractor.ts:79` shadowed the shared `TYPO_THRESHOLD` | Removed; import is now live |
| 5 | `brandSimilarityOf` dead export | Deleted |
| 6 | Demo printed `raw ML : undefined` for allowlisted URLs | Prints `n/a (model skipped)` |
| 7 | Two extractor comments stated the root-slash classes backwards | Corrected in both, with the measurement |

`ondigitalocean.app` was added to `PLATFORM_HOSTS` (it was in the allowlist, so all
its tenants were being hard-cleared).

## 3. Open work queue

Ranked. Item A blocks any work on the FPR metric.

### A — BLOCKER for FPR work: training is not reproducible

Three seeded runs of `train.py` on unchanged code produced three different forests:

| Artifact | Total nodes |
|---|---|
| Shipped `assets/phishing_model.json` | 806,620 |
| `random_forest.pkl` as of Aug 14 | 846,454 |
| Re-run Aug 15, same code and seeds | 864,614 |

In-corpus metrics are stable to ~0.02 pt (90.64% / 6.62% FPR), so this is structural
drift, not a different model class. `SOURCE_OF_TRUTH.md` §3 previously claimed
byte-identical reproducibility; that claim is now marked superseded.

**Prime suspect:** an unseeded RNG or `set`/`dict` iteration order in the corpus
builder. Python randomises string hashing per process unless `PYTHONHASHSEED` is
pinned, so any code that iterates a `set` of URLs/domains and then samples from it
will pick a different subset each run. Look at `build_legit_urls`,
`measure_structure`, `_synth_*` and the `phi_hosts` set logic in `train.py`.

**Why it blocks:** a corpus experiment that moves FPR from 16% to 14% is
uninterpretable until you know the run-to-run noise floor. Fix determinism, verify by
two consecutive runs producing identical node counts, then measure the noise floor
across 2–3 deliberately different seeds.

Repro:

```bash
python ml-pipeline/train.py   # ~5 min 9 s measured, incl. 5-fold CV
python -c "import joblib; rf=joblib.load('models/random_forest.pkl'); print(sum(t.tree_.node_count for t in rf.estimators_))"
```

### B — the headline FPR is measured on a model that isn't shipped

`validate_unknown_legit.py:83` loads `models/random_forest.pkl`; the extension loads
`assets/phishing_model.json`. Different forests (846k–865k vs 806,620 nodes). So the
~15–16% ML-tier and ~9.9% pipeline figures describe a model nobody runs.

Same trap family as `test_url.py`, which is already flagged for this. Fix: score the
curated and sampled populations through the shipped artifact — `demo_supervisor.mjs`
already does exactly this for single URLs (bundled TS extractor + committed model JSON
+ real reputation logic), so it mostly needs the population loops lifted from
`validate_unknown_legit.py`.

Two smaller defects in the same harness, worth fixing while there:
- `PHISH_MIN = 0.85`, but the shipped red band is **0.90**. It over-reports hard alarms.
- It builds `https://domain` with no root slash, so it scores a URL shape the browser
  never sends. See `memory.md` §2.

### C — the FPR gap itself (needs A and B first)

ML-tier FPR ~16% against a <10% target. Root cause diagnosed: `DomainLength` is the
model's **#2 feature** (0.1238 importance) and encodes suffix structure as risk, so
mechanically longer regional domains (`gtbank.com.ng`) are penalised.

Do **not** try removing the length features — tested, and curated FPR nearly doubled
(18.1% → 34.7%) with recall and accuracy both down (`feature_config.py:28-32`).

The lever is corpus-level: distribution-match the legitimate class against the
phishing class on **domain length and suffix shape**, the same technique that already
worked twice on this project (path structure 60.4% → 18.1%; query/digit composition
20.8% → 15.4% sampled). Note that every *feature*-level attempt on this metric has
failed and every *corpus*-level attempt has succeeded.

Watch the validation-contamination trap: the honest unknown-legit population is
top-1m rank ≥120,000. Training on deep ranks burns it. Partition instead (e.g. train
55k–300k, validate 500k+).

### D — the one design decision deliberately not taken

The guard withholds the platform discount but never adds risk, so a clone the model
scores below 0.50 on raw features still reads CLEAN
(`paypal-verify-login.neocities.org` = 0.124). Escalating brand impersonation to
positive evidence would catch it, at the cost of flagging legitimate brand-adjacent
projects on free hosts (`apple-music-clone.vercel.app`) and adding a third authority
type to `CONTEXT.md`. Documented as a limitation in `SUPERVISOR_DEMO.md` and shown
deliberately in the demo. Revisit only if the supervisor pushes on it.

### E — smaller known items

- Only 10 brands tracked; `instagram` absent.
- Non-platform brand squats rely on the model alone (`microsoft-verify-login.phishcorp.co` = 0.596).
- `PLATFORM_HOSTS` coverage: several user-content hosts sit in the allowlist but are
  not on the platform list, so their tenants are still hard-cleared —
  `sharepoint.com`, `typeform.com`, `jotform.com`, `wix.com`, `windows.net`,
  `firebaseio.com`, `forms.gle`. Classifying these needs a judgement about corporate
  tenants (a legit `contoso.sharepoint.com` vs a phishing one) that could introduce
  false positives, so it was left as a data decision rather than guessed at.
- `shap_mapping.json` is model-derived and would need regenerating after any retrain,
  as would the calibrated 0.50/0.90 bands (`sweep_thresholds.py`).
- ~20 MB model, ~1 s MV3 cold start per worker wake.
- `cross_validate_ts.mjs` prints stale text for a 21-feature model.

## 4. Suggested next steps

1. **Step 0 — fix training determinism** (§3 item A). Verify with two consecutive
   runs producing identical node counts.
2. **Measure the noise floor** — 2–3 deliberately different seeds, unknown-legit FPR
   each time. ~7 min per seed. This tells you what change size is real.
3. **Re-point the FPR harness at the shipped model** (§3 item B), and fix its
   `PHISH_MIN` band and missing root slash while you're in there. After this you can
   answer "what is your false positive rate?" defensibly.
4. **Then, and only then, the corpus experiment** (§3 item C) — distribution-match
   domain length and suffix shape in the legitimate class.
5. If a retrain is adopted: re-export via `export_model_json.py`, regenerate
   `shap_mapping.json`, **re-calibrate the 0.50/0.90 bands** (`sweep_thresholds.py` —
   they were tuned to the old model's score distribution), re-measure, update
   `SOURCE_OF_TRUTH.md`, rebuild.
6. Append a dated entry to `IMPLEMENTATION_NOTE.md` for whatever lands (standing
   project convention).

## 5. Environment notes (Windows, this repo)

- **Two shells.** PowerShell is primary; the Bash tool is separate and takes POSIX
  syntax. Multi-line git messages need a **heredoc** (`git commit -F - <<'EOF'`),
  *not* a PowerShell here-string (`@'…'@`) — the latter silently prefixes `@` into
  the commit subject.
- **Bash cwd persists between calls.** A `cd phishing-extension` in one call
  affects the next. Use absolute paths.
- **Never grep the repo root unscoped.** `datasets/`, `*.docx`, and the 20 MB model
  JSON make it time out. Scope to `phishing-extension/src` or `ml-pipeline`, or use
  the Grep tool with a `path`.
- `pnpm build` must have been run at least once: `demo_supervisor.mjs` reads the
  model from `build/chrome-mv3-prod/assets/`, not `assets/`.
