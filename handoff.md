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

**Steps 0 and B are complete.** Training reproducibility was tested and holds (§3 A),
and the FPR harness now scores the shipped artifact (§3 B). The corpus experiment on the
FPR (§3 C) is unblocked and is the next substantive piece of work.

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

Ranked. A was cleared, B is done, C was run and its intervention rejected on
measurement; **D and E are what remain, and both are judgement calls rather than work**.

### A — RESOLVED: training IS reproducible (was flagged as a blocker)

**Tested and cleared Aug 15, 2026.** Two consecutive runs of `train.py` on identical
code produced **identical** forests — 864,614 nodes both times — with identical metrics
(90.64% accuracy, FPR 6.62%, 5-fold CV 0.9038 ± 0.0025). Environment: Python 3.11.9,
scikit-learn 1.3.0, numpy 1.24.3; the repo `venv` and system Python carry the same
versions and the two `tldextract` caches hold the same PSL snapshot.

An earlier note in this file inferred non-determinism from three differing node counts
(806,620 / 846,454 / 864,614). That inference was wrong: those came from three
different tree states, not from randomness. The 846,454 figure cannot be reproduced
from the committed tree — the only training-relevant change since Aug 14 is a comment —
so it was most likely measured against uncommitted working-tree state.

**Consequences:**
- **Corpus experiments are safe to interpret.** No noise floor needs establishing
  first; a before/after difference in a fixed environment is real.
- Cite **864,614** as the current retrain baseline, not 846,454.
- Still true, and unaffected: the *shipped* 806,620-node model does not reproduce from
  current code (the root-slash strip landed after it was trained), so it must not be
  silently replaced.
- Determinism holds **per environment**. Pin the interpreter and library versions when
  comparing runs, and re-baseline after any dependency change.

Repro (~5 min per run, incl. 5-fold CV):

```bash
python ml-pipeline/train.py
python -c "import joblib; rf=joblib.load('models/random_forest.pkl'); print(sum(t.tree_.node_count for t in rf.estimators_))"
```

### B — DONE: the FPR harness now scores the shipped artifact

`validate_unknown_legit.py` defaulted to `models/random_forest.pkl` (whatever `train.py`
last produced, 864,614 nodes) rather than the committed `assets/phishing_model.json`
(806,620). Fixed by adding a `ShippedModel` scorer that walks the committed JSON with the
same scaling and traversal as `rf-inference.ts`; `--model pkl` keeps the old path for
measuring a retrain before exporting it, and prints a warning.

The Python traversal was cross-checked against the JS one in `demo_supervisor.mjs` on
four URLs spanning the range (0.199 / 0.596 / 0.838 / 0.866) — exact match — and the
loader reports 806,620 nodes, confirming it read the shipped forest.

**Measured on the shipped model:**

| Set | n | ML FPR | Pipeline FPR | Hard red |
|---|---|---|---|---|
| curated | 144 | 21.5% | 16.7% | 0.7% |
| sampled | 4,000 | **15.4%** | **9.4%** | **0.8%** |

The published figures were therefore correct — the drift would have corrupted the *next*
measurement, not the existing ones. The retrain scores about a point worse (sampled 16.5%
/ 10.2%), consistent with keeping the committed model.

Also fixed here: `PHISH_MIN` was 0.85 against a shipped red band of 0.90, over-reporting
hard alarms; now 0.90, and the 0.8% above is at that band.

**The root-slash sub-item needed no fix** — verified that `https://d` and `https://d/`
now yield byte-identical features, because `38e820d` strips a lone root slash in both
extractors. Documented in the harness so it is not re-opened. Do not append slashes to
path URLs: there a trailing slash is real path structure.

Residual approximation: 5 of 4,000 sampled URLs (0.12%) are platform tenants, where the
harness models adapter A only. It counts and prints them, bounding the error at ~0.13 pt,
and deliberately does not reimplement `reputation.ts`.

### C — DONE (intervention rejected): the FPR gap is an information ceiling

Ran the corpus experiment. Three measurements, each of which changed the plan:

**1. The inherited diagnosis was false.** `DomainLength` — blamed across the docs —
contributes **−0.03 sd** against the flagged population. The training classes barely
differ on it (legit 9.31 vs phishing 8.99; legit domains are marginally *longer*), and
the compound-suffix mechanism it rested on was already removed in `0ca9429`, which
redefined the feature as the registrable **label** length. Its #2 Gini importance
(0.1238) reflects use in interaction splits, not error attribution. Retracted in
`SOURCE_OF_TRUTH.md`, `memory.md` and `SUPERVISOR_DEMO.md`.

**2. The real driver is `TLDLegitimateProb` at +1.59 sd** (2.5x the next factor).
Flagged legit sites average 0.596 suffix trust vs training legit's 0.779.

**3. But "distribution-match the legit class" was also wrong.** Mean suffix trust is
~0.785 across the *entire* top-1m at every rank depth, so the legit class is already
representative on average — drawing from deeper Umbrella ranks changes nothing (0.786
at top-55k vs 0.784 at 55k–120k, measured on 8k samples per band). The gap is in the
tail: only 0.9% of training legit sits below 0.35 trust.

So the experiment became hard-example oversampling: substitute 10,000 top-sites entries
with real legit domains on low-trust suffixes, class size held constant.

| metric | OFF | 10,000 | shipped model |
|---|---|---|---|
| sampled ML FPR | 16.3% | 15.7% | **14.9%** |
| sampled pipeline FPR | 11.5% | 11.1% | 10.4% |
| hard red alarms | 1.2% | **0.5%** | 1.0% |
| recall | 87.66% | 86.86% | 88.80% |
| held-out accuracy | 90.64% | 89.84% | 91.58% |
| nodes | 864,614 | 935,950 | 806,620 |

**Rejected** against a decision rule fixed before the numbers existed (keep if FPR
improves >1pt and recall drops <2pt). 0.6pt of FPR for 0.8pt of recall, 0.9 of
precision, 0.8 of accuracy and 8% more model — and at 15.7% still worse than what
already ships. Reproduce with `N_LOW_TRUST_LEGIT = 10000` in `train.py`; the code and
the full ablation are kept, only the constant is zero.

**Worth revisiting only if the objective changes:** hard red alarms more than halved
(1.2% → 0.5%). Only PHISHING blocks navigation, so if hard-red rate becomes the primary
objective rather than flagged-rate, this is the one lever measured so far that moves it.

**What remains is an information ceiling, not a corpus bug.** `.app` carries 6,368
phishing rows against 200 legitimate; `.co` 0.182; `.xyz` 0.292. Real legitimate sites
on those suffixes are a genuine minority and a URL string does not separate them. That
is why the reputation layer exists, and why 9.4% pipeline — not 15.4% ML-tier — is the
number a user experiences.

Tooling added: `ml-pipeline/diagnose_fpr.py` reproduces the whole diagnosis in one
command and records its own findings in its docstring.

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

1. ~~Fix training determinism~~ — **done**, it was never broken (§3 A).
2. ~~Re-point the FPR harness at the shipped model~~ — **done** (§3 B). "What is your
   false positive rate?" now has a defensible answer: 15.4% ML-tier / 9.4% pipeline on
   n=4,000, measured on the forest the extension loads.
3. ~~The corpus experiment~~ — **done, intervention rejected** (§3 C). The diagnosis it
   was based on turned out to be false, and the replacement intervention lost more than
   it gained. The residual FPR is an information ceiling, which is a finding rather than
   a task.

**Nothing on this list is blocking a demo.** What is left is judgement, not work:

4. Decide §3 D (whether brand impersonation should add risk rather than only withhold a
   discount). Currently documented as a deliberate limitation and shown in the demo.
5. Decide whether to extend `PLATFORM_HOSTS` to the user-content hosts listed in §3 E —
   a data judgement about corporate tenants that could introduce false positives.
6. For the write-up: the three strongest results are the train/serve parity gate
   (0 mismatches / 20,160 values), the honest metric provenance (every figure measured
   on the shipped artifact), and the documented ablations — including two rejected ones
   and one retracted diagnosis. That last item is a contribution, not an embarrassment;
   most published work on PhiUSIIL reports 99%+ by exploiting a contaminated column.
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
