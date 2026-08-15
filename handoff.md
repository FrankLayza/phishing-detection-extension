# PhishGuard — Handoff

**As of:** August 15, 2026 · branch `main` · working tree clean · nothing unpushed beyond the two commits below.

Read `architecture.md` for structure, `memory.md` for traps, `SOURCE_OF_TRUTH.md`
for numbers. This file is the transient layer: what just landed, what's open, and
what to pick up. It supersedes the state section of `WORK_SESSION.md`, which is
stale (Aug 5).

---

## 1. What just landed

```
eb3e2b3 feat: brand-impersonation guard for platform-hosted clones
7f77ebc chore: ignore demo-generated bundles and dissertation scratch files
```

`eb3e2b3` is the substantive one. It was authored by a previous model; this session
committed it and reviewed it. Contents:

- **New `src/ml/reputation.ts`** — extracts the inline allowlist out of
  `background/index.ts` into one seam, `evaluate(url, features)`, with three
  adapters (allowlist / suffix trust / hosting platforms). See `architecture.md` §6.
- **New `src/ml/brands.ts`** — brand vocabulary + typo machinery moved out of the
  extractor so the guard and the extractor share one list. Adds
  `brandTokenInSubdomain`.
- **The guard itself** — the advisory platform correction is withheld when a
  subdomain carries a brand token, so `microsoft-verify-login.netlify.app` keeps
  its full risk score instead of being cleared to CLEAN.
- **`popup.tsx`** — was dropping Reputation-category signals on ML-sourced
  results, which would have made the new signals invisible.
- **`demo_supervisor.mjs` + `SUPERVISOR_DEMO.md`** — demo path through the real
  bundled extractor, committed model, and same reputation logic.
- **Docs** — guard documented in `CONTEXT.md`; `SOURCE_OF_TRUTH.md` records both
  the failed extractor-side experiment and the committed-model/retrain divergence.

## 2. Verification performed this session

All green. Commands are the exact ones run.

| Check | Command | Result |
|---|---|---|
| Typecheck | `cd phishing-extension && npx tsc --noEmit` | clean |
| Parity gate | `node ml-pipeline/gen_parity_features.mjs && python ml-pipeline/check_parity.py` | **0 mismatches / 20,160 values** |
| Shipped model present | `md5sum phishing-extension/{assets,build/chrome-mv3-prod/assets}/phishing_model.json` | identical (`c39d40f…`) |
| Documented demo scores | `node ml-pipeline/demo_supervisor.mjs` | all 11 URLs reproduce `SUPERVISOR_DEMO.md` exactly |

The parity result is the meaningful one: moving `levenshtein` / `typoSimilarity` /
`HOMOGLYPHS` / `BRANDS` into `brands.ts` is behaviour-preserving.

## 3. Open findings — the actual work queue

Seven defects found by review, **none fixed**. Findings 1–3 change verdict
behaviour, and this repo's convention is that verdict changes are deliberate
reviewed decisions, so they were left for a decision rather than patched. All were
confirmed against the shipped pipeline or the corpus, not reasoned about.

Repro for 1–3 (one command):

```bash
node ml-pipeline/demo_supervisor.mjs \
  "https://microsoft-verify-login.railway.app" \
  "https://paypal-verify-login.neocities.org" \
  "https://microsoft-verify-login.sharepoint.com" \
  "https://paypal-login.forms.gle" \
  "https://paypal.vercel.app" \
  "https://microsoft.netlify.app" \
  "https://apple.surge.sh" \
  "https://paple-login.vercel.app/signin" \
  "https://payapl-login.vercel.app/signin"
```

---

### Finding 1 — CRITICAL: the hard allowlist runs before the guard and matches platform domains

Adapter A is consulted with the **platform's** registrable domain, because the PSL
trie is ICANN-only (`architecture.md` §6 caveat). `railway.app` and `neocities.org`
are both in `top_domains.json`, so anything hosted under them short-circuits to
CLEAN 0.05 — before adapter C, before the model, before the guard.

| URL | Actual |
|---|---|
| `microsoft-verify-login.railway.app` | **CLEAN 0.05** (allowlist) |
| `paypal-verify-login.neocities.org` | **CLEAN 0.05** (allowlist) |
| `microsoft-verify-login.sharepoint.com` | **CLEAN 0.05** (allowlist) |
| `paypal-login.forms.gle` | **CLEAN 0.05** (allowlist) |

Not limited to `PLATFORM_HOSTS`: **any** subdomain of **any** allowlisted domain is
hard-cleared. Also in the allowlist and user-content-capable — `wix.com`,
`windows.net`, `sharepoint.com`, `forms.gle`, `typeform.com`, `jotform.com`,
`firebaseio.com`, `ondigitalocean.app`, `vercel.com`, `netlify.com`. These are
real, actively-abused phishing vectors.

*Candidate fix:* in `reputation.ts:evaluate`, test `PLATFORM_HOSTS` **before** the
allowlist, or filter platform/user-content suffixes out of the allowlist in
`init()`. Either changes verdicts — needs a decision. Enumerate the list against
`top_domains.json` first:

```bash
node -e "
const s=new Set(JSON.parse(require('fs').readFileSync('phishing-extension/assets/top_domains.json','utf8')));
const {PLATFORM_HOSTS}=require('./phishing-extension/src/ml/reputation.ts');" # or just grep the array
```

### Finding 2 — HIGH: the single-label exemption is free to claim on 16 of 18 platforms

`brandTokenInSubdomain` skips a subdomain that IS exactly one brand label, so
`microsoft.github.io` (the org's own project page) gets the normal correction. That
reasoning holds for `github.io`/`gitlab.io`, where `<name>.github.io` requires
owning the org. It is applied to **all 18 platforms**, including ones where a bare
brand project name is first-come-first-served:

| URL | Actual |
|---|---|
| `paypal.vercel.app` | **CLEAN 0.232** |
| `microsoft.netlify.app` | **CLEAN 0.291** |
| `apple.surge.sh` | **CLEAN 0.142** |

These are *worse than pre-guard*: they receive the TLD correction that pushes them
under the CLEAN line. `paypal.vercel.app` is also roughly the first thing a
supervisor would type.

*Candidate fix:* restrict the exemption to identity-bound platforms. Pass the
matched platform into `brandTokenInSubdomain` and gate the `continue` at
`brands.ts:136` on an allow-set of `{github.io, gitlab.io}`.

### Finding 3 — MEDIUM: threshold boundary inconsistent, and reachable

`brandSimilarityOf` uses `max < TYPO_THRESHOLD ? 0 : max` (accepts exactly 0.6,
matching Python). `brandTokenInSubdomain` uses `sim > TYPO_THRESHOLD` (rejects
exactly 0.6). `paple` and `aplpe` — adjacent transpositions of `apple` — score
**exactly 0.6000**:

| URL | Actual |
|---|---|
| `paple-login.vercel.app/signin` | **CLEAN 0.253** (guard misses) |
| `payapl-login.vercel.app/signin` (0.667) | SUSPICIOUS 0.868 (guard fires) |

*Fix:* `brands.ts:143` → `>=`. One character. Only `apple` is 5 letters, so this is
the narrow case, but it's a free correctness win.

### Finding 4 — LOW: the "one source of truth" refactor left the duplicate in place

`brands.ts`'s header states the point is that "a second copy cannot drift", but
`feature-extractor.ts:79` still declares `const TYPO_THRESHOLD = 0.6` inside
`computeBrandSimilarity`, shadowing the value imported on line 18. The import is
dead and the duplicate literal survives at exactly the spot the module was created
to eliminate. *Fix:* delete line 79. Parity gate covers the change.

### Finding 5 — LOW: dead export

`brandSimilarityOf` (`brands.ts:105`) is exported and imported by nothing. Either
wire it into `computeBrandSimilarity` (it duplicates that logic) or drop it.

### Finding 6 — COSMETIC: demo prints `undefined`

`demo_supervisor.mjs:71` returns early for allowlisted URLs without `raw` /
`correction` keys, so the supervisor-facing output shows `raw ML : undefined`.
Two lines.

### Finding 7 — DOCS: two extractor comments state the root-slash classes backwards

Found while writing `memory.md`, and measured directly against
`datasets/phiusiil.csv` rather than inherited from notes.

- `feature-extractor.ts:176-177` and `lexical_extractor.py:56-57` both say
  "PhiUSIIL **legitimate** rows are 31.4% root-slash while **phishing** rows are
  0.0%".
- Measured: legitimate (`label == 1`, n=134,850) = **0.00%**; phishing
  (`label == 0`, n=100,945) = **31.45%** (31,744 rows). Exactly inverted.

Label convention confirmed two ways: `gen_tld_rates.py:130` builds its *legit*
domain list from `label == 1`, and inspection agrees (label 1:
`southbankmosaics.com`, `uni-mainz.de`; label 0: `f0519141.xsph.ru`,
`shprakserf.gq`).

This matters beyond tidiness: under the inverted premise the observed bug is
impossible — a legit-leaning token cannot push homepages *toward* phishing, yet
`google.com` went 0.207 → 0.880 when the slash was added. The correct account is
that the root slash is a **phishing**-class token and the browser puts one on every
homepage. The number in `SOURCE_OF_TRUTH.md` §3 is right; the two code comments are
wrong.

Repro:

```bash
python -c "
import pandas as pd
df = pd.read_csv('datasets/phiusiil.csv', usecols=['URL','label'])
rs = lambda u: (lambda r: r.endswith('/') and r.count('/')==1)(str(u).split('://',1)[-1])
df['rs'] = df.URL.map(rs)
print(df.groupby('label').rs.agg(['size','sum','mean']))
"
```

*Fix:* comment-only, no behaviour change, parity unaffected. Swap the two class
names in both files.

---

## 4. Design boundary to be aware of (not a bug)

The guard only **withholds help** — it never adds risk. A brand-impersonation clone
the model scores below 0.5 raw stays CLEAN, and
`microsoft-verify-login.netlify.app` at 0.828 is SUSPICIOUS, not blocked. That is
consistent with "advisory authority", but it means `SUPERVISOR_DEMO.md`'s pillar 3
("stops platform-hosted clones from being cleared") claims more than ships. Guard
coverage is bounded by the model's raw score.

Also still open from earlier sessions (documented, not regressions): unknown-legit
ML-tier FPR 15.4% vs a <10% target; `instagram` absent from `BRANDS`; non-platform
brand squats rely on the model alone; 19.4 MB model bundle; `shap_mapping.json`
staleness; `cross_validate_ts.mjs` prints stale text.

## 5. Suggested next steps

1. Decide on findings 1–3 (verdict-affecting). 1 is the one that undermines the
   guard's stated purpose.
2. Land 4–7 freely; they're behaviour-neutral. Re-run the parity gate after 4.
3. Before any demo, run the finding 1–3 repro above so nobody types
   `paypal.vercel.app` in front of a supervisor cold.
4. If findings are fixed, re-measure unknown-legit FPR
   (`validate_unknown_legit.py`) — findings 1 and 2 currently *suppress* false
   positives, so fixing them will move FPR up. That trade needs to be recorded in
   `SOURCE_OF_TRUTH.md`.
5. Append a dated entry to `IMPLEMENTATION_NOTE.md` for whatever lands (standing
   project convention).

## 6. Environment notes (Windows, this repo)

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
