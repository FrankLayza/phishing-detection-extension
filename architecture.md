# PhishGuard — Architecture

How the system is put together: components, data flow, seams, and the invariants
that keep it correct. Companion docs:

| Doc | Role |
|---|---|
| `SOURCE_OF_TRUTH.md` | Authoritative **numbers** (metrics, model config, dataset). Never restate metrics here — link to it. |
| `CONTEXT.md` | Domain **vocabulary** (verdict, hard vs advisory authority, hosting platform…). |
| `handoff.md` | **Current state** — what just landed, what's open, what to do next. |
| `memory.md` | **Traps** — failure modes this project has already hit; read before validating anything. |
| `IMPLEMENTATION_NOTE.md` | Dated **changelog** of every implementation step. |
| `SUPERVISOR_DEMO.md` | Demo script + expected scores. |

---

## 1. Shape of the system

Two halves that must agree on one thing — the feature vector.

```
   PYTHON (train time)                         TYPESCRIPT (serve time)
   ml-pipeline/                                phishing-extension/src/

   features/lexical_extractor.py  ═══parity═══  content/feature-extractor.ts
            │                        gate                    │
            ▼                                                ▼
      train.py  ──►  random_forest.pkl                 ml/rf-inference.ts
            │                                                ▲
            ▼                                                │
   export_model_json.py ──► assets/phishing_model.json ──────┘
                                    (20.6 MB, bundled)
```

The **parity gate** (`ml-pipeline/check_parity.py`) is the load-bearing invariant:
both extractors must emit byte-identical values for the same URL, or the model is
scored on features it was never trained on. See §5.

## 2. Runtime data flow (Chrome MV3)

```
  page load
     │
     ▼
  content.ts ─── extractPageFeatures(url, html) ──► 21 lexical features
     │           (content/feature-extractor.ts)
     │           NOTE: html is passed but unused — lexical-only by design (§4)
     │
     │ chrome.runtime.sendMessage("ANALYZE_PAGE")
     ▼
  background/index.ts   ← service worker; cold-starts on every wake (see memory.md)
     │
     ├─ 0. sender.id !== runtime.id  ──► reject   (stops pages forging an oracle)
     │
     ├─ 1. urlCache.get(url)         ──► hit? return  (1 h TTL, in-memory)
     │
     ├─ 2. reputation.evaluate(url, features)        ── ml/reputation.ts
     │       │
     │       ├─ kind "allowlisted" ──► HARD SHORT-CIRCUIT: score 0.05,
     │       │                         source OVERRIDE, model never runs
     │       │
     │       ├─ kind "platform"    ──► advisory; carries a corrected vector
     │       │                         (+ `impersonation` when the guard fires)
     │       │
     │       └─ kind "unknown"     ──► raw features, model decides
     │
     ├─ 3. mlRunner.predict(features)          ── ml/rf-inference.ts, RAW first
     │       │
     │       └─ correctionApplied = platform && !impersonation && raw < 0.90
     │              └─ if true: re-predict on rep.features (TLD trust neutralised)
     │
     ├─ 3b. Google Safe Browsing — ONLY if user supplied a key AND
     │       |score − threshold| < 0.15. Network egress happens here and
     │       nowhere else. A GSB match forces score 0.99.
     │
     ├─ 4. shapApproximator.getExplanations(usedFeatures)  ── ml/shap-approximator.ts
     │       └─ prepend rep.signals when correctionApplied || impersonation
     │
     └─ 5. persist: urlCache + storage.local[`result_<tabId>`] + action badge
              │
              ▼
          popup.tsx ─ reads result_<tabId>, DISCARDS it unless
                      result.url === live tab URL (stale-verdict guard)
                      then bands it: CLEAN <0.50 · SUSPICIOUS <0.90 · PHISHING ≥0.90
```

Storage lifecycle: `result_<tabId>` is removed on `tabs.onRemoved` **and** on
`tabs.onUpdated` when `changeInfo.url` changes. Both are required — see `memory.md`.

## 3. Module map

### Extension (`phishing-extension/src/`)

| File | Responsibility |
|---|---|
| `content.ts` | Injected per page. Extracts features, messages the worker. |
| `content/feature-extractor.ts` | **The serve-side extractor.** 21 features. Must mirror `lexical_extractor.py` exactly. |
| `background/index.ts` | Orchestrator. Owns the pipeline order and the correction/immunity rules. |
| `ml/rf-inference.ts` | Loads `phishing_model.json`; min-max scale + tree walk. `isPhishing = prob >= 0.5`. |
| `ml/reputation.ts` | **The reputation seam.** `evaluate(url, features)` → verdict. Three adapters (§6). |
| `ml/brands.ts` | Brand vocabulary + typo machinery (`levenshtein`, `typoSimilarity`, `brandTokenInSubdomain`). |
| `ml/tldextract.ts` | **The domain seam.** `parseHost` → `{subdomain, domain, suffix}`. 1:1 port of Python `tldextract`. |
| `ml/psl-trie.ts` | Generated Public Suffix List trie (6,933 rules, **ICANN-only** — see §6 caveat). |
| `ml/tld-rates.ts` | Generated `TLD_LEGIT_RATES` + `TLD_LEGIT_PRIOR`, feeds `TLDLegitimateProb`. |
| `ml/shap-approximator.ts` | Per-feature contribution estimates from `shap_mapping.json`. |
| `popup.tsx` | Verdict UI, bands, signal list, stale-verdict guard. |
| `options/index.tsx` | Risk threshold, GSB toggle + key. |
| `utils/cache.ts` | In-memory URL→result cache, 1 h TTL. |

### Pipeline (`ml-pipeline/`)

| File | Responsibility |
|---|---|
| `train.py` | Builds the corpus, trains, evaluates. Fully seeded (`random_state=42`). |
| `features/lexical_extractor.py` | **The train-side extractor.** The other half of parity. |
| `export_model_json.py` | `.pkl` → browser-bundleable JSON. |
| `check_parity.py` | **The parity gate.** Python vs the real bundled TS extractor. |
| `gen_parity_features.mjs` | esbuilds the TS extractor, writes `parity_ts.json` (960 URLs). |
| `gen_psl_trie.py` / `gen_tld_rates.py` | Generate `psl-trie.ts` / `tld-rates.ts`. |
| `demo_supervisor.mjs` | Scores URLs through the **real** shipped path (bundled extractor + committed model + reputation). |
| `validate_unknown_legit.py` | Unknown-legit FPR — the metric that actually gates the product. |
| `score_shipped.mjs` | Scores a URL list against the shipped artifact. |

## 4. Why lexical-only

DOM/content features were removed: they caused train/serve skew severe enough that
`google.com` scored 91.8% PHISHING. `content.ts` still passes `html` into
`extractPageFeatures` for signature compatibility, but nothing reads it. All 21
features derive from the URL string alone, which is also what makes parity testable.

Feature list: see `src/types/index.ts` (`FeatureVector`).

## 5. Invariants

Break one of these and the product is silently wrong. Items 4, 5 and 9 are currently
**violated** and tracked in `handoff.md` §3.

1. **Train/serve parity.** `check_parity.py` must report 0 mismatches across
   20,160 values (960 URLs × 21). Run it after *any* extractor edit.
2. **The parity gate must rebuild its bundle.** It has twice passed against a
   stale `__parity_bundle.mjs`. `gen_parity_features.mjs` rebuilds via the esbuild
   JS API — run it first, always.
3. **Validate the built artifact, not the source.** Harnesses that read
   `src/` can be green while `build/` ships no model at all.
4. **The committed model is authoritative.** `assets/phishing_model.json` does
   *not* byte-reproduce from current code; a retrain yields a different forest and
   ~0.8pt worse FPR. Never silently replace it. (`SOURCE_OF_TRUTH.md` §3.)
5. **Training is currently non-deterministic** — three seeded runs gave 806,620 /
   846,454 / 864,614 nodes. Until fixed, no before/after model comparison is valid.
   (`handoff.md` §3 A.)
6. **Reputation may soften, never alarm.** Only the allowlist is hard authority.
   The platform adapter can lower a score, never raise one.
7. **A verdict must never outlive its page.** Two layers: URL equality check in
   the popup, plus `tabs.onUpdated` eviction.
8. **Browser URL shape ≠ corpus URL shape.** Chrome sends `https://d/`; the
   corpus holds `https://d`. That trailing slash was worth +26 points of FPR.
9. **Measure the artifact that ships.** `validate_unknown_legit.py` currently loads
   `random_forest.pkl`, not the shipped JSON, so its FPR figures describe a different
   model. (`handoff.md` §3 B.)

## 6. The reputation layer

One seam, three adapters of deliberately different authority (vocabulary in
`CONTEXT.md`):

| Adapter | Authority | Effect |
|---|---|---|
| **A — domain allowlist** (`assets/top_domains.json`, 30k) | **Hard** | Registrable domain match → CLEAN 0.05, model skipped entirely. **Not consulted for platform tenants** (see caveat). |
| **B — suffix trust** (`tld-rates.ts`) | Feeds a feature | Drives `TLDLegitimateProb` inside the extractor. Peer adapter so trust knowledge has one home. |
| **C — hosting platforms** (`PLATFORM_HOSTS`, 19 suffixes) | **Advisory** | Neutralises `TLDLegitimateProb` to the corpus prior. Other 20 features untouched. |

Three rules protect adapter C from clearing real phish:

- **Hard-red immunity** — the model scores the **raw** vector first; only a raw
  score `< 0.90` may be re-scored with the corrected vector.
- **Brand-impersonation immunity** — the correction is withheld entirely when
  `brandTokenInSubdomain` fires, at any score.
- **Tenant isolation** — adapter A is skipped when the host is a *tenant* under a
  platform (`host !== platform && host.endsWith("." + platform)`). A tenant is not
  its platform.

The bare-brand-label exemption (`microsoft.github.io` is Microsoft's own page) applies
only on `IDENTITY_BOUND_PLATFORMS` — `github.io`, `gitlab.io` — where holding the label
required holding the identity. On a deploy-anywhere platform the same name is a
first-come-first-served project name, so `paypal.vercel.app` stays guarded.

**Known limit, by design:** the guard only *withholds* the discount; it never adds
risk. A clone the model scores below 0.50 on raw features still reads CLEAN. See
`CONTEXT.md`, "Withholding is not accusing".

> **Structural caveat that shapes all of adapter C.** `psl-trie.ts` is
> **ICANN-only** — it contains no private suffixes (`vercel.app`, `netlify.app`,
> `github.io` are all absent). So for `foo.vercel.app`, `parseHost` returns
> `subdomain="foo"`, `domain="vercel"`, `suffix="app"`, and the registrable domain
> is **`vercel.app`** — the platform itself, not the tenant. Two consequences:
>
> 1. The brand guard works *because* the tenant name lands in `subdomain`.
> 2. Adapter A would otherwise be consulted with the **platform's** domain. Several
>    platforms are popular enough to sit in the top-30k list (`railway.app`,
>    `neocities.org`), which cleared every tenant under them to CLEAN 0.05 before the
>    model or the guard ran. Fixed Aug 15, 2026 by the tenant-isolation rule above.
>
> Residual gap: user-content hosts that are in the allowlist but *not* on
> `PLATFORM_HOSTS` still hard-clear their tenants — `sharepoint.com`, `typeform.com`,
> `jotform.com`, `wix.com`, `windows.net`, `firebaseio.com`, `forms.gle`. Extending the
> list is a data decision (a legit `contoso.sharepoint.com` must not become a false
> positive), tracked in `handoff.md` §3 E.
>
> Adding private suffixes to the PSL trie would silently invert both behaviours.
> It is a parity-affecting change (the Python side uses the same rule set) and must
> be treated as a model-level decision, not a dependency bump.

## 7. Boundaries

- **Network egress:** exactly one path — the optional GSB fallback, user key only,
  borderline scores only. Everything else is on-device.
- **Trust boundary:** `sender.id !== chrome.runtime.id` rejects messages from web
  pages. Without it the extension is a scoring oracle for tuning evasive URLs.
- **Generated files — never hand-edit:** `ml/psl-trie.ts`, `ml/tld-rates.ts`,
  `assets/phishing_model.json`, `assets/shap_mapping.json`.
- **Build:** `pnpm build` (Plasmo) then `postbuild` copies runtime assets into
  `build/chrome-mv3-prod/assets/`. The copy step is what puts the model on disk;
  without it the extension loads with no model.
