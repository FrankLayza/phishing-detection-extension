# PhishGuard — Domain Glossary

Domain language for the PhishGuard project. Terms added/updated as decisions
crystallize during design work; see `SOURCE_OF_TRUTH.md` for the measured model.

## Core domain

- **Verdict** — the three-tier classification a page receives: CLEAN /
  SUSPICIOUS / PHISHING (popup bands, `verdictFor`). Derived from a risk score.
- **Risk score** — 0–1 phishing probability from the on-device Random Forest,
  after reputation corrections are applied.
- **On-device** — all detection runs locally in the browser; no URL ever leaves
  the device except the optional Google Safe Browsing fallback for borderline
  cases (and that only when the user supplies an API key).

## Reputation (added Aug 12, 2026 — Reputation module)

- **Reputation module** — one seam (`reputation.evaluate(url, features)`) behind
  which every "how trusted is this URL?" fact lives. Three adapters:
  domain allowlist (hard), suffix trust (feeds a feature), hosting platforms
  (advisory).
- **Hard authority** — a reputation input that can alone decide a verdict. Only
  the domain allowlist is hard: a known-popular registrable domain (google.com)
  short-circuits to CLEAN before the model runs.
- **Tenant** (added Aug 15, 2026) — a site deployed under someone else's hosting
  platform (`my-portfolio.vercel.app`). A tenant is **not** its platform: the
  allowlist is not consulted for tenants, because the PSL trie is ICANN-only and
  therefore resolves `evil.railway.app` to the registrable domain `railway.app` —
  the platform, which is itself popular enough to sit in the top-30k list.
  Consulting it there cleared every tenant of a popular platform to CLEAN 0.05
  before the model or the brand guard ran. Renting space in a well-known building
  does not make you the landlord (`reputation.ts`, `isTenant`).
- **Identity-bound platform** (added Aug 15, 2026) — a platform whose subdomain
  namespace is tied to an account that had to be claimed, so `<brand>.<platform>`
  really is the brand's own page. `microsoft.github.io` belongs to the Microsoft
  org and nobody else can hold it. Only these platforms grant the bare-brand-label
  exemption below; on a deploy-anywhere platform the same name is a
  first-come-first-served project name. Currently `github.io` and `gitlab.io`
  (`IDENTITY_BOUND_PLATFORMS` in `reputation.ts`).
- **Advisory authority** — an input that can *never* clear a page on its own;
  it only removes a false reason to flag. The hosting-platform adapter is
  advisory: it neutralises `TLDLegitimateProb` to the corpus prior for
  platform-hosted URLs and leaves the other 20 features untouched.
- **Hard-red immunity** — a platform correction never downgrades a hard
  verdict. In the ANCILLARY pipeline the model is first scored on the **raw**
  features; only a raw score below the PHISHING cut (0.90) may be re-scored
  with the neutralised vector. A page at or above 0.90 raw stays PHISHING —
  platform membership can soften a borderline, never a red alarm
  (`phishing-extension/src/background/index.ts`).
- **Hosting platform** — a service where any third party can deploy a
  user-facing site (`*.vercel.app`, `*.github.io`, `*.netlify.app`, …).
  Dual-use by construction: phishing clones and legit project pages coexist on
  the same platform, so platform membership carries no class signal by itself.
- **Brand-impersonation immunity** (added Aug 14, 2026) — the platform
  correction never applies where the subdomain claims to be a brand. In the
  ANCILLARY pipeline the model is first scored on the **raw** features; a
  platform-hosted URL whose subdomain carries a brand token (`microsoft-verify-login.netlify.app`,
  `secure-paypal-verify.vercel.app`) is NOT re-scored with the neutralised
  vector, regardless of raw score. Without this guard the clone's only
  phishing signal — the low-trust `.app` TLD — was the very feature the
  correction removed, dropping it to CLEAN. Guarded in `reputation.ts`
  (adapter C) via `brandTokenInSubdomain`; the verdict keeps a
  `BrandImpersonation` signal. A subdomain that IS exactly one brand label
  (`microsoft.github.io` — the org's own project page) is legitimate and gets
  the normal correction — but **only on an identity-bound platform**. That
  exemption was originally granted on every platform, which handed it to anyone
  who claimed a brand as a project name (`paypal.vercel.app` scored CLEAN 0.232);
  narrowed Aug 15, 2026.
- **Withholding is not accusing** (added Aug 15, 2026) — the brand guard only
  removes the platform discount; it never adds risk. A clone the model scores
  below 0.50 on its own raw features therefore still reads CLEAN
  (`paypal-verify-login.neocities.org` = 0.124, where `.org` carries high suffix
  trust). This follows from advisory authority and is a deliberate limit, not a
  bug: making impersonation *positive* evidence would introduce a third authority
  type and would flag legitimate brand-adjacent projects on free hosts.
- **Why the guard lives in reputation, not the extractor** — a brand token
  inside a subdomain label is only separable by reputation. The model cannot
  tell `apple-relay.cloudflare.com` (legit CDN, allowlisted) from
  `microsoft-verify-login.netlify.app` (phish clone) — both carry brand tokens
  in compound subdomains, and an experiment that taught the extractor to score
  them collapsed `URLSimilarityIndex` to 0.0037 importance with FPR 6.54%
  (was 5.87%). Trusted infra vs deploy-anywhere platforms is exactly the
  distinction the Reputation module exists to make.
- **Legitimate project page** — a real site hosted as a subdomain of a hosting
  platform (e.g. `my-portfolio.vercel.app`), currently the largest source of
  false positives (`.app` trust 0.095 alone pushes it into SUSPICIOUS).

## Domain parsing

- **Registrable domain (eTLD+1)** — the effective top-level domain plus the
  second-level label a registrar controls (`google.com`, `bbc.co.uk`). The type
  the domain allowlist stores; resolved through the single domain seam `parseHost`
  in `src/ml/tldextract.ts`.