/**
 * Reputation module — one interface for every "how trusted is this URL?" question.
 * =================================================================================
 * Deep module: a small interface (`evaluate(url, rawFeatures)`) over three adapters:
 *
 *   A. Domain allowlist (assets/top_domains.json)   - HARD authority
 *      A known-popular registrable domain (google.com). Short-circuits the whole
 *      model to CLEAN. This is the real site; URL-only signals cannot add value.
 *
 *   B. Suffix trust (tld-rates.ts)                  - feeds a feature
 *      Drives TLDLegitimateProb inside feature-extractor.ts (not owned here).
 *      Kept as a peer adapter so reputation knowledge has ONE seam to query.
 *
 *   C. Hosting platforms (PLATFORM_HOSTS, new)      - ADVISORY authority
 *      e.g. *.vercel.app, *.github.io, *.netlify.app. Anyone can deploy here, so
 *      platform membership by itself carries NO class signal — legit project pages
 *      and phishing clones coexist on the same platform (29 vs 45 on vercel.app in
 *      the corpus). Advisory means it can never clear a page on its own: it only
 *      neutralises the TLD-trust feature to the corpus prior (TLDLegitimateProb is
 *      the model's #1 SHAP feature, r −0.93, and the sole driver of the *.vercel.app
 *      false positive). The remaining 20 features are untouched, so a phishing clone
 *      that carries URLSimilarityIndex / DegitRatio / path-brand weight still flags.
 *
 *      BRAND-IMPERSONATION GUARD (added Aug 14, 2026): the neutralisation is
 *      WITHHELD when the subdomain carries a brand token
 *      ('microsoft-verify-login.netlify.app'). Without the guard, the clone's only
 *      phishing signal — the low-trust .app TLD — was the very feature the platform
 *      correction removed, dropping it to CLEAN. Platform membership may soften a
 *      page on every signal BUT brand impersonation: the correction never applies
 *      where the subdomain claims to be a brand. This mirrors hard-red immunity
 *      (see CONTEXT.md) and lives in reputation.ts because brand-in-subdomain is
 *      only separable by reputation (trusted infra vs deploy-anywhere platforms),
 *      not by the model — the model cannot tell 'apple-relay.cloudflare.com' from
 *      'microsoft-verify-login.netlify.app'.
 *
 * The module returns verdict.code, the registrable domain (via the single domain
 * seam `parseHost`), a platform match, the possibly-corrected feature vector, and
 * the explanation signal(s) for the popup.
 */
import type { FeatureVector, ShapExplanation } from "../types";
import { parseHost, rawHost } from "./tldextract";
import { TLD_LEGIT_PRIOR } from "./tld-rates";
import { brandTokenInSubdomain } from "./brands";

/** Platform suffix list — where a third party can deploy a user-facing site. */
export const PLATFORM_HOSTS: readonly string[] = [
  "vercel.app",
  "netlify.app",
  "github.io",
  "gitlab.io",
  "pages.dev",
  "firebaseapp.com",
  "web.app",
  "surge.sh",
  "glitch.me",
  "repl.co",
  "onrender.com",
  "herokuapp.com",
  "azurewebsites.net",
  "azurestaticapps.net",
  "neocities.org",
  "static.app",
  "fly.dev",
  "railway.app",
];

export type ReputationKind = "allowlisted" | "platform" | "unknown";

export interface ReputationVerdict {
  /** Which adapter decided, if any. */
  kind: ReputationKind;
  /** eTLD+1 registrable domain (the type the allowlist stores). */
  registrableDomain: string;
  /** Platform suffix that matched, when kind === "platform". */
  platform?: string;
  /** Feature vector to pass to inference — TLDLegitimateProb neutralised for platform hosts. */
  features: FeatureVector;
  /**
   * Brand token found in the subdomain of a platform host, when the advisory
   * neutralisation was withheld (kind === "platform"). Undefined otherwise.
   */
  impersonation?: string;
  /** Explanation signal(s) for the popup. Empty unless a reputation adapter decided. */
  signals: ShapExplanation[];
}

export class Reputation {
  private allowlist: Set<string> | null = null;

  constructor(allowlist?: Set<string>) {
    if (allowlist) this.allowlist = allowlist;
  }

  /** Load the domain allowlist. No-op if already loaded or injected via constructor. */
  async init(): Promise<void> {
    if (this.allowlist) return;
    try {
      const resp = await fetch(chrome.runtime.getURL("assets/top_domains.json"));
      this.allowlist = new Set<string>(await resp.json());
      console.log(
        `PhishGuard: Reputation allowlist loaded (${this.allowlist.size} domains)`
      );
    } catch (e) {
      console.error("PhishGuard: failed to load allowlist", e);
      this.allowlist = new Set();
    }
  }

  /** Evaluate one URL against every reputation adapter behind the seam. */
  async evaluate(
    url: string,
    rawFeatures: FeatureVector
  ): Promise<ReputationVerdict> {
    await this.init();

    const host = rawHost(url).toLowerCase();
    const parts = parseHost(host);
    const registrableDomain = parts.suffix
      ? `${parts.domain}.${parts.suffix}`
      : parts.domain;

    // Adapter A — hard allowlist of known-popular registrable domains.
    if (this.allowlist?.has(registrableDomain)) {
      return {
        kind: "allowlisted",
        registrableDomain,
        features: rawFeatures,
        signals: [
          {
            feature: "Reputation",
            value: 1,
            importance: 1,
            description: "Recognized as a well-known, popular website (reputation allowlist)",
            category: "Reputation",
          },
        ],
      };
    }

    // Adapter C — hosting platform. Advisory: neutralise TLD trust only.
    // Subdomains share the platform ("myapp.vercel.app"), the bare suffix is the
    // console/root ("github.io" is itself a landable page).
    const platform = PLATFORM_HOSTS.find(
      (p) => host === p || host.endsWith("." + p)
    );
    if (platform) {
      // Brand-impersonation guard: if the subdomain claims to be a brand, the
      // advisory correction is withheld. The TLD neutralisation removes the
      // model's #1 phishing signal (low-trust TLD) — exactly the reason a clone
      // like 'microsoft-verify-login.netlify.app' would otherwise drop to CLEAN.
      // A platform correction may soften a page on every signal BUT brand
      // impersonation. Mirrors hard-red immunity (CONTEXT.md). The subdomain IS
      // the whole label (microsoft.github.io — the org's own project page) is
      // legitimate and passes through the normal correction.
      const impersonation = brandTokenInSubdomain(parts.subdomain || "");
      if (impersonation) {
        return {
          kind: "platform",
          registrableDomain,
          platform,
          impersonation,
          features: rawFeatures,
          signals: [
            {
              feature: "BrandImpersonation",
              value: 1,
              importance: 1,
              description: `Subdomain impersonates "${impersonation}" on ${platform} — TLD-trust correction withheld; the page keeps its full risk score`,
              category: "Reputation",
            },
          ],
        };
      }
      const corrected = { ...rawFeatures, TLDLegitimateProb: TLD_LEGIT_PRIOR };
      return {
        kind: "platform",
        registrableDomain,
        platform,
        features: corrected,
        signals: [
          {
            feature: "PlatformHosting",
            value: 1,
            importance: 0.9,
            description: `Hosted on ${platform} — a platform where anyone can deploy. TLD trust treated as neutral; other signals still checked.`,
            category: "Reputation",
          },
        ],
      };
    }

    // Neither adapter claimed the URL — the model decides on the raw features.
    return {
      kind: "unknown",
      registrableDomain,
      features: rawFeatures,
      signals: [],
    };
  }
}

/** Shared instance for the extension runtime. */
export const reputation = new Reputation();