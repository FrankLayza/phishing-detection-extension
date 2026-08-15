/**
 * Brand-typosquatting vocabulary — ONE source of truth for the TS side.
 *
 * Both the feature extractor (URLSimilarityIndex) and the reputation module
 * (brand-impersonation guard) read BRANDS and the typo machinery from here, so
 * a second copy cannot drift into a different list. The Python pipeline keeps
 * its own copy in ml-pipeline/features/lexical_extractor.py; the parity gate
 * (check_parity.py) compares the FEATURE VALUES the real bundled extractor
 * emits against Python, so any divergence in this module is caught there.
 */

/** Brand list for typosquatting detection — matches Python BRANDS list */
export const BRANDS: readonly string[] = [
  "google", "microsoft", "apple", "amazon", "facebook",
  "paypal", "netflix", "bankofamerica", "chase", "wellsfargo",
];

/** Similarity above this counts as deliberate typosquatting. Matches Python. */
export const TYPO_THRESHOLD = 0.6;

/** Visually confusable substitutions used by real typosquatters. Matches Python HOMOGLYPHS. */
const HOMOGLYPHS: Record<string, string> = {
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s",
  "7": "t", "8": "b", "9": "g", $: "s", "@": "a", "|": "l",
};

/** Normalise homoglyph substitutions back to their letter form. Matches Python _deleet. */
function deleet(s: string): string {
  let out = "";
  for (const c of s) out += HOMOGLYPHS[c] ?? c;
  return out;
}

/**
 * Levenshtein distance — exact port of Python levenshtein(a, b).
 * Standard DP implementation.
 */
export function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () =>
    new Array(n + 1).fill(0)
  );
  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      dp[i][j] = Math.min(
        dp[i - 1][j] + 1,
        dp[i][j - 1] + 1,
        dp[i - 1][j - 1] + cost
      );
    }
  }
  return dp[m][n];
}

/** candidate is brand with one character doubled: appple <- apple. Matches Python. */
function isDoublingOf(candidate: string, brand: string): boolean {
  if (candidate.length !== brand.length + 1) return false;
  for (let i = 0; i < candidate.length; i++) {
    if (candidate.slice(0, i) + candidate.slice(i + 1) !== brand) continue;
    const c = candidate[i];
    if ((i > 0 && candidate[i - 1] === c) || (i + 1 < candidate.length && candidate[i + 1] === c)) {
      return true;
    }
  }
  return false;
}

/** candidate is brand with two adjacent chars swapped: payapl <- paypal. Matches Python. */
function isTranspositionOf(candidate: string, brand: string): boolean {
  if (candidate.length !== brand.length) return false;
  const diff: number[] = [];
  for (let i = 0; i < brand.length; i++) if (candidate[i] !== brand[i]) diff.push(i);
  if (diff.length !== 2 || diff[1] - diff[0] !== 1) return false;
  const [i, j] = diff;
  return candidate[i] === brand[j] && candidate[j] === brand[i];
}

/**
 * Levenshtein similarity to `brand`, but only when the difference looks like
 * deliberate typosquatting. Raw edit distance cannot make this call: '/apply'
 * vs 'apple' scores 0.80 while the real typosquat '/g00gle' vs 'google' scores
 * only 0.67. What separates them is WHICH characters differ. Matches Python
 * _typo_similarity.
 */
export function typoSimilarity(candidate: string, brand: string): number {
  if (!candidate || candidate === brand) return 0.0;
  const normalised = deleet(candidate);
  const gated =
    normalised === brand ||
    isDoublingOf(normalised, brand) ||
    isTranspositionOf(normalised, brand);
  if (!gated) return 0.0;
  const dist = levenshtein(candidate, brand);
  return 1 - dist / Math.max(candidate.length, brand.length);
}

/**
 * Whether a subdomain carries a brand token — the reputation-side check.
 *
 * Phishing deployed on hosting platforms hides the brand in the subdomain
 * ('microsoft-verify-login.netlify.app', 'paypa1-login.vercel.app'). The SLD
 * is the platform, so the model's domain similarity sees only 'netlify' and
 * scores 0. This scans the subdomain labels instead.
 *
 * `allowBareBrandLabel` exempts a subdomain that IS exactly one brand label
 * ('microsoft.github.io'). Pass it ONLY for platforms whose subdomain namespace
 * is identity-bound — `<name>.github.io` requires owning the `name` org, so the
 * bare label really is the brand's own project page. On a deploy-anywhere
 * platform the same name is first-come-first-served, so 'paypal.vercel.app' is
 * claimable by anyone and must NOT be exempt. The caller owns that distinction
 * (see IDENTITY_BOUND_PLATFORMS in reputation.ts); this module only knows brands.
 */
export function brandTokenInSubdomain(
  subdomain: string,
  allowBareBrandLabel = false
): string | null {
  if (!subdomain) return null;
  const labels = subdomain.split(".").filter((s) => s);
  const singleLabel = labels.length === 1;
  for (const label of labels) {
    const tokens = label.split("-");
    // <brand>.github.io — the org's own project page. Skip ONLY the whole-label
    // exact case, and only on an identity-bound platform. A brand token beside
    // other tokens is impersonation regardless.
    if (allowBareBrandLabel && singleLabel && tokens.length === 1 && BRANDS.includes(tokens[0])) {
      continue;
    }
    for (const token of tokens) {
      for (const brand of BRANDS) {
        if (token === brand) return brand;
        // >=, not >: TYPO_THRESHOLD is inclusive everywhere else (Python uses
        // `< THRESHOLD -> 0`). With `>` a single transposition of a 5-letter
        // brand landed on exactly 0.6 and slipped the guard ('paple' <- 'apple').
        if (typoSimilarity(token, brand) >= TYPO_THRESHOLD) return brand;
      }
    }
  }
  return null;
}