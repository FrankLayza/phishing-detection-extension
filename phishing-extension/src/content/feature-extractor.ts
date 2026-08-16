/**
 * PhishGuard Browser-Side Feature Extractor
 * ==========================================
 * Extracts the 21 lexical URL features used by the Python pipeline and the
 * shipped Random Forest. The feature names and order must remain identical on
 * both sides of the train/serve boundary.
 *
 * Python references:
 *   ml-pipeline/features/lexical_extractor.py
 */
import type { FeatureVector } from "../types";
import { parseHost, rawHost, rawPath } from "../ml/tldextract";
import { TLD_LEGIT_PRIOR, TLD_LEGIT_RATES } from "../ml/tld-rates";
import { BRANDS, TYPO_THRESHOLD, levenshtein, typoSimilarity } from "../ml/brands";

// ---------------------------------------------------------------------------
// Constants — must match Python lexical_extractor.py exactly
// ---------------------------------------------------------------------------

/**
 * TLD legitimacy rates — the SAME generated numbers Python reads from
 * ml-pipeline/features/tld_rates.json (both emitted by gen_tld_rates.py).
 * Unknown suffixes fall back to the measured corpus prior rather than a flat
 * 0.50, which used to penalise legitimate country suffixes (.ng, .com.au) and
 * flatter hostile ones (.app, .xyz, .top).
 */

/** Expected character frequencies — matches Python char_probability() */
const EXPECTED_CHAR_FREQ: Record<string, number> = {
  a: 0.08, e: 0.07, i: 0.06, o: 0.06, r: 0.05,
  t: 0.05, n: 0.05, s: 0.05, l: 0.04, c: 0.04,
  "/": 0.10, ".": 0.08, "-": 0.03, "_": 0.01,
};

/** Special character set — matches Python: '!@#$%^*()[]{}|;:<>' */
const SPECIAL_CHARS = new Set("!@#$%^*()[]{}|;:<>".split(""));

// ---------------------------------------------------------------------------
// Helper functions — ported 1:1 from Python lexical_extractor.py
// ---------------------------------------------------------------------------

/**
 * Legitimacy rate for a registered suffix, walking the suffix hierarchy:
 * exact match, then successively shorter parents, then the corpus prior.
 * A suffix never seen in training ("sch.ng") inherits "ng" rather than a
 * global default. Exact port of tld_legitimate_rate() in lexical_extractor.py.
 */
function tldLegitimateRate(suffix: string): number {
  let s = (suffix || "").toLowerCase();
  while (s) {
    const hit = TLD_LEGIT_RATES[s];
    if (hit !== undefined) return hit;
    const dot = s.indexOf(".");
    if (dot === -1) break;
    s = s.slice(dot + 1);
  }
  return TLD_LEGIT_PRIOR;
}


/**
 * Brand similarity / typosquatting score.
 * Exact port of Python compute_brand_similarity(domain, url).
 *
 * Returns 0.0–1.0:
 *   0.0 = domain IS the real brand (e.g. google.com)
 *   0.5–0.9 = domain looks similar (typosquatting)
 *   1.0 = a URL path segment exactly matches a brand name
 */
function computeBrandSimilarity(domainSld: string, url: string): number {
  // --- Domain portion: skip exact matches (it IS the real brand) ---
  // Only HIGH similarity counts as typosquatting (e.g. paypa1~paypal, g00gle~google).
  // Coincidental moderate distance (github~google ≈ 0.33) is NOT typosquatting and
  // must score 0, or legitimate non-brand domains get flagged. Matches Python.
  // TYPO_THRESHOLD is imported from ../ml/brands — do not redeclare it here; a
  // local copy silently shadowed the shared constant and defeated the whole point
  // of that module.
  let domainMaxSim = 0.0;
  for (const brand of BRANDS) {
    if (domainSld === brand) {
      domainMaxSim = 0.0;
      break;
    }
    const dist = levenshtein(domainSld, brand);
    const sim = 1 - dist / Math.max(domainSld.length, brand.length);
    if (sim > domainMaxSim) domainMaxSim = sim;
  }
  if (domainMaxSim < TYPO_THRESHOLD) domainMaxSim = 0.0;

  // --- Path portion: exact match here IS suspicious ---
  // Near-matches are gated by typoSimilarity so ordinary English segments
  // ('/apply', '/apps', '/amazing') score 0 while real path-based squats
  // ('/paypa1', '/micros0ft') still score high. Matches Python.
  let pathMaxSim = 0.0;
  // Raw path (no WHATWG percent-encoding) to match Python's urlparse().path.
  const path = rawPath(url);
  const segments = path.split("/").filter((s) => s.length >= 4).map((s) => s.toLowerCase());
  for (const segment of segments) {
    for (const brand of BRANDS) {
      if (segment === brand) return 1.0; // definite brand abuse
      const sim = typoSimilarity(segment, brand);
      if (sim > pathMaxSim) pathMaxSim = sim;
    }
  }
  if (pathMaxSim < TYPO_THRESHOLD) pathMaxSim = 0.0;

  return Math.max(domainMaxSim, pathMaxSim);
}

/**
 * Character continuation rate.
 * Exact port of Python continuation_rate(url).
 * Counts consecutive same-type (alpha-alpha or digit-digit) pairs.
 */
function continuationRate(url: string): number {
  if (url.length < 2) return 0.0;
  let continuations = 0;
  for (let i = 1; i < url.length; i++) {
    // Unicode-aware like Python str.isalpha()/str.isdigit().
    const prevAlpha = /\p{L}/u.test(url[i - 1]);
    const currAlpha = /\p{L}/u.test(url[i]);
    const prevDigit = /\p{Nd}/u.test(url[i - 1]);
    const currDigit = /\p{Nd}/u.test(url[i]);
    if ((prevAlpha && currAlpha) || (prevDigit && currDigit)) {
      continuations++;
    }
  }
  return continuations / (url.length - 1);
}

/**
 * Character probability score.
 * Exact port of Python char_probability(url).
 * Sums expected frequencies of each character.
 */
function charProbability(url: string): number {
  if (!url) return 0.0;
  let score = 0.0;
  for (const char of url.toLowerCase()) {
    if (char in EXPECTED_CHAR_FREQ) {
      score += EXPECTED_CHAR_FREQ[char];
    }
  }
  return url.length > 0 ? Math.min(score / url.length, 1.0) : 0.0;
}

/**
 * Domain (SLD + TLD) and subdomain decomposition is delegated to src/ml/tldextract.ts —
 * a 1:1 port of the Python `tldextract` algorithm (Public Suffix List), so the browser
 * computes the same DomainLength / NoOfSubDomain / TLDLegitimateProb / URLSimilarityIndex
 * values as training. Previously this file used a 14-entry hardcoded TLD dict, which
 * diverged on country/compound TLDs and IP hosts (~10% of URLs — see check_parity.py).
 */

// ---------------------------------------------------------------------------
// Main extractor — produces all 21 lexical features in canonical index order
// ---------------------------------------------------------------------------

export function extractPageFeatures(url: string, _html?: string): FeatureVector {
  // -------------------------------------------------------------------------
  // URL NORMALISATION — matches Python lexical_extractor.py lines 18-23
  // -------------------------------------------------------------------------
  url = url.trim().toLowerCase();
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "http://" + url;
  }
  // Strip 'www.' to prevent dataset bias — matches Python exactly
  url = url.replace("://www.", "://");

  // Strip a lone ROOT trailing slash ('https://x.com/' -> 'https://x.com').
  //
  // This is the browser-facing half of the bug: window.location.href always
  // reports a homepage slash-terminated, and in the training corpus the root
  // slash is a PHISHING-class token — measured on datasets/phiusiil.csv, 31.45%
  // of phishing rows (31,744 / 100,945, label==0) end in a bare root slash
  // against 0.00% of legitimate rows (0 / 134,850, label==1) — while
  // build_legit_urls() never emits a bare slash either. So '/' pointed at
  // phishing, and every real homepage landed on the wrong side of it.
  // (Corrected Aug 15, 2026: this comment previously had the two classes
  // swapped, which made the measurement below impossible to explain.)
  //
  // Measured on the shipped model, n=1,500 unknown-legit homepages:
  //   bare  https://d   ->  12.6% flagged (mean 0.256)
  //   slash https://d/  ->  39.0% flagged (mean 0.406)
  // google.com 0.207 -> 0.880, gtbank.com 0.199 -> 0.892; 11 of 12 major
  // homepages flipped. The same slash on phishing URLs moved recall 91.7% ->
  // 93.2%, so it carries no phishing signal to lose. A root slash is
  // semantically identical to no slash (RFC 3986 s6.2.3).
  //
  // Only the ROOT slash is stripped — '/path/' keeps its trailing slash.
  // Mirrors lexical_extractor.py exactly; the parity gate covers it.
  if (/^https?:\/\/[^/]+\/$/.test(url)) {
    url = url.slice(0, -1);
  }

  // Parse URL components
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    // Fallback for malformed URLs
    parsed = new URL("http://invalid.local");
  }

  // Hostname as Python's tldextract sees it: raw string, no percent-decoding,
  // no IDN punycode conversion (see tldextract.ts rawHost).
  const hostname = rawHost(url);
  const parsedHost = parseHost(hostname);
  // Mirrors Python lexical_extractor.py:
  //   domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix
  //            else extracted.domain
  const domain = parsedHost.suffix
    ? `${parsedHost.domain}.${parsedHost.suffix}`
    : parsedHost.domain;
  const domainSld = parsedHost.domain;
  const tld = parsedHost.suffix;

  // =========================================================================
  // GROUP A: LEXICAL FEATURES (indices 0–20)
  // =========================================================================

  // [0] URLLength — len(url)
  const URLLength = url.length;

  // [1] DomainLength — len(registrable SLD label), NOT len(SLD.TLD).
  // A compound suffix (.com.ng, .co.uk) mechanically lengthens SLD.TLD, which
  // let the model read suffix structure as risk and flagged regional sites on
  // length alone. The SLD label is identical across a site's TLD variants.
  // Mirrors lexical_extractor.py: len(extracted.domain).
  const DomainLength = domainSld ? domainSld.length : domain.length;

  // [2] IsDomainIP — regex on netloc (strip port first)
  const hostNoPort = hostname.split(":")[0];
  const IsDomainIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostNoPort)
    ? 1
    : 0;

  // [3] URLSimilarityIndex — brand typosquatting score
  const URLSimilarityIndex = computeBrandSimilarity(domainSld, url);

  // [4] CharContinuationRate — consecutive same-type char ratio
  const CharContinuationRate = continuationRate(url);

  // [5] TLDLegitimateProb — TLD trust score lookup
  const TLDLegitimateProb = tldLegitimateRate(tld);

  // [6] URLCharProb — expected character frequency score
  const URLCharProb = charProbability(url);

  // [7] NoOfSubDomain — subdomain component count
  // Mirrors Python: subdomain_parts = extracted.subdomain.split('.')
  //                  if extracted.subdomain else []
  const NoOfSubDomain = parsedHost.subdomain
    ? parsedHost.subdomain.split(".").length
    : 0;

  // [8] HasObfuscation — any %XX encoding present
  const obfuscationCount = (url.match(/%/g) || []).length;
  const HasObfuscation = obfuscationCount > 0 ? 1 : 0;

  // [9] NoOfObfuscatedChar — count of % chars
  const NoOfObfuscatedChar = obfuscationCount;

  // [10] ObfuscationRatio — obfuscation density
  const ObfuscationRatio = url.length > 0 ? obfuscationCount / url.length : 0;

  // [11] NoOfLettersInURL — alpha character count
  // Unicode-aware (\p{L}) to match Python str.isalpha() on IDN URLs.
  const letters = (url.match(/\p{L}/gu) || []).length;
  const NoOfLettersInURL = letters;

  // [12] LetterRatioInURL — alpha ratio
  const LetterRatioInURL = url.length > 0 ? letters / url.length : 0;

  // [13] NoOfDegitsInURL — digit character count
  // Unicode-aware (\p{Nd}) to match Python str.isdigit().
  const digits = (url.match(/\p{Nd}/gu) || []).length;
  const NoOfDegitsInURL = digits;

  // [14] DegitRatioInURL — digit ratio
  const DegitRatioInURL = url.length > 0 ? digits / url.length : 0;

  // [15] NoOfEqualsInURL
  const NoOfEqualsInURL = (url.match(/=/g) || []).length;

  // [16] NoOfQMarkInURL
  const NoOfQMarkInURL = (url.match(/\?/g) || []).length;

  // [17] NoOfAmpersandInURL
  const NoOfAmpersandInURL = (url.match(/&/g) || []).length;

  // [18] NoOfOtherSpecialCharsInURL — count of chars in '!@#$%^*()[]{}|;:<>'
  let specialCount = 0;
  for (const c of url) {
    if (SPECIAL_CHARS.has(c)) specialCount++;
  }
  const NoOfOtherSpecialCharsInURL = specialCount;

  // [19] SpacialCharRatioInURL — special char density
  const SpacialCharRatioInURL =
    url.length > 0 ? specialCount / url.length : 0;

  // [20] IsHTTPS
  const IsHTTPS = parsed.protocol === "https:" ? 1 : 0;

  // =========================================================================
  // Return the 21 lexical features in canonical index order (0–20).
  // =========================================================================
  return {
    URLLength,                    // 0
    DomainLength,                 // 1
    IsDomainIP,                   // 2
    URLSimilarityIndex,           // 3
    CharContinuationRate,         // 4
    TLDLegitimateProb,            // 5
    URLCharProb,                  // 6
    NoOfSubDomain,                // 7
    HasObfuscation,               // 8
    NoOfObfuscatedChar,           // 9
    ObfuscationRatio,             // 10
    NoOfLettersInURL,             // 11
    LetterRatioInURL,             // 12
    NoOfDegitsInURL,              // 13
    DegitRatioInURL,              // 14
    NoOfEqualsInURL,              // 15
    NoOfQMarkInURL,               // 16
    NoOfAmpersandInURL,           // 17
    NoOfOtherSpecialCharsInURL,   // 18
    SpacialCharRatioInURL,        // 19
    IsHTTPS,                      // 20
  };
}
