/**
 * PhishGuard Browser-Side Feature Extractor
 * ==========================================
 * Extracts all 44 features matching the Python pipeline exactly.
 * Canonical feature index order from PRD Section 3.2.
 *
 * Group A: Lexical Features  (indices 0–20)  — from URL string only
 * Group B: Domain Features   (indices 21–30) — from DOM/HTML
 * Group C: Content Features  (indices 31–43) — from DOM/HTML
 *
 * Python references:
 *   ml-pipeline/features/lexical_extractor.py
 *   ml-pipeline/features/content_extractor.py
 */
import type { FeatureVector } from "../types";

// ---------------------------------------------------------------------------
// Constants — must match Python lexical_extractor.py exactly
// ---------------------------------------------------------------------------

/** Brand list for typosquatting detection — matches Python BRANDS list */
const BRANDS = [
  "google", "microsoft", "apple", "amazon", "facebook",
  "paypal", "netflix", "bankofamerica", "chase", "wellsfargo",
];

/** TLD trustworthiness scores — matches Python TLD_SCORES dict */
const TLD_SCORES: Record<string, number> = {
  com: 0.95, org: 0.90, net: 0.85,
  edu: 0.98, gov: 0.99, "co.uk": 0.90,
  de: 0.92, fr: 0.91, jp: 0.93,
  tk: 0.10, ml: 0.15, ga: 0.15,
  cf: 0.15, gq: 0.15,
};

/** Expected character frequencies — matches Python char_probability() */
const EXPECTED_CHAR_FREQ: Record<string, number> = {
  a: 0.08, e: 0.07, i: 0.06, o: 0.06, r: 0.05,
  t: 0.05, n: 0.05, s: 0.05, l: 0.04, c: 0.04,
  "/": 0.10, ".": 0.08, "-": 0.03, "_": 0.01,
};

/** Special character set — matches Python: '!@#$%^*()[]{}|;:<>' */
const SPECIAL_CHARS = new Set("!@#$%^*()[]{}|;:<>".split(""));

/** Social network domains — matches Python content_extractor.py */
const SOCIAL_PATTERNS = [
  "facebook.com", "twitter.com", "linkedin.com",
  "instagram.com", "youtube.com",
];

// ---------------------------------------------------------------------------
// Helper functions — ported 1:1 from Python lexical_extractor.py
// ---------------------------------------------------------------------------

/**
 * Levenshtein distance — exact port of Python levenshtein(a, b).
 * Standard DP implementation.
 */
function levenshtein(a: string, b: string): number {
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

  // --- Path portion: exact match here IS suspicious ---
  let pathMaxSim = 0.0;
  try {
    const path = new URL(url).pathname;
    const segments = path.split("/").filter((s) => s.length >= 4).map((s) => s.toLowerCase());
    for (const segment of segments) {
      for (const brand of BRANDS) {
        if (segment === brand) return 1.0; // definite brand abuse
        const dist = levenshtein(segment, brand);
        const sim = 1 - dist / Math.max(segment.length, brand.length);
        if (sim > pathMaxSim) pathMaxSim = sim;
      }
    }
  } catch {
    // URL parse failure — ignore path portion
  }

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
    const prevAlpha = /[a-zA-Z]/.test(url[i - 1]);
    const currAlpha = /[a-zA-Z]/.test(url[i]);
    const prevDigit = /[0-9]/.test(url[i - 1]);
    const currDigit = /[0-9]/.test(url[i]);
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
 * Extract TLD from hostname.
 * Handles compound TLDs like "co.uk" by checking against TLD_SCORES keys.
 * Falls back to last dot-separated part.
 */
function extractTld(hostname: string): string {
  const parts = hostname.split(".");
  if (parts.length >= 2) {
    // Check compound TLD first (e.g., "co.uk")
    const compound = parts.slice(-2).join(".");
    if (compound in TLD_SCORES) return compound;
  }
  return parts[parts.length - 1] || "";
}

/**
 * Extract the second-level domain (SLD) from a hostname.
 * e.g. "mail.google.com" → "google", "bbc.co.uk" → "bbc"
 */
function extractSld(hostname: string): string {
  const parts = hostname.split(".");
  if (parts.length >= 2) {
    const compound = parts.slice(-2).join(".");
    if (compound in TLD_SCORES) {
      // SLD is the part before the compound TLD
      return parts.length >= 3 ? parts[parts.length - 3] : parts[0];
    }
  }
  // Standard: SLD is second-to-last
  return parts.length >= 2 ? parts[parts.length - 2] : parts[0];
}

/**
 * Extract domain (SLD + TLD) from hostname, matching Python's
 * `f"{extracted.domain}.{extracted.suffix}"` from tldextract.
 */
function extractDomain(hostname: string): string {
  const tld = extractTld(hostname);
  const sld = extractSld(hostname);
  return tld ? `${sld}.${tld}` : sld;
}

/**
 * Count subdomain parts, matching Python's
 * `extracted.subdomain.split('.') if extracted.subdomain else []`
 */
function countSubdomains(hostname: string): number {
  const tld = extractTld(hostname);
  const parts = hostname.split(".");
  // For compound TLD like co.uk: domain.co.uk → 0 subdomains
  // sub.domain.co.uk → 1 subdomain
  const tldParts = tld.split(".").length;
  const sldAndTldParts = 1 + tldParts; // SLD + TLD parts
  const subParts = parts.length - sldAndTldParts;
  return Math.max(0, subParts);
}

// ---------------------------------------------------------------------------
// Main extractor — produces all 44 features in canonical index order
// ---------------------------------------------------------------------------

export function extractPageFeatures(url: string, html: string): FeatureVector {
  // -------------------------------------------------------------------------
  // URL NORMALISATION — matches Python lexical_extractor.py lines 18-23
  // -------------------------------------------------------------------------
  url = url.trim().toLowerCase();
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "http://" + url;
  }
  // Strip 'www.' to prevent dataset bias — matches Python exactly
  url = url.replace("://www.", "://");

  // Parse URL components
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    // Fallback for malformed URLs
    parsed = new URL("http://invalid.local");
  }

  const hostname = parsed.hostname;
  const domain = extractDomain(hostname);
  const domainSld = extractSld(hostname);
  const tld = extractTld(hostname);

  // =========================================================================
  // GROUP A: LEXICAL FEATURES (indices 0–20)
  // =========================================================================

  // [0] URLLength — len(url)
  const URLLength = url.length;

  // [1] DomainLength — len(domain) where domain = SLD.TLD
  const DomainLength = domain.length;

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
  const TLDLegitimateProb = TLD_SCORES[tld.toLowerCase()] ?? 0.50;

  // [6] URLCharProb — expected character frequency score
  const URLCharProb = charProbability(url);

  // [7] NoOfSubDomain — subdomain component count
  const NoOfSubDomain = countSubdomains(hostname);

  // [8] HasObfuscation — any %XX encoding present
  const obfuscationCount = (url.match(/%/g) || []).length;
  const HasObfuscation = obfuscationCount > 0 ? 1 : 0;

  // [9] NoOfObfuscatedChar — count of % chars
  const NoOfObfuscatedChar = obfuscationCount;

  // [10] ObfuscationRatio — obfuscation density
  const ObfuscationRatio = url.length > 0 ? obfuscationCount / url.length : 0;

  // [11] NoOfLettersInURL — alpha character count
  const letters = (url.match(/[a-zA-Z]/g) || []).length;
  const NoOfLettersInURL = letters;

  // [12] LetterRatioInURL — alpha ratio
  const LetterRatioInURL = url.length > 0 ? letters / url.length : 0;

  // [13] NoOfDegitsInURL — digit character count
  const digits = (url.match(/[0-9]/g) || []).length;
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
  // GROUP B: DOMAIN FEATURES (indices 21–30) — from DOM
  // =========================================================================

  // Parse HTML for DOM queries
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, "text/html");

  // [21] DomainAgeBucket — HARDCODE=0 per PRD. WHOIS not available in browser.
  const DomainAgeBucket = 0;

  // [22] HasTitle — page has <title> tag with non-empty text
  const titleEl = doc.querySelector("title");
  const titleText = titleEl?.textContent?.trim() || "";
  const HasTitle = titleText ? 1 : 0;

  // [23] DomainTitleMatchScore — domain SLD appears in page title
  let DomainTitleMatchScore = 0.0;
  if (titleText && domainSld) {
    DomainTitleMatchScore = titleText.toLowerCase().includes(domainSld)
      ? 1.0
      : 0.0;
  }

  // [24] URLTitleMatchScore — ratio of URL path segments found in title
  let URLTitleMatchScore = 0.0;
  const pathParts = parsed.pathname
    .split("/")
    .filter((p) => p.length > 3)
    .map((p) => p.toLowerCase());
  if (titleText && pathParts.length > 0) {
    const titleLower = titleText.toLowerCase();
    const matches = pathParts.filter((p) => titleLower.includes(p)).length;
    URLTitleMatchScore = matches / pathParts.length;
  }

  // [25] HasFavicon — <link rel="...icon..."> present
  const HasFavicon = doc.querySelector('link[rel*="icon"]') ? 1 : 0;

  // [26] Robots — <meta name="robots"> present (case-insensitive)
  const Robots = doc.querySelector('meta[name="robots" i]')
    ? 1
    : doc.querySelector("meta[name]") &&
        Array.from(doc.querySelectorAll("meta[name]")).some(
          (m) => (m as HTMLMetaElement).name.toLowerCase() === "robots"
        )
      ? 1
      : 0;

  // [27] IsResponsive — <meta name="viewport"> present (case-insensitive)
  const IsResponsive = doc.querySelector('meta[name="viewport" i]')
    ? 1
    : doc.querySelector("meta[name]") &&
        Array.from(doc.querySelectorAll("meta[name]")).some(
          (m) => (m as HTMLMetaElement).name.toLowerCase() === "viewport"
        )
      ? 1
      : 0;

  // [28] NoOfURLRedirect — not available in content script. Default 0.
  const NoOfURLRedirect = 0;

  // [29] NoOfSelfRedirect — not available in content script. Default 0.
  const NoOfSelfRedirect = 0;

  // [30] HasDescription — <meta name="description"> present (case-insensitive)
  let HasDescription = 0;
  const metaTags = Array.from(doc.querySelectorAll("meta[name]"));
  for (let i = 0; i < metaTags.length; i++) {
    const m = metaTags[i] as HTMLMetaElement;
    if (m.name.toLowerCase() === "description") {
      const content = m.content?.trim();
      HasDescription = content ? 1 : 0;
      break;
    }
  }

  // =========================================================================
  // GROUP C: CONTENT FEATURES (indices 31–43) — from HTML content
  // =========================================================================

  const lines = html.split("\n");

  // [31] LineOfCode — number of HTML lines
  const LineOfCode = lines.length;

  // [32] LargestLineLength — max line length
  const LargestLineLength =
    lines.length > 0 ? Math.max(...lines.map((l) => l.length)) : 0;

  // [33] NoOfPopup — count of window.open() calls in <script> tags
  let NoOfPopup = 0;
  const scripts = doc.querySelectorAll("script");
  scripts.forEach((s) => {
    const content = s.textContent || "";
    if (content.includes("window.open")) NoOfPopup++;
  });

  // [34] NoOfiFrame — count of <iframe> elements
  const NoOfiFrame = doc.querySelectorAll("iframe").length;

  // [35] HasExternalFormSubmit — form action points to external domain
  let HasExternalFormSubmit = 0;
  const forms = Array.from(doc.querySelectorAll("form"));
  for (let i = 0; i < forms.length; i++) {
    const action = forms[i].getAttribute("action") || "";
    if (action.startsWith("http") && !action.startsWith(url)) {
      // More precise: check if the action domain differs from current domain
      try {
        const actionHost = new URL(action).hostname;
        if (actionHost !== hostname) {
          HasExternalFormSubmit = 1;
          break;
        }
      } catch {
        // If action URL is malformed but starts with http, flag it
        HasExternalFormSubmit = 1;
        break;
      }
    }
  }

  // [36] HasSocialNet — links to major social networks
  let HasSocialNet = 0;
  const links = Array.from(doc.querySelectorAll("a[href]"));
  for (let i = 0; i < links.length; i++) {
    const href = links[i].getAttribute("href") || "";
    if (SOCIAL_PATTERNS.some((s) => href.includes(s))) {
      HasSocialNet = 1;
      break;
    }
  }

  // [37] HasSubmitButton — <input type="submit"> or <button type="submit">
  const HasSubmitButton =
    doc.querySelector('input[type="submit"]') ||
    doc.querySelector('button[type="submit"]')
      ? 1
      : 0;

  // [38] HasHiddenFields — <input type="hidden">
  const HasHiddenFields = doc.querySelector('input[type="hidden"]') ? 1 : 0;

  // [39] HasPasswordField — <input type="password">
  const HasPasswordField = doc.querySelector('input[type="password"]') ? 1 : 0;

  // Get all visible text for keyword matching — matches Python soup.get_text().lower()
  const bodyText = (doc.body?.innerText || doc.body?.textContent || "").toLowerCase();

  // [40] Bank — text contains banking keywords
  // Python: ['bank', 'banking', 'account number']
  const Bank =
    bodyText.includes("bank") ||
    bodyText.includes("banking") ||
    bodyText.includes("account number")
      ? 1
      : 0;

  // [41] Pay — text contains payment keywords
  // Python: ['payment', 'paypal', 'checkout', 'credit card']
  const Pay =
    bodyText.includes("payment") ||
    bodyText.includes("paypal") ||
    bodyText.includes("checkout") ||
    bodyText.includes("credit card")
      ? 1
      : 0;

  // [42] Crypto — text contains crypto keywords
  // Python: ['bitcoin', 'crypto', 'wallet', 'blockchain']
  const Crypto =
    bodyText.includes("bitcoin") ||
    bodyText.includes("crypto") ||
    bodyText.includes("wallet") ||
    bodyText.includes("blockchain")
      ? 1
      : 0;

  // [43] HasCopyrightInfo — text contains 'copyright' or '©'
  // Python: 'copyright' in text or '\u00a9' in text
  const HasCopyrightInfo =
    bodyText.includes("copyright") || bodyText.includes("\u00a9") ? 1 : 0;

  // =========================================================================
  // Return in canonical index order (indices 0–43)
  // =========================================================================
  return {
    // Group A: Lexical (0–20)
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
    // Group B: Domain (21–30)
    DomainAgeBucket,              // 21
    HasTitle,                     // 22
    DomainTitleMatchScore,        // 23
    URLTitleMatchScore,           // 24
    HasFavicon,                   // 25
    Robots,                       // 26
    IsResponsive,                 // 27
    NoOfURLRedirect,              // 28
    NoOfSelfRedirect,             // 29
    HasDescription,               // 30
    // Group C: Content (31–43)
    LineOfCode,                   // 31
    LargestLineLength,            // 32
    NoOfPopup,                    // 33
    NoOfiFrame,                   // 34
    HasExternalFormSubmit,         // 35
    HasSocialNet,                 // 36
    HasSubmitButton,              // 37
    HasHiddenFields,              // 38
    HasPasswordField,             // 39
    Bank,                         // 40
    Pay,                          // 41
    Crypto,                       // 42
    HasCopyrightInfo,             // 43
  };
}
