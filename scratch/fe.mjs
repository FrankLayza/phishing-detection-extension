// phishing-extension/src/content/feature-extractor.ts
var BRANDS = [
  "google",
  "microsoft",
  "apple",
  "amazon",
  "facebook",
  "paypal",
  "netflix",
  "bankofamerica",
  "chase",
  "wellsfargo"
];
var TLD_SCORES = {
  com: 0.95,
  org: 0.9,
  net: 0.85,
  edu: 0.98,
  gov: 0.99,
  "co.uk": 0.9,
  de: 0.92,
  fr: 0.91,
  jp: 0.93,
  tk: 0.1,
  ml: 0.15,
  ga: 0.15,
  cf: 0.15,
  gq: 0.15
};
var EXPECTED_CHAR_FREQ = {
  a: 0.08,
  e: 0.07,
  i: 0.06,
  o: 0.06,
  r: 0.05,
  t: 0.05,
  n: 0.05,
  s: 0.05,
  l: 0.04,
  c: 0.04,
  "/": 0.1,
  ".": 0.08,
  "-": 0.03,
  "_": 0.01
};
var SPECIAL_CHARS = new Set("!@#$%^*()[]{}|;:<>".split(""));
function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from(
    { length: m + 1 },
    () => new Array(n + 1).fill(0)
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
function computeBrandSimilarity(domainSld, url) {
  let domainMaxSim = 0;
  for (const brand of BRANDS) {
    if (domainSld === brand) {
      domainMaxSim = 0;
      break;
    }
    const dist = levenshtein(domainSld, brand);
    const sim = 1 - dist / Math.max(domainSld.length, brand.length);
    if (sim > domainMaxSim) domainMaxSim = sim;
  }
  let pathMaxSim = 0;
  try {
    const path = new URL(url).pathname;
    const segments = path.split("/").filter((s) => s.length >= 4).map((s) => s.toLowerCase());
    for (const segment of segments) {
      for (const brand of BRANDS) {
        if (segment === brand) return 1;
        const dist = levenshtein(segment, brand);
        const sim = 1 - dist / Math.max(segment.length, brand.length);
        if (sim > pathMaxSim) pathMaxSim = sim;
      }
    }
  } catch {
  }
  return Math.max(domainMaxSim, pathMaxSim);
}
function continuationRate(url) {
  if (url.length < 2) return 0;
  let continuations = 0;
  for (let i = 1; i < url.length; i++) {
    const prevAlpha = /[a-zA-Z]/.test(url[i - 1]);
    const currAlpha = /[a-zA-Z]/.test(url[i]);
    const prevDigit = /[0-9]/.test(url[i - 1]);
    const currDigit = /[0-9]/.test(url[i]);
    if (prevAlpha && currAlpha || prevDigit && currDigit) {
      continuations++;
    }
  }
  return continuations / (url.length - 1);
}
function charProbability(url) {
  if (!url) return 0;
  let score = 0;
  for (const char of url.toLowerCase()) {
    if (char in EXPECTED_CHAR_FREQ) {
      score += EXPECTED_CHAR_FREQ[char];
    }
  }
  return url.length > 0 ? Math.min(score / url.length, 1) : 0;
}
function extractTld(hostname) {
  const parts = hostname.split(".");
  if (parts.length >= 2) {
    const compound = parts.slice(-2).join(".");
    if (compound in TLD_SCORES) return compound;
  }
  return parts[parts.length - 1] || "";
}
function extractSld(hostname) {
  const parts = hostname.split(".");
  if (parts.length >= 2) {
    const compound = parts.slice(-2).join(".");
    if (compound in TLD_SCORES) {
      return parts.length >= 3 ? parts[parts.length - 3] : parts[0];
    }
  }
  return parts.length >= 2 ? parts[parts.length - 2] : parts[0];
}
function extractDomain(hostname) {
  const tld = extractTld(hostname);
  const sld = extractSld(hostname);
  return tld ? `${sld}.${tld}` : sld;
}
function countSubdomains(hostname) {
  const tld = extractTld(hostname);
  const parts = hostname.split(".");
  const tldParts = tld.split(".").length;
  const sldAndTldParts = 1 + tldParts;
  const subParts = parts.length - sldAndTldParts;
  return Math.max(0, subParts);
}
function extractPageFeatures(url, _html) {
  url = url.trim().toLowerCase();
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "http://" + url;
  }
  url = url.replace("://www.", "://");
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    parsed = new URL("http://invalid.local");
  }
  const hostname = parsed.hostname;
  const domain = extractDomain(hostname);
  const domainSld = extractSld(hostname);
  const tld = extractTld(hostname);
  const URLLength = url.length;
  const DomainLength = domain.length;
  const hostNoPort = hostname.split(":")[0];
  const IsDomainIP = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostNoPort) ? 1 : 0;
  const URLSimilarityIndex = computeBrandSimilarity(domainSld, url);
  const CharContinuationRate = continuationRate(url);
  const TLDLegitimateProb = TLD_SCORES[tld.toLowerCase()] ?? 0.5;
  const URLCharProb = charProbability(url);
  const NoOfSubDomain = countSubdomains(hostname);
  const obfuscationCount = (url.match(/%/g) || []).length;
  const HasObfuscation = obfuscationCount > 0 ? 1 : 0;
  const NoOfObfuscatedChar = obfuscationCount;
  const ObfuscationRatio = url.length > 0 ? obfuscationCount / url.length : 0;
  const letters = (url.match(/[a-zA-Z]/g) || []).length;
  const NoOfLettersInURL = letters;
  const LetterRatioInURL = url.length > 0 ? letters / url.length : 0;
  const digits = (url.match(/[0-9]/g) || []).length;
  const NoOfDegitsInURL = digits;
  const DegitRatioInURL = url.length > 0 ? digits / url.length : 0;
  const NoOfEqualsInURL = (url.match(/=/g) || []).length;
  const NoOfQMarkInURL = (url.match(/\?/g) || []).length;
  const NoOfAmpersandInURL = (url.match(/&/g) || []).length;
  let specialCount = 0;
  for (const c of url) {
    if (SPECIAL_CHARS.has(c)) specialCount++;
  }
  const NoOfOtherSpecialCharsInURL = specialCount;
  const SpacialCharRatioInURL = url.length > 0 ? specialCount / url.length : 0;
  const IsHTTPS = parsed.protocol === "https:" ? 1 : 0;
  return {
    URLLength,
    // 0
    DomainLength,
    // 1
    IsDomainIP,
    // 2
    URLSimilarityIndex,
    // 3
    CharContinuationRate,
    // 4
    TLDLegitimateProb,
    // 5
    URLCharProb,
    // 6
    NoOfSubDomain,
    // 7
    HasObfuscation,
    // 8
    NoOfObfuscatedChar,
    // 9
    ObfuscationRatio,
    // 10
    NoOfLettersInURL,
    // 11
    LetterRatioInURL,
    // 12
    NoOfDegitsInURL,
    // 13
    DegitRatioInURL,
    // 14
    NoOfEqualsInURL,
    // 15
    NoOfQMarkInURL,
    // 16
    NoOfAmpersandInURL,
    // 17
    NoOfOtherSpecialCharsInURL,
    // 18
    SpacialCharRatioInURL,
    // 19
    IsHTTPS
    // 20
  };
}
export {
  extractPageFeatures
};
