/**
 * Diagnose a single URL: feature vector, per-feature contribution to the
 * verdict, and the score under BOTH the current asset model and whatever
 * model is sitting in build/ — so we can tell which one the browser ran.
 *
 * Usage: node diagnose_url.mjs "https://example.com/path"
 */
import { readFileSync, existsSync } from "fs";

const URL_IN = process.argv[2];
if (!URL_IN) {
  console.error('Usage: node diagnose_url.mjs "<url>"');
  process.exit(1);
}

// ---- feature extractor (port of src/content/feature-extractor.ts) ----------
const BRANDS = [
  "google", "facebook", "amazon", "apple", "microsoft", "paypal", "netflix",
  "instagram", "whatsapp", "linkedin", "twitter", "chase", "wellsfargo",
  "bankofamerica", "citibank", "dhl", "fedex", "ups", "usps", "ebay",
  "dropbox", "adobe", "outlook", "office365", "icloud", "steam", "spotify",
];
const TLD_SCORES = {
  com: 0.95, org: 0.90, net: 0.85, edu: 0.98, gov: 0.99, "co.uk": 0.90,
  de: 0.92, fr: 0.91, jp: 0.93, tk: 0.10, ml: 0.15, ga: 0.15, cf: 0.15, gq: 0.15,
};
const EXPECTED_CHAR_FREQ = {
  a: 0.08, e: 0.07, i: 0.06, o: 0.06, r: 0.05, t: 0.05, n: 0.05, s: 0.05,
  l: 0.04, c: 0.04,
};
const SPECIAL_CHARS = new Set("!@#$%^*()[]{}|;:<>".split(""));
const MULTI_TLDS = new Set(["co.uk","ac.uk","com.au","co.jp","com.br","co.in","com.ng","org.uk","gov.uk","net.au"]);

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (!m) return n; if (!n) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++)
      cur[j] = Math.min(prev[j]+1, cur[j-1]+1, prev[j-1] + (a[i-1]===b[j-1]?0:1));
    prev = cur;
  }
  return prev[n];
}
function computeBrandSimilarity(sld, url) {
  let best = 0;
  for (const b of BRANDS) {
    if (sld === b) return 0;
    const sim = 1 - levenshtein(sld, b) / Math.max(sld.length, b.length);
    if (sim > best) best = sim;
  }
  for (const b of BRANDS) if (url.includes(b) && sld !== b) best = Math.max(best, 0.85);
  return best >= 0.6 ? best : 0;
}
function continuationRate(url) {
  if (url.length < 2) return 0;
  const type = c => (/[a-z]/i.test(c) ? "a" : /[0-9]/.test(c) ? "d" : "s");
  let runs = 0;
  for (let i = 1; i < url.length; i++) if (type(url[i]) === type(url[i-1])) runs++;
  return runs / (url.length - 1);
}
function charProbability(url) {
  const letters = url.toLowerCase().match(/[a-z]/g) || [];
  if (!letters.length) return 0;
  let s = 0; for (const c of letters) s += EXPECTED_CHAR_FREQ[c] ?? 0.01;
  return s / letters.length;
}
function extractTld(h) {
  const p = h.split(".");
  if (p.length >= 3 && MULTI_TLDS.has(p.slice(-2).join("."))) return p.slice(-2).join(".");
  return p[p.length-1] || "";
}
function extractSld(h) {
  const t = extractTld(h), tp = t.split(".").length, p = h.split(".");
  return p[p.length-1-tp] || "";
}
function extractDomain(h) { const s = extractSld(h), t = extractTld(h); return s ? `${s}.${t}` : t; }
function countSubdomains(h) {
  const t = extractTld(h), tp = t.split(".").length;
  return Math.max(0, h.split(".").length - (1 + tp));
}

function extract(rawUrl) {
  let url = rawUrl.trim().toLowerCase();
  if (!url.startsWith("http://") && !url.startsWith("https://")) url = "http://" + url;
  url = url.replace("://www.", "://");
  let parsed; try { parsed = new URL(url); } catch { parsed = new URL("http://invalid.local"); }
  const hostname = parsed.hostname;
  const domain = extractDomain(hostname), sld = extractSld(hostname), tld = extractTld(hostname);
  const obf = (url.match(/%/g)||[]).length;
  const letters = (url.match(/[a-zA-Z]/g)||[]).length;
  const digits = (url.match(/[0-9]/g)||[]).length;
  let sp = 0; for (const c of url) if (SPECIAL_CHARS.has(c)) sp++;
  return {
    _meta: { normalised: url, hostname, domain, sld, tld },
    URLLength: url.length,
    DomainLength: domain.length,
    IsDomainIP: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname.split(":")[0]) ? 1 : 0,
    URLSimilarityIndex: computeBrandSimilarity(sld, url),
    CharContinuationRate: continuationRate(url),
    TLDLegitimateProb: TLD_SCORES[tld.toLowerCase()] ?? 0.50,
    URLCharProb: charProbability(url),
    NoOfSubDomain: countSubdomains(hostname),
    HasObfuscation: obf > 0 ? 1 : 0,
    NoOfObfuscatedChar: obf,
    ObfuscationRatio: url.length ? obf/url.length : 0,
    NoOfLettersInURL: letters,
    LetterRatioInURL: url.length ? letters/url.length : 0,
    NoOfDegitsInURL: digits,
    DegitRatioInURL: url.length ? digits/url.length : 0,
    NoOfEqualsInURL: (url.match(/=/g)||[]).length,
    NoOfQMarkInURL: (url.match(/\?/g)||[]).length,
    NoOfAmpersandInURL: (url.match(/&/g)||[]).length,
    NoOfOtherSpecialCharsInURL: sp,
    SpacialCharRatioInURL: url.length ? sp/url.length : 0,
    IsHTTPS: parsed.protocol === "https:" ? 1 : 0,
  };
}

function isLeaf(n){return "v" in n;}
function predictTree(t,f){while(!isLeaf(t)) t = f[t.f]<=t.t ? t.l : t.r; return t.v;}

function scoreWith(modelPath, feats) {
  if (!existsSync(modelPath)) return null;
  const m = JSON.parse(readFileSync(modelPath, "utf-8"));
  const raw = m.feature_names.map(n => feats[n] ?? 0);
  const scaled = raw.map((v,i) => v * m.scaler.scale[i] + m.scaler.min[i]);
  const probs = new Array(m.classes.length).fill(0);
  for (const t of m.trees) { const l = predictTree(t, scaled); for (let c=0;c<probs.length;c++) probs[c]+=l[c]; }
  for (let c=0;c<probs.length;c++) probs[c] /= m.n_estimators;
  return { score: probs[1], nTrees: m.n_estimators, nFeat: m.n_features, raw, scaled, names: m.feature_names };
}

const feats = extract(URL_IN);
const meta = feats._meta; delete feats._meta;

const allowlist = new Set(JSON.parse(readFileSync("phishing-extension/assets/top_domains.json","utf-8")));
function allowHit(url) {
  let host; try { host = new URL(url).hostname.toLowerCase().replace(/^www\./,""); } catch { return null; }
  const labels = host.split(".");
  for (let take=2; take<=3 && take<=labels.length; take++) {
    const cand = labels.slice(-take).join(".");
    if (allowlist.has(cand)) return cand;
  }
  return null;
}

console.log("=".repeat(88));
console.log(`  URL: ${URL_IN}`);
console.log("=".repeat(88));
console.log(`  normalised : ${meta.normalised}`);
console.log(`  hostname   : ${meta.hostname}`);
console.log(`  registrable: ${meta.domain}   (sld=${meta.sld}, tld=${meta.tld})`);
const hit = allowHit(URL_IN);
console.log(`  allowlist  : ${hit ? `HIT on "${hit}" -> CLEAN, ML never runs` : "MISS -> goes to ML"}`);

const A = scoreWith("phishing-extension/assets/phishing_model.json", feats);
const B = scoreWith("phishing-extension/build/chrome-mv3-prod/assets/phishing_model.json", feats);

function verdict(s){ return s < 0.5 ? "CLEAN" : s <= 0.85 ? "SUSPICIOUS" : "PHISHING"; }

console.log("\n  MODEL COMPARISON");
console.log("  " + "-".repeat(84));
if (A) console.log(`  assets/ (retrained, ${A.nTrees} trees)  score=${A.score.toFixed(4)}  -> ${verdict(A.score)}`);
if (B) console.log(`  build/  (shipped,   ${B.nTrees} trees)  score=${B.score.toFixed(4)}  -> ${verdict(B.score)}`);

console.log("\n  FEATURE VECTOR (raw -> scaled)");
console.log("  " + "-".repeat(84));
const ref = A || B;
for (let i = 0; i < ref.names.length; i++) {
  const n = ref.names[i];
  const flag = (n === "TLDLegitimateProb" && feats[n] === 0.50) ? "  <-- TLD NOT IN LOOKUP, defaulted" : "";
  console.log(`  ${n.padEnd(28)} ${String(ref.raw[i]).slice(0,12).padStart(12)} -> ${ref.scaled[i].toFixed(6).padStart(11)}${flag}`);
}

// Counterfactual: which single feature change flips the verdict?
console.log("\n  COUNTERFACTUALS (what would make this CLEAN?)");
console.log("  " + "-".repeat(84));
const tests = [
  ["TLDLegitimateProb -> 0.95 (as if .com)", { TLDLegitimateProb: 0.95 }],
  ["NoOfSubDomain -> 0 (no 'audit.' prefix)", { NoOfSubDomain: 0 }],
  ["both of the above", { TLDLegitimateProb: 0.95, NoOfSubDomain: 0 }],
];
for (const [label, patch] of tests) {
  const f2 = { ...feats, ...patch };
  const r = scoreWith("phishing-extension/assets/phishing_model.json", f2);
  console.log(`  ${label.padEnd(42)} ${r.score.toFixed(4)}  -> ${verdict(r.score)}`);
}
