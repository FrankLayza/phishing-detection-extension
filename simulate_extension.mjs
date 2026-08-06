/**
 * End-to-end runtime simulation of the extension's decision pipeline.
 *
 * Replicates, in order, exactly what background/index.ts does:
 *   1. cache lookup (skipped — cold start)
 *   2. reputation allowlist short-circuit  (top_domains.json, eTLD+1, 2 and 3 labels)
 *   3. ML inference                        (phishing_model.json, scaler, tree traversal)
 *   4. GSB fallback                        (reported, not called — needs a user key)
 * then applies popup.tsx's verdictFor() tiering and shap-approximator.ts's
 * explanation selection.
 *
 * Feature extraction is a faithful port of src/content/feature-extractor.ts.
 *
 * Usage: node simulate_extension.mjs [pathToModelJson]
 */
import { readFileSync } from "fs";

const MODEL_PATH = process.argv[2] || "phishing-extension/assets/phishing_model.json";

// ---------------------------------------------------------------------------
// Feature extractor — port of src/content/feature-extractor.ts
// ---------------------------------------------------------------------------
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
const MULTI_TLDS = new Set(["co.uk", "ac.uk", "com.au", "co.jp", "com.br", "co.in", "com.ng", "org.uk", "gov.uk", "net.au"]);

function levenshtein(a, b) {
  const m = a.length, n = b.length;
  if (!m) return n;
  if (!n) return m;
  let prev = Array.from({ length: n + 1 }, (_, i) => i);
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
    }
    prev = cur;
  }
  return prev[n];
}

function computeBrandSimilarity(sld, url) {
  let best = 0;
  for (const brand of BRANDS) {
    if (sld === brand) return 0;               // exact brand = legitimate
    const d = levenshtein(sld, brand);
    const sim = 1 - d / Math.max(sld.length, brand.length);
    if (sim > best) best = sim;
  }
  // path-portion brand mention is itself suspicious
  for (const brand of BRANDS) {
    if (url.includes(brand) && sld !== brand) {
      best = Math.max(best, 0.85);
    }
  }
  return best >= 0.6 ? best : 0;               // v5 threshold
}

function continuationRate(url) {
  if (url.length < 2) return 0;
  let runs = 0;
  const type = (c) => (/[a-z]/i.test(c) ? "a" : /[0-9]/.test(c) ? "d" : "s");
  for (let i = 1; i < url.length; i++) {
    if (type(url[i]) === type(url[i - 1])) runs++;
  }
  return runs / (url.length - 1);
}

function charProbability(url) {
  const letters = url.toLowerCase().match(/[a-z]/g) || [];
  if (!letters.length) return 0;
  let sum = 0;
  for (const c of letters) sum += EXPECTED_CHAR_FREQ[c] ?? 0.01;
  return sum / letters.length;
}

function extractTld(hostname) {
  const parts = hostname.split(".");
  if (parts.length >= 3) {
    const last2 = parts.slice(-2).join(".");
    if (MULTI_TLDS.has(last2)) return last2;
  }
  return parts[parts.length - 1] || "";
}

function extractSld(hostname) {
  const tld = extractTld(hostname);
  const tldParts = tld.split(".").length;
  const parts = hostname.split(".");
  return parts[parts.length - 1 - tldParts] || "";
}

function extractDomain(hostname) {
  const sld = extractSld(hostname);
  const tld = extractTld(hostname);
  return sld ? `${sld}.${tld}` : tld;
}

function countSubdomains(hostname) {
  const tld = extractTld(hostname);
  const tldParts = tld.split(".").length;
  const parts = hostname.split(".");
  return Math.max(0, parts.length - (1 + tldParts));
}

function extractPageFeatures(rawUrl) {
  let url = rawUrl.trim().toLowerCase();
  if (!url.startsWith("http://") && !url.startsWith("https://")) url = "http://" + url;
  url = url.replace("://www.", "://");
  let parsed;
  try { parsed = new URL(url); } catch { parsed = new URL("http://invalid.local"); }

  const hostname = parsed.hostname;
  const domain = extractDomain(hostname);
  const domainSld = extractSld(hostname);
  const tld = extractTld(hostname);
  const hostNoPort = hostname.split(":")[0];

  const obf = (url.match(/%/g) || []).length;
  const letters = (url.match(/[a-zA-Z]/g) || []).length;
  const digits = (url.match(/[0-9]/g) || []).length;
  let specialCount = 0;
  for (const c of url) if (SPECIAL_CHARS.has(c)) specialCount++;

  return {
    URLLength: url.length,
    DomainLength: domain.length,
    IsDomainIP: /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostNoPort) ? 1 : 0,
    URLSimilarityIndex: computeBrandSimilarity(domainSld, url),
    CharContinuationRate: continuationRate(url),
    TLDLegitimateProb: TLD_SCORES[tld.toLowerCase()] ?? 0.50,
    URLCharProb: charProbability(url),
    NoOfSubDomain: countSubdomains(hostname),
    HasObfuscation: obf > 0 ? 1 : 0,
    NoOfObfuscatedChar: obf,
    ObfuscationRatio: url.length ? obf / url.length : 0,
    NoOfLettersInURL: letters,
    LetterRatioInURL: url.length ? letters / url.length : 0,
    NoOfDegitsInURL: digits,
    DegitRatioInURL: url.length ? digits / url.length : 0,
    NoOfEqualsInURL: (url.match(/=/g) || []).length,
    NoOfQMarkInURL: (url.match(/\?/g) || []).length,
    NoOfAmpersandInURL: (url.match(/&/g) || []).length,
    NoOfOtherSpecialCharsInURL: specialCount,
    SpacialCharRatioInURL: url.length ? specialCount / url.length : 0,
    IsHTTPS: parsed.protocol === "https:" ? 1 : 0,
  };
}

// ---------------------------------------------------------------------------
// Model + allowlist
// ---------------------------------------------------------------------------
const model = JSON.parse(readFileSync(MODEL_PATH, "utf-8"));
const allowlist = new Set(JSON.parse(readFileSync("phishing-extension/assets/top_domains.json", "utf-8")));
const shapMapping = JSON.parse(readFileSync("phishing-extension/assets/shap_mapping.json", "utf-8"));

function isLeaf(n) { return "v" in n; }
function predictTree(tree, f) {
  while (!isLeaf(tree)) tree = f[tree.f] <= tree.t ? tree.l : tree.r;
  return tree.v;
}

function isAllowlisted(url) {
  let host;
  try { host = new URL(url).hostname.toLowerCase().replace(/^www\./, ""); }
  catch { return false; }
  const labels = host.split(".");
  for (let take = 2; take <= 3 && take <= labels.length; take++) {
    if (allowlist.has(labels.slice(-take).join("."))) return true;
  }
  return false;
}

function mlPredict(features) {
  const raw = model.feature_names.map((n) => features[n] ?? 0);
  const scaled = raw.map((v, i) => v * model.scaler.scale[i] + model.scaler.min[i]);
  const probs = new Array(model.classes.length).fill(0);
  for (const t of model.trees) {
    const leaf = predictTree(t, scaled);
    for (let c = 0; c < probs.length; c++) probs[c] += leaf[c];
  }
  for (let c = 0; c < probs.length; c++) probs[c] /= model.n_estimators;
  return probs.length > 1 ? probs[1] : probs[0];
}

// popup.tsx verdictFor()
function verdictFor(score) {
  if (score < 0.5) return "CLEAN";
  if (score <= 0.85) return "SUSPICIOUS";
  return "PHISHING";
}

// shap-approximator.ts getExplanations()
function getExplanations(features) {
  const out = [];
  for (const [feat, val] of Object.entries(features)) {
    const m = shapMapping[feat];
    if (!m) continue;
    const isImportantBinary = feat === "IsHTTPS" || feat === "DomainTitleMatchScore";
    if (val > 0 || isImportantBinary) {
      out.push({ feature: feat, value: val, importance: m.importance });
    }
  }
  out.sort((a, b) => b.importance - a.importance);
  return out.slice(0, 5);
}

// full pipeline, mirroring background/index.ts order
function runPipeline(url) {
  if (isAllowlisted(url)) {
    return { url, verdict: "CLEAN", score: 0.05, source: "OVERRIDE", explanations: ["Reputation"] };
  }
  const features = extractPageFeatures(url);
  const score = mlPredict(features);
  const expl = getExplanations(features).map((e) => e.feature);
  return { url, verdict: verdictFor(score), score, source: "ML", explanations: expl };
}

// ---------------------------------------------------------------------------
// Test corpus
// ---------------------------------------------------------------------------
const LEGIT = [
  "https://google.com/", "https://github.com/", "https://wikipedia.org/",
  "https://paypal.com/", "https://stackoverflow.com/", "https://bbc.co.uk/",
  "https://microsoft.com/", "https://amazon.com/dp/B08N5WRWNW",
  "https://accounts.google.com/signin", "https://docs.python.org/3/library/os.html",
  "https://en.wikipedia.org/wiki/Phishing", "https://gtbank.com/",
  "https://jumia.com.ng/", "https://flutterwave.com/",
];
const PHISH = [
  "http://secure-paypal-login.tk/verify/account",
  "http://g00gle-security.ml/alert/verify",
  "http://amaz0n-security.ga/update-payment",
  "http://micr0soft-support.cf/password-reset",
  "http://192.168.1.100/banking-login",
  "http://login-appleid.secure-check.tk/verify",
  "http://paypa1-security.gq/update/billing",
  "http://chase-banking-secure.ml/signin?user=12345",
  "http://netfl1x-account.ga/verify/payment",
  "http://faceb00k-security.tk/confirm/login?id=abc123&ref=email",
];
// Unknown-but-legitimate: NOT in the top-30k allowlist. This is the
// population the pre-fix model failed on entirely (0/4), and the one the
// corpus fix targets. Regional banks/fintech/e-commerce and small business
// sites, with paths — appending a path was the dominant failure mode.
const UNKNOWN_LEGIT = [
  "https://joesplumbingleeds.co.uk/contact",
  "https://stmarysprimary-ng.org/admissions",
  "https://oakwood-dental-clinic.com/book-appointment",
  "https://lagostechhub.com.ng/events/2026",
  "https://gtbank.com/personal-banking/savings-accounts",
  "https://flutterwave.com/pricing",
  "https://jumia.com.ng/smartphones",
  "https://zenithbank.com/branches/lagos-island",
  "https://riverside-veterinary.co.uk/support/faq",
  "https://greenfield-academy.edu.ng/admissions/requirements",
  "https://paystack.com/docs/api",
  "https://punchng.com/category/news",
];

console.log(`Model: ${MODEL_PATH}`);
console.log(`  ${model.n_estimators} trees, ${model.n_features} features`);
console.log(`  allowlist: ${allowlist.size} domains, shap_mapping: ${Object.keys(shapMapping).length} features\n`);

function report(title, urls, expectPhish) {
  console.log("=".repeat(92));
  console.log(`  ${title}`);
  console.log("=".repeat(92));
  let correct = 0, allow = 0;
  for (const u of urls) {
    const r = runPipeline(u);
    const flagged = r.verdict !== "CLEAN";
    const ok = expectPhish ? flagged : !flagged;
    if (ok) correct++;
    if (r.source === "OVERRIDE") allow++;
    const mark = ok ? "PASS" : "FAIL";
    console.log(`  ${mark}  ${r.verdict.padEnd(11)} ${r.score.toFixed(4)}  ${r.source.padEnd(8)} ${u.slice(0, 52)}`);
  }
  console.log(`  --> ${correct}/${urls.length} correct  (${allow} resolved by allowlist)\n`);
  return { correct, total: urls.length };
}

const a = report("KNOWN LEGITIMATE (expect CLEAN)", LEGIT, false);
const b = report("PHISHING (expect SUSPICIOUS or PHISHING)", PHISH, true);
const c = report("UNKNOWN LEGITIMATE — not in allowlist (expect CLEAN)", UNKNOWN_LEGIT, false);

console.log("=".repeat(92));
console.log("  SUMMARY");
console.log("=".repeat(92));
console.log(`  Known legitimate:   ${a.correct}/${a.total}`);
console.log(`  Phishing:           ${b.correct}/${b.total}`);
console.log(`  Unknown legitimate: ${c.correct}/${c.total}   <-- the real-world weak spot`);
const tot = a.correct + b.correct + c.correct;
const n = a.total + b.total + c.total;
console.log(`  OVERALL:            ${tot}/${n} (${(tot / n * 100).toFixed(1)}%)`);

// Explanation-layer check
console.log("\n" + "=".repeat(92));
console.log("  EXPLANATION LAYER (shap_mapping.json coverage)");
console.log("=".repeat(92));
const modelFeats = model.feature_names;
const mapFeats = Object.keys(shapMapping);
const missing = modelFeats.filter((f) => !mapFeats.includes(f));
const extra = mapFeats.filter((f) => !modelFeats.includes(f));
console.log(`  model features:        ${modelFeats.length}`);
console.log(`  shap_mapping features: ${mapFeats.length}`);
console.log(`  MISSING from mapping (can never be shown to the user): ${missing.length ? missing.join(", ") : "none"}`);
console.log(`  STALE in mapping (not in model):                       ${extra.length ? extra.join(", ") : "none"}`);
const sample = runPipeline("http://secure-paypal-login.tk/verify/account");
console.log(`\n  Example explanations for a phishing URL: ${sample.explanations.join(", ")}`);
