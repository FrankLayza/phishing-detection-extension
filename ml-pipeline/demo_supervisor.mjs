// Supervisor demo — score URLs through the REAL shipped pipeline.
// This is exactly what the extension runs:
//   reputation.ts (allowlist / platform correction / brand-impersonation guard)
//   -> feature-extractor.ts (the shipped TS extractor, bundled)
//   -> phishing_model.json (the committed model in build/)
// The verdict thresholds are the calibrated ones (CLEAN <0.50, SUSPICIOUS <0.90, PHISHING >=0.90).
import { readFileSync, existsSync } from "fs";
import { createRequire } from "module";
import path from "path";

const require = createRequire(import.meta.url);
const EXT = "phishing-extension";

function findEsbuild() {
  const direct = path.join(EXT, "node_modules", "esbuild");
  if (existsSync(direct)) return require(path.resolve(direct));
  const pnpmDir = path.join(EXT, "node_modules", ".pnpm");
  const { readdirSync } = require("fs");
  for (const d of readdirSync(pnpmDir)) {
    if (d.startsWith("esbuild@")) {
      const p = path.join(pnpmDir, d, "node_modules", "esbuild");
      if (existsSync(p)) return require(path.resolve(p));
    }
  }
  throw new Error("esbuild not found");
}

const esbuild = findEsbuild();
await esbuild.build({
  entryPoints: [path.join(EXT, "src/content/feature-extractor.ts")],
  bundle: true,
  format: "esm",
  outfile: "ml-pipeline/__score_bundle.mjs",
  platform: "neutral",
  logLevel: "error",
});
await esbuild.build({
  entryPoints: [path.join(EXT, "src/ml/reputation.ts")],
  bundle: true,
  format: "esm",
  outfile: "ml-pipeline/__rep_bundle.mjs",
  platform: "neutral",
  logLevel: "error",
});

const { extractPageFeatures } = await import("../ml-pipeline/__score_bundle.mjs?t=" + Date.now());
const { Reputation } = await import("../ml-pipeline/__rep_bundle.mjs?t=" + Date.now());

function isLeaf(n) { return "v" in n; }
function predictTree(t, f) { while (!isLeaf(t)) t = f[t.f] <= t.t ? t.l : t.r; return t.v; }

const MODEL = `${EXT}/build/chrome-mv3-prod/assets/phishing_model.json`;
const m = JSON.parse(readFileSync(MODEL, "utf-8"));
const allowlist = new Set(JSON.parse(readFileSync(`${EXT}/assets/top_domains.json`, "utf-8")));
const rep = new Reputation(allowlist);

function mlScore(features) {
  const raw = m.feature_names.map((n) => features[n] ?? 0);
  const scaled = raw.map((v, i) => v * m.scaler.scale[i] + m.scaler.min[i]);
  const probs = new Array(m.classes.length).fill(0);
  for (const t of m.trees) { const l = predictTree(t, scaled); for (let c = 0; c < probs.length; c++) probs[c] += l[c]; }
  for (let c = 0; c < probs.length; c++) probs[c] /= m.n_estimators;
  return probs[1];
}

const verdict = (s) => (s < 0.5 ? "CLEAN" : s < 0.9 ? "SUSPICIOUS" : "PHISHING");

async function run(url) {
  const features = extractPageFeatures(url, "");
  const repResult = await rep.evaluate(url, features);
  if (repResult.kind === "allowlisted") {
    return { url, verdict: "CLEAN", score: 0.05, source: "allowlist", signals: repResult.signals.map((s) => s.feature).join(" + ") };
  }
  let raw = mlScore(features);
  let score = raw;
  const correctionApplied =
    repResult.kind === "platform" && !repResult.impersonation && raw < 0.9;
  if (correctionApplied) score = mlScore(repResult.features);
  const signals = correctionApplied || repResult.impersonation
    ? repResult.signals.map((s) => s.feature).join(" + ")
    : "ML only";
  return {
    url,
    verdict: verdict(score),
    score: score.toFixed(3),
    raw,
    correction: correctionApplied ? "YES (TLD neutralised)" : repResult.impersonation ? "WITHHELD (brand guard)" : "no",
    signals,
  };
}

const URLS = process.argv.slice(2).length ? process.argv.slice(2) : [
  // Legit / trusted
  "https://www.google.com", "https://github.com", "https://gtbank.com",
  // Legit infra (allowlisted CDNs)
  "https://apple-relay.cloudflare.com",
  // Legit project pages on hosting platforms (the old false-positive class)
  "https://my-portfolio.vercel.app", "https://microsoft.github.io", "https://google.github.io",
  // Brand-impersonation clones on platforms (the recall gap that was fixed)
  "https://microsoft-verify-login.netlify.app",
  "https://secure-paypal-verify.vercel.app/account/login",
  "https://paypa1-login.vercel.app/confirm",
  // Non-platform brand squats (known honest gap — model's verdict, no reputation help)
  "https://microsoft-verify-login.phishcorp.co",
];

console.log("=".repeat(100));
console.log("PhishGuard — supervisor demo. Real shipped pipeline (reputation + model + calibrated verdicts).");
console.log("=".repeat(100));
for (const u of URLS) {
  const r = await run(u);
  console.log(`\n  ${r.url}`);
  console.log(`    verdict   : ${r.verdict}   (score ${r.score})`);
  console.log(`    raw ML    : ${r.raw}`);
  console.log(`    correction: ${r.correction}`);
  console.log(`    signals   : ${r.signals}`);
}
console.log("\n" + "=".repeat(100));