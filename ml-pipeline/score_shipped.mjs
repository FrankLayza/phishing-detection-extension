// Score URLs through the REAL shipped extractor + the REAL built model JSON.
// diagnose_url.mjs carries a drifted inlined copy of the extractor, so its
// numbers cannot be trusted (hardcoded TLD_SCORES, ASCII-only letter regex).
// This bundles src/content/feature-extractor.ts the same way the parity gate
// does, so what we score here is what Chrome actually runs.
import { readFileSync, existsSync } from "fs";
import { createRequire } from "module";
import path from "path";

const require = createRequire(import.meta.url);
const EXT = "phishing-extension";

// Locate esbuild under pnpm's strict layout (see parity-gate memory).
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
const OUT = "ml-pipeline/__score_bundle.mjs";
await esbuild.build({
  entryPoints: [path.join(EXT, "src/content/feature-extractor.ts")],
  bundle: true,
  format: "esm",
  outfile: OUT,
  platform: "neutral",
  logLevel: "error",
});

const { extractPageFeatures } = await import("../ml-pipeline/__score_bundle.mjs?t=" + Date.now());

function isLeaf(n) { return "v" in n; }
function predictTree(t, f) { while (!isLeaf(t)) t = f[t.f] <= t.t ? t.l : t.r; return t.v; }

const MODEL = `${EXT}/build/chrome-mv3-prod/assets/phishing_model.json`;
const m = JSON.parse(readFileSync(MODEL, "utf-8"));
const allowlist = new Set(JSON.parse(readFileSync(`${EXT}/assets/top_domains.json`, "utf-8")));

function allowHit(url) {
  let host;
  try { host = new URL(url).hostname.toLowerCase().replace(/^www\./, ""); } catch { return null; }
  const labels = host.split(".");
  for (let take = 2; take <= 3 && take <= labels.length; take++) {
    const cand = labels.slice(-take).join(".");
    if (allowlist.has(cand)) return cand;
  }
  return null;
}

function score(url) {
  const f = extractPageFeatures(url, "");
  const raw = m.feature_names.map((n) => f[n] ?? 0);
  const scaled = raw.map((v, i) => v * m.scaler.scale[i] + m.scaler.min[i]);
  const probs = new Array(m.classes.length).fill(0);
  for (const t of m.trees) { const l = predictTree(t, scaled); for (let c = 0; c < probs.length; c++) probs[c] += l[c]; }
  for (let c = 0; c < probs.length; c++) probs[c] /= m.n_estimators;
  return { s: probs[1], f };
}

const verdict = (s) => (s < 0.5 ? "CLEAN" : s < 0.9 ? "SUSPICIOUS" : "PHISHING");

const URLS = process.argv.slice(2).length ? process.argv.slice(2) : [
  "https://gtbank.com", "https://www.gtbank.com/", "https://paystack.com", "https://www.paystack.com/",
];

for (const u of URLS) {
  const { s, f } = score(u);
  const hit = allowHit(u);
  console.log(`\n${u}`);
  console.log(`  allowlist : ${hit ? `HIT "${hit}" -> CLEAN (ML skipped)` : "MISS -> ML runs"}`);
  console.log(`  ML score  : ${s.toFixed(4)}  -> ${verdict(s)}`);
  console.log(`  key feats : TLDLegitimateProb=${f.TLDLegitimateProb}  DomainLength=${f.DomainLength}  URLLength=${f.URLLength}  NoOfSubDomain=${f.NoOfSubDomain}  CharContinuationRate=${f.CharContinuationRate?.toFixed?.(4)}`);
}
