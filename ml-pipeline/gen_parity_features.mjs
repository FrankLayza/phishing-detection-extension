/**
 * Train/serve parity harness — Python vs the REAL shipped TS extractor.
 *
 * Imports src/content/feature-extractor.ts directly (esbuild-bundled on every
 * run, so it can never test a stale copy), so this checks the code the
 * extension actually runs. An earlier attempt used simulate_extension.mjs's
 * inlined copy of the extractor, which has drifted from the real one
 * (different BRANDS list, no compound-TLD handling in charProbability) and
 * therefore reported false mismatches.
 *
 * Usage:
 *   node ml-pipeline/gen_parity_features.mjs   # writes parity_ts.json
 *   python ml-pipeline/check_parity.py         # compares against Python
 */
import { readdirSync, readFileSync, writeFileSync } from "fs";
import { createRequire } from "module";
import { dirname, join, resolve } from "path";
import { fileURLToPath } from "url";

// Rebuild the bundle EVERY run. It used to be a manual prebuild step, and a
// stale bundle silently reported 287 false divergences once already (see the
// Aug 7 commit) and 960 more when tld-rates.ts landed: the harness scored the
// previous extractor while claiming to test the current one. A parity gate that
// can pass or fail on a stale artifact is not a gate.
const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");
const ext = join(root, "phishing-extension");
const bundle = join(here, "__parity_bundle.mjs");
// esbuild's JS API rather than its CLI: Node >=20 refuses to spawnSync a
// .CMD shim on Windows (EINVAL), and this needs no shell either way.
// esbuild is a transitive dep of plasmo, so pnpm's strict layout keeps it in
// .pnpm rather than node_modules/esbuild — resolve it from there, tolerating
// either layout and any version.
const req = createRequire(join(ext, "package.json"));
let esbuild;
try {
  esbuild = req("esbuild");
} catch {
  const store = join(ext, "node_modules", ".pnpm");
  const dir = readdirSync(store).find((d) => d.startsWith("esbuild@"));
  if (!dir) throw new Error(`esbuild not found under ${store} — run pnpm install`);
  esbuild = req(join(store, dir, "node_modules", "esbuild"));
}
await esbuild.build({
  entryPoints: [join(ext, "src", "content", "feature-extractor.ts")],
  outfile: bundle,
  bundle: true,
  format: "esm",
  platform: "neutral",
  logLevel: "warning",
});

const { extractPageFeatures } = await import(
  `file://${bundle.replace(/\\/g, "/")}?t=${Date.now()}`
);

const urls = JSON.parse(readFileSync(join(root, "parity_urls.json"), "utf-8"));
const out = {};
let failed = 0;
for (const u of urls) {
  try {
    out[u] = extractPageFeatures(u);
  } catch (e) {
    failed++;
    out[u] = { __error: String(e) };
  }
}
writeFileSync("parity_ts.json", JSON.stringify(out, null, 1));
console.log(`TS features written for ${urls.length} URLs (${failed} extraction errors)`);
