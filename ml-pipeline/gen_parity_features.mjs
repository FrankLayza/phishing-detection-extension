/**
 * Train/serve parity harness — Python vs the REAL shipped TS extractor.
 *
 * Imports src/content/feature-extractor.ts directly (bundled by esbuild), so
 * this checks the code the extension actually runs. An earlier attempt used
 * simulate_extension.mjs's inlined copy of the extractor, which has drifted
 * from the real one (different BRANDS list, no compound-TLD handling in
 * charProbability) and therefore reported false mismatches.
 *
 * Usage:
 *   node ml-pipeline/gen_parity_features.mjs   # writes parity_ts.json
 *   python ml-pipeline/check_parity.py         # compares against Python
 */
import { readFileSync, writeFileSync } from "fs";
import { extractPageFeatures } from "./__parity_bundle.mjs";

const urls = JSON.parse(readFileSync("parity_urls.json", "utf-8"));
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
