/**
 * Copy the runtime assets the service worker fetches into the built extension.
 *
 * Why this exists: these three files used to reach build/ as a side effect of
 * `web_accessible_resources: ["assets/*"]` in package.json. That entry was
 * removed in 357f33e because it exposed the whole ~20 MB model to every page
 * visited, letting an attacker probe the decision boundary offline. Dropping it
 * was correct, but it was also the only thing copying the files, so the built
 * extension silently shipped without a model: every fetch below threw, the
 * allowlist fell back to empty (background/index.ts catches it), and ML
 * inference failed on every page.
 *
 * `chrome.runtime.getURL()` + `fetch()` from the service worker does NOT require
 * web_accessible_resources -- that gate only governs access from web pages and
 * content scripts. All three loads run in the worker, so copying is sufficient
 * and keeps the model unreachable from page context.
 *
 * Keep ASSETS in sync with the getURL("assets/...") call sites.
 */
import { copyFileSync, mkdirSync, existsSync, statSync } from "fs";
import { dirname, join } from "path";
import { fileURLToPath } from "url";

const root = dirname(fileURLToPath(import.meta.url)) + "/..";
const outDir = join(root, "build", "chrome-mv3-prod", "assets");

/** Fetched at runtime by the service worker -- see the cited call sites. */
const ASSETS = [
  "phishing_model.json", // src/ml/rf-inference.ts       -> MLRunner.init()
  "shap_mapping.json",   // src/ml/shap-approximator.ts  -> ShapApproximator.init()
  "top_domains.json",    // src/background/index.ts      -> initAllowlist()
];

const buildDir = join(root, "build", "chrome-mv3-prod");
if (!existsSync(buildDir)) {
  console.error(`copy-assets: ${buildDir} does not exist -- run \`plasmo build\` first.`);
  process.exit(1);
}

mkdirSync(outDir, { recursive: true });

let copied = 0;
for (const name of ASSETS) {
  const src = join(root, "assets", name);
  if (!existsSync(src)) {
    // Fail loudly: a missing model that only surfaces as a console error inside
    // the service worker is exactly how this broke unnoticed the first time.
    console.error(`copy-assets: missing required asset ${src}`);
    process.exit(1);
  }
  copyFileSync(src, join(outDir, name));
  const kb = Math.round(statSync(src).size / 1024);
  console.log(`copy-assets: ${name} (${kb} KB)`);
  copied++;
}

console.log(`copy-assets: ${copied}/${ASSETS.length} assets -> build/chrome-mv3-prod/assets/`);
