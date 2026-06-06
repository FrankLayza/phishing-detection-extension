/**
 * Cross-validation script: verifies TypeScript RF inference matches Python pipeline.
 * 
 * Loads the SAME model JSON used by the extension (phishing_model.json),
 * feeds in the EXACT raw feature vectors captured from Python, applies scaling
 * and tree traversal, and compares the phishing probability.
 * 
 * Usage:  node cross_validate_ts.mjs
 */
import { readFileSync } from "fs";

// -------------------------------------------------------------------
// 1. Load the Python-captured cross-validation data
// -------------------------------------------------------------------
const cvData = JSON.parse(
  readFileSync("cross_validation_data.json", "utf-8")
);

// -------------------------------------------------------------------
// 2. Load the phishing_model.json (same file the extension uses)
// -------------------------------------------------------------------
const model = JSON.parse(
  readFileSync("phishing-extension/assets/phishing_model.json", "utf-8")
);

console.log(`Model: ${model.n_estimators} trees, ${model.n_features} features`);
console.log(`Classes: [${model.classes}]`);
console.log(`Feature names (first 5): ${model.feature_names.slice(0, 5).join(", ")}...`);
console.log(`Scaler min[0..4]: ${model.scaler.min.slice(0, 5)}`);
console.log(`Scaler scale[0..4]: ${model.scaler.scale.slice(0, 5)}`);
console.log();

// -------------------------------------------------------------------
// 3. Tree traversal — exact copy from onnx-runner.ts
// -------------------------------------------------------------------
function isLeaf(node) {
  return "v" in node;
}

function predictTree(tree, features) {
  if (isLeaf(tree)) {
    return tree.v;
  }
  if (features[tree.f] <= tree.t) {
    return predictTree(tree.l, features);
  }
  return predictTree(tree.r, features);
}

// -------------------------------------------------------------------
// 4. Two scaler implementations to compare
// -------------------------------------------------------------------

/** CURRENT onnx-runner.ts formula (WRONG) */
function scaleWrong(raw, min, scale) {
  return raw.map((val, i) => (val - min[i]) * scale[i]);
}

/** CORRECT sklearn MinMaxScaler formula: X_scaled = X * scale_ + min_ */
function scaleCorrect(raw, min, scale) {
  return raw.map((val, i) => val * scale[i] + min[i]);
}

// -------------------------------------------------------------------
// 5. Run inference with a given scaled array
// -------------------------------------------------------------------
function runInference(scaledArray, trees, nClasses) {
  const probs = new Array(nClasses).fill(0);
  for (const tree of trees) {
    const leafProbs = predictTree(tree, scaledArray);
    for (let c = 0; c < probs.length; c++) {
      probs[c] += leafProbs[c];
    }
  }
  for (let c = 0; c < probs.length; c++) {
    probs[c] /= trees.length;
  }
  return probs;
}

// -------------------------------------------------------------------
// 6. Run cross-validation for each URL
// -------------------------------------------------------------------
const TOLERANCE = 0.01;
let allPassed = true;

console.log("=".repeat(80));
console.log("  CROSS-VALIDATION: Python vs TypeScript Inference");
console.log("=".repeat(80));

for (const result of cvData.results) {
  console.log(`\n${"─".repeat(80)}`);
  console.log(`  URL: ${result.url}`);
  console.log(`${"─".repeat(80)}`);

  const raw = result.raw_vector;
  const pythonProb = result.ml_phish_prob;
  const pythonScaled = result.scaled_vector;

  // --- Test WRONG formula (current onnx-runner.ts) ---
  const wrongScaled = scaleWrong(raw, model.scaler.min, model.scaler.scale);
  const wrongProbs = runInference(wrongScaled, model.trees, model.classes.length);
  const wrongPhishProb = wrongProbs[1];

  // --- Test CORRECT formula ---
  const correctScaled = scaleCorrect(raw, model.scaler.min, model.scaler.scale);
  const correctProbs = runInference(correctScaled, model.trees, model.classes.length);
  const correctPhishProb = correctProbs[1];

  // --- Compare scaled values with Python ---
  let scalerMismatchCount = 0;
  let scalerMismatchDetails = [];
  for (let i = 0; i < raw.length; i++) {
    const pyScaled = pythonScaled[i];
    const tsCorrect = correctScaled[i];
    const tsWrong = wrongScaled[i];
    const diff = Math.abs(pyScaled - tsCorrect);
    if (diff > 0.0001) {
      scalerMismatchCount++;
      scalerMismatchDetails.push({
        idx: i,
        feature: result.feature_names[i],
        python: pyScaled,
        tsCorrect: tsCorrect,
        tsWrong: tsWrong,
        diff: diff,
      });
    }
  }

  const correctDiff = Math.abs(pythonProb - correctPhishProb);
  const wrongDiff = Math.abs(pythonProb - wrongPhishProb);
  const passed = correctDiff <= TOLERANCE;

  console.log(`\n  Python ML score:            ${pythonProb.toFixed(6)}`);
  console.log(`  TS (CORRECT formula):       ${correctPhishProb.toFixed(6)}   diff=${correctDiff.toFixed(6)}  ${correctDiff <= TOLERANCE ? "✓ PASS" : "✗ FAIL"}`);
  console.log(`  TS (WRONG/current formula):  ${wrongPhishProb.toFixed(6)}   diff=${wrongDiff.toFixed(6)}  ${wrongDiff <= TOLERANCE ? "✓ PASS" : "✗ FAIL"}`);

  if (scalerMismatchCount > 0) {
    console.log(`\n  ⚠ Scaler mismatches (correct formula vs Python): ${scalerMismatchCount}`);
    for (const m of scalerMismatchDetails.slice(0, 5)) {
      console.log(`    [${m.idx}] ${m.feature}: Python=${m.python.toFixed(8)} TS=${m.tsCorrect.toFixed(8)} diff=${m.diff.toFixed(8)}`);
    }
  } else {
    console.log(`  ✓ All 44 scaled values match Python within 0.0001 tolerance`);
  }

  if (!passed) {
    allPassed = false;
    // Find which tree diverges first
    console.log(`\n  Divergence analysis (first tree mismatch with CORRECT scaler):`);
    for (let t = 0; t < model.trees.length; t++) {
      const pyTreeProb = result.per_tree_probs[t];
      const tsLeaf = predictTree(model.trees[t], correctScaled);
      const tsTreeProb = tsLeaf[1];
      if (Math.abs(pyTreeProb - tsTreeProb) > 0.0001) {
        console.log(`    Tree ${t}: Python=${pyTreeProb.toFixed(6)} TS=${tsTreeProb.toFixed(6)}`);
        if (t >= 4) {
          console.log(`    ... (showing first 5 divergent trees)`);
          break;
        }
      }
    }
  }
}

// -------------------------------------------------------------------
// 7. Summary
// -------------------------------------------------------------------
console.log(`\n${"=".repeat(80)}`);
console.log(`  SUMMARY`);
console.log(`${"=".repeat(80)}`);

console.log(`\n  SCALER BUG IDENTIFIED IN onnx-runner.ts:`);
console.log(`    Current formula:  (val - min[i]) * scale[i]   ← WRONG`);
console.log(`    Correct formula:  val * scale[i] + min[i]     ← sklearn MinMaxScaler`);
console.log(`    (min_ and scale_ are sklearn's pre-computed attributes,`);
console.log(`     NOT data_min_/data_max_)`);

console.log(`\n  Results with CORRECT formula:`);
console.log(`  ${"URL".padEnd(45)} ${"Python".padEnd(12)} ${"TS".padEnd(12)} ${"Diff".padEnd(10)} ${"Status"}`);
console.log(`  ${"-".repeat(85)}`);
for (const result of cvData.results) {
  const raw = result.raw_vector;
  const correctScaled = scaleCorrect(raw, model.scaler.min, model.scaler.scale);
  const probs = runInference(correctScaled, model.trees, model.classes.length);
  const tsProb = probs[1];
  const pyProb = result.ml_phish_prob;
  const diff = Math.abs(pyProb - tsProb);
  const status = diff <= TOLERANCE ? "✓ PASS" : "✗ FAIL";
  console.log(`  ${result.url.padEnd(45)} ${pyProb.toFixed(6).padEnd(12)} ${tsProb.toFixed(6).padEnd(12)} ${diff.toFixed(6).padEnd(10)} ${status}`);
}

console.log(`\n  OVERALL: ${allPassed ? "✓ ALL PASS — fix the scaler formula and ship it" : "✗ SOME FAILURES — investigate tree divergence"}`);
console.log(`${"=".repeat(80)}`);
