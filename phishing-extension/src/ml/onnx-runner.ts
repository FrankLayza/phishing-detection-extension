/**
 * Lightweight Random Forest inference engine.
 * Loads the model from a compact JSON file exported by export_model_json.py.
 * No ONNX dependency required — pure TypeScript tree traversal.
 */
import type { FeatureVector } from "../types";

interface TreeLeaf {
  v: number[];  // class probabilities [p_safe, p_phishing]
}

interface TreeNode {
  f: number;     // feature index
  t: number;     // threshold
  l: TreeNode | TreeLeaf;  // left child (<=)
  r: TreeNode | TreeLeaf;  // right child (>)
}

interface ModelData {
  n_estimators: number;
  n_features: number;
  classes: number[];
  feature_names: string[];
  scaler: { min: number[]; scale: number[] };
  trees: (TreeNode | TreeLeaf)[];
}

function isLeaf(node: TreeNode | TreeLeaf): node is TreeLeaf {
  return "v" in node;
}

function predictTree(tree: TreeNode | TreeLeaf, features: number[]): number[] {
  if (isLeaf(tree)) {
    return tree.v;
  }
  if (features[tree.f] <= tree.t) {
    return predictTree(tree.l, features);
  }
  return predictTree(tree.r, features);
}

export class MLRunner {
  private model: ModelData | null = null;

  async init() {
    if (this.model) return;

    const modelUrl = chrome.runtime.getURL("assets/phishing_model.json");
    const resp = await fetch(modelUrl);
    this.model = await resp.json();
    console.log(`PhishGuard: Model loaded (${this.model!.n_estimators} trees, ${this.model!.n_features} features)`);
  }

  async predict(features: FeatureVector): Promise<{ isPhishing: boolean; score: number }> {
    await this.init();
    const model = this.model!;

    // Map feature object to array in correct order
    const rawArray = model.feature_names.map(
      (name) => (features as unknown as Record<string, number>)[name] ?? 0
    );

    // Apply MinMaxScaler: scaled = x * scale_ + min_
    // (min_ and scale_ are sklearn's pre-computed attributes, NOT data_min_/data_max_)
    const scaledArray = rawArray.map(
      (val, i) => val * model.scaler.scale[i] + model.scaler.min[i]
    );

    // Average predictions from all trees
    const probs = new Array(model.classes.length).fill(0);
    for (const tree of model.trees) {
      const leafProbs = predictTree(tree, scaledArray);
      for (let c = 0; c < probs.length; c++) {
        probs[c] += leafProbs[c];
      }
    }
    for (let c = 0; c < probs.length; c++) {
      probs[c] /= model.n_estimators;
    }

    // classes[1] = phishing probability
    const phishingProb = probs.length > 1 ? probs[1] : probs[0];

    return {
      isPhishing: phishingProb >= 0.5,
      score: phishingProb,
    };
  }
}
