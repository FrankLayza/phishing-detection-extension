"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.MLRunner = void 0;
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
class MLRunner {
    constructor() {
        this.model = null;
    }
    async init() {
        if (this.model)
            return;
        const modelUrl = chrome.runtime.getURL("assets/phishing_model.json");
        const resp = await fetch(modelUrl);
        this.model = await resp.json();
        console.log(`PhishGuard: Model loaded (${this.model.n_estimators} trees, ${this.model.n_features} features)`);
    }
    async predict(features) {
        await this.init();
        const model = this.model;
        // Map feature object to array in correct order
        const rawArray = model.feature_names.map((name) => features[name] ?? 0);
        // Apply MinMaxScaler: scaled = x * scale_ + min_
        // (min_ and scale_ are sklearn's pre-computed attributes, NOT data_min_/data_max_)
        const scaledArray = rawArray.map((val, i) => val * model.scaler.scale[i] + model.scaler.min[i]);
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
exports.MLRunner = MLRunner;
