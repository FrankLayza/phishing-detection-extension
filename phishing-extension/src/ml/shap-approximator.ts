import type { FeatureVector, ShapExplanation } from "../types";

export class ShapApproximator {
  private shapMapping: any = null;

  async init() {
    if (this.shapMapping) return;
    const url = chrome.runtime.getURL("assets/shap_mapping.json");
    const resp = await fetch(url);
    this.shapMapping = await resp.json();
  }

  async getExplanations(features: FeatureVector): Promise<ShapExplanation[]> {
    await this.init();
    
    const explanations: ShapExplanation[] = [];
    
    for (const [feat, val] of Object.entries(features)) {
      const mapping = this.shapMapping[feat];
      if (!mapping) continue;

      // Simple heuristic: if the feature is non-zero (or high), it contributes.
      // We use the pre-computed importance from SHAP.
      if (val > 0) {
        explanations.push({
          feature: feat,
          value: val as number,
          importance: mapping.importance,
          description: mapping.description,
          category: mapping.category
        });
      }
    }

    // Sort by importance descending
    explanations.sort((a, b) => b.importance - a.importance);
    return explanations.slice(0, 5); // Return top 5
  }
}
