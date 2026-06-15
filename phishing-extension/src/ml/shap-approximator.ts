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

      const numericVal = val as number;
      const isImportantBinary = feat === "IsHTTPS" || feat === "DomainTitleMatchScore";
      
      // Heuristic: include if non-zero, or if it is a binary legitimacy indicator (where 0 or 1 is meaningful)
      if (numericVal > 0 || isImportantBinary) {
        let description = mapping.description;
        
        if (feat === "IsHTTPS") {
          description = numericVal === 1
            ? "HTTPS is present — reduces phishing risk"
            : "No HTTPS encryption — increases phishing risk";
        } else if (feat === "DomainTitleMatchScore") {
          description = numericVal > 0.5
            ? "Domain matches page title — reduces phishing risk"
            : "Domain does not match page title — increases phishing risk";
        }

        explanations.push({
          feature: feat,
          value: numericVal,
          importance: mapping.importance,
          description: description,
          category: mapping.category
        });
      }
    }

    // Sort by importance descending
    explanations.sort((a, b) => b.importance - a.importance);
    return explanations.slice(0, 5); // Return top 5
  }
}
