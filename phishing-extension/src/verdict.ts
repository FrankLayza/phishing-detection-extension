export const CLEAN_MAX = 0.5;
export const PHISHING_MIN = 0.9;

export type Verdict = "CLEAN" | "SUSPICIOUS" | "PHISHING";

export function verdictFor(score: number): Verdict {
  if (score < CLEAN_MAX) return "CLEAN";
  if (score < PHISHING_MIN) return "SUSPICIOUS";
  return "PHISHING";
}
