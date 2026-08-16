import type { Verdict } from "../verdict";

/**
 * v3 lexical-only feature set (21 URL-string features).
 * DOM/content features were dropped to eliminate train/serve skew — these
 * are self-extracted identically in Python and TypeScript for exact parity.
 * See SOURCE_OF_TRUTH.md / feature_config.py.
 */
export interface FeatureVector {
  URLLength: number; DomainLength: number; IsDomainIP: number;
  URLSimilarityIndex: number; CharContinuationRate: number;
  TLDLegitimateProb: number; URLCharProb: number; NoOfSubDomain: number;
  HasObfuscation: number; NoOfObfuscatedChar: number; ObfuscationRatio: number;
  NoOfLettersInURL: number; LetterRatioInURL: number; NoOfDegitsInURL: number;
  DegitRatioInURL: number; NoOfEqualsInURL: number; NoOfQMarkInURL: number;
  NoOfAmpersandInURL: number; NoOfOtherSpecialCharsInURL: number;
  SpacialCharRatioInURL: number; IsHTTPS: number;
}

export type FeatureArray = Float32Array;

export interface ModelPrediction {
  score: number;
  verdict: Verdict;
  threatType?: string;
  source: 'ML' | 'GSB' | 'OVERRIDE';
}

export interface ShapExplanation {
  feature: string;
  value: number;
  importance: number;
  description: string;
  category: string;
}

export interface DetectionResult {
  url: string;
  timestamp: number;
  prediction: ModelPrediction;
  explanations: ShapExplanation[];
  processingTimeMs: number;
}
