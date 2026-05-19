export interface FeatureVector {
  URLLength: number; DomainLength: number; IsDomainIP: number;
  URLSimilarityIndex: number; CharContinuationRate: number;
  TLDLegitimateProb: number; URLCharProb: number; NoOfSubDomain: number;
  HasObfuscation: number; NoOfObfuscatedChar: number; ObfuscationRatio: number;
  NoOfLettersInURL: number; LetterRatioInURL: number; NoOfDegitsInURL: number;
  DegitRatioInURL: number; NoOfEqualsInURL: number; NoOfQMarkInURL: number;
  NoOfAmpersandInURL: number; NoOfOtherSpecialCharsInURL: number;
  SpacialCharRatioInURL: number; IsHTTPS: number; DomainAgeBucket: number;
  HasTitle: number; DomainTitleMatchScore: number; URLTitleMatchScore: number;
  HasFavicon: number; Robots: number; IsResponsive: number;
  NoOfURLRedirect: number; NoOfSelfRedirect: number; HasDescription: number;
  LineOfCode: number; LargestLineLength: number; NoOfPopup: number;
  NoOfiFrame: number; HasExternalFormSubmit: number; HasSocialNet: number;
  HasSubmitButton: number; HasHiddenFields: number; HasPasswordField: number;
  Bank: number; Pay: number; Crypto: number; HasCopyrightInfo: number;
}

export type FeatureArray = Float32Array;

export interface ModelPrediction {
  isPhishing: boolean;
  score: number;
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
