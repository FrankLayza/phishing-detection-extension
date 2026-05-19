import type { FeatureVector } from "../types";

export function extractPageFeatures(url: string, html: string): FeatureVector {
  const features: Partial<FeatureVector> = {};
  
  // Lexical & Domain (Basic extraction)
  features.URLLength = url.length;
  features.DomainLength = new URL(url).hostname.length;
  features.IsHTTPS = url.startsWith("https") ? 1 : 0;
  features.IsDomainIP = /^[0-9.]+$/.test(new URL(url).hostname) ? 1 : 0;
  features.URLSimilarityIndex = 0; // Requires external checking in a real impl
  
  // Character probabilities
  features.NoOfSubDomain = new URL(url).hostname.split('.').length - 2;
  features.NoOfObfuscatedChar = (url.match(/%[0-9a-fA-F]{2}/g) || []).length;
  features.ObfuscationRatio = features.NoOfObfuscatedChar / url.length;
  features.NoOfLettersInURL = (url.match(/[a-zA-Z]/g) || []).length;
  features.LetterRatioInURL = features.NoOfLettersInURL / url.length;
  features.NoOfDegitsInURL = (url.match(/[0-9]/g) || []).length;
  features.DegitRatioInURL = features.NoOfDegitsInURL / url.length;
  features.NoOfEqualsInURL = (url.match(/=/g) || []).length;
  features.NoOfQMarkInURL = (url.match(/\?/g) || []).length;
  features.NoOfAmpersandInURL = (url.match(/&/g) || []).length;
  
  // Content features from DOM
  const parser = new DOMParser();
  const doc = parser.parseFromString(html, "text/html");
  
  features.LineOfCode = html.split('\n').length;
  features.LargestLineLength = Math.max(...html.split('\n').map(l => l.length));
  
  features.HasTitle = doc.title ? 1 : 0;
  features.HasFavicon = doc.querySelector('link[rel*="icon"]') ? 1 : 0;
  features.HasPasswordField = doc.querySelector('input[type="password"]') ? 1 : 0;
  features.HasHiddenFields = doc.querySelector('input[type="hidden"]') ? 1 : 0;
  
  const text = doc.body?.innerText?.toLowerCase() || '';
  features.Bank = text.includes('bank') || text.includes('account') ? 1 : 0;
  features.Pay = text.includes('pay') || text.includes('checkout') ? 1 : 0;
  features.Crypto = text.includes('crypto') || text.includes('wallet') ? 1 : 0;
  features.HasCopyrightInfo = text.includes('copyright') || text.includes('©') ? 1 : 0;

  // Fill remaining features with 0 to complete the 44 features
  const defaultFeatures: FeatureVector = {
    URLLength: 0, DomainLength: 0, IsDomainIP: 0, URLSimilarityIndex: 0,
    CharContinuationRate: 0, TLDLegitimateProb: 0, URLCharProb: 0, NoOfSubDomain: 0,
    HasObfuscation: 0, NoOfObfuscatedChar: 0, ObfuscationRatio: 0, NoOfLettersInURL: 0,
    LetterRatioInURL: 0, NoOfDegitsInURL: 0, DegitRatioInURL: 0, NoOfEqualsInURL: 0,
    NoOfQMarkInURL: 0, NoOfAmpersandInURL: 0, NoOfOtherSpecialCharsInURL: 0,
    SpacialCharRatioInURL: 0, IsHTTPS: 0, DomainAgeBucket: 0, HasTitle: 0,
    DomainTitleMatchScore: 0, URLTitleMatchScore: 0, HasFavicon: 0, Robots: 0,
    IsResponsive: 0, NoOfURLRedirect: 0, NoOfSelfRedirect: 0, HasDescription: 0,
    LineOfCode: 0, LargestLineLength: 0, NoOfPopup: 0, NoOfiFrame: 0,
    HasExternalFormSubmit: 0, HasSocialNet: 0, HasSubmitButton: 0, HasHiddenFields: 0,
    HasPasswordField: 0, Bank: 0, Pay: 0, Crypto: 0, HasCopyrightInfo: 0
  };

  return { ...defaultFeatures, ...features } as FeatureVector;
}
