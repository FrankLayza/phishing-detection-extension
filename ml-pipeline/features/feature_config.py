"""
Feature configuration — single source of truth for feature set & order.

v3 (parity-safe): the model now uses ONLY the 21 lexical (URL-string)
features. The DOM/content features were dropped because they suffer
fundamental train/serve skew — the PhiUSIIL dataset computed them from
server-fetched HTML, but the browser extension computes them from the
live rendered DOM, so values like LineOfCode (the old #1 feature) ranged
2..442,700 in training yet arrived unscaled and out-of-distribution at
inference, producing false positives on legitimate sites (e.g. google.com
scoring 91.8% PHISHING).

Lexical features are self-extracted by the SAME code path in Python
(features/lexical_extractor.py) and TypeScript
(phishing-extension/src/content/feature-extractor.ts), guaranteeing exact
train/inference parity. See SOURCE_OF_TRUTH.md.
"""

# v4: robust subset. The raw length/count features (URLLength, DomainLength,
# NoOfLettersInURL, NoOfDegitsInURL, and the No-Of-* counts) were dropped because
# they ENCODE a population bias in PhiUSIIL: legitimate URLs are obscure
# long-named domains while phishing/short famous brands are shorter, so the model
# learned "short domain => phishing" and flagged real homepages (google.com etc.).
# We keep only scale-invariant, generalizable signals: TLD legitimacy, brand/typo
# similarity, IP-as-host, obfuscation, subdomain count, and length-normalized
# character ratios. These separate real phishing (.tk/.gq TLDs, typosquats, digits,
# obfuscation) from legitimate sites without keying on raw URL length.
LEXICAL_FEATURES = [
    'IsDomainIP', 'URLSimilarityIndex', 'CharContinuationRate',
    'TLDLegitimateProb', 'URLCharProb', 'NoOfSubDomain',
    'HasObfuscation', 'ObfuscationRatio', 'LetterRatioInURL',
    'DegitRatioInURL', 'SpacialCharRatioInURL', 'IsHTTPS'
]

# Dropped from the model (train/serve skew). Kept here, empty, so any
# pipeline code referencing them degrades gracefully to "no content features".
DOMAIN_FEATURES = []
CONTENT_FEATURES = []

ALL_FEATURES = LEXICAL_FEATURES + DOMAIN_FEATURES + CONTENT_FEATURES
assert len(ALL_FEATURES) == 12  # v4 robust scale-invariant lexical subset

FEATURE_CATEGORIES = {
    'URL_STRUCTURE': LEXICAL_FEATURES,
    'DOMAIN_TRUST': DOMAIN_FEATURES,
    'PAGE_CONTENT': CONTENT_FEATURES
}
