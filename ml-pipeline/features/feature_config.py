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

# v4: all 21 lexical features are KEPT.
#
# An earlier note here claimed the raw length/count features (URLLength,
# DomainLength, NoOfLettersInURL, NoOfDegitsInURL and the No-Of-* counts) had
# been dropped because they encoded a population bias in PhiUSIIL. They were
# never actually removed from this list, and — measured on the fixed corpus —
# they should not be. Dropping them to a 12-feature scale-invariant subset was
# tested (Aug 2026) and was worse on every axis:
#
#     metric                    21-feature      12-feature
#     curated unknown-legit FPR      18.1%          34.7%
#     sampled unknown-legit FPR      19.1%          29.0%
#     phishing recall                90.8%          87.8%
#     held-out accuracy             0.9282         0.8461
#
# The original reasoning confused two different problems. The real bias was in
# the CORPUS, not the features: the legitimate class was built by attaching a
# fixed list of short, shallow paths to top-sites domains while the phishing
# class carried real paths, so URL *structure* leaked the label. That is fixed
# in train.py (build_legit_urls / measure_structure). With structure matched
# across classes, length and count features carry genuine signal — long
# hyphenated hostnames and digit-heavy addresses really are informative — and
# removing them only discards evidence.
LEXICAL_FEATURES = [
    'URLLength', 'DomainLength', 'IsDomainIP', 'URLSimilarityIndex',
    'CharContinuationRate', 'TLDLegitimateProb', 'URLCharProb', 'NoOfSubDomain',
    'HasObfuscation', 'NoOfObfuscatedChar', 'ObfuscationRatio', 'NoOfLettersInURL',
    'LetterRatioInURL', 'NoOfDegitsInURL', 'DegitRatioInURL', 'NoOfEqualsInURL',
    'NoOfQMarkInURL', 'NoOfAmpersandInURL', 'NoOfOtherSpecialCharsInURL',
    'SpacialCharRatioInURL', 'IsHTTPS'
]

# Dropped from the model (train/serve skew). Kept here, empty, so any
# pipeline code referencing them degrades gracefully to "no content features".
DOMAIN_FEATURES = []
CONTENT_FEATURES = []

ALL_FEATURES = LEXICAL_FEATURES + DOMAIN_FEATURES + CONTENT_FEATURES
assert len(ALL_FEATURES) == 21  # v4 robust scale-invariant lexical subset

FEATURE_CATEGORIES = {
    'URL_STRUCTURE': LEXICAL_FEATURES,
    'DOMAIN_TRUST': DOMAIN_FEATURES,
    'PAGE_CONTENT': CONTENT_FEATURES
}
