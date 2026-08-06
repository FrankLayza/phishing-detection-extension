"""
Generate phishing-extension/assets/shap_mapping.json from the TRAINED model.
=============================================================================
This file drives the popup's "why" panel. It was previously hand-maintained and
drifted badly: it held 12 of the 21 model features with importances from an
older model, and was missing DomainLength (the #2 feature) and URLLength — so
the popup could never cite the signals that actually drove those verdicts.

Deriving it from models/feature_importance.json makes drift impossible: every
model feature gets an entry, with the current importance, on every retrain.

Usage: python ml-pipeline/gen_shap_mapping.py
Run this after train.py, before `pnpm build`.
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from features.feature_config import (ALL_FEATURES, CONTENT_FEATURES,
                                     DOMAIN_FEATURES, LEXICAL_FEATURES)

OUT_PATH = 'phishing-extension/assets/shap_mapping.json'
IMPORTANCE_PATH = 'models/feature_importance.json'

# User-facing copy per feature. Phrased as an observation about the URL, not a
# verdict: the popup shows importance weight, not per-prediction direction, so
# the text must not assert "this is why it's phishing".
DESCRIPTIONS = {
    'URLLength': 'Overall length of the web address',
    'DomainLength': 'Length of the domain name',
    'IsDomainIP': 'Uses a raw IP address instead of a domain name',
    'URLSimilarityIndex': 'Domain closely resembles a well-known brand (possible typosquat)',
    'CharContinuationRate': 'Runs of repeated character types in the address',
    'TLDLegitimateProb': 'Trust level of the domain ending (.com, .tk, etc.)',
    'URLCharProb': 'How typical the character mix is for a real web address',
    'NoOfSubDomain': 'Number of subdomain levels (e.g. login.secure.example.com)',
    'HasObfuscation': 'Address contains percent-encoded characters',
    'NoOfObfuscatedChar': 'Count of percent-encoded characters',
    'ObfuscationRatio': 'Share of the address that is percent-encoded',
    'NoOfLettersInURL': 'Count of letters in the address',
    'LetterRatioInURL': 'Share of the address that is letters',
    'NoOfDegitsInURL': 'Count of digits in the address',
    'DegitRatioInURL': 'Share of the address that is digits',
    'NoOfEqualsInURL': "Count of '=' characters (query parameters)",
    'NoOfQMarkInURL': "Count of '?' characters (query strings)",
    'NoOfAmpersandInURL': "Count of '&' characters (chained parameters)",
    'NoOfOtherSpecialCharsInURL': 'Count of unusual special characters',
    'SpacialCharRatioInURL': 'Share of the address that is special characters',
    'IsHTTPS': 'Whether the connection is encrypted (HTTPS)',
}

# Thresholds used only for emphasis in the UI, where a meaningful cut exists.
THRESHOLDS = {
    'NoOfSubDomain': {'high': 3, 'medium': 2},
    'TLDLegitimateProb': {'high': 0.3, 'medium': 0.5},
    'URLSimilarityIndex': {'high': 0.8, 'medium': 0.6},
    'ObfuscationRatio': {'high': 0.1, 'medium': 0.05},
    'DegitRatioInURL': {'high': 0.3, 'medium': 0.15},
    'SpacialCharRatioInURL': {'high': 0.1, 'medium': 0.05},
    'URLLength': {'high': 75, 'medium': 45},
    'DomainLength': {'high': 25, 'medium': 18},
}


def category_for(feat):
    if feat in LEXICAL_FEATURES:
        return 'URL_STRUCTURE'
    if feat in DOMAIN_FEATURES:
        return 'DOMAIN_TRUST'
    if feat in CONTENT_FEATURES:
        return 'PAGE_CONTENT'
    return 'URL_STRUCTURE'


def main():
    if not os.path.exists(IMPORTANCE_PATH):
        sys.exit(f'ERROR: {IMPORTANCE_PATH} not found — run train.py first.')

    with open(IMPORTANCE_PATH) as f:
        importances = json.load(f)

    missing_desc = [f for f in ALL_FEATURES if f not in DESCRIPTIONS]
    if missing_desc:
        sys.exit(f'ERROR: no user-facing description for: {missing_desc}\n'
                 f'Add them to DESCRIPTIONS in this script.')

    mapping = {}
    for feat in ALL_FEATURES:
        if feat not in importances:
            print(f'  WARNING: {feat} absent from {IMPORTANCE_PATH}, importance set to 0')
        mapping[feat] = {
            'importance': float(importances.get(feat, 0.0)),
            'category': category_for(feat),
            'description': DESCRIPTIONS[feat],
            'thresholds': THRESHOLDS.get(feat, {}),
        }

    # Emit in descending importance so the file reads as a ranking.
    mapping = dict(sorted(mapping.items(), key=lambda kv: -kv[1]['importance']))

    with open(OUT_PATH, 'w') as f:
        json.dump(mapping, f, indent=2)

    print(f'Wrote {OUT_PATH}')
    print(f'  features: {len(mapping)} (model has {len(ALL_FEATURES)})')
    print(f'  top 5: {", ".join(list(mapping)[:5])}')
    stale = [f for f in importances if f not in ALL_FEATURES]
    if stale:
        print(f'  note: dropped features not in current set: {stale}')


if __name__ == '__main__':
    main()
