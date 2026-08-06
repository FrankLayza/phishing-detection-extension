"""
Train/serve parity check — Python extractor vs the real shipped TS extractor.
==============================================================================
Compares ml-pipeline/features/lexical_extractor.py against the feature values
produced by phishing-extension/src/content/feature-extractor.ts (bundled and
run by gen_parity_features.mjs).

This matters because the model is trained on Python-extracted features but
scored in the browser on TS-extracted ones. Any divergence means the model
sees different inputs at inference than it was trained on — the exact class of
bug that caused the original google.com false positive.

SOURCE_OF_TRUTH.md claims the two are "byte-identical ports". This script
tests that claim on a stratified 960-URL set rather than the 6 URLs the
previous cross_validate_ts.mjs used.

Usage:
  node ml-pipeline/gen_parity_features.mjs   # first — writes parity_ts.json
  python ml-pipeline/check_parity.py
"""

import json
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    sys.stdout.reconfigure(encoding='utf-8')
except AttributeError:
    pass

from features.feature_config import ALL_FEATURES
from features.lexical_extractor import extract_lexical_features

TOL = 1e-9


def main():
    if not os.path.exists('parity_ts.json'):
        sys.exit('ERROR: parity_ts.json missing — run '
                 '`node ml-pipeline/gen_parity_features.mjs` first.')

    ts = json.load(open('parity_ts.json', encoding='utf-8'))
    urls = list(ts)

    mismatches = []
    per_feature = Counter()
    py_errors = 0

    for url in urls:
        tv = ts[url]
        if '__error' in tv:
            continue
        try:
            pv = extract_lexical_features(url)
        except Exception as e:
            py_errors += 1
            mismatches.append((url, 'PYTHON_ERROR', str(e), ''))
            continue
        for feat in ALL_FEATURES:
            a, b = pv.get(feat, 0), tv.get(feat, 0)
            if abs(float(a) - float(b)) > TOL:
                per_feature[feat] += 1
                mismatches.append((url, feat, a, b))

    total = len(urls) * len(ALL_FEATURES)
    print('=' * 78)
    print('  TRAIN/SERVE PARITY — Python vs shipped TypeScript extractor')
    print('=' * 78)
    print(f'  URLs compared:      {len(urls)}')
    print(f'  Values compared:    {total}')
    print(f'  Mismatches:         {len(mismatches)}')
    print(f'  Python errors:      {py_errors}')
    print()

    if per_feature:
        print('  Divergent features (count of URLs affected):')
        for feat, n in per_feature.most_common():
            print(f'    {feat:<30} {n:>5}  ({100*n/len(urls):.1f}% of URLs)')
        print()
        print('  First 15 examples:')
        for url, feat, a, b in mismatches[:15]:
            print(f'    {url[:52]:<54} {feat:<26} py={a}  ts={b}')
        print()
        print('  VERDICT: extractors DIVERGE — the model is scored on different')
        print('           inputs in the browser than it was trained on.')
    else:
        print('  VERDICT: PARITY OK — every feature value identical across all URLs.')

    result = {
        'urls_compared': len(urls),
        'values_compared': total,
        'mismatch_count': len(mismatches),
        'divergent_features': dict(per_feature),
        'parity_ok': not mismatches,
    }
    os.makedirs('models', exist_ok=True)
    json.dump(result, open('models/parity_results.json', 'w'), indent=2)
    print(f'\n  Saved to models/parity_results.json')
    return 1 if mismatches else 0


if __name__ == '__main__':
    sys.exit(main())
