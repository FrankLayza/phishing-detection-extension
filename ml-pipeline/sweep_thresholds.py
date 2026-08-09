"""Joint FPR / recall sweep over the CLEAN threshold.

The extension's CLEAN cut has never been calibrated — it inherited 0.50 from
sklearn's argmax default, which is a *classification* convention, not a product
decision. This script measures both sides of that choice together:

  * false-positive rate on unknown-legitimate sites (the acceptance metric), and
  * phishing recall on the held-out test split (the thing we must not trade away).

Reports both against every candidate threshold so the choice is made on evidence
rather than convention. Reuses validate_unknown_legit's populations verbatim so
the FPR column is comparable with every figure already in the docs.

Usage:  python ml-pipeline/sweep_thresholds.py
"""
import json
import os
import sys

import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
os.chdir(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from validate_unknown_legit import (  # noqa: E402
    ALL_FEATURES, build_curated, build_sampled, is_allowlisted,
    load_allowlist, load_model, score,
)

CANDIDATES = [0.50, 0.55, 0.60, 0.65, 0.70, 0.75, 0.80]


def phishing_scores(rf, scaler):
    """
    Score the held-out rows. train.py dumps the exact split to
    processed_data.pkl, so this is the same test set the reported recall and
    confusion matrix came from — no re-derivation, no chance of drift.
    NOTE: the dumped X_test is UNSCALED (the split is saved before the scaler
    is applied), so it must be transformed here.
    """
    import joblib
    _, X_test, _, y_test = joblib.load('processed_data.pkl')
    p = rf.predict_proba(scaler.transform(X_test))[:, 1]
    y_test = np.asarray(y_test)
    return p[y_test == 1], p[y_test == 0]


def main():
    rf, scaler = load_model()
    allowlist = load_allowlist()

    curated = build_curated()
    sampled = build_sampled(allowlist)
    p_cur = score(curated, rf, scaler)
    p_sam = score(sampled, rf, scaler)
    on_cur = np.array([is_allowlisted(u, allowlist) for u in curated])
    on_sam = np.array([is_allowlisted(u, allowlist) for u in sampled])

    p_phish, p_legit_test = phishing_scores(rf, scaler)

    print()
    print('=' * 92)
    print('  CLEAN-threshold sweep — false positives vs phishing recall')
    print('=' * 92)
    print(f'  {"thresh":>7} {"curated FPR":>12} {"sampled FPR":>12} '
          f'{"pipeline FPR":>13} {"recall":>9} {"test-legit FPR":>15}')
    print('  ' + '-' * 88)

    rows = []
    for t in CANDIDATES:
        cur_ml = float((p_cur >= t).mean())
        sam_ml = float((p_sam >= t).mean())
        cur_pipe = float(((p_cur >= t) & ~on_cur).mean())
        sam_pipe = float(((p_sam >= t) & ~on_sam).mean())
        recall = float((p_phish >= t).mean())
        test_fpr = float((p_legit_test >= t).mean())
        rows.append(dict(threshold=t, curated_ml_fpr=cur_ml, sampled_ml_fpr=sam_ml,
                         curated_pipeline_fpr=cur_pipe, sampled_pipeline_fpr=sam_pipe,
                         recall=recall, test_legit_fpr=test_fpr))
        print(f'  {t:>7.2f} {100*cur_ml:>11.1f}% {100*sam_ml:>11.1f}% '
              f'{100*sam_pipe:>12.1f}% {100*recall:>8.2f}% {100*test_fpr:>14.2f}%')

    print()
    print('  Read this as a trade, not a fix: every step right cuts false alarms')
    print('  and gives up some recall. Pick the point that meets the FPR target')
    print('  with the least recall lost, then state both numbers together.')

    os.makedirs('models', exist_ok=True)
    with open('models/threshold_sweep.json', 'w') as f:
        json.dump(rows, f, indent=2)
    print('\n  Saved to models/threshold_sweep.json')


if __name__ == '__main__':
    main()
