"""
Compute SHAP values for the trained model and PERSIST them to JSON.

Rationale: generate_shap_plots.py printed mean|SHAP| to stdout and saved PNGs
only, so the dissertation's SHAP table (Table 4.8) had no verifiable artifact
behind it. This script writes models/shap_values.json so every number in that
table can be traced to a file, exactly like feature_importance.json backs
Table 4.6.

Output: models/shap_values.json
  {
    "n_samples": 500,
    "random_seed": 42,
    "features": [
      {"feature": ..., "mean_abs_shap": ..., "mean_shap": ..., "direction": ...},
      ...   # sorted by mean_abs_shap descending
    ]
  }
"""
import os
import sys
import json
import warnings

import joblib
import numpy as np

warnings.filterwarnings('ignore')

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features.feature_config import ALL_FEATURES

N_SAMPLES = 500
SEED = 42


def main():
    print("Loading model + scaler...")
    model = joblib.load('models/random_forest.pkl')
    scaler = joblib.load('models/scaler.pkl')

    print("Rebuilding the held-out test split (same seed/stratify as train.py)...")
    from train import load_and_prepare_dataset
    from sklearn.model_selection import train_test_split

    X, y = load_and_prepare_dataset()
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.2, random_state=SEED, stratify=y
    )
    X_test_scaled = scaler.transform(X_test)

    rng = np.random.RandomState(SEED)
    n = min(N_SAMPLES, len(X_test_scaled))
    idx = rng.choice(len(X_test_scaled), n, replace=False)
    X_sample = X_test_scaled[idx]

    print(f"Computing exact TreeExplainer SHAP values for {n} samples...")
    import shap
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_sample)

    # Binary classifier: pick the phishing-class contribution.
    if isinstance(shap_values, list):
        sv = shap_values[1]
    elif shap_values.ndim == 3:
        sv = shap_values[:, :, 1]
    else:
        sv = shap_values

    mean_abs = np.mean(np.abs(sv), axis=0)
    mean_signed = np.mean(sv, axis=0)

    # Direction of effect: correlation between a feature's VALUE and its SHAP
    # contribution across the sample. Positive => higher values push the
    # prediction toward phishing. This is the quantity that justifies a
    # "direction of effect" claim; the mean signed SHAP does NOT, since it only
    # reports the average contribution over whatever class mix the sample has.
    rows = []
    for i, feat in enumerate(ALL_FEATURES):
        x = X_sample[:, i]
        s = sv[:, i]
        if np.std(x) < 1e-12 or np.std(s) < 1e-12:
            corr = float('nan')
            direction = 'no effect (constant)'
        else:
            corr = float(np.corrcoef(x, s)[0, 1])
            if corr > 0.15:
                direction = 'positive: higher value -> phishing'
            elif corr < -0.15:
                direction = 'negative: lower value -> phishing'
            else:
                direction = 'mixed / context-dependent'
        rows.append({
            'feature': feat,
            'mean_abs_shap': float(mean_abs[i]),
            'mean_shap': float(mean_signed[i]),
            'value_shap_corr': corr,
            'direction': direction,
        })
    rows.sort(key=lambda r: r['mean_abs_shap'], reverse=True)

    out = {'n_samples': int(n), 'random_seed': SEED, 'features': rows}
    os.makedirs('models', exist_ok=True)
    with open('models/shap_values.json', 'w') as f:
        json.dump(out, f, indent=2)

    print("\n  Rank  Feature                              mean|SHAP|    mean SHAP     corr  Direction")
    print("  " + "-" * 92)
    for r, row in enumerate(rows, 1):
        corr = row['value_shap_corr']
        corr_s = '   n/a' if corr != corr else f'{corr:+6.2f}'
        print(f"  {r:<5} {row['feature']:<35} {row['mean_abs_shap']:>11.6f} "
              f"{row['mean_shap']:>+12.6f}  {corr_s}  {row['direction']}")

    print("\nSaved models/shap_values.json")


if __name__ == "__main__":
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
    main()
