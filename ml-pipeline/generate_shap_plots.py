"""
Generate SHAP summary plot for the Random Forest phishing model.
Uses the model directly with synthetic representative data.
"""
import joblib
import numpy as np
import pandas as pd
import sys
import os
import warnings
warnings.filterwarnings('ignore')

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features.feature_config import ALL_FEATURES

def generate_shap_analysis():
    print("Loading model...")
    model = joblib.load('models/random_forest.pkl')
    scaler = joblib.load('models/scaler.pkl')

    # Re-derive test data from the actual dataset (same as train.py)
    print("Loading datasets to get test split...")
    from train import load_and_prepare_dataset
    X, y = load_and_prepare_dataset()

    from sklearn.model_selection import train_test_split
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Scale test data
    X_test_scaled = scaler.transform(X_test)

    # Subsample for SHAP (500 samples for a good plot)
    np.random.seed(42)
    n_samples = min(500, len(X_test_scaled))
    idx = np.random.choice(len(X_test_scaled), n_samples, replace=False)
    X_sample = X_test_scaled[idx]

    print(f"Computing SHAP values for {n_samples} samples...")
    print("(This may take a few minutes...)")

    import shap

    # Use TreeExplainer for Random Forest (fast, exact)
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_sample)

    # For binary classification, shap_values is a list of 2 arrays
    # shap_values[1] = SHAP values for the phishing class
    if isinstance(shap_values, list):
        shap_vals_phishing = shap_values[1]
    else:
        shap_vals_phishing = shap_values

    # --- Plot 1: SHAP Summary (Beeswarm) Plot ---
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt

    print("\nGenerating SHAP summary plot...")
    plt.figure(figsize=(10, 8))
    shap.summary_plot(
        shap_vals_phishing,
        X_sample,
        feature_names=ALL_FEATURES,
        show=False,
        max_display=15
    )
    plt.title("SHAP Summary Plot - Feature Impact on Phishing Prediction", fontsize=13, pad=15)
    plt.tight_layout()
    plt.savefig('models/shap_summary_plot.png', dpi=200, bbox_inches='tight')
    plt.close()
    print("  Saved: models/shap_summary_plot.png")

    # --- Plot 2: SHAP Bar Plot (Mean |SHAP|) ---
    plt.figure(figsize=(10, 8))
    shap.summary_plot(
        shap_vals_phishing,
        X_sample,
        feature_names=ALL_FEATURES,
        plot_type="bar",
        show=False,
        max_display=15
    )
    plt.title("Mean Absolute SHAP Values - Feature Importance", fontsize=13, pad=15)
    plt.tight_layout()
    plt.savefig('models/shap_bar_plot.png', dpi=200, bbox_inches='tight')
    plt.close()
    print("  Saved: models/shap_bar_plot.png")

    # --- Print Top 15 SHAP values ---
    mean_abs_shap = np.mean(np.abs(shap_vals_phishing), axis=0)
    feature_shap = list(zip(ALL_FEATURES, mean_abs_shap))
    feature_shap.sort(key=lambda x: x[1], reverse=True)

    print("\n" + "=" * 60)
    print("  Top 15 Features by Mean |SHAP Value|")
    print("=" * 60)
    print(f"  {'Rank':<5} {'Feature':<35} {'Mean |SHAP|':>12}")
    print(f"  {'-'*55}")
    for i, (feat, val) in enumerate(feature_shap[:15], 1):
        print(f"  {i:<5} {feat:<35} {val:>12.6f}")

    # --- Directionality analysis ---
    print("\n" + "=" * 60)
    print("  Feature Directionality (Mean SHAP, not absolute)")
    print("  Positive = pushes toward PHISHING")
    print("  Negative = pushes toward LEGITIMATE")
    print("=" * 60)
    mean_shap = np.mean(shap_vals_phishing, axis=0)
    feature_dir = list(zip(ALL_FEATURES, mean_shap))
    feature_dir.sort(key=lambda x: abs(x[1]), reverse=True)
    for feat, val in feature_dir[:15]:
        direction = "-> PHISHING" if val > 0 else "-> LEGITIMATE"
        print(f"  {feat:<35} {val:>+10.6f}  {direction}")

    print("\nSHAP analysis complete.")

if __name__ == "__main__":
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
    generate_shap_analysis()
