"""
evaluate.py - Standalone model evaluation script
Per Section 9.3 of the Consolidated_Implementation_Guide.md
"""
import sys
import os
import json
import numpy as np
import joblib
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score,
    f1_score, confusion_matrix, roc_auc_score,
    classification_report
)
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend
import matplotlib.pyplot as plt
import seaborn as sns

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features.feature_config import ALL_FEATURES

def evaluate():
    print("=" * 60)
    print("  PhishGuard Model Evaluation Report")
    print("=" * 60)

    # ---------------------------------------------------------------
    # Load model, scaler, and pre-saved processed data
    # ---------------------------------------------------------------
    model  = joblib.load('models/random_forest.pkl')
    scaler = joblib.load('models/scaler.pkl')

    # We load from models/evaluation_results.json if it exists (fast)
    # Otherwise we re-run full evaluation on processed_data.pkl
    results_path = 'models/evaluation_results.json'
    if os.path.exists(results_path):
        print("\nLoading cached evaluation results from models/evaluation_results.json")
        with open(results_path) as f:
            cached = json.load(f)
        print(f"\n  Accuracy:  {cached['accuracy']:.4f}")
        print(f"  Precision: {cached['precision']:.4f}")
        print(f"  Recall:    {cached['recall']:.4f}")
        print(f"  F1-Score:  {cached['f1_score']:.4f}")
        print(f"\n  Confusion Matrix:")
        cm = np.array(cached['confusion_matrix'])
        print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
        print(f"    FN={cm[1][0]}  TP={cm[1][1]}")
        print(f"\n  False Positive Rate: {cm[0][1]/(cm[0][0]+cm[0][1]):.4f}")
        print(f"  False Negative Rate: {cm[1][0]/(cm[1][0]+cm[1][1]):.4f}")
        _plot_confusion_matrix(cm)
        _print_feature_importance(model)
        return

    # Full re-evaluation
    print("\nLoading processed data from processed_data.pkl...")
    try:
        data = joblib.load('processed_data.pkl')
    except FileNotFoundError:
        print("ERROR: processed_data.pkl not found. Run `python ml-pipeline/train.py` first.")
        sys.exit(1)

    # Support both old (4-tuple) and new (5-tuple) formats
    if len(data) == 6:
        X_train, X_val, X_test, y_train, y_val, y_test = data
    elif len(data) == 4:
        X_train, X_test, y_train, y_test = data
        X_val, y_val = X_test, y_test
    else:
        print(f"ERROR: Unexpected data format with {len(data)} elements.")
        sys.exit(1)

    X_test_scaled = scaler.transform(X_test)
    y_pred = model.predict(X_test_scaled)
    y_prob = model.predict_proba(X_test_scaled)[:, 1]

    results = {
        'accuracy':         accuracy_score(y_test, y_pred),
        'precision':        precision_score(y_test, y_pred),
        'recall':           recall_score(y_test, y_pred),
        'f1_score':         f1_score(y_test, y_pred),
        'auc_roc':          roc_auc_score(y_test, y_prob),
        'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
    }

    print(f"\n  Accuracy:  {results['accuracy']:.4f}")
    print(f"  Precision: {results['precision']:.4f}")
    print(f"  Recall:    {results['recall']:.4f}")
    print(f"  F1-Score:  {results['f1_score']:.4f}")
    print(f"  AUC-ROC:   {results['auc_roc']:.4f}")

    cm = np.array(results['confusion_matrix'])
    print(f"\n  Confusion Matrix:")
    print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"    FN={cm[1][0]}  TP={cm[1][1]}")
    print(f"\n  False Positive Rate: {cm[0][1]/(cm[0][0]+cm[0][1]):.4f}")
    print(f"  False Negative Rate: {cm[1][0]/(cm[1][0]+cm[1][1]):.4f}")

    print("\n  Full Classification Report:")
    print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))

    with open(results_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n  Results saved to {results_path}")

    _plot_confusion_matrix(cm)
    _print_feature_importance(model)

def _plot_confusion_matrix(cm: np.ndarray):
    try:
        os.makedirs('models', exist_ok=True)
        fig, ax = plt.subplots(figsize=(6, 5))
        sns.heatmap(
            cm, annot=True, fmt='d', cmap='Blues',
            xticklabels=['Predicted Safe', 'Predicted Phishing'],
            yticklabels=['Actual Safe', 'Actual Phishing'], ax=ax
        )
        ax.set_title('PhishGuard Confusion Matrix', fontsize=14, fontweight='bold')
        plt.tight_layout()
        path = 'models/confusion_matrix.png'
        plt.savefig(path, dpi=150)
        plt.close()
        print(f"\n  Confusion matrix chart saved to {path}")
    except Exception as e:
        print(f"  (Chart generation skipped: {e})")

def _print_feature_importance(model):
    importance_path = 'models/feature_importance.json'
    if os.path.exists(importance_path):
        with open(importance_path) as f:
            importances = json.load(f)
        top10 = list(importances.items())[:10]
        print("\n  Top 10 Most Important Features:")
        print(f"  {'Feature':<38} {'Importance':>10}")
        print(f"  {'-'*50}")
        for feat, imp in top10:
            bar = '#' * int(imp * 200)
            print(f"  {feat:<38} {imp:>8.4f}  {bar}")
    else:
        importances = dict(zip(ALL_FEATURES, model.feature_importances_))
        sorted_imp = sorted(importances.items(), key=lambda x: x[1], reverse=True)
        print("\n  Top 10 Most Important Features:")
        for feat, imp in sorted_imp[:10]:
            print(f"    {feat:<38} {imp:.4f}")

    print("\n" + "="*60)

if __name__ == "__main__":
    evaluate()
