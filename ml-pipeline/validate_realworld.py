"""
Real-world URL validation for the PhishGuard model.
Tests the trained model against curated safe and phishing URL patterns
using only lexical features (no page fetch required).
"""
import sys
import os
import json
import numpy as np
import pandas as pd
import joblib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from features.feature_config import ALL_FEATURES, DOMAIN_FEATURES, CONTENT_FEATURES
from features.lexical_extractor import extract_lexical_features

# -------------------------------------------------------------------------
# Curated test URLs — these should NEVER be in the training data
# -------------------------------------------------------------------------
TEST_CASES = [
    # --- SAFE URLs (label=0) ---
    {"url": "https://google.com",                   "label": 0, "note": "Major search engine"},
    {"url": "https://github.com",                   "label": 0, "note": "Developer platform"},
    {"url": "https://stackoverflow.com",            "label": 0, "note": "Q&A site"},
    {"url": "https://bbc.co.uk",                    "label": 0, "note": "News site (.co.uk TLD)"},
    {"url": "https://wikipedia.org",                "label": 0, "note": "Encyclopedia"},
    {"url": "https://microsoft.com",                "label": 0, "note": "Tech company"},
    {"url": "https://amazon.com/dp/B08N5WRWNW",    "label": 0, "note": "Amazon product page"},
    {"url": "https://docs.python.org/3/library/os.html", "label": 0, "note": "Python docs"},
    {"url": "https://en.wikipedia.org/wiki/Phishing", "label": 0, "note": "Wikipedia article"},
    {"url": "https://accounts.google.com/signin",   "label": 0, "note": "Real Google login"},

    # --- PHISHING URLs (label=1) ---
    {"url": "http://secure-paypal-login.tk/verify/account",     "label": 1, "note": ".tk + paypal impersonation"},
    {"url": "http://g00gle-security.ml/alert/verify",           "label": 1, "note": ".ml + google typosquat"},
    {"url": "http://amaz0n-security.ga/update-payment",         "label": 1, "note": ".ga + amazon typosquat"},
    {"url": "http://micr0soft-support.cf/password-reset",       "label": 1, "note": ".cf + microsoft typosquat"},
    {"url": "http://192.168.1.100/banking-login",               "label": 1, "note": "IP address + banking"},
    {"url": "http://login-appleid.secure-check.tk/verify",      "label": 1, "note": ".tk + apple impersonation"},
    {"url": "http://paypa1-security.gq/update/billing",         "label": 1, "note": ".gq + paypal typosquat"},
    {"url": "http://chase-banking-secure.ml/signin?user=12345", "label": 1, "note": ".ml + chase impersonation"},
    {"url": "http://netfl1x-account.ga/verify/payment",         "label": 1, "note": ".ga + netflix typosquat"},
    {"url": "http://faceb00k-security.tk/confirm/login?id=abc123&ref=email", "label": 1, "note": ".tk + facebook typosquat"},
]


def validate():
    """Run model predictions on curated test URLs."""
    print("=" * 70)
    print("  PhishGuard Real-World URL Validation")
    print("=" * 70)

    model = joblib.load('models/random_forest.pkl')
    scaler = joblib.load('models/scaler.pkl')

    results = []
    correct = 0
    total = len(TEST_CASES)

    for tc in TEST_CASES:
        url = tc['url']
        expected = tc['label']
        note = tc['note']

        # Extract lexical features (same as inference)
        lexical = extract_lexical_features(url)

        # Build full feature vector with content/domain = 0
        # (simulates page-not-fetched scenario)
        features = {f: 0 for f in ALL_FEATURES}
        features.update(lexical)

        df = pd.DataFrame([features], columns=ALL_FEATURES)
        X_scaled = scaler.transform(df)

        prob = model.predict_proba(X_scaled)[0][1]
        predicted = 1 if prob >= 0.5 else 0
        is_correct = predicted == expected

        if is_correct:
            correct += 1

        status = "[OK]" if is_correct else "[FAIL]"
        label_str = "PHISH" if expected == 1 else "SAFE"
        pred_str = "PHISH" if predicted == 1 else "SAFE"

        results.append({
            'url': url,
            'expected': label_str,
            'predicted': pred_str,
            'probability': prob,
            'correct': is_correct,
            'note': note,
        })

        print(f"\n  {status} {url}")
        print(f"     Expected: {label_str} | Predicted: {pred_str} (p={prob:.3f})")
        if not is_correct:
            print(f"     [MISMATCH] - {note}")

    # Summary
    accuracy = correct / total
    safe_cases = [r for r in results if r['expected'] == 'SAFE']
    phish_cases = [r for r in results if r['expected'] == 'PHISH']
    safe_correct = sum(1 for r in safe_cases if r['correct'])
    phish_correct = sum(1 for r in phish_cases if r['correct'])

    print(f"\n{'=' * 70}")
    print(f"  VALIDATION SUMMARY")
    print(f"{'=' * 70}")
    print(f"  Overall:   {correct}/{total} correct ({accuracy:.1%})")
    print(f"  Safe URLs:    {safe_correct}/{len(safe_cases)} correct")
    print(f"  Phishing URLs: {phish_correct}/{len(phish_cases)} correct")

    if accuracy < 0.8:
        print(f"\n  [WARNING] Accuracy below 80% - model needs improvement!")
    elif accuracy < 0.9:
        print(f"\n  [ACCEPTABLE] - but could be improved with more training data")
    else:
        print(f"\n  [EXCELLENT] Strong real-world detection performance!")

    # Save results
    with open('models/realworld_validation.json', 'w') as f:
        json.dump({
            'accuracy': accuracy,
            'total': total,
            'correct': correct,
            'safe_accuracy': safe_correct / len(safe_cases) if safe_cases else 0,
            'phish_accuracy': phish_correct / len(phish_cases) if phish_cases else 0,
            'results': results,
        }, f, indent=2)
    print(f"\n  Results saved to models/realworld_validation.json")
    print(f"{'=' * 70}")

    return accuracy


if __name__ == "__main__":
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
    validate()
