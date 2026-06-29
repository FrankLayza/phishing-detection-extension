"""
Regenerate cross_validation_data.json for the v3 lexical-only model.

For each validation URL: self-extract the 21 lexical features (the SAME code
path the browser extension uses), scale with the trained MinMaxScaler, and run
the Random Forest. Writes the raw vector, scaled vector, feature names, and the
Python phishing probability so cross_validate_ts.mjs can confirm the TypeScript
inference reproduces these scores exactly.
"""
import os, sys, json
import joblib
import numpy as np

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features.feature_config import ALL_FEATURES
from features.lexical_extractor import extract_lexical_features

ROOT = os.path.dirname(os.path.abspath(__file__)) + "/.."
os.chdir(ROOT)

URLS = [
    "https://google.com",
    "https://github.com",
    "https://wikipedia.org",
    "https://paypal.com",
    "https://secure-paypal-login.tk/verify/account",
    "http://192.168.1.1/login.php?account=verify",
]

model = joblib.load("models/random_forest.pkl")
scaler = joblib.load("models/scaler.pkl")

results = []
for url in URLS:
    feats = extract_lexical_features(url)
    raw = [float(feats[f]) for f in ALL_FEATURES]
    scaled = scaler.transform([raw])[0]
    prob = float(model.predict_proba([scaled])[0][1])
    results.append({
        "url": url,
        "page_unreachable": False,
        "raw_vector": raw,
        "scaled_vector": [float(x) for x in scaled],
        "feature_names": list(ALL_FEATURES),
        "ml_phish_prob": prob,
    })
    print(f"  {url:50} p={prob:.4f}")

with open("cross_validation_data.json", "w") as f:
    json.dump({"results": results}, f, indent=1)
print(f"\nWrote cross_validation_data.json ({len(results)} URLs, {len(ALL_FEATURES)} features each)")
