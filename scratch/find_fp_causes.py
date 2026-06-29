import joblib
import numpy as np
import pandas as pd
import sys
import os

sys.path.insert(0, 'ml-pipeline')
from features.feature_config import ALL_FEATURES

# Load model and scaler
model = joblib.load('models/random_forest.pkl')
scaler = joblib.load('models/scaler.pkl')

# Base google.com vector (extracted from python live run)
base_vector = {
    'URLLength': 18.0,
    'DomainLength': 10.0,
    'IsDomainIP': 0.0,
    'URLSimilarityIndex': 0.0,
    'CharContinuationRate': 0.6470588235294118,
    'TLDLegitimateProb': 0.95,
    'URLCharProb': 0.042222222222222223,
    'NoOfSubDomain': 0.0,
    'HasObfuscation': 0.0,
    'NoOfObfuscatedChar': 0.0,
    'ObfuscationRatio': 0.0,
    'NoOfLettersInURL': 14.0,
    'LetterRatioInURL': 0.7777777777777778,
    'NoOfDegitsInURL': 0.0,
    'DegitRatioInURL': 0.0,
    'NoOfEqualsInURL': 0.0,
    'NoOfQMarkInURL': 0.0,
    'NoOfAmpersandInURL': 0.0,
    'NoOfOtherSpecialCharsInURL': 1.0,
    'SpacialCharRatioInURL': 0.05555555555555555,
    'IsHTTPS': 1.0,
    'DomainAgeBucket': 0.0,
    'HasTitle': 1.0,
    'DomainTitleMatchScore': 1.0,
    'URLTitleMatchScore': 0.0,
    'HasFavicon': 0.0,
    'Robots': 0.0,
    'IsResponsive': 0.0,
    'NoOfURLRedirect': 1.0,
    'NoOfSelfRedirect': 1.0,
    'HasDescription': 0.0,
    'LineOfCode': 148.0,
    'LargestLineLength': 15549.0,
    'NoOfPopup': 0.0,
    'NoOfiFrame': 0.0,
    'HasExternalFormSubmit': 0.0,
    'HasSocialNet': 0.0,
    'HasSubmitButton': 1.0,
    'HasHiddenFields': 1.0,
    'HasPasswordField': 0.0,
    'Bank': 0.0,
    'Pay': 0.0,
    'Crypto': 0.0,
    'HasCopyrightInfo': 1.0
}

def predict(vector):
    df = pd.DataFrame([vector], columns=ALL_FEATURES)
    X_scaled = scaler.transform(df.values)
    # Apply the IsHTTPS workaround from test_url.py
    if 'IsHTTPS' in ALL_FEATURES:
        idx = ALL_FEATURES.index('IsHTTPS')
        raw_val = float(df['IsHTTPS'].values[0])
        data_max = float(scaler.data_max_[idx])
        X_scaled[0, idx] = max(0.0, min(1.0, raw_val / data_max if data_max > 0 else 0.0))
    prob = model.predict_proba(X_scaled)[0][1]
    return prob

base_prob = predict(base_vector)
print(f"Base google.com probability: {base_prob:.4f}")

# 1. Test single feature variations
print("\n--- Testing Single Feature Variations ---")
for feat in ALL_FEATURES:
    # Try different logical variations for the feature
    val = base_vector[feat]
    test_vals = []
    if val == 0.0 or val == 1.0:
        test_vals = [1.0 - val] # flip binary feature
    elif feat in ['LineOfCode', 'LargestLineLength']:
        test_vals = [1.0, 5.0, 10.0, 50.0, 1000.0, 10000.0]
    elif feat == 'URLSimilarityIndex':
        test_vals = [0.1, 0.3, 0.5, 0.8, 1.0]
    elif feat == 'NoOfSubDomain':
        test_vals = [1.0, 2.0, 3.0, 5.0]
    elif feat in ['NoOfURLRedirect', 'NoOfSelfRedirect']:
        test_vals = [0.0, 2.0, 5.0]

    for tv in test_vals:
        modified = dict(base_vector)
        modified[feat] = tv
        prob = predict(modified)
        if abs(prob - base_prob) > 0.05:
            print(f"  {feat:30} changed to {tv:8} -> Prob: {prob:.4f} (diff: {prob-base_prob:+.4f})")

# 2. Test Chrome extension defaults/scenario
print("\n--- Testing Chrome Extension Specific Defaults (google.com) ---")
chrome_vector = dict(base_vector)
chrome_vector['NoOfURLRedirect'] = 0.0
chrome_vector['NoOfSelfRedirect'] = 0.0

# In Chrome, IsResponsive, Robots, HasFavicon might be extracted differently
# Let's see how changing multiple features at once affects it
chrome_prob = predict(chrome_vector)
print(f"With Redirects = 0: {chrome_prob:.4f}")

# What if LineOfCode is very small (like 10) and LargestLineLength is very small?
chrome_vector_small_page = dict(chrome_vector)
chrome_vector_small_page['LineOfCode'] = 10.0
chrome_vector_small_page['LargestLineLength'] = 100.0
print(f"With Redirects = 0 and LineOfCode = 10: {predict(chrome_vector_small_page):.4f}")

# What if URLSimilarityIndex is 1.0 (exact path segment match)?
chrome_vector_sim = dict(chrome_vector)
chrome_vector_sim['URLSimilarityIndex'] = 1.0
print(f"With Redirects = 0 and URLSimilarityIndex = 1.0: {predict(chrome_vector_sim):.4f}")
