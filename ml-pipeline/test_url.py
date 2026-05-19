"""
PhishGuard Detection Pipeline
==============================
Architecture (matches Consolidated_Implementation_Guide.md Section 1.2):

  STEP 1: Local ML Model (Random Forest via ONNX-trained sklearn model)
          - Extracts 44 lexical + content + domain features
          - Fast, private, no network calls needed

  STEP 2: Domain Age Check (whois)
          - Newly registered domains (<1yr) are high-risk

  STEP 3: Google Safe Browsing API fallback
          - Only triggered when ML confidence is borderline (40-70%)
          - Final authoritative verdict from Google's threat database

  STEP 4: Weighted Fusion + Verdict
          - Combines all signals into a final risk score

Set your Google Safe Browsing API key below or in env var GSB_API_KEY.
Get a free key at: https://developers.google.com/safe-browsing/v4/get-started
"""

import sys
import os
import json
import joblib
import pandas as pd
import requests
import datetime

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
from dotenv import load_dotenv
load_dotenv()

GSB_API_KEY = os.environ.get('GSB_API_KEY', 'YOUR_GSB_API_KEY_HERE')
GSB_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'

# ML model is borderline if phishing probability is between these values
BORDERLINE_LOW  = 0.40
BORDERLINE_HIGH = 0.70

# Weights for fusion
WEIGHT_ML  = 0.65
WEIGHT_GSB = 0.35

# Add ml-pipeline to sys.path so we can import the features package
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from features.feature_config import ALL_FEATURES, CONTENT_FEATURES
from features.lexical_extractor import extract_lexical_features
from features.content_extractor import extract_content_features

# --------------------------------------------------------------------------
# Domain Age via WHOIS
# --------------------------------------------------------------------------
def get_domain_age_bucket(domain: str) -> int:
    """
    0 = unknown/error
    1 = < 1 year (suspicious)
    2 = 1–3 years
    3 = > 3 years (trusted)
    """
    try:
        import whois
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation is None:
            return 0
        age_days = (datetime.datetime.now() - creation).days
        if age_days < 365:
            return 1
        elif age_days < 1095:
            return 2
        else:
            return 3
    except Exception:
        return 0

# --------------------------------------------------------------------------
# Google Safe Browsing API
# --------------------------------------------------------------------------
def check_google_safe_browsing(url: str) -> dict:
    """
    Returns:
      {'is_phishing': bool, 'threat_type': str or None, 'available': bool}
    """
    if GSB_API_KEY == 'YOUR_GSB_API_KEY_HERE':
        return {'is_phishing': False, 'threat_type': None, 'available': False}

    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "1.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        resp = requests.post(
            f"{GSB_ENDPOINT}?key={GSB_API_KEY}",
            json=payload,
            timeout=5
        )
        resp.raise_for_status()
        data = resp.json()
        matches = data.get('matches', [])
        if matches:
            threat_type = matches[0].get('threatType', 'UNKNOWN')
            return {'is_phishing': True, 'threat_type': threat_type, 'available': True}
        return {'is_phishing': False, 'threat_type': None, 'available': True}
    except Exception as e:
        return {'is_phishing': False, 'threat_type': None, 'available': False}

# --------------------------------------------------------------------------
# Unreachable page defaults (absence of legitimacy)
# --------------------------------------------------------------------------
UNREACHABLE_DEFAULTS = {f: 0 for f in CONTENT_FEATURES}
UNREACHABLE_DEFAULTS.update({
    'HasTitle': 0, 'HasDescription': 0, 'HasFavicon': 0,
    'IsResponsive': 0, 'Robots': 0, 'DomainTitleMatchScore': 0.0,
    'URLTitleMatchScore': 0.0, 'NoOfURLRedirect': 0, 'NoOfSelfRedirect': 0,
    'DomainAgeBucket': 0,
})

# --------------------------------------------------------------------------
# Main detection pipeline
# --------------------------------------------------------------------------
def detect(url: str, verbose: bool = True) -> dict:
    def log(msg): 
        if verbose: print(msg)

    log(f"\n{'='*60}")
    log(f"  PhishGuard Detection Pipeline")
    log(f"  URL: {url}")
    log(f"{'='*60}")

    fetch_url = url if url.startswith(('http://', 'https://')) else 'http://' + url

    # ------------------------------------------------------------------
    # STEP 1: Feature Extraction
    # ------------------------------------------------------------------
    log("\n[STEP 1] Extracting lexical features from URL string...")
    lexical_features = extract_lexical_features(url)

    html_features = {}
    page_unreachable = False
    response = None

    log("[STEP 1] Fetching live page content (timeout=7s)...")
    try:
        headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
        response = requests.get(fetch_url, timeout=7, headers=headers, allow_redirects=True)
        html = response.text
        log(f"         ✅ HTTP {response.status_code} — {len(html):,} chars, {len(response.history)} redirect(s)")
        html_features = extract_content_features(html, fetch_url, response=response)
    except requests.exceptions.ConnectionError:
        log("         ⚠️  DNS resolution failed — domain is dead or doesn't exist.")
        page_unreachable = True
    except requests.exceptions.Timeout:
        log("         ⚠️  Timeout — server not responding.")
        page_unreachable = True
    except Exception as e:
        log(f"         ⚠️  Fetch failed: {type(e).__name__}")
        page_unreachable = True

    if page_unreachable:
        log("         Using 'absence of legitimacy' defaults for content features.")
        html_features = dict(UNREACHABLE_DEFAULTS)

    # ------------------------------------------------------------------
    # STEP 1b: Domain Age (WHOIS)
    # ------------------------------------------------------------------
    import tldextract
    ext = tldextract.extract(fetch_url)
    domain = f"{ext.domain}.{ext.suffix}"

    log(f"[STEP 1] Checking domain age for '{domain}'...")
    age_bucket = get_domain_age_bucket(domain)
    html_features['DomainAgeBucket'] = age_bucket
    age_labels = {0: 'Unknown', 1: '<1 year (suspicious)', 2: '1-3 years', 3: '>3 years (trusted)'}
    log(f"         Domain age: {age_labels.get(age_bucket, 'Unknown')}")

    # ------------------------------------------------------------------
    # STEP 2: ML Inference
    # ------------------------------------------------------------------
    combined = {**lexical_features, **html_features}
    for f in ALL_FEATURES:
        if f not in combined:
            combined[f] = 0

    df = pd.DataFrame([combined], columns=ALL_FEATURES)

    log("\n[STEP 2] Running ML inference (Random Forest)...")
    scaler = joblib.load('models/scaler.pkl')
    model  = joblib.load('models/random_forest.pkl')

    X_scaled      = scaler.transform(df)
    ml_label      = model.predict(X_scaled)[0]
    ml_probs      = model.predict_proba(X_scaled)[0]
    ml_phish_prob = float(ml_probs[1])

    log(f"         ML prediction: {'PHISHING' if ml_label==1 else 'SAFE'} (p={ml_phish_prob:.3f})")

    # ------------------------------------------------------------------
    # STEP 3: Google Safe Browsing fallback (borderline cases)
    # ------------------------------------------------------------------
    gsb_result = {'is_phishing': False, 'threat_type': None, 'available': False, 'queried': False}
    is_borderline = BORDERLINE_LOW <= ml_phish_prob <= BORDERLINE_HIGH
    force_gsb = os.environ.get('FORCE_GSB', '0') == '1'

    has_api_key = GSB_API_KEY and GSB_API_KEY != 'YOUR_GSB_API_KEY_HERE'

    if is_borderline or force_gsb:
        reason = "Forced via flag" if force_gsb else f"Borderline confidence ({ml_phish_prob:.1%})"
        log(f"\n[STEP 3] ⚡ {reason} — querying Google Safe Browsing...")
        gsb_result = check_google_safe_browsing(fetch_url)
        gsb_result['queried'] = True
        if gsb_result['available']:
            status = f"FLAGGED ({gsb_result['threat_type']})" if gsb_result['is_phishing'] else "CLEAN"
            log(f"         GSB result: {status}")
        else:
            log("         GSB not available (no API key configured or network error).")
    else:
        log(f"\n[STEP 3] Skipping GSB (high-confidence ML result: {ml_phish_prob:.1%})")

    # ------------------------------------------------------------------
    # STEP 4: Weighted Fusion
    # ------------------------------------------------------------------
    log("\n[STEP 4] Computing final verdict...")

    gsb_score = 1.0 if gsb_result['is_phishing'] else 0.0

    if gsb_result['queried'] and gsb_result['available']:
        if gsb_result['is_phishing']:
             final_score = max(ml_phish_prob, 0.85) # GSB positive is a strong override
        else:
             final_score = (WEIGHT_ML * ml_phish_prob) + (WEIGHT_GSB * gsb_score)
    else:
        final_score = ml_phish_prob  # Trust ML fully when GSB not used

    # Hard overrides
    if page_unreachable and age_bucket == 1:
        final_score = max(final_score, 0.75)  # Dead + new domain = very suspicious

    is_phishing = final_score >= 0.5

    # ------------------------------------------------------------------
    # STEP 5: Display Verdict
    # ------------------------------------------------------------------
    print(f"\n{'='*60}")
    if page_unreachable:
        print(f"  ℹ️  Page was unreachable (domain dead or blocked)")
    if is_phishing:
        print(f"  🚨 VERDICT: PHISHING / MALICIOUS")
        print(f"  🚨 Risk Score: {final_score:.1%}")
    else:
        print(f"  ✅ VERDICT: SAFE / LEGITIMATE")
        print(f"  ✅ Risk Score: {final_score:.1%}  (below 50% threshold)")

    print(f"\n  Breakdown:")
    print(f"    ML Model Score:  {ml_phish_prob:.1%}")
    
    if gsb_result['queried'] and gsb_result['available']:
        gsb_str = f"FLAGGED ({gsb_result['threat_type']})" if gsb_result['is_phishing'] else "Clean"
    elif has_api_key:
        gsb_str = "Skipped (high ML confidence)"
    else:
        gsb_str = "Not configured (add GSB_API_KEY)"
        
    print(f"    Google Safe Browsing: {gsb_str}")
    print(f"    Domain Age: {age_labels.get(age_bucket, 'Unknown')}")

    # Top features
    importances = dict(zip(ALL_FEATURES, model.feature_importances_))
    top5 = sorted(importances.items(), key=lambda x: x[1], reverse=True)[:5]
    print(f"\n  Top 5 contributing features:")
    for feat, imp in top5:
        val = combined.get(feat, 'N/A')
        print(f"    {feat:<38} val={val}  weight={imp:.3f}")
    print(f"{'='*60}\n")

    return {
        'url': url,
        'is_phishing': is_phishing,
        'final_score': final_score,
        'ml_score': ml_phish_prob,
        'gsb': gsb_result,
        'domain_age_bucket': age_bucket,
        'page_unreachable': page_unreachable,
        'features': combined,
    }

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ml-pipeline/test_url.py <URL> [--force-gsb]")
        sys.exit(1)

    force = '--force-gsb' in sys.argv
    if force:
        os.environ['FORCE_GSB'] = '1'
        sys.argv.remove('--force-gsb')

    detect(sys.argv[1])
