"""
PhishGuard Detection Pipeline (v2 - 12-feature lexical-only)
=============================================================
Architecture:

  STAGE 1: Cache (skipped in CLI tool)

  STAGE 2: Reputation Allowlist
           - Checks registrable domain against top-sites list
           - Known-popular domains are short-circuited to CLEAN

  STAGE 3: On-device Random Forest (12 lexical features)
           - Extracts scale-invariant URL-string features
           - Fast, private, no network calls needed

  STAGE 4: Google Safe Browsing fallback
           - Only triggered when ML score is borderline (0.35-0.65)
           - Set GSB_API_KEY in .env to enable

Set your Google Safe Browsing API key in .env as GSB_API_KEY=your_key_here
"""

import sys
import os
import json
import joblib
import pandas as pd
import requests

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------
from dotenv import load_dotenv
load_dotenv()

GSB_API_KEY = os.environ.get('GSB_API_KEY', '')
GSB_ENDPOINT = 'https://safebrowsing.googleapis.com/v4/threatMatches:find'

# GSB fallback is triggered when ML score is in this borderline range
BORDERLINE_LOW  = 0.35
BORDERLINE_HIGH = 0.65

# Add ml-pipeline to sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from features.feature_config import ALL_FEATURES
from features.lexical_extractor import extract_lexical_features

# --------------------------------------------------------------------------
# Reputation Allowlist
# --------------------------------------------------------------------------
_allowlist: set = None

def load_allowlist() -> set:
    global _allowlist
    if _allowlist is not None:
        return _allowlist
    allowlist_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        '..', 'phishing-extension', 'assets', 'top_domains.json'
    )
    try:
        with open(allowlist_path, 'r') as f:
            _allowlist = set(json.load(f))
        print(f"         Allowlist loaded ({len(_allowlist):,} domains)")
    except Exception as e:
        print(f"         [WARNING] Could not load allowlist: {e}")
        _allowlist = set()
    return _allowlist

def is_allowlisted(url: str) -> bool:
    """True if the URL's registrable domain is a known-popular site."""
    allowlist = load_allowlist()
    if not allowlist:
        return False
    try:
        import tldextract
        ext = tldextract.extract(url)
        domain = f"{ext.domain}.{ext.suffix}".lower()
        if allowlist and domain in allowlist:
            return True
        # Also check last 2-3 labels (handles bbc.co.uk etc.)
        host = url.split('//')[-1].split('/')[0].lower().replace('www.', '')
        labels = host.split('.')
        for take in range(2, min(4, len(labels) + 1)):
            candidate = '.'.join(labels[-take:])
            if candidate in allowlist:
                return True
    except Exception:
        pass
    return False

# --------------------------------------------------------------------------
# Google Safe Browsing
# --------------------------------------------------------------------------
def check_gsb(url: str) -> dict:
    """Returns {'is_phishing': bool, 'threat_type': str|None, 'available': bool}"""
    if not GSB_API_KEY:
        return {'is_phishing': False, 'threat_type': None, 'available': False}

    payload = {
        "client": {"clientId": "phishguard", "clientVersion": "2.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    try:
        resp = requests.post(f"{GSB_ENDPOINT}?key={GSB_API_KEY}", json=payload, timeout=5)
        resp.raise_for_status()
        matches = resp.json().get('matches', [])
        if matches:
            return {'is_phishing': True, 'threat_type': matches[0].get('threatType'), 'available': True}
        return {'is_phishing': False, 'threat_type': None, 'available': True}
    except Exception as e:
        return {'is_phishing': False, 'threat_type': None, 'available': False}

# --------------------------------------------------------------------------
# Main detection pipeline
# --------------------------------------------------------------------------
def detect(url: str, audit: bool = False) -> dict:
    print(f"\n{'='*60}")
    print(f"  PhishGuard Detection Pipeline")
    print(f"  URL: {url}")
    print(f"{'='*60}")

    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    # ------------------------------------------------------------------
    # STAGE 2: Reputation Allowlist
    # ------------------------------------------------------------------
    print("\n[STAGE 2] Checking reputation allowlist...")
    if is_allowlisted(url):
        print(f"         [OK] Domain is on the trusted-sites allowlist")
        print(f"\n{'='*60}")
        print(f"  [VERDICT] CLEAN / SAFE")
        print(f"  [VERDICT] Risk Score: 5.0%")
        print(f"  [SOURCE]  Trusted-sites allowlist (on-device)")
        print(f"{'='*60}\n")
        return {
            'url': url, 'is_phishing': False, 'final_score': 0.05,
            'ml_score': None, 'source': 'ALLOWLIST'
        }
    print(f"         Domain not in allowlist — proceeding to ML model")

    # ------------------------------------------------------------------
    # STAGE 3: On-device ML (12 lexical features)
    # ------------------------------------------------------------------
    print("\n[STAGE 3] Extracting lexical features...")
    lexical = extract_lexical_features(url)

    # Build feature vector in canonical order
    row = {f: lexical.get(f, 0) for f in ALL_FEATURES}
    df = pd.DataFrame([row], columns=ALL_FEATURES)

    if audit:
        print("\n  Feature values:")
        for f in ALL_FEATURES:
            print(f"    {f:<35} {row[f]}")

    print("\n[STAGE 3] Running Random Forest inference...")
    scaler = joblib.load('models/scaler.pkl')
    model  = joblib.load('models/random_forest.pkl')

    X_scaled = scaler.transform(df)
    ml_prob  = float(model.predict_proba(X_scaled)[0][1])
    ml_label = 'PHISHING' if ml_prob >= 0.5 else 'CLEAN'
    print(f"         ML prediction: {ml_label} (score={ml_prob:.3f})")

    if audit:
        print(f"\n  Scaled feature vector:")
        for i, f in enumerate(ALL_FEATURES):
            print(f"    [{i}] {f:<35} raw={row[f]:<12} scaled={X_scaled[0][i]:.6f}")

    # ------------------------------------------------------------------
    # STAGE 4: Google Safe Browsing fallback (borderline only)
    # ------------------------------------------------------------------
    gsb_result = {'is_phishing': False, 'threat_type': None, 'available': False, 'queried': False}
    is_borderline = BORDERLINE_LOW <= ml_prob <= BORDERLINE_HIGH

    if is_borderline:
        print(f"\n[STAGE 4] Borderline score ({ml_prob:.1%}) — querying Google Safe Browsing...")
        gsb_result = check_gsb(url)
        gsb_result['queried'] = True
        if gsb_result['available']:
            status = f"FLAGGED ({gsb_result['threat_type']})" if gsb_result['is_phishing'] else "CLEAN"
            print(f"         GSB result: {status}")
        else:
            print("         GSB not available (no API key or network error)")
    else:
        print(f"\n[STAGE 4] Skipping GSB (high-confidence ML result: {ml_prob:.1%})")

    # ------------------------------------------------------------------
    # Final score fusion
    # ------------------------------------------------------------------
    if gsb_result['queried'] and gsb_result['available']:
        if gsb_result['is_phishing']:
            final_score = max(ml_prob, 0.99)
        else:
            final_score = min(ml_prob, 0.60)
    else:
        final_score = ml_prob

    if final_score < 0.50:
        verdict = "CLEAN"
    elif final_score < 0.85:
        verdict = "SUSPICIOUS"
    else:
        verdict = "PHISHING"

    # ------------------------------------------------------------------
    # Display verdict
    # ------------------------------------------------------------------
    print(f"\n{'='*60}")
    verdict_labels = {
        "CLEAN":     "CLEAN / SAFE",
        "SUSPICIOUS": "SUSPICIOUS / BORDERLINE",
        "PHISHING":  "PHISHING / MALICIOUS"
    }
    print(f"  [VERDICT] {verdict_labels[verdict]}")
    print(f"  [VERDICT] Risk Score: {final_score:.1%}")
    print(f"\n  Breakdown:")
    print(f"    ML Model Score:    {ml_prob:.1%}")

    if gsb_result['queried'] and gsb_result['available']:
        gsb_str = f"FLAGGED ({gsb_result['threat_type']})" if gsb_result['is_phishing'] else "Clean"
    elif GSB_API_KEY:
        gsb_str = "Skipped (score outside borderline range)"
    else:
        gsb_str = "Not configured (add GSB_API_KEY to .env)"
    print(f"    Google Safe Browsing: {gsb_str}")

    importances = dict(zip(ALL_FEATURES, model.feature_importances_))
    sorted_imp = sorted(importances.items(), key=lambda x: x[1], reverse=True)
    print(f"\n  Top features by importance:")
    for feat, imp in sorted_imp[:5]:
        val = row.get(feat, 'N/A')
        print(f"    {feat:<38} val={val}  weight={imp:.3f}")
    print(f"{'='*60}\n")

    return {
        'url': url,
        'is_phishing': verdict == "PHISHING",
        'final_score': final_score,
        'ml_score': ml_prob,
        'gsb': gsb_result,
        'source': 'ML'
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python ml-pipeline/test_url.py <URL> [--audit]")
        sys.exit(1)

    audit = '--audit' in sys.argv
    url_args = [a for a in sys.argv[1:] if not a.startswith('--')]

    if not url_args:
        print("Error: No URL provided.")
        sys.exit(1)

    detect(url_args[0], audit=audit)