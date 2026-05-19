import joblib
import json
import numpy as np
import sys
import os

# Add ml-pipeline/ to sys.path so 'features' package can be found
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from features.feature_config import ALL_FEATURES, FEATURE_CATEGORIES

def get_category(feature: str) -> str:
    for cat, feats in FEATURE_CATEGORIES.items():
        if feature in feats:
            return cat
    return "UNKNOWN"

FEATURE_DESCRIPTIONS = {
    'URLLength':                  'URL is unusually long (>75 chars is suspicious)',
    'DomainLength':               'Domain name is lengthy (may hide true destination)',
    'IsDomainIP':                 'Uses raw IP address instead of a domain name',
    'URLSimilarityIndex':         'Domain/path resembles a known brand (typosquatting)',
    'CharContinuationRate':       'Unusual character continuation patterns in URL',
    'TLDLegitimateProb':          'Top-level domain is associated with low-trust registrars',
    'URLCharProb':                'Unusual character distribution in URL string',
    'NoOfSubDomain':              'Excessive subdomain nesting (e.g. login.bank.evil.com)',
    'HasObfuscation':             'URL contains percent-encoded obfuscated characters',
    'NoOfObfuscatedChar':         'Multiple obfuscated characters found in URL',
    'ObfuscationRatio':           'High proportion of obfuscated characters',
    'NoOfLettersInURL':           'Total letter count in URL',
    'LetterRatioInURL':           'Ratio of letters to total URL length',
    'NoOfDegitsInURL':            'High digit count (common in auto-generated phishing URLs)',
    'DegitRatioInURL':            'Unusually high digit ratio in URL',
    'NoOfEqualsInURL':            'Multiple query parameter assignments',
    'NoOfQMarkInURL':             'Query string is present',
    'NoOfAmpersandInURL':         'Multiple query parameters chained',
    'NoOfOtherSpecialCharsInURL': 'Excessive special characters in URL',
    'SpacialCharRatioInURL':      'High special character density',
    'IsHTTPS':                    'Connection is not encrypted (no HTTPS)',
    'DomainAgeBucket':            'Domain was recently registered (<1 year = suspicious)',
    'HasTitle':                   'Page is missing a <title> tag',
    'DomainTitleMatchScore':      'Domain name does not match page title',
    'URLTitleMatchScore':         'URL path does not match page title content',
    'HasFavicon':                 'Missing website favicon (icon)',
    'Robots':                     'No robots.txt meta tag found',
    'IsResponsive':               'Non-responsive design (missing viewport meta tag)',
    'NoOfURLRedirect':            'Multiple external redirects detected',
    'NoOfSelfRedirect':           'Self-redirect loop detected',
    'HasDescription':             'Missing meta description tag',
    'LineOfCode':                 'Minimal page content (phishing pages are often sparse)',
    'LargestLineLength':          'Unusual or minified code structure',
    'NoOfPopup':                  'Popup windows detected (window.open calls)',
    'NoOfiFrame':                 'Hidden iframe elements embedded in page',
    'HasExternalFormSubmit':      'Form submits credentials to an external domain',
    'HasSocialNet':               'Social media links present (sign of legitimate site)',
    'HasSubmitButton':            'Submit button found (credentials collection)',
    'HasHiddenFields':            'Hidden form fields detected (data harvesting)',
    'HasPasswordField':           'Password input field is present on page',
    'Bank':                       'Banking-related keywords found in page text',
    'Pay':                        'Payment-related keywords found in page text',
    'Crypto':                     'Cryptocurrency keywords found in page text',
    'HasCopyrightInfo':           'Missing copyright information (sign of fake page)',
}

FEATURE_THRESHOLDS = {
    'URLLength':            {'high': 100, 'medium': 75},
    'NoOfSubDomain':        {'high': 3,   'medium': 2},
    'ObfuscationRatio':     {'high': 0.1, 'medium': 0.05},
    'URLSimilarityIndex':   {'high': 0.8, 'medium': 0.6},
    'TLDLegitimateProb':    {'high': 0.3, 'medium': 0.5},
    'DomainAgeBucket':      {'high': 0,   'medium': 1},
    'NoOfObfuscatedChar':   {'high': 5,   'medium': 2},
    'NoOfURLRedirect':      {'high': 5,   'medium': 2},
}

def get_feature_description(feature: str) -> str:
    return FEATURE_DESCRIPTIONS.get(feature, f'{feature} analysis')

def get_thresholds(feature: str) -> dict:
    return FEATURE_THRESHOLDS.get(feature, {})

def generate_explanation_mapping():
    model = joblib.load('models/random_forest.pkl')
    importances = model.feature_importances_
    
    explanations = {}
    for feat, importance in zip(ALL_FEATURES, importances):
        explanations[feat] = {
            'importance': float(importance),
            'category': get_category(feat),
            'description': get_feature_description(feat),
            'thresholds': get_thresholds(feat)
        }
    
    output_dir = 'phishing-extension/assets'
    os.makedirs(output_dir, exist_ok=True)
    
    with open(f'{output_dir}/shap_mapping.json', 'w') as f:
        json.dump(explanations, f, indent=2)
    
    category_importance = {}
    for cat, feats in FEATURE_CATEGORIES.items():
        cat_imp = sum(explanations[f]['importance'] for f in feats if f in explanations)
        category_importance[cat] = {
            'total_importance': float(cat_imp),
            'features': feats
        }
    
    with open(f'{output_dir}/category_importance.json', 'w') as f:
        json.dump(category_importance, f, indent=2)
    
    print(f"Generated explanations for {len(explanations)} features")
    print(f"Files written to: {output_dir}/")
    print(f"  - shap_mapping.json        ({len(explanations)} feature entries)")
    print(f"  - category_importance.json ({len(category_importance)} categories)")
    return explanations

if __name__ == "__main__":
    generate_explanation_mapping()
