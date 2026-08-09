import json
import os
import re
import math
from urllib.parse import urlparse
import tldextract

BRANDS = ['google', 'microsoft', 'apple', 'amazon', 'facebook',
          'paypal', 'netflix', 'bankofamerica', 'chase', 'wellsfargo']

# Per-suffix legitimacy rates for TLDLegitimateProb, measured on the training
# rows and shrunk toward the corpus prior. GENERATED — regenerate with
# `python ml-pipeline/gen_tld_rates.py`. Replaces a 14-entry hardcoded dict
# whose flat 0.50 default penalised legitimate country suffixes (.ng, .com.au)
# and flattered hostile ones (.app, .xyz, .top). The browser reads the same
# numbers from phishing-extension/src/ml/tld-rates.ts, emitted by the same
# generator, so train and serve agree by construction.
_RATES_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           'tld_rates.json')
with open(_RATES_PATH, encoding='utf-8') as _f:
    _TLD_RATES_DATA = json.load(_f)

TLD_SCORES = _TLD_RATES_DATA['rates']
# Unknown suffixes inherit the measured corpus base rate, not an arbitrary 0.50.
TLD_PRIOR = _TLD_RATES_DATA['prior']


def tld_legitimate_rate(suffix: str) -> float:
    """
    Legitimacy rate for a registered suffix, walking the suffix hierarchy:
    exact match, then successively shorter parents, then the corpus prior.
    So a suffix never seen in training ('sch.ng') inherits 'ng' rather than a
    global default. Ported 1:1 to tldLegitimateRate() in feature-extractor.ts.
    """
    s = (suffix or '').lower()
    while s:
        if s in TLD_SCORES:
            return TLD_SCORES[s]
        if '.' not in s:
            break
        s = s.split('.', 1)[1]
    return TLD_PRIOR

def extract_lexical_features(url: str) -> dict:
    url = url.strip().lower()
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    # Strip 'www.' subdomain to prevent dataset bias (100% of legit URLs contain www.)
    url = url.replace('://www.', '://')
    
    parsed = urlparse(url)
    extracted = tldextract.extract(url)
    domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
    
    features = {}
    features['URLLength'] = len(url)
    # DomainLength measures the registrable second-level label, NOT the full
    # SLD.TLD. A compound suffix (.com.ng, .co.uk) mechanically adds characters
    # to SLD.TLD, so the old definition let the model read suffix *structure*
    # as risk — the diagnosed regional-FPR mechanism (gtbank.com.ng scored
    # phishing on length alone). The label (the brand/org name) is the
    # meaningful length signal, and it is identical across a site's TLD
    # variants. Mirrored 1:1 in feature-extractor.ts.
    features['DomainLength'] = len(extracted.domain) if extracted.domain else len(domain)
    
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    features['IsDomainIP'] = 1 if re.match(ip_pattern, parsed.netloc.split(':')[0]) else 0
    
    features['URLSimilarityIndex'] = compute_brand_similarity(domain, url)
    features['CharContinuationRate'] = continuation_rate(url)
    features['TLDLegitimateProb'] = tld_legitimate_rate(extracted.suffix)
    features['URLCharProb'] = char_probability(url)
    
    subdomain_parts = extracted.subdomain.split('.') if extracted.subdomain else []
    features['NoOfSubDomain'] = len(subdomain_parts)
    
    obfuscation_count = url.count('%')
    features['HasObfuscation'] = 1 if obfuscation_count > 0 else 0
    features['NoOfObfuscatedChar'] = obfuscation_count
    features['ObfuscationRatio'] = obfuscation_count / len(url) if len(url) > 0 else 0
    
    letters = sum(1 for c in url if c.isalpha())
    digits = sum(1 for c in url if c.isdigit())
    equals = url.count('=')
    qmark = url.count('?')
    ampersand = url.count('&')
    special = sum(1 for c in url if c in '!@#$%^*()[]{}|;:<>')
    
    features['NoOfLettersInURL'] = letters
    features['LetterRatioInURL'] = letters / len(url) if len(url) > 0 else 0
    features['NoOfDegitsInURL'] = digits
    features['DegitRatioInURL'] = digits / len(url) if len(url) > 0 else 0
    features['NoOfEqualsInURL'] = equals
    features['NoOfQMarkInURL'] = qmark
    features['NoOfAmpersandInURL'] = ampersand
    features['NoOfOtherSpecialCharsInURL'] = special
    features['SpacialCharRatioInURL'] = special / len(url) if len(url) > 0 else 0
    features['IsHTTPS'] = 1 if parsed.scheme == 'https' else 0
    
    return features

# Visually confusable character substitutions used by real typosquatters
# (paypa1 -> paypal, g00gle -> google, micros0ft -> microsoft).
HOMOGLYPHS = {
    '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
    '7': 't', '8': 'b', '9': 'g', '$': 's', '@': 'a', '|': 'l',
}


def _deleet(s: str) -> str:
    """Normalise homoglyph substitutions back to their letter form."""
    return ''.join(HOMOGLYPHS.get(c, c) for c in s)


def _is_doubling_of(candidate: str, brand: str) -> bool:
    """candidate is brand with one character doubled: appple <- apple."""
    if len(candidate) != len(brand) + 1:
        return False
    for i in range(len(candidate)):
        if candidate[:i] + candidate[i + 1:] != brand:
            continue
        c = candidate[i]
        if (i > 0 and candidate[i - 1] == c) or \
           (i + 1 < len(candidate) and candidate[i + 1] == c):
            return True
    return False


def _is_transposition_of(candidate: str, brand: str) -> bool:
    """candidate is brand with two adjacent characters swapped: payapl <- paypal."""
    if len(candidate) != len(brand):
        return False
    diff = [i for i in range(len(brand)) if candidate[i] != brand[i]]
    if len(diff) != 2 or diff[1] - diff[0] != 1:
        return False
    i, j = diff
    return candidate[i] == brand[j] and candidate[j] == brand[i]


def _typo_similarity(candidate: str, brand: str) -> float:
    """
    Levenshtein similarity of `candidate` to `brand`, but ONLY when the
    difference looks like deliberate typosquatting. Raw edit distance cannot
    make this call: '/apply' vs 'apple' scores 0.80 while the real typosquat
    '/g00gle' vs 'google' scores only 0.67. What separates them is WHICH
    characters differ, so a near-match counts only if it is a homoglyph
    substitution, a doubled character, or an adjacent transposition.
    Ordinary words that happen to sit one edit away (apply, apps, amazing)
    score 0.0.
    """
    if not candidate or candidate == brand:
        return 0.0
    normalised = _deleet(candidate)
    gated = (
        normalised == brand
        or _is_doubling_of(normalised, brand)
        or _is_transposition_of(normalised, brand)
    )
    if not gated:
        return 0.0
    dist = levenshtein(candidate, brand)
    return 1 - (dist / max(len(candidate), len(brand)))


def compute_brand_similarity(domain: str, url: str = '') -> float:
    """
    Detects typosquatting and path-based brand impersonation.

    Returns a score 0.0–1.0:
      - 0.0 = domain IS the real brand (e.g. google.com → 0.0)
      - 0.5–0.9 = domain LOOKS SIMILAR to a brand (typosquatting)
      - 1.0 = a URL PATH SEGMENT exactly matches a brand name
              (e.g. evil.com/paypal/login → 1.0)
    """
    from urllib.parse import urlparse
    ext = tldextract.extract(url if url else domain)
    domain_sld = ext.domain.lower()  # second-level domain only

    # --- Domain portion: skip exact matches (it IS the real brand) ---
    # Only HIGH similarity counts as typosquatting (e.g. paypa1~paypal, g00gle~google).
    # Coincidental moderate distance (github~google ≈ 0.33) is NOT typosquatting and
    # must score 0, or legitimate non-brand domains get flagged.
    TYPO_THRESHOLD = 0.6
    domain_max_sim = 0.0
    for brand in BRANDS:
        if domain_sld == brand:
            # e.g. google.com → domain is 'google' = brand 'google' → score 0
            domain_max_sim = 0.0
            break
        dist = levenshtein(domain_sld, brand)
        sim = 1 - (dist / max(len(domain_sld), len(brand)))
        if sim > domain_max_sim:
            domain_max_sim = sim
    if domain_max_sim < TYPO_THRESHOLD:
        domain_max_sim = 0.0

    # --- Path portion: exact match here IS suspicious ---
    # Near-matches are gated by _typo_similarity so ordinary English segments
    # ('/apply', '/apps', '/amazing') score 0 while real path-based squats
    # ('/paypa1', '/micros0ft') still score high. See _typo_similarity.
    path_max_sim = 0.0
    if url:
        path = urlparse(url).path
        segments = [s.lower() for s in path.split('/') if len(s) >= 4]
        for segment in segments:
            for brand in BRANDS:
                if segment == brand:
                    return 1.0   # e.g. evil.com/chase/ → definite brand abuse
                sim = _typo_similarity(segment, brand)
                if sim > path_max_sim:
                    path_max_sim = sim
    if path_max_sim < TYPO_THRESHOLD:
        path_max_sim = 0.0

    return max(domain_max_sim, path_max_sim)

def levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1):
        dp[i][0] = i
    for j in range(n + 1):
        dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if a[i-1] == b[j-1] else 1
            dp[i][j] = min(dp[i-1][j] + 1, dp[i][j-1] + 1, dp[i-1][j-1] + cost)
    return dp[m][n]

def continuation_rate(url: str) -> float:
    if len(url) < 2:
        return 0.0
    continuations = 0
    for i in range(1, len(url)):
        prev_alpha = url[i-1].isalpha()
        curr_alpha = url[i].isalpha()
        prev_digit = url[i-1].isdigit()
        curr_digit = url[i].isdigit()
        if (prev_alpha and curr_alpha) or (prev_digit and curr_digit):
            continuations += 1
    return continuations / (len(url) - 1)

def char_probability(url: str) -> float:
    if not url:
        return 0.0
    expected = {
        'a': 0.08, 'e': 0.07, 'i': 0.06, 'o': 0.06, 'r': 0.05,
        't': 0.05, 'n': 0.05, 's': 0.05, 'l': 0.04, 'c': 0.04,
        '/': 0.10, '.': 0.08, '-': 0.03, '_': 0.01
    }
    score = 0.0
    for char in url.lower():
        if char in expected:
            score += expected[char]
    return min(score / len(url), 1.0) if len(url) > 0 else 0.0
