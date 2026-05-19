import re, math, tldextract
from urllib.parse import urlparse

SUSPICIOUS_KEYWORDS = ['login', 'signin', 'verify', 'secure', 'account',
                       'update', 'banking', 'confirm', 'password', 'paypal',
                       'ebay', 'amazon', 'apple', 'microsoft', 'google']

def url_entropy(url):
    prob = [url.count(c) / len(url) for c in set(url)]
    return -sum(p * math.log2(p) for p in prob)

def extract_features(url):
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    path = parsed.path
    domain = ext.domain + '.' + ext.suffix

    features = {
        # Lexical features
        'url_length': len(url),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_underscores': url.count('_'),
        'num_slashes': url.count('/'),
        'num_at': url.count('@'),
        'num_question': url.count('?'),
        'num_equals': url.count('='),
        'num_ampersand': url.count('&'),
        'num_percent': url.count('%'),
        'num_digits': sum(c.isdigit() for c in url),
        'num_special': sum(not c.isalnum() for c in url),
        'url_entropy': url_entropy(url),
        'has_ip': int(bool(re.match(r'https?://\d+\.\d+\.\d+\.\d+', url))),
        'is_https': int(parsed.scheme == 'https'),
        'has_port': int(bool(parsed.port)),
        # Domain features
        'domain_length': len(ext.domain),
        'subdomain_count': ext.subdomain.count('.') + 1 if ext.subdomain else 0,
        'tld_length': len(ext.suffix),
        'path_length': len(path),
        'num_path_components': len([p for p in path.split('/') if p]),
        # Keyword features
        'has_suspicious_keyword': int(any(k in url.lower() for k in SUSPICIOUS_KEYWORDS)),
        'num_suspicious_keywords': sum(url.lower().count(k) for k in SUSPICIOUS_KEYWORDS),
    }
    return features

if __name__ == '__main__':
    test_urls = [
        "https://www.google.com",  # Benign
        "http://paypal-login-secure.com/verify?account=123",  # Phishing-like
        "http://192.168.1.1/update.php"  # IP-based URL
    ]
    
    for url in test_urls:
        print(f"\n--- Testing URL: {url} ---")
        features = extract_features(url)
        for key, value in features.items():
            print(f"{key}: {value}")
