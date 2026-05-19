from bs4 import BeautifulSoup
import re

def extract_content_features(html: str, base_url: str, response=None) -> dict:
    """
    Extracts all 13 content features + 10 domain features from HTML.
    Pass the requests.Response object as 'response' to get redirect counts.
    """
    soup = BeautifulSoup(html, 'html.parser')
    features = {}

    # -------------------------------------------------------------------------
    # CONTENT FEATURES (13)
    # -------------------------------------------------------------------------
    lines = html.splitlines()
    features['LineOfCode'] = len(lines)
    features['LargestLineLength'] = max((len(l) for l in lines), default=0)

    scripts = soup.find_all('script')
    features['NoOfPopup'] = sum(1 for s in scripts if s.string and 'window.open' in s.string)
    features['NoOfiFrame'] = len(soup.find_all('iframe'))

    forms = soup.find_all('form')
    features['HasExternalFormSubmit'] = 0
    for form in forms:
        action = form.get('action', '')
        if action.startswith('http') and not action.startswith(base_url):
            features['HasExternalFormSubmit'] = 1
            break

    social_patterns = ['facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com', 'youtube.com']
    links = soup.find_all('a', href=True)
    features['HasSocialNet'] = 0
    for link in links:
        if any(s in link['href'] for s in social_patterns):
            features['HasSocialNet'] = 1
            break

    features['HasSubmitButton'] = 1 if (
        soup.find('input', {'type': 'submit'}) or soup.find('button', {'type': 'submit'})
    ) else 0
    features['HasHiddenFields'] = 1 if soup.find('input', {'type': 'hidden'}) else 0
    features['HasPasswordField'] = 1 if soup.find('input', {'type': 'password'}) else 0

    text = soup.get_text().lower()
    features['Bank']   = 1 if any(w in text for w in ['bank', 'banking', 'account number']) else 0
    features['Pay']    = 1 if any(w in text for w in ['payment', 'paypal', 'checkout', 'credit card']) else 0
    features['Crypto'] = 1 if any(w in text for w in ['bitcoin', 'crypto', 'wallet', 'blockchain']) else 0
    features['HasCopyrightInfo'] = 1 if ('copyright' in text or '\u00a9' in text) else 0

    # -------------------------------------------------------------------------
    # DOMAIN FEATURES extracted from HTML (10)
    # -------------------------------------------------------------------------

    # HasTitle: does the page have a <title> tag?
    title_tag = soup.find('title')
    title_text = title_tag.get_text().strip() if title_tag else ''
    features['HasTitle'] = 1 if title_text else 0

    # HasDescription: does the page have a meta description?
    desc_tag = soup.find('meta', attrs={'name': re.compile('description', re.I)})
    desc_text = desc_tag.get('content', '').strip() if desc_tag else ''
    features['HasDescription'] = 1 if desc_text else 0

    # HasFavicon: any link tag for icon?
    favicon = soup.find('link', rel=lambda r: r and any('icon' in x.lower() for x in r))
    features['HasFavicon'] = 1 if favicon else 0

    # IsResponsive: viewport meta tag present?
    viewport = soup.find('meta', attrs={'name': re.compile('viewport', re.I)})
    features['IsResponsive'] = 1 if viewport else 0

    # Robots: robots meta tag present?
    robots = soup.find('meta', attrs={'name': re.compile('robots', re.I)})
    features['Robots'] = 1 if robots else 0

    # DomainTitleMatchScore: how much does the domain appear in the title?
    from urllib.parse import urlparse
    import tldextract
    parsed  = urlparse(base_url)
    ext     = tldextract.extract(base_url)
    domain_name = ext.domain.lower()

    if title_text and domain_name:
        title_lower = title_text.lower()
        features['DomainTitleMatchScore'] = 1.0 if domain_name in title_lower else 0.0
    else:
        features['DomainTitleMatchScore'] = 0.0

    # URLTitleMatchScore: how much does the URL path appear in the title?
    path_parts = [p for p in parsed.path.split('/') if len(p) > 3]
    if title_text and path_parts:
        matches = sum(1 for p in path_parts if p.lower() in title_text.lower())
        features['URLTitleMatchScore'] = matches / len(path_parts)
    else:
        features['URLTitleMatchScore'] = 0.0

    # NoOfURLRedirect / NoOfSelfRedirect: from response history
    if response is not None and hasattr(response, 'history'):
        redirects = response.history
        features['NoOfURLRedirect'] = len(redirects)
        self_redirects = sum(
            1 for r in redirects
            if tldextract.extract(r.url).domain == domain_name
        )
        features['NoOfSelfRedirect'] = self_redirects
    else:
        features['NoOfURLRedirect'] = 0
        features['NoOfSelfRedirect'] = 0

    # DomainAgeBucket: 0=unknown, 1=<1yr (suspicious), 2=1-3yr, 3=>3yr (trusted)
    # Defaults to 0 (unknown) unless whois lookup is done in test_url.py
    features['DomainAgeBucket'] = 0

    return features

