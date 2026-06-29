"""
PhishGuard Model Training Pipeline (v2 — Self-Extracted Features)
=================================================================
Key change from v1: Lexical features are now SELF-EXTRACTED from raw URL
strings using our own extract_lexical_features() — the SAME function used
at inference time. This guarantees feature parity between training and
real-world detection.

Content/domain features are used from PhiUSIIL CSV where column names match.
A fraction of training samples have content features zeroed out so the model
learns to detect phishing from lexical signals alone (simulating pages that
can't be fetched).
"""

import pandas as pd
import numpy as np
import sys
import os
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from sklearn.preprocessing import MinMaxScaler
from imblearn.over_sampling import SMOTE
import joblib
import json
import time

# Add ml-pipeline/ to sys.path so 'features' package can be found
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from features.feature_config import ALL_FEATURES, LEXICAL_FEATURES, DOMAIN_FEATURES, CONTENT_FEATURES
from features.lexical_extractor import extract_lexical_features


def augment_legitimate_urls(phi, random_state=42):
    """
    Decorrelate URL *structure* (path / subdomain presence) from the label.

    In PhiUSIIL, 100% of legitimate URLs are bare domains (no path, no non-www
    subdomain), while ~27% of phishing URLs have a path and ~45% have a
    subdomain. A URL-only model therefore learns the *artifact* "has path or
    subdomain => legit / bare domain => phishing" (or its inverse), which makes
    it flag real homepages like https://google.com/ as phishing.

    Fix: bring the legitimate distribution UP to match the phishing distribution
    so structure carries no class information. The model is then forced to rely
    on genuine lexical content signals (typosquatting / URLSimilarityIndex, TLD
    legitimacy, obfuscation, digit and special-char statistics). We augment only
    the legitimate class because the phishing URLs already carry these structures
    naturally and we must not fabricate phishing examples.
    """
    # Target rates measured from the phishing class in this dataset.
    TARGET_PATH = 0.27
    TARGET_SUB = 0.45

    rng = np.random.RandomState(random_state)
    legit_indices = phi[phi['label'] == 1].index.values  # label 1 = legitimate (pre-inversion)

    subdomains = ['docs', 'en', 'mail', 'blog', 'support', 'login', 'store', 'app', 'dev', 'status', 'news', 'portal', 'api', 'admin', 'accounts']
    paths = [
        '/index.html', '/login', '/register', '/home', '/about', '/contact', '/faq',
        '/terms', '/privacy', '/products', '/item/12345', '/search', '/posts/hello-world',
        '/docs/api/v1', '/settings/profile', '/download', '/pricing', '/blog/news/2026/06',
        '/dp/b08n5wrwnw', '/3/library/os.html', '/wiki/phishing', '/signin', '/watch?v=dqw4w9wgxcq'
    ]

    print("Augmenting legitimate URLs to MATCH phishing structure distribution")
    print(f"  (target: {TARGET_SUB:.0%} subdomain, {TARGET_PATH:.0%} path — decorrelates structure from label)")

    subdomain_count = 0
    path_count = 0
    urls = phi['URL'].values.copy()

    for idx in legit_indices:
        url = str(urls[idx])
        # Independent draws so the marginal path/subdomain rates match phishing's.
        if rng.random() < TARGET_SUB:
            sub = rng.choice(subdomains)
            if '://www.' in url:
                url = url.replace('://www.', f'://{sub}.')
            elif '://' in url:
                url = url.replace('://', f'://{sub}.')
            subdomain_count += 1
        if rng.random() < TARGET_PATH:
            url = url.rstrip('/') + rng.choice(paths)
            path_count += 1
        urls[idx] = url

    phi['URL'] = urls
    n = len(legit_indices)
    print(f"  Legit URLs given a subdomain: {subdomain_count}/{n} ({subdomain_count/n:.0%})")
    print(f"  Legit URLs given a path:      {path_count}/{n} ({path_count/n:.0%})")
    return phi


# Curated popular, indisputably-legitimate domains across categories. PhiUSIIL's
# legitimate class is dominated by obscure long-named sites, so the model learns
# "short domain => phishing". Injecting these short, famous domains as legitimate
# examples corrects that population bias so real homepages aren't flagged.
POPULAR_LEGIT_DOMAINS = [
    # Tech / search / social
    'google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com',
    'linkedin.com', 'reddit.com', 'pinterest.com', 'tiktok.com', 'snapchat.com', 'whatsapp.com',
    'telegram.org', 'discord.com', 'twitch.tv', 'tumblr.com', 'quora.com', 'medium.com',
    'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com', 'spotify.com', 'adobe.com',
    'oracle.com', 'ibm.com', 'intel.com', 'nvidia.com', 'amd.com', 'dell.com', 'hp.com',
    'samsung.com', 'sony.com', 'cisco.com', 'salesforce.com', 'sap.com', 'vmware.com',
    'github.com', 'gitlab.com', 'bitbucket.org', 'stackoverflow.com', 'npmjs.com',
    'docker.com', 'kubernetes.io', 'mozilla.org', 'wikipedia.org', 'wikimedia.org',
    'cloudflare.com', 'digitalocean.com', 'heroku.com', 'vercel.com', 'netlify.com',
    'zoom.us', 'slack.com', 'dropbox.com', 'box.com', 'notion.so', 'figma.com', 'canva.com',
    'wordpress.com', 'wix.com', 'squarespace.com', 'shopify.com', 'godaddy.com',
    # Shopping / payments / finance
    'paypal.com', 'stripe.com', 'ebay.com', 'etsy.com', 'walmart.com', 'target.com',
    'bestbuy.com', 'costco.com', 'alibaba.com', 'aliexpress.com', 'wayfair.com',
    'visa.com', 'mastercard.com', 'americanexpress.com', 'chase.com', 'bankofamerica.com',
    'wellsfargo.com', 'citibank.com', 'capitalone.com', 'hsbc.com', 'barclays.co.uk',
    'coinbase.com', 'binance.com', 'kraken.com', 'moonpay.com', 'robinhood.com',
    # News / media / reference
    'bbc.com', 'bbc.co.uk', 'cnn.com', 'nytimes.com', 'theguardian.com', 'reuters.com',
    'forbes.com', 'bloomberg.com', 'wsj.com', 'economist.com', 'time.com', 'nature.com',
    'sciencedirect.com', 'jstor.org', 'arxiv.org', 'imdb.com', 'rottentomatoes.com',
    'espn.com', 'nationalgeographic.com', 'weather.com', 'accuweather.com',
    # Travel / services / misc
    'booking.com', 'airbnb.com', 'expedia.com', 'tripadvisor.com', 'uber.com', 'lyft.com',
    'doordash.com', 'grubhub.com', 'yelp.com', 'maps.google.com', 'gmail.com', 'outlook.com',
    'yahoo.com', 'bing.com', 'duckduckgo.com', 'baidu.com', 'yandex.com', 'naver.com',
    # Education / government / orgs
    'mit.edu', 'harvard.edu', 'stanford.edu', 'berkeley.edu', 'ox.ac.uk', 'cam.ac.uk',
    'coursera.org', 'edx.org', 'khanacademy.org', 'udemy.com', 'usa.gov', 'irs.gov',
    'nih.gov', 'cdc.gov', 'nasa.gov', 'who.int', 'un.org', 'europa.eu', 'gov.uk',
    'redcross.org', 'wikipedia.org', 'archive.org', 'ietf.org', 'w3.org',
    # Nigeria / Africa context (deployment region)
    'gtbank.com', 'firstbanknigeria.com', 'accessbankplc.com', 'zenithbank.com',
    'jumia.com.ng', 'konga.com', 'nairaland.com', 'flutterwave.com', 'paystack.com',
]


def inject_popular_legit(phi, random_state=42, variants_per_domain=12):
    """
    Append popular, well-known legitimate domains to the dataset as legitimate
    examples (label=1, pre-inversion). For each domain we add several variants —
    bare, www, and structure-matched path/subdomain forms — so the model learns
    that short, common-TLD brand domains are legitimate regardless of structure.
    """
    rng = np.random.RandomState(random_state)
    subdomains = ['www', 'app', 'login', 'account', 'my', 'secure', 'shop', 'help', 'support', 'en']
    paths = ['', '/', '/home', '/login', '/account', '/about', '/products', '/help',
             '/search?q=test', '/p/12345', '/signin', '/dashboard']

    rows = []
    for dom in POPULAR_LEGIT_DOMAINS:
        for _ in range(variants_per_domain):
            scheme = 'https://'
            host = dom
            if rng.random() < 0.45:
                host = rng.choice(subdomains) + '.' + dom
            path = rng.choice(paths) if rng.random() < 0.27 else ''
            rows.append({'URL': scheme + host + path, 'label': 1})

    inj = pd.DataFrame(rows)
    print(f"  Injecting {len(inj)} popular-legit URL variants "
          f"({len(POPULAR_LEGIT_DOMAINS)} domains x {variants_per_domain})")
    # Align columns with phi (other feature columns are unused for lexical-only)
    phi = pd.concat([phi, inj], ignore_index=True)
    return phi


TOP_SITES_PATH = 'datasets/top-1m.csv'
N_LEGIT = 110000  # number of top-sites domains to use as the legitimate class


def build_legit_urls_from_top_sites(n=N_LEGIT, random_state=42):
    """
    Build legitimate URLs from a real top-sites list (Cisco Umbrella top-1m).

    This REPLACES PhiUSIIL's legitimate class, which is biased toward obscure,
    long-named, bare domains and causes the model to flag real popular homepages.
    Top-sites domains are genuine, popular, mostly short-domain sites — the
    population the extension actually encounters.

    Each domain is emitted with structure (path / subdomain) matching the phishing
    class distribution (~27% path, ~45% subdomain) so URL *structure* carries no
    class information and the model must rely on genuine content signals.
    """
    rng = np.random.RandomState(random_state)
    top = pd.read_csv(TOP_SITES_PATH, header=None, names=['rank', 'domain'])
    domains = top['domain'].dropna().astype(str).head(n).tolist()

    subdomains = ['app', 'login', 'account', 'my', 'secure', 'shop', 'help',
                  'support', 'en', 'mail', 'portal', 'dev', 'news', 'store']
    paths = ['/home', '/login', '/account', '/about', '/products', '/help',
             '/search?q=test', '/p/12345', '/signin', '/dashboard', '/contact',
             '/pricing', '/terms', '/privacy', '/index.html']

    urls = []
    for d in domains:
        d = d.strip().lower()
        if not d or '.' not in d:
            continue
        host = d
        if not host.startswith('www.') and rng.random() < 0.45:
            host = rng.choice(subdomains) + '.' + host
        path = rng.choice(paths) if rng.random() < 0.27 else ''
        urls.append('https://' + host + path)
    print(f"  Top-sites legitimate URLs: {len(urls)} (from top {n} domains)")
    return urls


def load_and_prepare_dataset():
    """
    Build the training matrix from:
      - LEGITIMATE class: real top-sites domains (Cisco Umbrella top-1m),
        structure-augmented to match the phishing distribution.
      - PHISHING class:    PhiUSIIL phishing URLs (raw label == 0).
    Lexical features are SELF-EXTRACTED with the same function used at inference,
    guaranteeing train/serve parity. Labels: 1 = phishing, 0 = legitimate.
    """
    print("Loading PhiUSIIL (phishing class) + top-sites (legitimate class)...")
    phi = pd.read_csv('datasets/phiusiil.csv')
    phi = phi.dropna(subset=['URL'])
    phi = phi[phi['URL'].str.strip().astype(bool)]
    # PhiUSIIL raw encoding: 1 = legitimate, 0 = phishing. Keep only phishing.
    phish_urls = phi[phi['label'] == 0]['URL'].astype(str).tolist()
    print(f"  PhiUSIIL phishing URLs: {len(phish_urls)}")

    legit_urls = build_legit_urls_from_top_sites()

    urls = phish_urls + legit_urls
    y = np.array([1] * len(phish_urls) + [0] * len(legit_urls))  # 1=phish, 0=legit

    # ------------------------------------------------------------------
    # Self-extract lexical features (same code path as the browser extractor)
    # ------------------------------------------------------------------
    print("\nExtracting lexical features from raw URLs...")
    start = time.time()
    lexical_rows = []
    errors = 0
    for i, url in enumerate(urls):
        try:
            lexical_rows.append(extract_lexical_features(str(url)))
        except Exception:
            lexical_rows.append({f: 0 for f in LEXICAL_FEATURES})
            errors += 1
        if (i + 1) % 50000 == 0:
            print(f"  Processed {i+1}/{len(urls)} URLs ({errors} errors)")
    print(f"  Done: {len(lexical_rows)} URLs in {time.time()-start:.1f}s ({errors} errors)")

    X = pd.DataFrame(lexical_rows)[ALL_FEATURES].copy().fillna(0)

    # Neutralize IsHTTPS: legit are all https by construction; don't let scheme
    # become a spurious signal (modern phishing uses https too).
    if 'IsHTTPS' in X.columns:
        X['IsHTTPS'] = 1.0

    print(f"\nFinal dataset: {X.shape[0]} samples, {X.shape[1]} features")
    print(f"  Class distribution: legitimate={np.sum(y==0)}, phishing={np.sum(y==1)}")
    return X, y


def augment_with_missing_content(X, y, fraction=0.3):
    """
    Zero out content/domain features for a fraction of training samples.
    This teaches the model to detect phishing from lexical features alone
    (simulating pages that can't be fetched at inference time).
    """
    content_domain_cols = DOMAIN_FEATURES + CONTENT_FEATURES
    content_indices = [ALL_FEATURES.index(f) for f in content_domain_cols if f in ALL_FEATURES]

    # v3 lexical-only: no content/domain features to zero out. Skip entirely —
    # zeroing nothing and duplicating 30% of rows would only distort the set.
    if not content_indices:
        print("\nContent-zeroed augmentation: skipped (lexical-only feature set, no content features).")
        return X, y

    n_augment = int(len(X) * fraction)
    rng = np.random.RandomState(42)
    aug_indices = rng.choice(len(X), size=n_augment, replace=False)

    X_aug = X.copy()
    if isinstance(X_aug, pd.DataFrame):
        X_aug = X_aug.values

    X_zeroed = X_aug[aug_indices].copy()
    X_zeroed[:, content_indices] = 0

    X_combined = np.vstack([X_aug, X_zeroed])
    y_combined = np.concatenate([y, y[aug_indices]])

    print(f"\nContent-zeroed augmentation:")
    print(f"  Original samples: {len(X_aug)}")
    print(f"  Augmented samples: {len(X_zeroed)} ({fraction:.0%} with content=0)")
    print(f"  Total training set: {len(X_combined)}")

    return X_combined, y_combined


def preprocess_data(X, y):
    """Preprocess: split, SMOTE, normalize."""
    # Train-test split (stratified 80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    # Save raw split for evaluate.py
    joblib.dump((X_train, X_test, y_train, y_test), 'processed_data.pkl')
    print("Saved train/test split to processed_data.pkl")

    print(f"\nBefore SMOTE - Train: {dict(zip(*np.unique(y_train, return_counts=True)))}")

    # Augment training set with content-zeroed samples
    X_train, y_train = augment_with_missing_content(X_train, y_train, fraction=0.3)

    # SMOTE on training data ONLY (if imbalanced)
    class_counts = np.bincount(y_train.astype(int))
    if len(class_counts) == 2 and min(class_counts) / max(class_counts) < 0.8:
        print("\nApplying SMOTE to balance classes...")
        smote = SMOTE(random_state=42, k_neighbors=5)
        X_train, y_train = smote.fit_resample(X_train, y_train)
        print(f"After SMOTE - Train: {dict(zip(*np.unique(y_train, return_counts=True)))}")
    else:
        print(f"\nClasses already balanced, skipping SMOTE.")

    print(f"Test set: {dict(zip(*np.unique(y_test, return_counts=True)))}")

    # Normalize (0-1) for ONNX consistency
    scaler = MinMaxScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    os.makedirs('models', exist_ok=True)
    joblib.dump(scaler, 'models/scaler.pkl')
    print("Scaler saved to models/scaler.pkl")

    return X_train_scaled, X_test_scaled, y_train, y_test, scaler


def train_random_forest(X_train, y_train):
    """Train with 10-fold cross-validation."""
    rf = RandomForestClassifier(
        n_estimators=100,        # 100 trees
        max_depth=20,            # Prevent overfitting
        min_samples_split=5,
        min_samples_leaf=2,
        max_features='sqrt',     # Random subspace
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )

    # 10-fold stratified cross-validation
    print("\nRunning 10-fold stratified cross-validation...")
    cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
    cv_scores = cross_val_score(rf, X_train, y_train, cv=cv, scoring='accuracy')

    print(f"  10-Fold CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    print(f"  Per-fold: {[f'{s:.4f}' for s in cv_scores]}")

    # Train on full training set
    print("\nTraining final model on full training set...")
    rf.fit(X_train, y_train)

    return rf


def evaluate_model(model, X_test, y_test):
    """Comprehensive evaluation."""
    y_pred = model.predict(X_test)
    y_prob = model.predict_proba(X_test)[:, 1]

    results = {
        'accuracy': accuracy_score(y_test, y_pred),
        'precision': precision_score(y_test, y_pred),
        'recall': recall_score(y_test, y_pred),
        'f1_score': f1_score(y_test, y_pred),
        'confusion_matrix': confusion_matrix(y_test, y_pred).tolist()
    }

    print("\n" + "=" * 60)
    print("  EVALUATION RESULTS")
    print("=" * 60)
    print(f"  Accuracy:  {results['accuracy']:.4f}")
    print(f"  Precision: {results['precision']:.4f}")
    print(f"  Recall:    {results['recall']:.4f}")
    print(f"  F1-Score:  {results['f1_score']:.4f}")

    cm = np.array(results['confusion_matrix'])
    print(f"\n  Confusion Matrix:")
    print(f"    TN={cm[0][0]}  FP={cm[0][1]}")
    print(f"    FN={cm[1][0]}  TP={cm[1][1]}")
    if cm[0][0] + cm[0][1] > 0:
        print(f"\n  False Positive Rate: {cm[0][1]/(cm[0][0]+cm[0][1]):.4f}")
    if cm[1][0] + cm[1][1] > 0:
        print(f"  False Negative Rate: {cm[1][0]/(cm[1][0]+cm[1][1]):.4f}")

    # Feature importance
    importances = dict(zip(ALL_FEATURES, model.feature_importances_))
    sorted_imp = sorted(importances.items(), key=lambda x: x[1], reverse=True)

    print("\n  Top 15 Important Features:")
    print(f"  {'Feature':<38} {'Importance':>10}")
    print(f"  {'-'*50}")
    for feat, imp in sorted_imp[:15]:
        bar = '#' * int(imp * 100)
        print(f"  {feat:<38} {imp:>8.4f}  {bar}")

    # Save results
    with open('models/evaluation_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    with open('models/feature_importance.json', 'w') as f:
        json.dump(dict(sorted_imp), f, indent=2)

    print(f"\n  Results saved to models/evaluation_results.json")
    print(f"  Feature importance saved to models/feature_importance.json")

    return results


def main():
    os.makedirs('models', exist_ok=True)

    # Delete cached evaluation results to force re-evaluation
    cached = 'models/evaluation_results.json'
    if os.path.exists(cached):
        os.remove(cached)
        print(f"Deleted cached {cached}")

    print("=" * 60)
    print("  PhishGuard Training Pipeline v2")
    print("  (Self-extracted lexical features for train/inference parity)")
    print("=" * 60)

    X, y = load_and_prepare_dataset()

    print("\nPreprocessing...")
    X_train, X_test, y_train, y_test, scaler = preprocess_data(X, y)

    print("\nTraining Random Forest...")
    model = train_random_forest(X_train, y_train)

    print("\nEvaluating on held-out test set...")
    results = evaluate_model(model, X_test, y_test)

    joblib.dump(model, 'models/random_forest.pkl')
    print(f"\nModel saved to models/random_forest.pkl")

    # Save feature names for reference
    joblib.dump(ALL_FEATURES, 'models/feature_names.pkl')

    print("\n" + "=" * 60)
    print("  Training complete!")
    print("=" * 60)

    return model, scaler, results


if __name__ == "__main__":
    main()
