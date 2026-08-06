"""
Unknown-legitimate false-positive validation.
==============================================
The metric that actually decides whether PhishGuard is usable.

Held-out accuracy on the training corpus is NOT this number: the legitimate
class is partly synthesized, so in-corpus accuracy stays high while real
unknown sites get flagged. Measured on the pre-fix shipped model, held-out
accuracy was 94.02% while unknown legitimate sites scored 0/4 CLEAN.

This script scores legitimate domains that appear in NEITHER training
population — not in the Cisco top-{N_TOP_SITES} slice used for the top-sites
class, and not in PhiUSIIL's legitimate class. It reports the false-positive
rate at the shipped verdict tiers (CLEAN <0.50, SUSPICIOUS 0.50-0.85,
PHISHING >=0.85), both with and without the reputation allowlist, so the
ML tier is measured on its own.

Two populations are checked:
  1. CURATED  — hand-listed real sites the extension's users actually visit
                (regional banks, fintech, e-commerce, local business, schools).
                Includes path variants, because appending a path was the
                dominant pre-fix failure mode.
  2. SAMPLED  — a deep slice of the Cisco top-1m (ranks far below the training
                cut), giving a large unbiased unknown-legitimate sample.

Usage: python ml-pipeline/validate_unknown_legit.py
"""

import json
import os
import sys

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from features.feature_config import ALL_FEATURES
from features.lexical_extractor import extract_lexical_features

# Training cut — keep in sync with train.py N_TOP_SITES.
N_TOP_SITES = 55000
# Sample unknown-legit domains from below this rank so they cannot overlap
# the training slice even if N_TOP_SITES is raised somewhat.
UNKNOWN_RANK_FLOOR = 120000
N_SAMPLED = 4000

CLEAN_MAX = 0.50
PHISH_MIN = 0.85

# Real legitimate sites, deliberately outside the Western top-30k the
# allowlist covers. These are the population the pre-fix model failed on.
CURATED_BARE = [
    # Nigerian / African banking & fintech
    'gtbank.com', 'zenithbank.com', 'firstbanknigeria.com', 'uba.com',
    'accessbankplc.com', 'stanbicibtcbank.com', 'fidelitybank.ng',
    'flutterwave.com', 'paystack.com', 'interswitchng.com', 'moniepoint.com',
    # African e-commerce & media
    'jumia.com.ng', 'konga.com', 'jiji.ng', 'punchng.com', 'vanguardngr.com',
    'premiumtimesng.com', 'nairaland.com', 'takealot.com', 'news24.com',
    # Regional / non-Western mainstream
    'rediff.com', 'indiatimes.com', 'kompas.com', 'detik.com',
    'mercadolibre.com.ar', 'olx.com.br', 'sahibinden.com', 'hepsiburada.com',
    # Small business / institutional patterns
    'oakwood-dental-clinic.com', 'joesplumbingleeds.co.uk',
    'stmarysprimary-ng.org', 'lagostechhub.com.ng',
    'riverside-veterinary.co.uk', 'thecornerbakery-ng.com',
    'greenfield-academy.edu.ng', 'westside-physio.com.au',
]

# Realistic paths a legitimate site of each kind would serve.
CURATED_PATHS = [
    '/about', '/contact', '/services', '/products/catalogue',
    '/login', '/account/settings', '/blog/2026/announcement',
    '/support/faq', '/careers/openings', '/branches/lagos-island',
    '/personal-banking/savings-accounts', '/book-appointment',
    '/admissions/requirements', '/search?q=account&page=2',
]


def load_model():
    rf = joblib.load('models/random_forest.pkl')
    scaler = joblib.load('models/scaler.pkl')
    return rf, scaler


def load_allowlist():
    path = 'phishing-extension/assets/top_domains.json'
    if not os.path.exists(path):
        return set()
    with open(path) as f:
        return set(json.load(f))


def is_allowlisted(url, allowlist):
    host = url.split('//')[-1].split('/')[0].lower()
    if host.startswith('www.'):
        host = host[4:]
    labels = host.split('.')
    for take in (2, 3):
        if take <= len(labels) and '.'.join(labels[-take:]) in allowlist:
            return True
    return False


def score(urls, rf, scaler):
    rows = [extract_lexical_features(u) for u in urls]
    X = pd.DataFrame(rows)[ALL_FEATURES].fillna(0)
    X['IsHTTPS'] = 1.0
    return rf.predict_proba(scaler.transform(X))[:, 1]


def build_curated():
    """Bare domains plus path variants — path was the dominant failure mode."""
    rng = np.random.RandomState(42)
    urls = ['https://' + d for d in CURATED_BARE]
    for d in CURATED_BARE:
        for p in rng.choice(CURATED_PATHS, size=3, replace=False):
            urls.append('https://' + d + p)
    return urls


def build_sampled(allowlist):
    """Deep slice of top-1m: real sites, far below the training cut."""
    top = pd.read_csv('datasets/top-1m.csv', header=None, names=['rank', 'domain'])
    deep = top[top['rank'] >= UNKNOWN_RANK_FLOOR]['domain'].dropna().astype(str)
    phi = pd.read_csv('datasets/phiusiil.csv').dropna(subset=['URL'])
    phi_hosts = set()
    for u in phi[phi['label'] == 1]['URL'].astype(str):
        h = u.split('//')[-1].split('/')[0].lower()
        phi_hosts.add(h[4:] if h.startswith('www.') else h)
    pool = [d for d in deep if d not in phi_hosts]
    rng = np.random.RandomState(42)
    picked = list(rng.choice(pool, size=min(N_SAMPLED, len(pool)), replace=False))
    rng2 = np.random.RandomState(7)
    urls = []
    for d in picked:
        # Match real browsing: most visits carry a path.
        if rng2.random() < 0.5:
            urls.append('https://' + d + rng2.choice(CURATED_PATHS))
        else:
            urls.append('https://' + d)
    return urls


def report(name, urls, rf, scaler, allowlist):
    p = score(urls, rf, scaler)
    onlist = np.array([is_allowlisted(u, allowlist) for u in urls])
    flagged = p >= CLEAN_MAX
    phish = p >= PHISH_MIN
    # Extension behaviour: allowlisted URLs short-circuit to CLEAN.
    eff_flagged = flagged & ~onlist

    print('=' * 84)
    print(f'  {name}  (n={len(urls)})')
    print('=' * 84)
    print(f'  in reputation allowlist:        {onlist.sum():5d} ({100*onlist.mean():5.1f}%)')
    print(f'  ML tier alone — flagged:        {flagged.sum():5d} ({100*flagged.mean():5.1f}%)   <-- ML false-positive rate')
    print(f'  ML tier alone — PHISHING:       {phish.sum():5d} ({100*phish.mean():5.1f}%)')
    print(f'  full pipeline  — flagged:       {eff_flagged.sum():5d} ({100*eff_flagged.mean():5.1f}%)   <-- what users experience')
    print(f'  mean score {p.mean():.3f}   median {np.median(p):.3f}')

    unknown = ~onlist
    if unknown.sum():
        print(f'  --- restricted to NOT allowlisted (n={unknown.sum()}): '
              f'flagged {100*(p[unknown] >= CLEAN_MAX).mean():.1f}%, '
              f'PHISHING {100*(p[unknown] >= PHISH_MIN).mean():.1f}%')

    worst = np.argsort(-p)[:8]
    print('  worst offenders:')
    for i in worst:
        tag = 'allowlisted' if onlist[i] else 'ML-flagged ' if p[i] >= CLEAN_MAX else 'clean      '
        print(f'    {p[i]:.3f}  {tag}  {urls[i][:70]}')
    print()
    return {'n': len(urls), 'ml_fpr': float(flagged.mean()),
            'ml_phish_rate': float(phish.mean()),
            'pipeline_fpr': float(eff_flagged.mean()),
            'mean_score': float(p.mean())}


def main():
    rf, scaler = load_model()
    allowlist = load_allowlist()
    print(f'\nModel: models/random_forest.pkl ({rf.n_estimators} trees)')
    print(f'Allowlist: {len(allowlist)} domains\n')

    results = {}
    curated = build_curated()
    results['curated'] = report('CURATED unknown-legitimate (regional, fintech, small business)',
                                curated, rf, scaler, allowlist)
    sampled = build_sampled(allowlist)
    results['sampled'] = report(f'SAMPLED unknown-legitimate (top-1m rank >= {UNKNOWN_RANK_FLOOR})',
                                sampled, rf, scaler, allowlist)

    print('=' * 84)
    print('  SUMMARY — unknown-legitimate false-positive rate')
    print('=' * 84)
    for k, v in results.items():
        print(f'  {k:<10} n={v["n"]:<6} ML FPR {100*v["ml_fpr"]:5.1f}%   '
              f'pipeline FPR {100*v["pipeline_fpr"]:5.1f}%   mean {v["mean_score"]:.3f}')
    print()
    print('  Target: ML FPR < 10%. This is the acceptance metric for the')
    print('  extension, not held-out corpus accuracy.')

    os.makedirs('models', exist_ok=True)
    with open('models/unknown_legit_validation.json', 'w') as f:
        json.dump(results, f, indent=2)
    print('\n  Saved to models/unknown_legit_validation.json')


if __name__ == '__main__':
    main()
