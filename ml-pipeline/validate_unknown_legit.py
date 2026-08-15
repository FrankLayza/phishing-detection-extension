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
rate at the shipped verdict tiers (CLEAN <0.50, SUSPICIOUS 0.50-0.90,
PHISHING >=0.90), both with and without the reputation allowlist, so the
ML tier is measured on its own.

Scored by default against `phishing-extension/assets/phishing_model.json` — the
committed artifact the extension actually loads. Pass `--model pkl` to score
`models/random_forest.pkl` instead, which is useful for measuring a fresh retrain
before deciding whether to export it, but must NOT be quoted as the product
metric: the two are different forests (806,620 vs 864,614 nodes), and every FPR
figure this script published before Aug 15, 2026 described the .pkl.

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
import re
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

# The artifact the extension loads. Default scoring target — see ShippedModel.
SHIPPED_MODEL_JSON = 'phishing-extension/assets/phishing_model.json'

# Verdict bands. MUST match verdictFor() in phishing-extension/src/popup.tsx.
# PHISH_MIN was 0.85 here while the shipped red line is 0.90, which over-reported
# hard alarms; corrected Aug 15, 2026.
CLEAN_MAX = 0.50
PHISH_MIN = 0.90

# NOTE on URL shape: these populations are built as 'https://' + domain, with no
# root slash, while the browser always reports homepages slash-terminated. That
# used to matter a great deal (+26 points of FPR). It no longer does: commit
# 38e820d strips a lone ROOT slash in both extractors, so 'https://d' and
# 'https://d/' now yield byte-identical feature vectors. Verified Aug 15, 2026.
# Do not "fix" this by appending slashes to path URLs -- there a trailing slash is
# real path structure and would change the features.

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
    """The .pkl produced by the most recent train.py run. NOT what ships."""
    rf = joblib.load('models/random_forest.pkl')
    scaler = joblib.load('models/scaler.pkl')
    return rf, scaler


class ShippedModel:
    """
    Scores through the committed browser artifact — the forest the extension
    actually runs.

    Why this exists: this harness used to load models/random_forest.pkl, which is
    whatever train.py last produced (864,614 nodes) and not the committed model
    (806,620 nodes). Every FPR figure it reported therefore described a forest
    nobody runs. Same trap already documented for test_url.py. The .pkl path is
    kept behind --model pkl so a fresh retrain can still be measured BEFORE the
    decision to export it.

    Traversal and scaling mirror rf-inference.ts exactly (val * scale + min;
    <= goes left; soft-vote sum of per-tree class fractions / n_estimators),
    which the parity harness confirms against sklearn.
    """

    def __init__(self, path=SHIPPED_MODEL_JSON):
        with open(path) as fh:
            m = json.load(fh)
        self.path = path
        self.feature_names = m['feature_names']
        self.scale = np.asarray(m['scaler']['scale'], dtype=np.float64)
        self.offset = np.asarray(m['scaler']['min'], dtype=np.float64)
        self.trees = m['trees']
        self.n_estimators = m['n_estimators']
        self.node_count = sum(self._count(t) for t in self.trees)

    @staticmethod
    def _count(node):
        stack, n = [node], 0
        while stack:
            cur = stack.pop()
            n += 1
            if 'v' not in cur:
                stack.append(cur['l'])
                stack.append(cur['r'])
        return n

    def predict_proba_phish(self, X):
        """P(phishing) for a DataFrame of raw features, column order from the JSON."""
        raw = X.reindex(columns=self.feature_names).fillna(0).to_numpy(dtype=np.float64)
        scaled = raw * self.scale + self.offset
        out = np.empty(len(scaled), dtype=np.float64)
        for i, row in enumerate(scaled):
            total = 0.0
            for tree in self.trees:
                node = tree
                while 'v' not in node:
                    node = node['l'] if row[node['f']] <= node['t'] else node['r']
                total += node['v'][1]
            out[i] = total / self.n_estimators
        return out


def load_allowlist():
    path = 'phishing-extension/assets/top_domains.json'
    if not os.path.exists(path):
        return set()
    with open(path) as f:
        return set(json.load(f))


def is_allowlisted(url, allowlist):
    """
    Mirrors adapter A of src/ml/reputation.ts for this population.

    NOTE the deliberate simplification: reputation.ts also skips the allowlist for
    *platform tenants* (foo.vercel.app), because the ICANN-only PSL resolves those to
    the platform's own registrable domain, and it then applies the advisory TLD
    correction to them. Neither branch is reproduced here. _count_platform_tenants()
    reports how many tenants the population contains so the resulting error is
    bounded and visible -- it is ~5 of 4,000 (0.13pt) as of Aug 15, 2026.
    Do not grow this function into a second copy of reputation.ts; if that error ever
    matters, score the population through demo_supervisor.mjs instead.
    """
    host = url.split('//')[-1].split('/')[0].lower()
    if host.startswith('www.'):
        host = host[4:]
    labels = host.split('.')
    for take in (2, 3):
        if take <= len(labels) and '.'.join(labels[-take:]) in allowlist:
            return True
    return False


def _count_platform_tenants(urls):
    """
    How many URLs are tenants on a hosting platform, where this harness's
    reputation model diverges from the shipped one (see is_allowlisted).

    Reads PLATFORM_HOSTS straight out of reputation.ts so the two cannot drift.
    """
    src = 'phishing-extension/src/ml/reputation.ts'
    if not os.path.exists(src):
        return []
    with open(src, encoding='utf-8') as fh:
        block = re.search(r'PLATFORM_HOSTS[^=]*=\s*\[(.*?)\]', fh.read(), re.S)
    if not block:
        return []
    platforms = re.findall(r'"([^"]+)"', block.group(1))
    tenants = []
    for u in urls:
        host = u.split('//')[-1].split('/')[0].lower()
        if any(host.endswith('.' + p) for p in platforms):
            tenants.append(host)
    return tenants


def extract(urls):
    """Feature matrix for a URL list, using the same extractor training uses."""
    rows = [extract_lexical_features(u) for u in urls]
    X = pd.DataFrame(rows)[ALL_FEATURES].fillna(0)
    X['IsHTTPS'] = 1.0
    return X


def score(urls, model):
    """
    P(phishing) per URL. `model` is either a ShippedModel (the committed browser
    artifact) or an (rf, scaler) pair from the .pkl.
    """
    X = extract(urls)
    if isinstance(model, ShippedModel):
        return model.predict_proba_phish(X)
    rf, scaler = model
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


def report(name, urls, model, allowlist):
    p = score(urls, model)
    onlist = np.array([is_allowlisted(u, allowlist) for u in urls])
    tenants = _count_platform_tenants(urls)
    flagged = p >= CLEAN_MAX
    phish = p >= PHISH_MIN
    # Extension behaviour: allowlisted URLs short-circuit to CLEAN.
    eff_flagged = flagged & ~onlist

    print('=' * 84)
    print(f'  {name}  (n={len(urls)})')
    print('=' * 84)
    print(f'  in reputation allowlist:        {onlist.sum():5d} ({100*onlist.mean():5.1f}%)')
    print(f'  ML tier alone — flagged:        {flagged.sum():5d} ({100*flagged.mean():5.1f}%)   <-- ML false-positive rate')
    print(f'  ML tier alone — PHISHING:       {phish.sum():5d} ({100*phish.mean():5.1f}%)   <-- hard red alarms (>= {PHISH_MIN:.2f})')
    print(f'  full pipeline  — flagged:       {eff_flagged.sum():5d} ({100*eff_flagged.mean():5.1f}%)   <-- what users experience')
    print(f'  mean score {p.mean():.3f}   median {np.median(p):.3f}')
    if tenants:
        print(f'  platform tenants:               {len(tenants):5d} ({100*len(tenants)/len(urls):5.2f}%)'
              f'   <-- reputation approximated here, see is_allowlisted()')

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


def _wants_pkl(argv):
    """`--model pkl` scores the last train.py output instead of the shipped JSON."""
    if '--model' not in argv:
        return False
    i = argv.index('--model')
    return i + 1 < len(argv) and argv[i + 1] == 'pkl'


def main():
    use_pkl = _wants_pkl(sys.argv[1:])
    if use_pkl:
        model = load_model()
        rf, _ = model
        model_desc = (f'models/random_forest.pkl ({rf.n_estimators} trees, '
                      f'{sum(t.tree_.node_count for t in rf.estimators_)} nodes)')
        caveat = ('  !! This is the last train.py output, NOT the shipped model. Use for\n'
                  '     experiment before/after only; do not quote as the product metric.')
    else:
        model = ShippedModel()
        model_desc = (f'{model.path} ({model.n_estimators} trees, '
                      f'{model.node_count} nodes)  [SHIPPED ARTIFACT]')
        caveat = None

    allowlist = load_allowlist()
    print(f'\nModel: {model_desc}')
    if caveat:
        print(caveat)
    print(f'Bands: CLEAN < {CLEAN_MAX:.2f}  ·  SUSPICIOUS < {PHISH_MIN:.2f}  ·  PHISHING >= {PHISH_MIN:.2f}')
    print(f'Allowlist: {len(allowlist)} domains\n')

    results = {'model': model_desc}
    curated = build_curated()
    results['curated'] = report('CURATED unknown-legitimate (regional, fintech, small business)',
                                curated, model, allowlist)
    sampled = build_sampled(allowlist)
    results['sampled'] = report(f'SAMPLED unknown-legitimate (top-1m rank >= {UNKNOWN_RANK_FLOOR})',
                                sampled, model, allowlist)

    print('=' * 84)
    print('  SUMMARY — unknown-legitimate false-positive rate')
    print('=' * 84)
    print(f'  scored on: {model_desc}')
    for k, v in results.items():
        if k == 'model':
            continue
        print(f'  {k:<10} n={v["n"]:<6} ML FPR {100*v["ml_fpr"]:5.1f}%   '
              f'pipeline FPR {100*v["pipeline_fpr"]:5.1f}%   '
              f'hard red {100*v["ml_phish_rate"]:4.1f}%   mean {v["mean_score"]:.3f}')
    print()
    print('  Target: ML FPR < 10%. This is the acceptance metric for the')
    print('  extension, not held-out corpus accuracy.')

    os.makedirs('models', exist_ok=True)
    out = 'models/unknown_legit_validation.json' if not use_pkl \
        else 'models/unknown_legit_validation_pkl.json'
    with open(out, 'w') as f:
        json.dump(results, f, indent=2)
    print(f'\n  Saved to {out}')


if __name__ == '__main__':
    main()
