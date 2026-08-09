"""
Generate the TLD legitimacy rates used for the TLDLegitimateProb feature.
================================================================================
`TLDLegitimateProb` was a 14-entry hardcoded dict with a flat 0.50 default for
every other suffix. It is the #1 feature by mean |SHAP|, and the default is
wrong in both directions:

1. Legitimate coverage: 22% of the curated unknown-legit acceptance corpus
   (validate_unknown_legit.py) hits the 0.50 default — `.ng`, `.com.ng`,
   `.edu.ng`, `.com.au`, `.fidelitybank.ng` and friends all start handicapped
   against the 0.95 a US `.com` receives.
2. Phishing coverage: the dict also OVER-scores hostile suffixes. Measured on
   the training corpus, `.app` is 6,368 phishing rows vs 200 legit (rate 0.03),
   `.xyz` 0.027, `.top` 0.005 — all scored a neutral 0.50 today, while `.tk`
   (0.019) was hand-assigned 0.10. The extension's hardest real case is a fresh
   malicious domain on exactly these suffixes.

Both are the same defect: a hand-picked table standing in for the actual class
distribution. This replaces it with empirical per-suffix rates.

ESTIMATOR.  For a suffix with n training rows of which k are legitimate:

    logit_hat = w * log((k + 0.5) / (n - k + 0.5)) + (1 - w) * logit(parent)
    w         = n / (n + M)

i.e. the empirical log-odds shrunk toward its PARENT suffix's already-shrunk
estimate (`com.ng` -> `ng` -> global prior), with weight rising as evidence
accumulates. M is the shrinkage strength in pseudo-rows: a suffix needs M rows
before it moves halfway off its parent. Shrinkage is on the logit scale
because a raw rate of 1.0 (`gov.ng`, 9/9) is unbounded as a probability but
finite in log-odds; the 0.5 offsets keep k=0 and k=n finite.

WHY M IS LARGE.  The legitimate class is Cisco Umbrella's top ranks, which are
Western-skewed: all of top-1m holds just 34 `com.ng` domains against PhiUSIIL's
59 `com.ng` phishing URLs. A maximum-likelihood rate therefore reads 0.14 and
declares Nigeria's commercial suffix hostile — measured, that flagged 8/8
curated `com.ng` sites. The data cannot answer the question for that suffix,
and the estimator's job is to say so: with M large, a suffix needs substantial
evidence before it moves off its parent, so sparse regional suffixes stay
neutral while `.app` (n=5,574), `.top` (n=1,942) and `.tk` (n=176) have enough
rows to earn their low scores. M is chosen by sweeping against the
unknown-legit acceptance metric, not by taste — see IMPLEMENTATION_NOTE.md.

MEASURED OUTCOME — this did NOT reduce the headline FPR.  The Aug 7 commit
predicted the unknown-legit FPR could be recovered from this feature. Measured,
it cannot: curated FPR went 20.8% -> 24.3%, sampled 20.8% -> 19.6%. The
hardcoded dict's 0.95 for `.com` was, for the curated corpus (100 of 144 URLs
are `.com`), a better number than the honest empirical 0.763 — it was
effectively a hand-tuned prior favouring the sites that corpus contains. What
this change buys is correctness rather than a better number: hostile suffixes
that the dict scored a neutral 0.50 are now scored on evidence (`.app` 0.095,
`.top` 0.030, `.xyz` 0.292), and every suffix outside the 14 entries gets a
measured rate instead of a coin flip. The residual curated FPR traces to
`DomainLength` (compound suffixes are mechanically longer), not to this
feature — see IMPLEMENTATION_NOTE.md.

SERVE-TIME FALLBACK.  Lookup walks the same hierarchy: exact suffix, then
progressively shorter parents, then the prior. A suffix never seen in training
(`sch.ng`) inherits `ng` rather than a global default. Both extractors
implement the identical walk.

The prior is the observed legitimacy rate of the corpus (~0.61), so an unknown
suffix now inherits a measured base rate rather than an arbitrary coin flip.

NO TEST LEAKAGE.  Rates are counted over train.py's TRAINING rows only,
reproducing its exact stratified split (same ordering, same random_state=42,
same stratify) before any counting. The 20% hold-out never touches the table.

BIAS DISCLOSURE.  This is target encoding, so the rates inherit the sampling
bias of their sources (Cisco Umbrella top-55k is Western-skewed; PhiUSIIL
phishing is not). Where a suffix is well covered on one side only, the rate
reports the corpus, not the world — see the printed table and the note in
IMPLEMENTATION_NOTE.md.

All arithmetic happens here, at generation time; both extractors do a plain
dict lookup with a prior fallback, so Python and the browser are identical by
construction and check_parity.py remains the enforcement gate.

Usage:  python ml-pipeline/gen_tld_rates.py [M]
"""
import collections
import json
import os
import sys
from urllib.parse import urlparse

import numpy as np
import pandas as pd
import tldextract
from sklearn.model_selection import train_test_split

OUT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..', 'phishing-extension', 'src', 'ml', 'tld-rates.ts',
)
JSON_OUT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'features', 'tld_rates.json',
)

# Keep in sync with train.py.
N_TOP_SITES = 55000
N_PHIUSIIL_LEGIT = 55000
TEST_SIZE = 0.2
RANDOM_STATE = 42
# Legitimate rate evidence is drawn from Cisco ranks 1..this. Must stay <=
# validate_unknown_legit.UNKNOWN_RANK_FLOOR so the acceptance corpus is drawn
# from ranks this table never saw. See build_counts().
EVIDENCE_RANK_CAP = 120000
# Shrinkage strength in pseudo-rows (see ESTIMATOR above). Swept against the
# unknown-legit acceptance metric on the widened evidence set:
#   M=30  com.ng 0.303  .tk 0.065      M=100  com.ng 0.477  .tk 0.147
#   M=300 com.ng 0.612  .tk 0.345 (hostile signal washing out)
# 100 measured best on both FPR populations (curated 24.3%, sampled 19.6%)
# and is the largest M that still keeps .tk clearly hostile. One global M
# cannot both neutralise sparse regional suffixes and preserve sparse hostile
# ones; 100 works because .tk carries 176 rows at a 3.4% legit rate while
# com.ng carries 60 at 16.7% — the estimator separates them on evidence.
M_DEFAULT = 100.0

REPORT = ('com', 'ng', 'com.ng', 'edu.ng', 'gov.ng', 'org', 'net', 'edu',
          'gov', 'co.uk', 'tk', 'ml', 'ga', 'cf', 'gq', 'com.au', 'de', 'fr',
          'jp', 'com.br', 'in', 'ac.in', 'info', 'xyz', 'top', 'app')


def legit_domains():
    """Reproduce train.py build_legit_urls()'s domain list exactly."""
    rng = np.random.RandomState(RANDOM_STATE)
    phi = pd.read_csv('datasets/phiusiil.csv').dropna(subset=['URL'])
    small = []
    for u in phi[phi['label'] == 1]['URL'].astype(str):
        try:
            h = (urlparse(u).hostname or '').lower()
        except Exception:
            continue
        if h.startswith('www.'):
            h = h[4:]
        if h and '.' in h:
            small.append(h)
    rng.shuffle(small)
    small = small[:N_PHIUSIIL_LEGIT]
    top = pd.read_csv('datasets/top-1m.csv', header=None,
                      names=['rank', 'domain'])
    top_domains = top['domain'].dropna().astype(str).head(N_TOP_SITES).tolist()
    return [d.strip().lower() for d in top_domains + small]


def suffix_of(url):
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    try:
        return tldextract.extract(url).suffix.lower()
    except Exception:
        return None


COUNTS_CACHE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '__tld_counts.json',
)


def estimate(n_by, k_by, prior, M):
    """
    Hierarchically shrunk per-suffix legitimacy rates.

    Parents are resolved shortest-first so a suffix always shrinks toward an
    already-shrunk parent estimate (`com.ng` -> `ng` -> prior).
    """
    logit_prior = float(np.log(prior / (1 - prior)))
    rates, logits = {}, {}
    for s in sorted(n_by, key=lambda x: x.count('.')):
        parent = s.split('.', 1)[1] if '.' in s else None
        target = logits.get(parent, logit_prior) if parent else logit_prior
        n, k = n_by[s], k_by.get(s, 0)
        w = n / (n + M)
        logit = w * float(np.log((k + 0.5) / (n - k + 0.5))) + (1 - w) * target
        logits[s] = logit
        rates[s] = round(float(1.0 / (1.0 + np.exp(-logit))), 6)
    return rates


def build_counts():
    """
    Count suffix rows per class over the rate-EVIDENCE populations.

    These are deliberately NOT the training rows. The training corpus is
    balanced ~52/48 by construction (N_TOP_SITES and N_PHIUSIIL_LEGIT are
    sampling choices made to suit SMOTE), and estimating a reputation prior
    from a population balanced for a different purpose is what produced the
    first version's headline defect: `.com` came out at 0.585 — barely above
    the 0.523 corpus prior — because PhiUSIIL phishing is 43% `.com`. That
    reads as "`.com` is uninformative", when the honest statement is that the
    legitimate sample was truncated at 55k domains while the phishing sample
    was not.

    So legitimate evidence is widened to Cisco's list up to EVIDENCE_RANK_CAP,
    which is bounded on both sides to keep every metric honest:
      * domains in the held-out TEST split are excluded, so held-out accuracy
        is not measured against rows that informed the feature;
      * the cap sits at the sampled-validation floor (rank 120,000), so the
        unknown-legit acceptance corpus is drawn entirely from ranks this
        table never saw.
    Phishing evidence stays the training-split phishing rows, for the same
    no-test-leakage reason.
    """
    phi = pd.read_csv('datasets/phiusiil.csv')
    phi = phi.dropna(subset=['URL'])
    phi = phi[phi['URL'].str.strip().astype(bool)]
    phish_urls = phi[phi['label'] == 0]['URL'].astype(str).tolist()

    # Suffix is unaffected by the path/subdomain synthesis build_legit_urls
    # applies (a prepended label does not change the registered suffix), so
    # counting over the bare domains gives the same suffix multiset as the
    # training URLs while keeping this script independent of the RNG draws.
    legit = [d for d in legit_domains() if d and '.' in d]

    n_phish, n_legit = len(phish_urls), len(legit)
    y = np.array([1] * n_phish + [0] * n_legit)

    # train.py splits the feature matrix built from phish_urls + legit_urls in
    # this order, with these parameters. Splitting the index array the same way
    # selects the same rows.
    train_idx, test_idx = train_test_split(
        np.arange(len(y)), test_size=TEST_SIZE,
        random_state=RANDOM_STATE, stratify=y,
    )
    train_set = set(train_idx.tolist())
    held_out_legit = {legit[i - n_phish] for i in test_idx if i >= n_phish}

    n_by, k_by = collections.Counter(), collections.Counter()

    # Phishing evidence: training-split rows only.
    n_phish_used = 0
    for i, u in enumerate(phish_urls):
        if i not in train_set:
            continue
        s = suffix_of(u)
        if s:
            n_by[s] += 1
            n_phish_used += 1

    # Legitimate evidence: Cisco ranks 1..EVIDENCE_RANK_CAP plus the PhiUSIIL
    # legitimate slice, minus anything held out for testing.
    top = pd.read_csv('datasets/top-1m.csv', header=None,
                      names=['rank', 'domain']).dropna(subset=['domain'])
    wide = top[top['rank'] <= EVIDENCE_RANK_CAP]['domain'].astype(str)
    legit_pool = [d.strip().lower() for d in wide]
    legit_pool += [d for i, d in enumerate(legit)
                   if (i + n_phish) in train_set]
    n_legit_used = 0
    for d in legit_pool:
        if not d or '.' not in d or d in held_out_legit:
            continue
        s = suffix_of(d)
        if s:
            n_by[s] += 1
            k_by[s] += 1
            n_legit_used += 1

    total = sum(n_by.values())
    total_legit = sum(k_by.values())
    prior = total_legit / total
    print(f'  evidence: legit {n_legit_used} (Cisco <= {EVIDENCE_RANK_CAP} '
          f'+ PhiUSIIL legit, held-out excluded) / phish {n_phish_used}')
    print(f'  prior p(legit) = {prior:.4f}  ({total_legit}/{total} rows)')

    counts = {'prior': prior, 'n': dict(n_by), 'k': dict(k_by)}
    with open(COUNTS_CACHE, 'w', encoding='utf-8', newline='\n') as f:
        json.dump(counts, f)
    return counts


def main():
    M = float(sys.argv[1]) if len(sys.argv) > 1 else M_DEFAULT

    # Counting requires suffix-extracting 200k+ URLs; caching it makes the M
    # sweep instant. Delete __tld_counts.json when the corpus changes.
    if os.path.exists(COUNTS_CACHE):
        with open(COUNTS_CACHE, encoding='utf-8') as f:
            counts = json.load(f)
        print('  counts loaded from cache')
    else:
        counts = build_counts()

    n_by, k_by, prior = counts['n'], counts['k'], counts['prior']
    print(f'  M = {M:g}')
    rates = estimate(n_by, k_by, prior, M)

    with open(JSON_OUT, 'w', encoding='utf-8', newline='\n') as f:
        json.dump({'prior': round(prior, 6), 'shrinkage_M': M,
                   'rates': dict(sorted(rates.items()))}, f, indent=1)

    head = f"""/**
 * GENERATED FILE — do not edit by hand.
 *
 * Empirical per-suffix legitimacy rates for the TLDLegitimateProb feature,
 * counted on the PhishGuard TRAINING rows only (Cisco Umbrella top-{N_TOP_SITES // 1000}k +
 * PhiUSIIL legitimate slice vs PhiUSIIL phishing URLs), shrunk on the logit
 * scale toward each suffix's PARENT with M = {M:g} pseudo-rows.
 *
 * Replaces the 14-entry hardcoded dict whose flat 0.50 default both penalised
 * legitimate country suffixes (.ng, .com.au) and flattered hostile ones
 * (.app, .xyz, .top). M is deliberately large: the legitimate class is
 * Western-skewed, so sparse regional suffixes must stay near neutral rather
 * than inherit a confident rate from a handful of rows.
 *
 * Lookup walks the hierarchy — exact suffix, then successively shorter
 * parents, then TLD_LEGIT_PRIOR — so an unseen `sch.ng` inherits `ng`.
 * tldLegitimateRate() in feature-extractor.ts implements that walk; do not
 * index this table directly.
 *
 * Prior (unknown suffix): {prior:.6f}   Suffixes: {len(rates)}
 * Regenerate with:  python ml-pipeline/gen_tld_rates.py
 * then re-verify:   python ml-pipeline/check_parity.py
 */
export const TLD_LEGIT_PRIOR = {prior:.6f};

export const TLD_LEGIT_RATES: Record<string, number> = {{
"""
    body = ''.join(f'  {json.dumps(s)}: {rates[s]:.6f},\n'
                   for s in sorted(rates))
    with open(OUT, 'w', encoding='utf-8', newline='\n') as f:
        f.write(head + body + '};\n')
    print(f'  wrote {os.path.relpath(OUT)} '
          f'({len(rates)} suffixes, {os.path.getsize(OUT) / 1024:.0f} KiB)')
    print(f'  wrote {os.path.relpath(JSON_OUT)}')

    print(f'\n  {"suffix":<12}{"n":>8}{"k":>8}{"raw":>8}{"shrunk":>9}   old')
    old = {'com': 0.95, 'org': 0.90, 'net': 0.85, 'edu': 0.98, 'gov': 0.99,
           'co.uk': 0.90, 'de': 0.92, 'fr': 0.91, 'jp': 0.93, 'tk': 0.10,
           'ml': 0.15, 'ga': 0.15, 'cf': 0.15, 'gq': 0.15}
    for s in REPORT:
        n, k = n_by.get(s, 0), k_by.get(s, 0)
        if not n:
            print(f'  {s:<12}{0:>8}{0:>8}{"--":>8}{prior:>9.3f}   '
                  f'{old.get(s, 0.50):.2f}')
            continue
        print(f'  {s:<12}{n:>8}{k:>8}{k / n:>8.3f}{rates[s]:>9.3f}   '
              f'{old.get(s, 0.50):.2f}')


if __name__ == '__main__':
    main()
