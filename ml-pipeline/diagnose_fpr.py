"""
FPR diagnosis — which feature is the current false-positive driver?
===================================================================
Answers one question: for the unknown-legitimate sites the model flags, WHICH
feature makes them look phishing-like, and is that feature's training
distribution unrepresentative of real legitimate sites?

Why this script exists rather than a hypothesis. Every feature-level guess at this
metric has failed on this project (path brand-similarity gate, the TLD table, the
12-feature subset) and every corpus-level fix found by *measuring* has worked (path
structure 60.4% -> 18.1%; query/digit composition 20.8% -> 15.4%). The query/digit
leak was found by asking the model about its own false positives, not by theorising.
This reproduces that method in a rerunnable form.

It also exists because the inherited diagnosis went stale. SOURCE_OF_TRUTH.md and
memory.md blame `DomainLength` encoding compound-suffix structure as risk
(gtbank.com.ng being mechanically longer than gtbank.com). That mechanism was
already removed in 0ca9429, which redefined DomainLength as the length of the
registrable LABEL only -- so gtbank.com.ng and gtbank.com both score 6. Whatever
drives the residual FPR, it is not that.

Method:
  1. Training distributions per class, from processed_data.pkl (written by train.py).
  2. Score the unknown-legit populations through the SHIPPED model.
  3. For each feature, ask: do the FLAGGED legitimate URLs sit on the phishing side
     of the training legit distribution? Rank by how far, in training-legit sigmas,
     and signed so positive always means "looks more phishing-like".

A large positive gap means the model is flagging these sites on that feature AND the
synthesised legit class did not cover that region -- i.e. a corpus gap, which is the
class of defect that has actually responded to fixes here.

RESULT, first run (Aug 15, 2026, shipped model, 1,714 unknown-legit URLs reaching the
ML tier, 23.5% flagged):

    feature              train_legit  train_phish  flagged   gap_sd
    TLDLegitimateProb          0.779        0.552    0.598    +1.59
    NoOfSubDomain              1.162        0.710    0.336    +0.62
    SpacialCharRatioInURL      0.030        0.033    0.035    +0.37
    DegitRatioInURL            0.023        0.066    0.041    +0.36
    DomainLength               9.308        8.989    9.453    -0.03

Two conclusions worth not re-deriving:

  1. `DomainLength` is NOT involved (-0.03 sd), and the training classes barely differ
     on it (class_sep 0.07; legit domains are marginally LONGER than phishing ones).
     Its high permutation/Gini importance (0.1238, #2 in the model) comes from
     interaction splits, not from separating the classes on this population. High
     importance is not evidence of being the error's cause -- which is exactly the
     inference the older docs made.
  2. The driver is suffix trust, at 2.5x the next factor. But this is NOT an aggregate
     distribution mismatch: mean suffix trust is ~0.785 across the ENTIRE top-1m at
     every rank depth (measured in 8k samples per band), so the legit class is already
     representative on average. The gap is in the tail -- only 0.9% of training legit
     sits below 0.35 trust, while the flagged sites concentrate there. Hence the
     N_LOW_TRUST_LEGIT enrichment in train.py, which oversamples that tail rather than
     matching a distribution.

Usage: python ml-pipeline/diagnose_fpr.py
"""

import importlib.util
import os
import sys

import joblib
import numpy as np
import pandas as pd

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def _load_validator():
    """Reuse the validated harness rather than duplicating its scoring."""
    spec = importlib.util.spec_from_file_location(
        'validate_unknown_legit', os.path.join(HERE, 'validate_unknown_legit.py'))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def main():
    v = _load_validator()

    print('Loading training distributions from processed_data.pkl ...')
    X_train, X_test, y_train, y_test = joblib.load('processed_data.pkl')
    X_train = pd.DataFrame(X_train)
    # train.py labels: 1 = phishing, 0 = legitimate.
    tr_legit = X_train[np.asarray(y_train) == 0]
    tr_phish = X_train[np.asarray(y_train) == 1]
    print(f'  training legit={len(tr_legit)}  phish={len(tr_phish)}')

    model = v.ShippedModel()
    allow = v.load_allowlist()
    print(f'Scoring unknown-legit populations on {model.path} '
          f'({model.node_count} nodes) ...')

    urls = v.build_curated() + v.build_sampled(allow)
    # The ML tier is what we are diagnosing, so drop allowlisted URLs: they never
    # reach the model in the shipped pipeline.
    urls = [u for u in urls if not v.is_allowlisted(u, allow)]
    X_unk = v.extract(urls)
    p = model.predict_proba_phish(X_unk)
    flagged = p >= v.CLEAN_MAX
    print(f'  unknown-legit reaching the ML tier: {len(urls)}   '
          f'flagged: {flagged.sum()} ({100*flagged.mean():.1f}%)\n')

    feats = [c for c in X_train.columns if c in X_unk.columns]
    rows = []
    for f in feats:
        legit_mu = tr_legit[f].mean()
        legit_sd = tr_legit[f].std() or 1e-9
        phish_mu = tr_phish[f].mean()
        # Which way is "more phishing-like" for this feature, per training data?
        direction = np.sign(phish_mu - legit_mu) or 1.0
        fl_mu = X_unk.loc[flagged.nonzero()[0], f].mean() if flagged.any() else np.nan
        cl_mu = X_unk.loc[(~flagged).nonzero()[0], f].mean() if (~flagged).any() else np.nan
        gap = direction * (fl_mu - legit_mu) / legit_sd
        rows.append({
            'feature': f, 'train_legit': legit_mu, 'train_phish': phish_mu,
            'unk_flagged': fl_mu, 'unk_clean': cl_mu,
            'gap_sigma': gap,
            'class_sep': abs(phish_mu - legit_mu) / legit_sd,
        })

    df = pd.DataFrame(rows).sort_values('gap_sigma', ascending=False)
    pd.set_option('display.width', 150)
    print('=' * 118)
    print('  Flagged legitimate URLs vs the TRAINING legit class, in training-legit sigmas')
    print('  gap_sigma > 0  =>  flagged sites look MORE phishing-like on this feature')
    print('  class_sep      =>  how far apart the two training classes are (context)')
    print('=' * 118)
    print(df.to_string(index=False, float_format=lambda x: f'{x:9.3f}'))

    print()
    print('  TOP CANDIDATES (largest gap where the classes are also separated):')
    top = df[(df.gap_sigma > 0.25) & (df.class_sep > 0.1)].head(6)
    if top.empty:
        print('    none -- no single feature explains the flags; the cause is')
        print('    distributed, or lies in feature interactions rather than marginals.')
    for _, r in top.iterrows():
        print(f'    {r.feature:<28} flagged {r.unk_flagged:8.3f}  vs '
              f'train-legit {r.train_legit:8.3f}  '
              f'(phish {r.train_phish:8.3f})   gap {r.gap_sigma:5.2f} sd')


if __name__ == '__main__':
    main()
