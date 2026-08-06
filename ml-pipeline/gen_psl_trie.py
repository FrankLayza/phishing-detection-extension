"""
Regenerate the browser-side Public Suffix List data used for parity.
====================================================================
The Python training pipeline resolves domains with `tldextract`, which matches
hostnames against the Public Suffix List. The shipped TypeScript extractor had
only a 14-entry hardcoded TLD dict, so on country/compound TLDs (`.com.ng`,
`.com.au`, `ac.in` …) and IP hosts the browser computed DIFFERENT `DomainLength`
/ `NoOfSubDomain` values than the model was trained on — a real train/serve
skew (see `check_parity.py`).

This script emits the SAME rules tldextract uses at train time — the ICANN
(public) section of the snapshot bundled inside the installed tldextract
package — as a TypeScript module. `src/ml/tldextract.ts` then runs the exact
tldextract algorithm over these rules, so Python and the browser agree on every
domain.

Keep in sync with the Python environment: if `tldextract` is upgraded (or its
snapshot updated), re-run this script and re-run the parity check.

Usage:
  python ml-pipeline/gen_psl_trie.py
"""

import glob
import json
import os

import tldextract
from tldextract.suffix_list import extract_tlds_from_suffix_list

OUT = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    '..', 'phishing-extension', 'src', 'ml', 'psl-trie.ts',
)


def load_runtime_public_rules():
    """
    Load the public suffix rules the SAME way tldextract uses them at runtime.

    tldextract caches a live-fetched Public Suffix List (DiskCache under
    ``.suffix_cache``) and matches hostnames against THAT, not against its
    bundled snapshot. The snapshot and the cached list can differ by hundreds
    of rules, so generating from the snapshot would silently re-introduce
    train/serve divergence. We read the cached public list directly (offline,
    deterministic); if the cache is absent we fall back to the snapshot.
    """
    cache_dir = tldextract.cache.get_cache_dir()
    matches = glob.glob(
        os.path.join(cache_dir, 'publicsuffix.org-tlds', '*.json')
    )
    if matches:
        cached = json.load(open(matches[0], encoding='utf-8'))
        public_tlds, private_tlds = cached[0], cached[1]
        print(f'  source: runtime cache ({os.path.basename(matches[0])})')
        return public_tlds, private_tlds

    print('  source: bundled snapshot (runtime cache not found)')
    import pkgutil
    snapshot = pkgutil.get_data('tldextract', '.tld_set_snapshot').decode('utf-8')
    return extract_tlds_from_suffix_list(snapshot)


def main():
    public_tlds, private_tlds = load_runtime_public_rules()

    # tldextract default include_psl_private_domains=False → public section only.
    rules = sorted(public_tlds)
    print(f'tldextract v{tldextract.__version__}')
    print(f'  public rules:   {len(public_tlds)}')
    print(f'  private rules:  {len(private_tlds)} (excluded, matches Python default)')

    lines = ['/**']
    lines.append(' * GENERATED FILE — do not edit by hand.')
    lines.append(' *')
    lines.append(' * Public-Suffix-List rules (public/ICANN section only) that the')
    lines.append(' * Python training pipeline resolves domains against via')
    lines.append(' * `tldextract`. The browser parseHost() in tldextract.ts runs')
    lines.append(' * tldextract\'s algorithm over these rules so train and serve')
    lines.append(' * parse domains identically.')
    lines.append(' *')
    lines.append(f' * Generated from the tldextract runtime PSL (v{tldextract.__version__}).')
    lines.append(' * Regenerate with:  python ml-pipeline/gen_psl_trie.py')
    lines.append(' * and re-verify with: python ml-pipeline/check_parity.py')
    lines.append(' */')
    lines.append('export const PUBLIC_SUFFIX_RULES: readonly string[] = [')
    for r in rules:
        lines.append('  ' + json.dumps(r, ensure_ascii=False) + ',')
    lines.append('];')
    lines.append('')

    with open(OUT, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))

    print(f'  wrote {OUT} ({os.path.getsize(OUT)} bytes, {len(rules)} rules)')


if __name__ == '__main__':
    main()
