"""
Held-out validation populations — ONE definition, imported by everything.
========================================================================
These domains define the unknown-legitimate acceptance metric
(`validate_unknown_legit.py`). They must never enter the training corpus, so the
list lives here rather than inside the validator: `train.py` imports it to EXCLUDE
these domains from any corpus enrichment.

That exclusion is not hypothetical. The Aug 15, 2026 low-trust suffix experiment
sampled real legit domains from Cisco ranks 55k-500k and picked up `jumia.com.ng`,
which is a curated validation domain — contaminating 4 of the 144 curated URLs
(the bare domain plus its 3 path variants). Caught by an overlap check before the
result was used. Keeping one copy is what makes that check possible at all.

The sampled population is protected differently, by rank band: see
`UNKNOWN_RANK_FLOOR` in `validate_unknown_legit.py` and the assertion there that
compares it against `train.py`'s `TRAIN_RANK_MAX`.
"""

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

# Path shapes real sites carry. Appending a path was the dominant pre-fix
# failure mode, so the curated set is scored bare AND with these.
CURATED_PATHS = [
    '/about', '/contact', '/services', '/products/catalogue',
    '/login', '/account/settings', '/blog/2026/announcement',
    '/support/faq', '/careers/openings', '/branches/lagos-island',
    '/personal-banking/savings-accounts', '/book-appointment',
    '/admissions/requirements', '/search?q=account&page=2',
]

# Canary. These two lists DEFINE a published metric: change either one and every
# unknown-legit FPR figure in SOURCE_OF_TRUTH.md silently stops being comparable,
# with nothing downstream looking wrong. The counts are asserted so an accidental
# truncation fails loudly instead.
#
# This is not hypothetical. When these lists were moved here from
# validate_unknown_legit.py on Aug 15, 2026, CURATED_PATHS was retyped from memory
# rather than copied: 9 entries instead of 14, with '/contact' altered to
# '/contact-us'. That shifted the sampled ML FPR from 15.4% to 15.8% and the hard-red
# rate from 0.8% to 1.2%. It was caught only because those figures were expected to
# reproduce exactly. Copy from git, never retype.
#
# If you MEAN to change a population, update the count here, re-measure both
# populations, and update SOURCE_OF_TRUTH.md §3a in the same commit.
EXPECTED_CURATED_BARE = 36
EXPECTED_CURATED_PATHS = 14

if len(CURATED_BARE) != EXPECTED_CURATED_BARE or len(CURATED_PATHS) != EXPECTED_CURATED_PATHS:
    raise SystemExit(
        f'Validation population changed: CURATED_BARE={len(CURATED_BARE)} '
        f'(expected {EXPECTED_CURATED_BARE}), CURATED_PATHS={len(CURATED_PATHS)} '
        f'(expected {EXPECTED_CURATED_PATHS}). Every published unknown-legit FPR '
        f'figure assumes these populations. If the change is deliberate, update the '
        f'EXPECTED_* counts, re-measure, and update SOURCE_OF_TRUTH.md §3a together.')
