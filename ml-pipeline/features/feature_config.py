"""Feature configuration matching your research report."""

LEXICAL_FEATURES = [
    'URLLength', 'DomainLength', 'IsDomainIP', 'URLSimilarityIndex',
    'CharContinuationRate', 'TLDLegitimateProb', 'URLCharProb',
    'NoOfSubDomain', 'HasObfuscation', 'NoOfObfuscatedChar',
    'ObfuscationRatio', 'NoOfLettersInURL', 'LetterRatioInURL',
    'NoOfDegitsInURL', 'DegitRatioInURL', 'NoOfEqualsInURL',
    'NoOfQMarkInURL', 'NoOfAmpersandInURL', 'NoOfOtherSpecialCharsInURL',
    'SpacialCharRatioInURL', 'IsHTTPS'
]

DOMAIN_FEATURES = [
    'DomainAgeBucket', 'HasTitle', 'DomainTitleMatchScore',
    'URLTitleMatchScore', 'HasFavicon', 'Robots', 'IsResponsive',
    'NoOfURLRedirect', 'NoOfSelfRedirect', 'HasDescription'
]

CONTENT_FEATURES = [
    'LineOfCode', 'LargestLineLength', 'NoOfPopup', 'NoOfiFrame',
    'HasExternalFormSubmit', 'HasSocialNet', 'HasSubmitButton',
    'HasHiddenFields', 'HasPasswordField', 'Bank', 'Pay', 'Crypto',
    'HasCopyrightInfo'
]

ALL_FEATURES = LEXICAL_FEATURES + DOMAIN_FEATURES + CONTENT_FEATURES
assert len(ALL_FEATURES) == 44  # 21 lexical + 10 domain + 13 content

FEATURE_CATEGORIES = {
    'URL_STRUCTURE': LEXICAL_FEATURES[:10],
    'DOMAIN_TRUST': DOMAIN_FEATURES,
    'PAGE_CONTENT': CONTENT_FEATURES
}
