# PhishGuard - Project Requirements & Status Document (PRD)

## Purpose of This Document
This file is the single source of truth for the current state of the PhishGuard project. It is intended for an IDE-integrated AI assistant to scan the project folder, understand what has been built, what remains, and how to proceed without breaking existing functionality. Always re-read this file before making changes.

## Project Overview
PhishGuard is a privacy-preserving, AI-powered phishing detection Chrome browser extension built as a final year Computer Science capstone project. It performs on-device URL classification using a Random Forest classifier, provides SHAP-based explainability for each verdict, and optionally fuses results with external threat intelligence (Google Safe Browsing and PhishTank APIs).

## Tech Stack
- Extension framework: Plasmo (TypeScript + React, Chrome MV3)
- ML pipeline: Python (scikit-learn Random Forest, MinMaxScaler)
- Model export format: Compact JSON (`phishing_model.json`, approx 12.5 MB)
- Inference engine: Custom pure TypeScript decision tree traversal in `onnx-runner.ts` (no ONNX runtime is actually used despite the filename)
- Explainability: SHAP values, approximated client-side in the browser
- Build tool: pnpm
- Datasets: PhiUSIIL (UCI ML Repository), ISCXURL-2016 (Canadian Institute for Cybersecurity)
- External APIs: Google Safe Browsing, PhishTank

## Model Details
- Algorithm: Random Forest, 100 trees, 44 input features
- Verdict system: three tiers
  - CLEAN: score below 0.50
  - SUSPICIOUS: score between 0.50 and 0.85
  - PHISHING: score above 0.85
- Feature scaling: MinMaxScaler simplified because all `data_min_` values are zero, so scaling reduces to `clip(x / DATA_MAX[i], 0, 1)`
- Feature index 21 (`DomainAgeBucket`) must always be hardcoded to `0` in the TypeScript feature extractor, because its `data_max_` is zero, making it a constant feature
- Python and TypeScript inference pipelines have been cross-validated and confirmed to match within floating-point tolerance

## Current Build Status
- Builds successfully via `pnpm run build` with zero errors
- Live inference confirmed working on real URLs (google.com and paypal.com both correctly returned CLEAN verdicts)
- Popup UI correctly renders the verdict, risk score bar, SHAP-based explanation list, and a privacy footer

## Known Issues / Pending Fixes
1. **IsHTTPS explanation bug**: On HTTPS sites, the explanation text shows an inverted/incorrect message relative to the actual SHAP contribution direction.
2. **DomainTitleMatchScore explanation bug**: The explanation text shows a misleading low-score message regardless of the actual SHAP contribution direction. The message should be derived from the SHAP value's sign and magnitude, not assumed.

A fix prompt for these two bugs has already been prepared in a previous session. When addressing these, locate the explanation-text generation logic (likely in the SHAP explanation rendering module) and ensure the displayed message is conditional on the SHAP contribution sign for each feature, not a static template.

## Remaining Work
1. **Phishing URL validation test (final acceptance test)**: Run the extension against known phishing URLs and confirm it correctly returns SUSPICIOUS or PHISHING verdicts with appropriate risk scores. This is the last functional acceptance test before considering the build complete.
2. **Apply the two cosmetic SHAP explanation bug fixes** described above.
3. **Dissertation alignment (Chapters 3 to 5)**: The dissertation currently describes the model as exported in ONNX format. The implementation actually uses a compact JSON export with a custom TypeScript tree-traversal inference engine. Chapters 3 to 5 need to be updated to accurately describe:
   - The JSON model export format and its structure
   - The custom TypeScript inference engine in `onnx-runner.ts` (note: rename or clarify in documentation that no ONNX runtime is used)
   - The MinMaxScaler simplification and the hardcoded `DomainAgeBucket` feature
4. **Final submission packaging**: Once all the above are complete, prepare the final build artifact and supporting documentation for submission.

## Dissertation / Documentation Notes (for context, not for IDE code changes)
- Dissertation must follow the CSC-approved project format (cover page, title page, certification, approval, dedication, acknowledgments, abstract 150-250 words in past tense, table of contents, five chapters, references, appendices).
- Figure 3.2 (comparison of existing systems) must reference three specifically named systems: Do et al. 2024, Shajahan et al. 2025, and BKG10/PhishShield 2025.
- All citations must use APA 6th edition and must be real, verifiable references (a prior reference audit removed fake/vague citations and added the missing Lundberg and Lee 2017 SHAP citation).
- Academic prose should avoid AI writing patterns, em dashes, significance inflation, and formulaic openers.

## Working Conventions
- This project has two parallel workstreams: the extension build (code) and the dissertation (documentation). They periodically need reconciliation so the dissertation matches the actual implementation.
- When fixing bugs, prefer targeted, minimal changes that do not alter the validated model output behavior, since Python and TypeScript pipelines have been cross-validated.
- After any change to `onnx-runner.ts`, the feature extractor, or the model JSON handling, re-run the build (`pnpm run build`) and re-test live inference on at least one clean URL (e.g. google.com) to confirm no regression.

## Immediate Next Steps (Priority Order)
1. Run the phishing URL validation test.
2. Fix the `IsHTTPS` and `DomainTitleMatchScore` explanation text bugs.
3. Re-build and re-verify all verdict types (CLEAN, SUSPICIOUS, PHISHING) render correctly with correct explanations.
4. Update dissertation Chapters 3 to 5 to reflect the JSON export and TypeScript inference engine.
5. Package final submission.
