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
    Legitimate URLs in PhiUSIIL contain absolutely no paths and no subdomains other
    than 'www.'. This creates a major bias where the model learns that any URL with
    a path or non-www subdomain is phishing.
    This function randomly augments legitimate URLs in the dataset by adding realistic
    subdomains and paths, forcing the model to learn lexical patterns instead of relying
    on these biases.
    """
    rng = np.random.RandomState(random_state)
    legit_indices = phi[phi['label'] == 1].index.values
    
    subdomains = ['docs', 'en', 'mail', 'blog', 'support', 'login', 'store', 'app', 'dev', 'status', 'news', 'portal', 'api', 'admin', 'accounts']
    paths = [
        '/index.html', '/login', '/register', '/home', '/about', '/contact', '/faq', 
        '/terms', '/privacy', '/products', '/item/12345', '/search', '/posts/hello-world',
        '/docs/api/v1', '/settings/profile', '/download', '/pricing', '/blog/news/2026/06',
        '/dp/b08n5wrwnw', '/3/library/os.html', '/wiki/phishing', '/signin', '/watch?v=dqw4w9wgxcq'
    ]
    
    print("Augmenting legitimate URLs to reduce path/subdomain bias...")
    
    modified_count = 0
    subdomain_count = 0
    path_count = 0
    both_count = 0
    
    urls = phi['URL'].values.copy()
    
    for idx in legit_indices:
        url = str(urls[idx])
        # 40% unmodified, 30% path only, 20% subdomain only, 10% both
        mod_type = rng.choice([0, 1, 2, 3], p=[0.4, 0.3, 0.2, 0.1])
        
        if mod_type == 0:
            continue
            
        modified_count += 1
        
        # Add subdomain
        if mod_type in [2, 3]:
            sub = rng.choice(subdomains)
            if '://www.' in url:
                url = url.replace('://www.', f'://{sub}.')
            elif '://' in url:
                url = url.replace('://', f'://{sub}.')
            subdomain_count += 1
            
        # Add path
        if mod_type in [1, 3]:
            path = rng.choice(paths)
            url = url.rstrip('/') + path
            path_count += 1
            
        if mod_type == 3:
            both_count += 1
            
        urls[idx] = url
        
    phi['URL'] = urls
    print(f"  Total legitimate URLs modified: {modified_count} / {len(legit_indices)}")
    print(f"    Added path: {path_count}")
    print(f"    Added subdomain: {subdomain_count}")
    print(f"    Added both: {both_count}")
    return phi


def load_and_prepare_dataset():
    """
    Load PhiUSIIL dataset and build feature matrix with SELF-EXTRACTED
    lexical features + CSV-sourced content/domain features.
    """
    print("Loading PhiUSIIL dataset...")
    phi = pd.read_csv('datasets/phiusiil.csv')
    print(f"  Raw rows: {len(phi)}")

    # Ensure we have the URL column and label
    if 'URL' not in phi.columns:
        raise ValueError("PhiUSIIL CSV must have a 'URL' column")
    if 'label' not in phi.columns:
        raise ValueError("PhiUSIIL CSV must have a 'label' column")

    # Drop rows with missing URLs
    phi = phi.dropna(subset=['URL'])
    phi = phi[phi['URL'].str.strip().astype(bool)]
    print(f"  After dropping empty URLs: {len(phi)}")

    # Augment legitimate URLs to break path/subdomain dataset bias
    phi = augment_legitimate_urls(phi)

    # ------------------------------------------------------------------
    # STEP 1: Self-extract lexical features from raw URL strings
    #         (same function used at inference time)
    # ------------------------------------------------------------------
    print("\nExtracting lexical features from raw URLs...")
    print("  (This ensures train-time features match inference-time features)")

    start = time.time()
    lexical_rows = []
    errors = 0
    for i, url in enumerate(phi['URL']):
        try:
            feats = extract_lexical_features(str(url))
            lexical_rows.append(feats)
        except Exception:
            # Use zeros for URLs that fail extraction
            lexical_rows.append({f: 0 for f in LEXICAL_FEATURES})
            errors += 1

        if (i + 1) % 50000 == 0:
            elapsed = time.time() - start
            rate = (i + 1) / elapsed
            print(f"  Processed {i+1}/{len(phi)} URLs ({rate:.0f} URLs/sec, {errors} errors)")

    elapsed = time.time() - start
    print(f"  Done: {len(lexical_rows)} URLs in {elapsed:.1f}s ({errors} extraction errors)")

    lexical_df = pd.DataFrame(lexical_rows)

    # ------------------------------------------------------------------
    # STEP 2: Use PhiUSIIL's pre-computed content/domain features
    #         (these columns exist in the CSV with matching names)
    # ------------------------------------------------------------------
    print("\nMapping content/domain features from CSV columns...")
    content_domain_features = DOMAIN_FEATURES + CONTENT_FEATURES

    for feat in content_domain_features:
        if feat in phi.columns:
            lexical_df[feat] = phi[feat].values
        else:
            print(f"  WARNING: '{feat}' not in CSV — defaulting to 0")
            lexical_df[feat] = 0

    # ------------------------------------------------------------------
    # STEP 3: Assemble final feature matrix in correct order
    # ------------------------------------------------------------------
    X = lexical_df[ALL_FEATURES].copy()
    y = phi['label'].values.copy()

    # Convert labels to binary (0=legitimate, 1=phishing)
    # PhiUSIIL dataset: 1=legitimate, 0=phishing, so we invert them.
    y = np.array([0 if str(v).strip() in ['1', 'legitimate', 'good', 'safe'] else 1 for v in y])

    # Fill any remaining NaN with 0
    X = X.fillna(0)

    # Neutralize biased IsHTTPS feature to prevent dataset bias
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
