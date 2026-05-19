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

# Add ml-pipeline/ to sys.path so 'features' package can be found
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from features.feature_config import ALL_FEATURES
from features.lexical_extractor import extract_lexical_features

def load_and_merge_datasets():
    """Load PhiUSIIL and ISCXURL-2016, merge, standardize."""
    # Load PhiUSIIL (primary)
    phi = pd.read_csv('datasets/phiusiil.csv') # Path adjusted to match actual location
    
    # Map columns - adjust based on actual schema
    phi_features = {}
    for feat in ALL_FEATURES:
        if feat in phi.columns:
            phi_features[feat] = phi[feat]
        else:
            # Alternative names mapping
            alt_names = {
                'URLLength': ['url_length', 'URL_LENGTH', 'URL_Length'],
                'DomainLength': ['domain_length', 'DOMAIN_LENGTH', 'Domain_Length'],
                'IsDomainIP': ['is_ip', 'IS_IP', 'HasIpAddress', 'IsDomainIP'],
                'IsHTTPS': ['is_https', 'IS_HTTPS', 'HasHTTPS', 'IsHTTPS'],
                'NoOfSubDomain': ['subdomain_count', 'NumSubDomain', 'NoOfSubDomain'],
                'HasObfuscation': ['has_obfuscation', 'HasObfuscation'],
            }
            found = False
            for alt in alt_names.get(feat, []):
                if alt in phi.columns:
                    phi_features[feat] = phi[alt]
                    found = True
                    break
            if not found:
                phi_features[feat] = pd.Series(0, index=phi.index)  # Default
    
    phi_df = pd.DataFrame(phi_features)
    phi_df['label'] = phi['label'] if 'label' in phi.columns else phi['class']
    
    # Load ISCXURL-2016 (secondary)
    iscx = pd.read_csv('datasets/All.csv') # Actual path of ISCX dataset
    iscx = iscx[iscx['URL_Type_obf_Type'].isin(['phishing', 'benign'])]
    iscx['label'] = iscx['URL_Type_obf_Type'].map({'phishing': 1, 'benign': 0})
    
    iscx_features = {}
    for feat in ALL_FEATURES:
        if feat in iscx.columns:
            iscx_features[feat] = iscx[feat]
        else:
            iscx_features[feat] = pd.Series(0, index=iscx.index)
    
    iscx_df = pd.DataFrame(iscx_features)
    iscx_df['label'] = iscx['label']
    
    # Merge
    combined = pd.concat([phi_df, iscx_df], ignore_index=True)
    combined = combined.drop_duplicates()
    combined = combined.fillna(combined.median(numeric_only=True))
    
    return combined

def preprocess_data(df):
    """Preprocess: encode, normalize, split, SMOTE."""
    X = df[ALL_FEATURES]
    y = df['label'].apply(lambda x: 1 if str(x).lower() in ['1', 'phishing', 'bad', 'malicious'] else 0)
    
    # Train-test split (stratified 80/20)
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    print(f"Before SMOTE - Train: {dict(y_train.value_counts())}")
    
    # SMOTE on training data ONLY
    smote = SMOTE(random_state=42, k_neighbors=5)
    X_train_resampled, y_train_resampled = smote.fit_resample(X_train, y_train)
    
    print(f"After SMOTE - Train: {dict(pd.Series(y_train_resampled).value_counts())}")
    print(f"Test set: {dict(y_test.value_counts())}")
    
    # Normalize (0-1) for ONNX consistency
    scaler = MinMaxScaler()
    X_train_scaled = scaler.fit_transform(X_train_resampled)
    X_test_scaled = scaler.transform(X_test)
    
    joblib.dump(scaler, 'models/scaler.pkl')
    
    return X_train_scaled, X_test_scaled, y_train_resampled, y_test, scaler

def train_random_forest(X_train, y_train):
    """Train with 10-fold cross-validation."""
    rf = RandomForestClassifier(
        n_estimators=100,        # Your report: 100 trees
        max_depth=20,            # Your report: prevent overfitting
        min_samples_split=5,
        min_samples_leaf=2,
        max_features='sqrt',     # Random subspace
        random_state=42,
        n_jobs=-1,
        class_weight='balanced'
    )
    
    # 10-fold stratified cross-validation
    cv = StratifiedKFold(n_splits=10, shuffle=True, random_state=42)
    cv_scores = cross_val_score(rf, X_train, y_train, cv=cv, scoring='accuracy')
    
    print(f"\n10-Fold CV Accuracy: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
    print(f"CV Scores: {cv_scores}")
    
    # Train on full training set
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
    
    print("\n" + "="*50)
    print("EVALUATION RESULTS")
    print("="*50)
    print(f"Accuracy:  {results['accuracy']:.4f}")
    print(f"Precision: {results['precision']:.4f}")
    print(f"Recall:    {results['recall']:.4f}")
    print(f"F1-Score:  {results['f1_score']:.4f}")
    print(f"\nConfusion Matrix:")
    print(np.array(results['confusion_matrix']))
    
    # Feature importance
    importances = dict(zip(ALL_FEATURES, model.feature_importances_))
    sorted_imp = sorted(importances.items(), key=lambda x: x[1], reverse=True)
    
    print("\nTop 10 Important Features:")
    for feat, imp in sorted_imp[:10]:
        print(f"  {feat}: {imp:.4f}")
    
    # Save results
    with open('models/evaluation_results.json', 'w') as f:
        json.dump(results, f, indent=2)
    with open('models/feature_importance.json', 'w') as f:
        json.dump(dict(sorted_imp), f, indent=2)
    
    return results

def main():
    os.makedirs('models', exist_ok=True)
    
    print("Loading datasets...")
    df = load_and_merge_datasets()
    print(f"Total samples: {len(df)}")
    
    print("\nPreprocessing...")
    X_train, X_test, y_train, y_test, scaler = preprocess_data(df)
    
    print("\nTraining Random Forest...")
    model = train_random_forest(X_train, y_train)
    
    print("\nEvaluating...")
    results = evaluate_model(model, X_test, y_test)
    
    joblib.dump(model, 'models/random_forest.pkl')
    print("\nModel saved to models/random_forest.pkl")
    
    return model, scaler, results

if __name__ == "__main__":
    main()
