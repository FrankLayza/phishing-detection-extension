import pandas as pd
import numpy as np
from feature_extraction import extract_features
from imblearn.over_sampling import SMOTE
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
import joblib

# Load PhiUSIIL - use the URL column and label
phiusiil = pd.read_csv('datasets/phiusiil.csv')
# Adjust column names to match actual file
phiusiil = phiusiil[['URL', 'label']].rename(columns={'URL': 'url', 'label': 'label'})

# Load ISCX - filter to phishing and benign only
iscx = pd.read_csv('datasets/All.csv')
iscx = iscx[iscx['URL_Type_obf_Type'].isin(['phishing', 'benign'])]
iscx['label'] = iscx['URL_Type_obf_Type'].map({'phishing': 1, 'benign': 0})
iscx = iscx[['URL', 'label']].rename(columns={'URL': 'url'})

# Combine and shuffle
df = pd.concat([phiusiil, iscx], ignore_index=True).sample(frac=1, random_state=42)
df = df.dropna(subset=['url'])

# Extract features
print('Extracting features from', len(df), 'URLs...')
features_list = [extract_features(u) for u in df['url']]
X = pd.DataFrame(features_list)
y = df['label'].values

# Handle class imbalance with SMOTE
print('Applying SMOTE...')
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X, y)

# Train/Validation/Test split (70/15/15)
X_train, X_temp, y_train, y_temp = train_test_split(
    X_resampled, y_resampled, test_size=0.30, random_state=42, stratify=y_resampled)
X_val, X_test, y_val, y_test = train_test_split(
    X_temp, y_temp, test_size=0.50, random_state=42, stratify=y_temp)

# Save
joblib.dump((X_train, X_val, X_test, y_train, y_val, y_test), 'processed_data.pkl')
joblib.dump(list(X.columns), 'feature_names.pkl')
print('Preprocessing complete.')
