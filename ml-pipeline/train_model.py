import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, precision_score, recall_score, f1_score

def train_and_evaluate():
    print("Loading preprocessed data...")
    # Load the processed data
    X_train, X_val, X_test, y_train, y_val, y_test = joblib.load('processed_data.pkl')
    
    print("Training Random Forest Classifier...")
    # Initialize and train the model
    model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)
    model.fit(X_train, y_train)
    
    # Evaluate on validation set
    print("\n--- Validation Set Evaluation ---")
    y_val_pred = model.predict(X_val)
    print(f"Accuracy: {accuracy_score(y_val, y_val_pred):.4f}")
    print(f"Precision: {precision_score(y_val, y_val_pred):.4f}")
    print(f"Recall: {recall_score(y_val, y_val_pred):.4f}")
    print(f"F1-Score: {f1_score(y_val, y_val_pred):.4f}")
    print("\nClassification Report (Validation):")
    print(classification_report(y_val, y_val_pred))

    # Evaluate on test set
    print("\n--- Test Set Evaluation ---")
    y_test_pred = model.predict(X_test)
    print(f"Accuracy: {accuracy_score(y_test, y_test_pred):.4f}")
    print(f"Precision: {precision_score(y_test, y_test_pred):.4f}")
    print(f"Recall: {recall_score(y_test, y_test_pred):.4f}")
    print(f"F1-Score: {f1_score(y_test, y_test_pred):.4f}")
    print("\nClassification Report (Test):")
    print(classification_report(y_test, y_test_pred))

    print("\nSaving the trained model...")
    joblib.dump(model, 'phishing_model.pkl')
    print("Model saved successfully to 'phishing_model.pkl'.")

if __name__ == "__main__":
    train_and_evaluate()
