"""
Export Random Forest model as compact JSON for browser inference.
Bypasses ONNX entirely — produces a lightweight JSON tree structure
that can be evaluated with a simple recursive JS function.
"""
import joblib
import json
import os
import numpy as np

def tree_to_dict(tree, feature_names):
    """Convert a single DecisionTree to a compact dict."""
    tree_ = tree.tree_
    
    def recurse(node_id):
        if tree_.children_left[node_id] == -1:  # Leaf node
            # Normalize class counts to probabilities
            counts = tree_.value[node_id][0]
            total = counts.sum()
            return {"v": [round(float(c / total), 6) for c in counts]}
        
        return {
            "f": int(tree_.feature[node_id]),         # feature index
            "t": round(float(tree_.threshold[node_id]), 6),  # threshold
            "l": recurse(int(tree_.children_left[node_id])),  # left child (<=)
            "r": recurse(int(tree_.children_right[node_id]))  # right child (>)
        }
    
    return recurse(0)

def export_model():
    model = joblib.load('models/random_forest.pkl')
    scaler = joblib.load('models/scaler.pkl')
    
    # Get feature names
    from features.feature_config import ALL_FEATURES
    
    print(f"Model: {model.n_estimators} trees, {model.n_features_in_} features")
    print(f"Classes: {model.classes_.tolist()}")
    
    # Export all trees
    trees = []
    for i, estimator in enumerate(model.estimators_):
        tree_dict = tree_to_dict(estimator, ALL_FEATURES)
        trees.append(tree_dict)
        if (i + 1) % 10 == 0:
            print(f"  Exported tree {i + 1}/{model.n_estimators}")
    
    # Export scaler parameters
    scaler_data = {
        "min": [round(float(x), 8) for x in scaler.min_],
        "scale": [round(float(x), 8) for x in scaler.scale_]
    }
    
    # Build final model payload
    model_json = {
        "n_estimators": model.n_estimators,
        "n_features": model.n_features_in_,
        "classes": model.classes_.tolist(),
        "feature_names": ALL_FEATURES,
        "scaler": scaler_data,
        "trees": trees
    }
    
    output_path = 'phishing-extension/assets/phishing_model.json'
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    with open(output_path, 'w') as f:
        json.dump(model_json, f, separators=(',', ':'))  # Compact JSON
    
    size_kb = os.path.getsize(output_path) / 1024
    print(f"\n[OK] Model exported: {output_path}")
    print(f"   Size: {size_kb:.1f} KB")
    
    # Verify by running a test prediction
    # Use a named DataFrame so MinMaxScaler (fitted with feature names) doesn't warn.
    import pandas as pd
    test_df = pd.DataFrame(np.zeros((1, model.n_features_in_)), columns=ALL_FEATURES)
    sklearn_pred = model.predict_proba(test_df)[0]
    
    # Simulate JSON inference
    def predict_tree(tree, features):
        if "v" in tree:
            return tree["v"]
        if features[tree["f"]] <= tree["t"]:
            return predict_tree(tree["l"], features)
        else:
            return predict_tree(tree["r"], features)
    
    # Average all trees
    scaled_input = scaler.transform(test_df)[0]
    probs = np.zeros(len(model.classes_))
    for tree in trees:
        leaf_probs = predict_tree(tree, scaled_input)
        probs += np.array(leaf_probs)
    probs /= len(trees)
    
    print(f"\n   Verification (zero-vector input):")
    print(f"   sklearn predict_proba: {sklearn_pred}")
    print(f"   JSON inference:        {probs}")
    print(f"   Match: {'[OK] YES' if np.allclose(sklearn_pred, probs, atol=1e-4) else '[FAIL] NO'}")
    
    return output_path

if __name__ == "__main__":
    os.chdir(os.path.dirname(os.path.abspath(__file__)) + '/..')
    export_model()
