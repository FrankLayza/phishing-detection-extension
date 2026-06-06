"""
Benchmark inference time for the phishing detection model.
Measures average prediction latency per URL across multiple runs.
"""
import joblib
import numpy as np
import time
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from features.feature_config import ALL_FEATURES

def benchmark_sklearn():
    """Benchmark sklearn model inference time."""
    model = joblib.load('models/random_forest.pkl')
    scaler = joblib.load('models/scaler.pkl')

    # Create a realistic test input (random features in [0,1] range)
    np.random.seed(42)
    test_inputs = np.random.rand(100, len(ALL_FEATURES)).astype(np.float32)

    # Warm-up
    for i in range(10):
        scaled = scaler.transform(test_inputs[i:i+1])
        model.predict_proba(scaled)

    # Benchmark: 1000 single-URL predictions
    times = []
    for i in range(1000):
        x = test_inputs[i % 100:i % 100 + 1]
        start = time.perf_counter()
        scaled = scaler.transform(x)
        model.predict_proba(scaled)
        end = time.perf_counter()
        times.append((end - start) * 1000)  # Convert to ms

    times = np.array(times)
    print("=" * 60)
    print("  sklearn Model Inference Benchmark (1000 runs)")
    print("=" * 60)
    print(f"  Mean:   {times.mean():.3f} ms per URL")
    print(f"  Median: {np.median(times):.3f} ms per URL")
    print(f"  Std:    {times.std():.3f} ms")
    print(f"  Min:    {times.min():.3f} ms")
    print(f"  Max:    {times.max():.3f} ms")
    print(f"  P95:    {np.percentile(times, 95):.3f} ms")
    print(f"  P99:    {np.percentile(times, 99):.3f} ms")
    return times

def benchmark_json_model():
    """Benchmark JSON tree-traversal inference (simulates browser)."""
    json_path = 'phishing-extension/assets/phishing_model.json'
    if not os.path.exists(json_path):
        print("\n  JSON model not found, skipping JSON benchmark.")
        return None

    with open(json_path, 'r') as f:
        model_data = json.load(f)

    trees = model_data['trees']
    scaler_min = np.array(model_data['scaler']['min'])
    scaler_scale = np.array(model_data['scaler']['scale'])
    n_classes = len(model_data['classes'])

    def predict_tree(tree, features):
        if "v" in tree:
            return tree["v"]
        if features[tree["f"]] <= tree["t"]:
            return predict_tree(tree["l"], features)
        else:
            return predict_tree(tree["r"], features)

    def predict(features):
        # Scale
        scaled = features * scaler_scale + scaler_min
        # Predict with all trees
        probs = np.zeros(n_classes)
        for tree in trees:
            leaf_probs = predict_tree(tree, scaled)
            probs += np.array(leaf_probs)
        probs /= len(trees)
        return probs

    np.random.seed(42)
    test_inputs = np.random.rand(100, len(ALL_FEATURES))

    # Warm-up
    for i in range(10):
        predict(test_inputs[i])

    # Benchmark
    times = []
    for i in range(1000):
        x = test_inputs[i % 100]
        start = time.perf_counter()
        predict(x)
        end = time.perf_counter()
        times.append((end - start) * 1000)

    times = np.array(times)
    print("\n" + "=" * 60)
    print("  JSON Tree-Traversal Inference Benchmark (1000 runs)")
    print("  (Simulates browser-side inference)")
    print("=" * 60)
    print(f"  Mean:   {times.mean():.3f} ms per URL")
    print(f"  Median: {np.median(times):.3f} ms per URL")
    print(f"  Std:    {times.std():.3f} ms")
    print(f"  Min:    {times.min():.3f} ms")
    print(f"  Max:    {times.max():.3f} ms")
    print(f"  P95:    {np.percentile(times, 95):.3f} ms")
    print(f"  P99:    {np.percentile(times, 99):.3f} ms")
    return times

def benchmark_onnx():
    """Benchmark ONNX Runtime inference time."""
    onnx_path = 'phishing-extension/assets/phishing_model.onnx'
    if not os.path.exists(onnx_path):
        print("\n  ONNX model not found, skipping ONNX benchmark.")
        return None

    import onnxruntime as ort
    sess = ort.InferenceSession(onnx_path)
    input_name = sess.get_inputs()[0].name

    np.random.seed(42)
    test_inputs = np.random.rand(100, len(ALL_FEATURES)).astype(np.float32)

    # Warm-up
    for i in range(10):
        sess.run(None, {input_name: test_inputs[i:i+1]})

    # Benchmark
    times = []
    for i in range(1000):
        x = test_inputs[i % 100:i % 100 + 1]
        start = time.perf_counter()
        sess.run(None, {input_name: x})
        end = time.perf_counter()
        times.append((end - start) * 1000)

    times = np.array(times)
    print("\n" + "=" * 60)
    print("  ONNX Runtime Inference Benchmark (1000 runs)")
    print("=" * 60)
    print(f"  Mean:   {times.mean():.3f} ms per URL")
    print(f"  Median: {np.median(times):.3f} ms per URL")
    print(f"  Std:    {times.std():.3f} ms")
    print(f"  Min:    {times.min():.3f} ms")
    print(f"  Max:    {times.max():.3f} ms")
    print(f"  P95:    {np.percentile(times, 95):.3f} ms")
    print(f"  P99:    {np.percentile(times, 99):.3f} ms")
    return times

if __name__ == "__main__":
    os.chdir(os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
    benchmark_sklearn()
    benchmark_json_model()
    benchmark_onnx()
    print("\n[OK] Benchmarking complete.")
