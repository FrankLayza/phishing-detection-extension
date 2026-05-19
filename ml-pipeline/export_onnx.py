import joblib
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
import onnx
import os

def export_model():
    model = joblib.load('models/random_forest.pkl')
    scaler = joblib.load('models/scaler.pkl')
    
    num_features = 44  # 21 lexical + 10 domain + 13 content
    initial_type = [('float_input', FloatTensorType([None, num_features]))]
    
    try:
        onnx_model = convert_sklearn(
            model, 
            initial_types=initial_type, 
            target_opset=15,
            options={type(model): {'zipmap': False}}
        )
        
        output_path = 'phishing-extension/assets/phishing_model.onnx'
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        
        with open(output_path, 'wb') as f:
            f.write(onnx_model.SerializeToString())
        
        model_size_kb = os.path.getsize(output_path) / 1024
        print(f"ONNX model exported: {output_path}")
        print(f"Model size: {model_size_kb:.1f} KB")
        
    except Exception as e:
        print(f"Export failed with error: {str(e)[:500]}")
        import traceback
        traceback.print_exc(limit=2)
        return None
    
    # Verify
    import onnxruntime as ort
    sess = ort.InferenceSession(output_path)
    print(f"Inputs: {[i.name for i in sess.get_inputs()]}")
    print(f"Outputs: {[o.name for o in sess.get_outputs()]}")
    
    import numpy as np
    test_input = np.zeros((1, num_features), dtype=np.float32)
    result = sess.run(None, {'float_input': test_input})
    print(f"Test prediction: {result[0]}")
    
    return output_path

if __name__ == "__main__":
    export_model()
