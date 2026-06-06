import joblib
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

def test_export():
    try:
        model = joblib.load('models/random_forest.pkl')
        print(f"Model loaded, n_features_in_: {model.n_features_in_}")
        
        initial_type = [('float_input', FloatTensorType([None, model.n_features_in_]))]
        
        onnx_model = convert_sklearn(
            model, 
            initial_types=initial_type
        )
        print("Export successful!")
    except Exception as e:
        print(f"Export failed. Type: {type(e).__name__}")
        msg = str(e)
        print(f"Message length: {len(msg)}")
        print(f"Start of message: {msg[:1000]}")

if __name__ == "__main__":
    test_export()
