import joblib
import json
import os

scaler = joblib.load('models/scaler.pkl')

output = {
    'min': scaler.min_.tolist(),
    'scale': scaler.scale_.tolist()
}

os.makedirs('phishing-extension/assets', exist_ok=True)
with open('phishing-extension/assets/scaler.json', 'w') as f:
    json.dump(output, f)

print("Scaler exported to phishing-extension/assets/scaler.json")
