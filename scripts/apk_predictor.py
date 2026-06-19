import sys
import os
import pandas as pd

# Resolve paths
current_dir = os.path.dirname(os.path.abspath(__file__))
if os.path.basename(current_dir) == "scripts":
    project_root = os.path.abspath(os.path.join(current_dir, ".."))
else:
    project_root = os.path.abspath(current_dir)

# Add src/ directory to the path to import core modules
sys.path.append(os.path.join(project_root, "src"))
from core_analyzer import load_ml_model, load_feature_names, predict_malware

# Load model and feature names (dynamically resolves relative paths)
try:
    model_path = os.path.join(project_root, "models", "malware_model.pkl")
    features_path = os.path.join(project_root, "data", "drebin_features.json")
    
    model = load_ml_model(model_path)
    feature_names = load_feature_names(features_path)
except Exception as e:
    print(f"Error loading model or features: {e}")
    sys.exit(1)

print("Total Features:", len(feature_names))

# Simulate permissions matching suspicious features
# Note: features map to short names like SEND_SMS, READ_CONTACTS, etc.
permissions = [
    "android.permission.SEND_SMS",
    "android.permission.READ_CONTACTS",
    "android.permission.INTERNET",
    "android.permission.WRITE_EXTERNAL_STORAGE"
]

# ML Prediction
ml_prediction, malware_prob, benign_prob, confidence = predict_malware(permissions, model, feature_names)

print("\nPrediction:")
print("MALWARE" if ml_prediction == "MALWARE" else "BENIGN")

print("\nConfidence:")
print(f"Benign: {benign_prob:.2f}%")
print(f"Malware: {malware_prob:.2f}%")
