import json
import sys
import os

# Add src/ directory to the path to import core modules
sys.path.append(os.path.join(os.path.dirname(__file__), "src"))
from core_analyzer import calculate_risk_score, load_ml_model, load_feature_names, predict_malware

# Resolve manifest file path (handles root and restructured structure)
manifest_path = "malware_manifest.json"
if not os.path.exists(manifest_path):
    manifest_path = os.path.join(os.path.dirname(__file__), "samples", "malware_manifest.json")

if not os.path.exists(manifest_path):
    print(f"Error: Manifest file not found at {manifest_path}")
    sys.exit(1)

# Load manifest
with open(manifest_path, "r") as f:
    manifest = json.load(f)

permissions = manifest.get("permissions", [])

# Calculate Risk Score
score, _, _ = calculate_risk_score(permissions)

# Load model and feature names (dynamically resolves relative paths)
try:
    model_path = os.path.join(os.path.dirname(__file__), "models", "malware_model.pkl") if not os.path.exists("malware_model.pkl") else "malware_model.pkl"
    features_path = os.path.join(os.path.dirname(__file__), "data", "drebin_features.json") if not os.path.exists("data/drebin_features.json") else "data/drebin_features.json"
    
    model = load_ml_model(model_path)
    feature_names = load_feature_names(features_path)
except Exception as e:
    print(f"Error loading model or features: {e}")
    sys.exit(1)

# ML Prediction
ml_prediction, malware_prob, benign_prob, confidence = predict_malware(permissions, model, feature_names)

verdict = "Malware" if ml_prediction == "MALWARE" else "Benign"

# Report
report = {
    "package": str(manifest.get("package", "unknown")),
    "risk_score": int(score),
    "prediction": str(verdict),
    "benign_probability": float(round(benign_prob, 2)),
    "malware_probability": float(round(malware_prob, 2))
}

print("\n===== APK ANALYSIS REPORT =====")
print(json.dumps(report, indent=2))
