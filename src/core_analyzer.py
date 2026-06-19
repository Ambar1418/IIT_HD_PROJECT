import os
import json
import joblib
import pandas as pd

# High-risk and medium-risk permission definitions
HIGH_RISK_PERMISSIONS = {
    "android.permission.SEND_SMS": 20,
    "android.permission.READ_SMS": 20,
    "android.permission.RECEIVE_SMS": 20,
    "android.permission.REQUEST_INSTALL_PACKAGES": 20,
    "android.permission.QUERY_ALL_PACKAGES": 20,
    "android.permission.READ_CONTACTS": 20
}

MEDIUM_RISK_PERMISSIONS = {
    "android.permission.INTERNET": 10,
    "android.permission.CAMERA": 10,
    "android.permission.RECORD_AUDIO": 10,
    "android.permission.ACCESS_FINE_LOCATION": 10
}

def load_feature_names(features_path=None):
    """Loads the list of 215 feature names for the Drebin dataset model."""
    if features_path is None:
        # Resolve path relative to this file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        features_path = os.path.abspath(os.path.join(current_dir, "../data/drebin_features.json"))
        
    with open(features_path, "r") as f:
        return json.load(f)

def load_ml_model(model_path=None):
    """Loads the trained XGBoost model from the specified file."""
    if model_path is None:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        model_path = os.path.abspath(os.path.join(current_dir, "../models/malware_model.pkl"))
    
    return joblib.load(model_path)

def calculate_risk_score(permissions, services=None):
    """
    Calculates the risk score based on static permissions and services.
    Matches the business logic of dashboard.py exactly.
    """
    if services is None:
        services = []
        
    score = 0
    findings = []
    
    # Permission checks
    for p in permissions:
        if p in HIGH_RISK_PERMISSIONS:
            score += HIGH_RISK_PERMISSIONS[p]
            findings.append(f"⚠️ High Risk Permission: {p}")
        elif p in MEDIUM_RISK_PERMISSIONS:
            score += MEDIUM_RISK_PERMISSIONS[p]
            findings.append(f"⚠️ Medium Risk Permission: {p}")
            
    # VPN Detection in Services
    for service in services:
        if "vpn" in service.lower():
            score += 20
            findings.append("🚨 VPN Service Detected")
            
    score = min(score, 100)
    
    if score >= 70:
        severity = "HIGH"
    elif score >= 40:
        severity = "MEDIUM"
    else:
        severity = "LOW"
        
    return score, severity, findings

def prepare_feature_vector(permissions, feature_names):
    """Maps Android manifest permissions into the 215 Drebin feature vector format."""
    # Initialize empty vector with all 0s
    features = {feature: 0 for feature in feature_names}
    
    # Map permission names to feature columns (using short names)
    for p in permissions:
        short_name = p.split(".")[-1]
        if short_name in features:
            features[short_name] = 1
            
    return pd.DataFrame([features])

def predict_malware(permissions, model, feature_names):
    """Runs the ML model classifier to predict the probability of malware."""
    X = prepare_feature_vector(permissions, feature_names)
    
    pred = model.predict(X)[0]
    prob = model.predict_proba(X)[0]
    
    benign_prob = float(prob[0] * 100)
    malware_prob = float(prob[1] * 100)
    confidence = max(benign_prob, malware_prob)
    ml_prediction = "MALWARE" if pred == 1 else "BENIGN"
    
    return ml_prediction, malware_prob, benign_prob, confidence
