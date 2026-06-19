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

# MITRE ATT&CK mapping for Android permissions
MITRE_ATTACK_MAPPING = {
    "android.permission.RECEIVE_BOOT_COMPLETED": {
        "tactic": "Persistence (TA0003)",
        "technique": "Boot or Logon Autostart Execution (T1547)",
        "description": "App registers to start automatically when the device boots."
    },
    "android.permission.SYSTEM_ALERT_WINDOW": {
        "tactic": "Defense Evasion (TA0005)",
        "technique": "Overlay Injection (T1509)",
        "description": "Displays window overlays, which can block UI elements or capture key events (phishing overlay attacks)."
    },
    "android.permission.REQUEST_INSTALL_PACKAGES": {
        "tactic": "Lateral Movement (TA0008)",
        "technique": "Software Deployment (T1072)",
        "description": "Allows the app to deploy and install secondary application packages, commonly seen in droppers."
    },
    "android.permission.QUERY_ALL_PACKAGES": {
        "tactic": "Discovery (TA0007)",
        "technique": "Software Discovery (T1518)",
        "description": "Enables enumeration of all installed applications, allowing reconnaissance for banking or 2FA target apps."
    },
    "android.permission.READ_CONTACTS": {
        "tactic": "Collection (TA0009)",
        "technique": "Email/Contact List Harvesting (T1114)",
        "description": "Accesses user address book to harvest contact information, phone numbers, and email accounts."
    },
    "android.permission.READ_SMS": {
        "tactic": "Credential Access (TA0006) / Collection (TA0009)",
        "technique": "Input Capture (T1056) / SMS Interception",
        "description": "Enables access to read existing text messages, which can contain OTPs, authentication tokens, and private exchanges."
    },
    "android.permission.RECEIVE_SMS": {
        "tactic": "Credential Access (TA0006) / Collection (TA0009)",
        "technique": "SMS Interception (T1056)",
        "description": "Intercepts incoming text messages, frequently used to grab 2FA codes before they reach the user."
    },
    "android.permission.SEND_SMS": {
        "tactic": "Impact (TA0040)",
        "technique": "Financial Fraud / Premium Billing",
        "description": "Sends messages in the background, exposing the user to unsolicited SMS billing and premium subscription fraud."
    },
    "android.permission.RECORD_AUDIO": {
        "tactic": "Collection (TA0009)",
        "technique": "Audio Capture (T1125)",
        "description": "Records ambient sound and conversations using the device microphone for intelligence collection."
    },
    "android.permission.CAMERA": {
        "tactic": "Collection (TA0009)",
        "technique": "Video Capture (T1125)",
        "description": "Accesses device cameras to capture photos/videos silently."
    },
    "android.permission.ACCESS_FINE_LOCATION": {
        "tactic": "Collection (TA0009)",
        "technique": "Location Tracking (T1125)",
        "description": "Gathers precise geographical telemetry of the user."
    },
    "android.permission.ACCESS_COARSE_LOCATION": {
        "tactic": "Collection (TA0009)",
        "technique": "Location Tracking (T1125)",
        "description": "Gathers coarse geographical telemetry of the user."
    },
    "android.permission.INTERNET": {
        "tactic": "Command and Control (TA0011)",
        "technique": "Application Layer Protocol (T1071)",
        "description": "Establishes connections to arbitrary domains to transfer harvested data or receive updates from a C2 server."
    },
    "android.permission.READ_EXTERNAL_STORAGE": {
        "tactic": "Collection (TA0009)",
        "technique": "Data from Local System (T1005)",
        "description": "Reads user documents, PDFs, pictures, and database files stored in shared folders."
    },
    "android.permission.WRITE_EXTERNAL_STORAGE": {
        "tactic": "Impact (TA0040)",
        "technique": "Data Encrypted for Impact (T1486)",
        "description": "Modifies or encrypts local file system contents, potentially supporting ransomware behaviors."
    }
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

def get_mitre_attack_mapping(permissions):
    """
    Groups flagged permissions under corporate MITRE ATT&CK tactics & techniques.
    """
    mapped_findings = {}
    for p in permissions:
        if p in MITRE_ATTACK_MAPPING:
            mapping = MITRE_ATTACK_MAPPING[p]
            tactic = mapping["tactic"]
            if tactic not in mapped_findings:
                mapped_findings[tactic] = []
            mapped_findings[tactic].append({
                "permission": p,
                "technique": mapping["technique"],
                "description": mapping["description"]
            })
    return mapped_findings
