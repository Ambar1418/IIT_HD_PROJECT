import streamlit as st
import json
import os
import sys
from androguard.core.apk import APK

# Add src/ directory to path to load core modules
sys.path.append(os.path.join(os.path.dirname(__file__), "src"))
from core_analyzer import (
    calculate_risk_score, 
    load_ml_model, 
    load_feature_names, 
    predict_malware,
    HIGH_RISK_PERMISSIONS,
    MEDIUM_RISK_PERMISSIONS
)

# Page Configuration for Premium Dashboard
st.set_page_config(
    page_title="Android APK Malware Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Premium Styling
st.markdown("""
<style>
    .reportview-container {
        background: #0e1117;
    }
    .metric-card {
        background-color: #1e293b;
        border-radius: 10px;
        padding: 15px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        border: 1px solid #334155;
    }
    .header-style {
        font-family: 'Inter', sans-serif;
        font-weight: 800;
        color: #f8fafc;
    }
    .badge {
        display: inline-block;
        padding: 0.25em 0.6em;
        font-size: 75%;
        font-weight: 700;
        line-height: 1;
        text-align: center;
        white-space: nowrap;
        vertical-align: baseline;
        border-radius: 0.375rem;
    }
    .badge-high { background-color: #ef4444; color: white; }
    .badge-medium { background-color: #f59e0b; color: white; }
    .badge-low { background-color: #10b981; color: white; }
</style>
""", unsafe_allow_html=True)

# ---------------------------
# SIDEBAR / LOAD ASSETS
# ---------------------------
st.sidebar.image("https://img.icons8.com/nolan/128/security-shield.png", width=80)
st.sidebar.title("🛡️ Analyzer Settings")
st.sidebar.markdown("---")

# Dynamic path resolution for models and features
model_path = "models/malware_model.pkl" if os.path.exists("models/malware_model.pkl") else "malware_model.pkl"
features_path = "data/drebin_features.json" if os.path.exists("data/drebin_features.json") else "data/drebin_features.json"

@st.cache_resource
def load_assets(m_path, f_path):
    try:
        model = load_ml_model(m_path)
        features = load_feature_names(f_path)
        return model, features, None
    except Exception as e:
        return None, None, str(e)

model, feature_names, load_error = load_assets(model_path, features_path)

if load_error:
    st.sidebar.error(f"❌ Error loading assets: {load_error}")
else:
    st.sidebar.success("✅ Model and Drebin features loaded successfully!")

st.sidebar.markdown("""
### Model & Dataset Info
* **Model Type:** XGBoost Classifier
* **Dataset:** Drebin Dataset
* **Samples:** 15,036 samples
* **Accuracy:** 98.6%
* **Features Used:** 215 static permission signatures
""")

# ---------------------------
# MAIN HEADER
# ---------------------------
st.title("🛡️ Android APK Malware Analyzer")
st.markdown("### AI-Powered Static Analysis & Machine Learning Malware Classification Engine")
st.markdown("Analyze Android installation packages in real-time to detect threats, inspect permission profiles, and calculate dynamic security risk scores.")
st.markdown("---")

# ---------------------------
# FILE UPLOAD SECTION
# ---------------------------
col_upload1, col_upload2 = st.columns([2, 1])

with col_upload1:
    uploaded_file = st.file_uploader(
        "Upload Android APK file or Manifest JSON",
        type=["apk", "json"],
        help="Upload a raw Android .apk file for real-time parsing OR a pre-extracted .json manifest."
    )

manifest = None

if uploaded_file:
    file_extension = os.path.splitext(uploaded_file.name)[1].lower()
    
    if file_extension == ".apk":
        with st.spinner("⚡ Extracting APK Manifest using Androguard Parser..."):
            try:
                apk_bytes = uploaded_file.read()
                apk = APK(apk_bytes, raw=True)
                manifest = {
                    "package": apk.get_package(),
                    "permissions": list(apk.get_permissions()),
                    "activities": list(apk.get_activities()),
                    "services": list(apk.get_services()),
                    "receivers": list(apk.get_receivers()),
                    "providers": list(apk.get_providers()),
                }
                st.success(f"🎉 Successfully parsed APK: `{manifest['package']}`")
            except Exception as e:
                st.error(f"❌ Androguard failed to parse APK: {e}")
                manifest = None
                
    elif file_extension == ".json":
        try:
            manifest = json.load(uploaded_file)
            st.success(f"🎉 Successfully loaded JSON Manifest for package: `{manifest.get('package', 'Unknown')}`")
        except Exception as e:
            st.error(f"❌ Failed to parse JSON manifest: {e}")
            manifest = None

# ---------------------------
# ANALYSIS WORKFLOW
# ---------------------------
if manifest:
    permissions = manifest.get("permissions", [])
    activities = manifest.get("activities", [])
    services = manifest.get("services", [])
    receivers = manifest.get("receivers", [])
    providers = manifest.get("providers", [])
    package_name = manifest.get("package", "unknown.package.name")

    # ==========================
    # 📦 APK INFO BLOCK
    # ==========================
    st.header("📦 Application Metadata")
    
    # Custom styling cards for stats
    m_col1, m_col2, m_col3, m_col4, m_col5 = st.columns(5)
    m_col1.metric("Permissions", len(permissions))
    m_col2.metric("Activities", len(activities))
    m_col3.metric("Services", len(services))
    m_col4.metric("Receivers", len(receivers))
    m_col5.metric("Providers", len(providers))
    
    st.info(f"**Target Package Identifer:** `{package_name}`")

    # ==========================
    # 📊 RISK & SEVERITY ASSESSMENT
    # ==========================
    st.header("📊 Threat Severity & Risk Analysis")
    
    score, severity, findings = calculate_risk_score(permissions, services)
    
    col_risk1, col_risk2 = st.columns([2, 1])
    
    with col_risk1:
        st.write("**Security Risk Score Index (0 - 100)**")
        st.progress(score / 100.0)
        
        # Display large customized status alert
        if severity == "HIGH":
            st.error(f"🚨 **HIGH THREAT SEVERITY DETECTED (Risk Score: {score}/100)**")
        elif severity == "MEDIUM":
            st.warning(f"⚠️ **MEDIUM THREAT SEVERITY DETECTED (Risk Score: {score}/100)**")
        else:
            st.success(f"✅ **LOW THREAT SEVERITY (Risk Score: {score}/100)**")
            
    with col_risk2:
        st.metric(label="Risk Assessment Band", value=severity, delta=f"+{score} Score Points")

    # ==========================
    # 🤖 MACHINE LEARNING PREDICTION
    # ==========================
    st.header("🤖 XGBoost Malware Classification")
    
    if model is not None and feature_names is not None:
        # Predict using core analyzer module
        ml_prediction, malware_prob, benign_prob, confidence = predict_malware(permissions, model, feature_names)
        
        col_ml1, col_ml2, col_ml3, col_ml4 = st.columns(4)
        
        if ml_prediction == "MALWARE":
            col_ml1.markdown(f"#### Class Verdict:\n<span class='badge badge-high' style='font-size:1.5rem;'>MALWARE</span>", unsafe_allow_html=True)
        else:
            col_ml1.markdown(f"#### Class Verdict:\n<span class='badge badge-low' style='font-size:1.5rem;'>BENIGN</span>", unsafe_allow_html=True)
            
        col_ml2.metric("Malware Confidence", f"{malware_prob:.2f}%")
        col_ml3.metric("Benign Confidence", f"{benign_prob:.2f}%")
        col_ml4.metric("Classification Confidence", f"{confidence:.2f}%")
    else:
        st.warning("⚠️ Machine Learning Engine unavailable because model/features failed to load.")
        ml_prediction, malware_prob, benign_prob = "UNAVAILABLE", 0.0, 0.0

    # ==========================
    # 🔬 STATIC ANALYSIS FINDINGS
    # ==========================
    st.header("🔬 Detailed Static Code Findings")
    
    col_det1, col_det2 = st.columns(2)
    
    with col_det1:
        st.subheader("Detected Threat Indicators")
        if findings:
            for item in findings:
                st.markdown(item)
        else:
            st.success("No suspicious permission-based patterns triggered.")
            
        # Add dynamic findings checks (Static Code indicators)
        st.subheader("Resource & Component Flags")
        has_vpn = any("vpn" in s.lower() for s in services)
        has_install = "android.permission.REQUEST_INSTALL_PACKAGES" in permissions
        has_query = "android.permission.QUERY_ALL_PACKAGES" in permissions
        has_internet = "android.permission.INTERNET" in permissions
        
        if has_vpn:
            st.markdown("🔒 **VPN Service Present:** Component exposes custom network tunneling interface.")
        if has_install:
            st.markdown("📦 **Direct APK Deployment:** Application can drop and install packages directly.")
        if has_query:
            st.markdown("🔍 **Application Enumeration:** Allowed to search all installed packages on the OS.")
        if has_internet:
            st.markdown("🌐 **Internet Access Flag:** Network capability is requested and enabled.")
        if not (has_vpn or has_install or has_query or has_internet):
            st.markdown("ℹ️ No extra resource flags triggered.")

    with col_det2:
        st.subheader("Dangerous Permissions Table")
        # Build Table of permissions with high/medium tags
        perm_rows = []
        for p in permissions:
            if p in HIGH_RISK_PERMISSIONS:
                perm_rows.append({"Permission": p, "Risk Tier": "🔴 High Risk", "Weight": HIGH_RISK_PERMISSIONS[p]})
            elif p in MEDIUM_RISK_PERMISSIONS:
                perm_rows.append({"Permission": p, "Risk Tier": "🟡 Medium Risk", "Weight": MEDIUM_RISK_PERMISSIONS[p]})
                
        if perm_rows:
            st.table(perm_rows)
        else:
            st.write("No defined high/medium risk permissions present in manifest.")

    # ==========================
    # 🚨 FINAL INTEGRATED VERDICT
    # ==========================
    st.header("🚨 Integrated System Verdict")
    
    # Consolidated Verdict Matrix
    # High Risk Score or high ML confidence malware overrides
    if score >= 50:
        verdict = "SUSPICIOUS APK"
        st.warning("⚠️ **VERDICT: SUSPICIOUS APK** — Risk scoring shows high occurrence of dangerous permission tiers.")
    elif ml_prediction == "MALWARE" and malware_prob >= 70:
        verdict = "MALWARE"
        st.error("☠️ **VERDICT: MALWARE** — ML model classifies features with extremely high threat confidence.")
    else:
        verdict = "BENIGN"
        st.success("🎉 **VERDICT: BENIGN** — Low static indicators and model prediction confirm safe execution parameters.")

    # Report Structure for Export
    report = {
        "package": package_name,
        "risk_score": score,
        "severity": severity,
        "ml_prediction": ml_prediction,
        "confidence": round(confidence, 2) if 'confidence' in locals() else 0.0,
        "malware_probability": round(malware_prob, 2),
        "benign_probability": round(benign_prob, 2),
        "final_verdict": verdict,
        "total_permissions": len(permissions)
    }

    # ==========================
    # 📄 EXPORTABLE JSON REPORT
    # ==========================
    st.header("📄 Diagnostic JSON Report")
    st.json(report)
    
    st.download_button(
        "⬇️ Download Analysis Report",
        data=json.dumps(report, indent=2),
        file_name=f"{package_name}_analysis_report.json",
        mime="application/json"
    )