import streamlit as st
import json
import os
import sys
import tempfile
from fpdf import FPDF
from androguard.core.apk import APK

# Add src/ directory to path to load core modules
sys.path.append(os.path.join(os.path.dirname(__file__), "src"))
from core_analyzer import (
    calculate_risk_score, 
    load_ml_model, 
    load_feature_names, 
    predict_malware,
    get_mitre_attack_mapping,
    HIGH_RISK_PERMISSIONS,
    MEDIUM_RISK_PERMISSIONS
)
from llm_explainer import (
    generate_security_explanation,
    format_explanation_markdown
)

# Page Configuration for Premium Dashboard
st.set_page_config(
    page_title="Android APK Malware Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom styling for premium UI dashboard
st.markdown("""
<style>
    /* Main Layout Themes */
    .reportview-container {
        background-color: #0b0f19;
    }
    
    /* Premium CSS metric cards */
    .custom-card {
        background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%);
        border: 1px solid #334155;
        border-radius: 12px;
        padding: 20px;
        text-align: center;
        box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
        transition: transform 0.2s ease-in-out;
    }
    .custom-card:hover {
        transform: translateY(-5px);
        border-color: #3b82f6;
    }
    .custom-card h4 {
        margin: 0;
        color: #94a3b8;
        font-size: 0.85rem;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }
    .custom-card p {
        margin: 10px 0 0 0;
        color: #f8fafc;
        font-size: 1.8rem;
        font-weight: 800;
        line-height: 1;
    }
    
    /* Threat Level Badges */
    .verdict-badge {
        display: inline-block;
        padding: 8px 16px;
        font-size: 1rem;
        font-weight: 700;
        border-radius: 8px;
        text-align: center;
        text-transform: uppercase;
    }
    .verdict-malware {
        background-color: #ef4444;
        color: #ffffff;
        border: 1px solid #b91c1c;
        box-shadow: 0 0 15px rgba(239, 68, 68, 0.4);
    }
    .verdict-suspicious {
        background-color: #f59e0b;
        color: #ffffff;
        border: 1px solid #b45309;
        box-shadow: 0 0 15px rgba(245, 158, 11, 0.4);
    }
    .verdict-benign {
        background-color: #10b981;
        color: #ffffff;
        border: 1px solid #047857;
        box-shadow: 0 0 15px rgba(16, 185, 129, 0.4);
    }
</style>
""", unsafe_allow_html=True)

# ---------------------------
# PDF REPORT EXPORTER CLASS
# ---------------------------
class APKAnalysisPDF(FPDF):
    def header(self):
        # Slate top header rule
        self.set_font("helvetica", "B", 16)
        self.set_text_color(15, 23, 42) # Dark Slate
        self.cell(0, 10, "Android APK Malware Analysis Report", ln=True, align="L")
        self.set_font("helvetica", "I", 9)
        self.set_text_color(100, 116, 139) # Light Slate
        self.cell(0, 5, "Platform Diagnostics & Artificial Intelligence Threat Assessment", ln=True, align="L")
        self.line(10, 26, 200, 26)
        self.ln(10)
        
    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(148, 163, 184)
        # Page Number
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}} | Confidential System Intelligence Diagnostic Report", align="C")

def build_pdf_report(report_data, exp_dict, permissions_list, tactics_dict):
    """
    Assembles a styled PDF report using fpdf2 and outputs bytes for download.
    Removes emojis dynamically to avoid standard font encoding crashes.
    """
    pdf = APKAnalysisPDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=20)
    
    # ------------------
    # Section 1: Metadata
    # ------------------
    pdf.set_font("helvetica", "B", 12)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 8, "1. Application Metadata", ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)
    
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(51, 65, 85)
    pdf.cell(50, 6, f"Package Identifier:", border=0)
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(0, 6, str(report_data["package"]), border=0, ln=True)
    
    pdf.set_font("helvetica", "", 10)
    pdf.cell(50, 6, "Total Permissions Flagged:", border=0)
    pdf.cell(0, 6, str(report_data["total_permissions"]), border=0, ln=True)
    pdf.ln(4)
    
    # ------------------
    # Section 2: Classifier Scores
    # ------------------
    pdf.set_font("helvetica", "B", 12)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 8, "2. Threat Classification & Metrics", ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)
    
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(51, 65, 85)
    
    pdf.cell(50, 6, "ML Classification Verdict:", border=0)
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(0, 6, str(report_data["ml_prediction"]), border=0, ln=True)
    
    pdf.set_font("helvetica", "", 10)
    pdf.cell(50, 6, "Malware Confidence Score:", border=0)
    pdf.cell(0, 6, f"{report_data['malware_probability']:.2f}%", border=0, ln=True)
    
    pdf.cell(50, 6, "Heuristic Risk Index:", border=0)
    pdf.cell(0, 6, f"{report_data['risk_score']}/100 ({report_data['severity']})", border=0, ln=True)
    
    pdf.cell(50, 6, "Integrated Platform Verdict:", border=0)
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(0, 6, str(report_data["final_verdict"]), border=0, ln=True)
    pdf.ln(4)

    # ------------------
    # Section 3: MITRE ATT&CK Mapping
    # ------------------
    if tactics_dict:
        pdf.set_font("helvetica", "B", 12)
        pdf.set_text_color(30, 41, 59)
        pdf.cell(0, 8, "3. MITRE ATT&CK Adversary Techniques Map", ln=True)
        pdf.line(10, pdf.get_y(), 200, pdf.get_y())
        pdf.ln(3)
        
        pdf.set_font("helvetica", "", 9)
        for tactic, entries in tactics_dict.items():
            pdf.set_font("helvetica", "B", 10)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(0, 6, f"Tactic: {tactic}", ln=True)
            pdf.set_text_color(51, 65, 85)
            pdf.set_font("helvetica", "", 9)
            for entry in entries:
                text_line = f"  - Technique: {entry['technique']} | Permission: {entry['permission']}\n    Detail: {entry['description']}"
                pdf.multi_cell(0, 5, text_line, new_x="LMARGIN", new_y="NEXT")
                pdf.ln(1)
            pdf.ln(2)

    # ------------------
    # Section 4: AI Security Explanation
    # ------------------
    pdf.set_font("helvetica", "B", 12)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 8, "4. Artificial Intelligence Security Assessment", ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)
    
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(0, 6, "Executive Summary:", ln=True)
    pdf.set_font("helvetica", "", 9)
    pdf.multi_cell(0, 5, str(exp_dict.get("executive_summary", "No summary generated.")), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(0, 6, "Flagged Indicators & Analysis:", ln=True)
    pdf.set_font("helvetica", "", 9)
    reasons = exp_dict.get("flagged_reasons", [])
    if isinstance(reasons, str):
        cleaned_reasons = reasons.replace("⚠️", "[WARNING]").replace("🚨", "[ALERT]").replace("🔴", "[CRITICAL]")
        pdf.multi_cell(0, 5, cleaned_reasons, new_x="LMARGIN", new_y="NEXT")
    else:
        for reason in reasons:
            cleaned_reason = reason.replace("⚠️", "[WARNING]").replace("🚨", "[ALERT]").replace("🔴", "[CRITICAL]")
            pdf.multi_cell(0, 5, f"- {cleaned_reason}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(0, 6, "Dangerous Permission Exposures:", ln=True)
    pdf.set_font("helvetica", "", 9)
    caps = exp_dict.get("dangerous_permissions", [])
    if isinstance(caps, str):
        cleaned_caps = caps.replace("⚠️", "[WARNING]").replace("🚨", "[ALERT]").replace("🔴", "[CRITICAL]")
        pdf.multi_cell(0, 5, cleaned_caps, new_x="LMARGIN", new_y="NEXT")
    else:
        for cap in caps:
            cleaned_cap = cap.replace("⚠️", "[WARNING]").replace("🚨", "[ALERT]").replace("🔴", "[CRITICAL]")
            pdf.multi_cell(0, 5, f"- {cleaned_cap}", new_x="LMARGIN", new_y="NEXT")
    if not caps:
        pdf.cell(0, 5, "None identified.", ln=True)
    pdf.ln(3)
    
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(0, 6, "Threat Level Evaluation:", ln=True)
    pdf.set_font("helvetica", "", 9)
    pdf.multi_cell(0, 5, str(exp_dict.get("threat_level_assessment", "")), new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(0, 6, "Mitigation Recommendations:", ln=True)
    pdf.set_font("helvetica", "", 9)
    recs = exp_dict.get("user_recommendation", [])
    if isinstance(recs, str):
        cleaned_recs = recs.replace("⚠️", "[WARNING]").replace("🚨", "[ALERT]").replace("🔴", "[CRITICAL]").replace("🟡", "[AUDIT]")
        pdf.multi_cell(0, 5, cleaned_recs, new_x="LMARGIN", new_y="NEXT")
    else:
        for rec in recs:
            cleaned_rec = rec.replace("⚠️", "[WARNING]").replace("🚨", "[ALERT]").replace("🔴", "[CRITICAL]").replace("🟡", "[AUDIT]")
            pdf.multi_cell(0, 5, f"- {cleaned_rec}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(3)
    
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(0, 6, "Enterprise Business Impact:", ln=True)
    pdf.set_font("helvetica", "", 9)
    impacts = exp_dict.get("business_impact", [])
    if isinstance(impacts, str):
        pdf.multi_cell(0, 5, impacts, new_x="LMARGIN", new_y="NEXT")
    else:
        for impact in impacts:
            pdf.multi_cell(0, 5, f"- {impact}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    
    if "_info" in exp_dict:
        pdf.set_font("helvetica", "I", 7)
        pdf.set_text_color(148, 163, 184)
        pdf.cell(0, 5, f"Information: {exp_dict['_info']}", ln=True)

    return bytes(pdf.output())

# ---------------------------
# SIDEBAR SETTINGS
# ---------------------------
st.sidebar.image("https://img.icons8.com/nolan/128/security-shield.png", width=80)
st.sidebar.title("🛡️ Controls & API config")
st.sidebar.markdown("---")

# LLM Config API key
groq_key = st.sidebar.text_input("Enter GROQ API Key (Optional)", type="password", help="Paste your Groq API Key to enable Llama 3.3 AI explanations. If left blank, local heuristics explanation will be active.")
if not groq_key:
    groq_key = os.environ.get("GROQ_API_KEY", "")

if groq_key:
    st.sidebar.success("🔑 Groq LLM Explainer Ready!")
else:
    st.sidebar.info("💡 Running in Local Heuristics Explainer mode.")

# Assets path mapping
model_path = "models/malware_model.pkl" if os.path.exists("models/malware_model.pkl") else "../models/malware_model.pkl"
features_path = "data/drebin_features.json" if os.path.exists("data/drebin_features.json") else "../data/drebin_features.json"

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
    st.sidebar.error(f"❌ Error loading model: {load_error}")
else:
    st.sidebar.success("✅ XGBoost Model Ready!")

st.sidebar.markdown("""
### Model Specifications
- **Trained Classifier:** XGBoost
- **Dataset:** Drebin Malware Dataset
- **Classification Accuracy:** 98.6%
- **Input Signatures:** 215 Features
""")

# ---------------------------
# MAIN HEADER
# ---------------------------
st.title("🛡️ Android APK Malware Analyzer")
st.markdown("### AI-Powered Multi-Layer Threat Classification Platform")
st.markdown("Extract static attributes from Android packages (`.apk`) and feed them through a multi-tier risk-scoring engine, XGBoost classifier, MITRE ATT&CK analyzer, and a Groq Llama 3.3 LLM security layer.")
st.markdown("---")

# ---------------------------
# FILE UPLOAD SECTION
# ---------------------------
uploaded_file = st.file_uploader(
    "Upload APK file or Android Manifest JSON",
    type=["apk", "json"],
    help="Upload a raw APK file to dynamically parse permissions and services using Androguard, or upload a JSON manifest report."
)

manifest = None

if uploaded_file:
    file_extension = os.path.splitext(uploaded_file.name)[1].lower()
    
    if file_extension == ".apk":
        with st.spinner("⚡ Running Androguard Manifest Decompiler..."):
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
                st.error(f"❌ Androguard failed to extract manifest: {e}")
                manifest = None
                
    elif file_extension == ".json":
        try:
            manifest = json.load(uploaded_file)
            st.success(f"🎉 Loaded JSON Manifest profile: `{manifest.get('package', 'Unknown')}`")
        except Exception as e:
            st.error(f"❌ Invalid JSON structure: {e}")
            manifest = None

# ---------------------------
# COMPREHENSIVE ANALYSIS
# ---------------------------
if manifest:
    permissions = manifest.get("permissions", [])
    activities = manifest.get("activities", [])
    services = manifest.get("services", [])
    receivers = manifest.get("receivers", [])
    providers = manifest.get("providers", [])
    package_name = manifest.get("package", "unknown.package.identifier")

    # ==========================
    # 📦 SECTION 1: METADATA CARDS
    # ==========================
    st.header("📦 Application Structural Metadata")
    
    # Render customized cards via CSS
    card_cols = st.columns(5)
    
    labels = ["Permissions", "Activities", "Services", "Receivers", "Providers"]
    vals = [len(permissions), len(activities), len(services), len(receivers), len(providers)]
    
    for idx, col in enumerate(card_cols):
        col.markdown(f"""
        <div class="custom-card">
            <h4>{labels[idx]}</h4>
            <p>{vals[idx]}</p>
        </div>
        """, unsafe_allow_html=True)
        
    st.markdown(f"<div style='margin-top: 15px;'><strong>Package Namespace:</strong> <code>{package_name}</code></div>", unsafe_allow_html=True)
    st.markdown("---")

    # ==========================
    # 🚨 SECTION 2: RISK SCORING & ML VERDICT
    # ==========================
    st.header("📊 Classification Verdicts & Metrics")
    
    score, severity, findings = calculate_risk_score(permissions, services)
    
    # Machine Learning Inference
    if model is not None and feature_names is not None:
        ml_prediction, malware_prob, benign_prob, confidence = predict_malware(permissions, model, feature_names)
    else:
        st.warning("Model and feature files failed to load. ML prediction unavailable.")
        ml_prediction, malware_prob, benign_prob, confidence = "UNAVAILABLE", 0.0, 0.0, 0.0

    # Verdict Matrix Integration
    if score >= 50:
        final_verdict = "SUSPICIOUS APK"
        badge_class = "verdict-suspicious"
    elif ml_prediction == "MALWARE" and malware_prob >= 70:
        final_verdict = "MALWARE"
        badge_class = "verdict-malware"
    else:
        final_verdict = "BENIGN"
        badge_class = "verdict-benign"

    col_metrics1, col_metrics2 = st.columns([1, 1])
    
    with col_metrics1:
        st.subheader("Integrated Platform Verdict")
        st.markdown(f"""
        <div style="margin: 15px 0;">
            <span class="verdict-badge {badge_class}">{final_verdict}</span>
        </div>
        """, unsafe_allow_html=True)
        
        st.subheader("Heuristic Risk Engine")
        st.write(f"**Security Risk Score Index:** {score}/100")
        st.progress(score / 100.0)
        
        # Color-coded progress alerts
        if severity == "HIGH":
            st.error("🔴 **HIGH RISK SEVERITY:** Suspicious combinations or high quantity of dangerous permissions found.")
        elif severity == "MEDIUM":
            st.warning("🟠 **MEDIUM RISK SEVERITY:** Standard location, media, or network communication requests.")
        else:
            st.success("🟢 **LOW RISK SEVERITY:** Common system utilities permissions only.")

    with col_metrics2:
        st.subheader("Malware Classifier Probability")
        
        # Display SVG Gauge indicator
        stroke_color = "#ef4444" if ml_prediction == "MALWARE" else "#10b981"
        # Circumference is 377. Compute offset
        offset = 377 - (377 * confidence / 100.0)
        
        gauge_html = f"""
        <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; background-color: #1e293b; border-radius: 12px; padding: 25px; border: 1px solid #334155;">
            <svg width="150" height="150" viewBox="0 0 150 150">
                <circle cx="75" cy="75" r="60" stroke="#334155" stroke-width="12" fill="transparent" />
                <circle cx="75" cy="75" r="60" stroke="{stroke_color}" stroke-width="12" fill="transparent"
                        stroke-dasharray="377" stroke-dashoffset="{offset}" stroke-linecap="round"
                        transform="rotate(-90 75 75)" style="transition: stroke-dashoffset 0.8s ease-in-out;" />
                <text x="75" y="82" fill="#f8fafc" font-size="24" font-weight="bold" text-anchor="middle">{confidence:.2f}%</text>
            </svg>
            <div style="color: #94a3b8; margin-top: 15px; font-weight: 700; font-size: 1.1rem; text-transform: uppercase;">
                {ml_prediction} Confidence
            </div>
            <div style="display: flex; justify-content: space-around; width: 100%; margin-top: 15px; font-size: 0.9rem; color: #cbd5e1;">
                <div>Benign: {benign_prob:.2f}%</div>
                <div>Malware: {malware_prob:.2f}%</div>
            </div>
        </div>
        """
        st.markdown(gauge_html, unsafe_allow_html=True)

    st.markdown("---")

    # ==========================
    # 🛡️ SECTION 3: MITRE ATT&CK MAPPING
    # ==========================
    st.header("📌 MITRE ATT&CK Adversary Techniques Map")
    st.markdown("Static permissions mapped to industry-standard adversary tactic groups:")
    
    tactics = get_mitre_attack_mapping(permissions)
    
    if tactics:
        t_cols = st.columns(len(tactics) if len(tactics) <= 3 else 3)
        for idx, (tactic, entries) in enumerate(tactics.items()):
            col_target = t_cols[idx % len(t_cols)]
            with col_target:
                with st.expander(f"📁 {tactic} ({len(entries)} Flagged)", expanded=True):
                    for entry in entries:
                        st.markdown(f"🚩 **{entry['technique']}**")
                        st.markdown(f"<span style='color: #94a3b8; font-size:0.85rem;'>API: <code>{entry['permission']}</code></span>", unsafe_allow_html=True)
                        st.write(entry['description'])
                        st.markdown("<hr style='margin: 8px 0; border-color: #334155;'>", unsafe_allow_html=True)
    else:
        st.success("✅ No structural permissions mapped directly to aggressive MITRE ATT&CK techniques.")

    st.markdown("---")

    # ==========================
    # 🧠 SECTION 4: AI SECURITY EXPLANATION
    # ==========================
    st.header("🤖 Artificial Intelligence Security Assessment")
    
    with st.spinner("🤖 Consulting Llama 3.3 Malware Explainer Engine..."):
        # Generate the explanation dictionary using our explainer module
        explanation = generate_security_explanation(
            package_name=package_name,
            permissions=permissions,
            risk_score=score,
            severity=severity,
            ml_prediction=ml_prediction,
            malware_prob=malware_prob,
            final_verdict=final_verdict,
            api_key=groq_key
        )
        
    # Render Executive Summary inside a styled warning/info box
    summary = explanation.get("executive_summary", "")
    if final_verdict == "MALWARE":
        st.error(f"**Executive Security Summary:** {summary}")
    elif final_verdict == "SUSPICIOUS APK":
        st.warning(f"**Executive Security Summary:** {summary}")
    else:
        st.info(f"**Executive Security Summary:** {summary}")

    # Display full explanation
    st.markdown(format_explanation_markdown(explanation))
    
    st.markdown("---")

    # ==========================
    # 📄 EXPORTS (JSON & PDF)
    # ==========================
    st.header("⬇️ Download & Export Diagnostic Reports")
    
    report_data = {
        "package": package_name,
        "risk_score": score,
        "severity": severity,
        "ml_prediction": ml_prediction,
        "malware_probability": round(malware_prob, 2),
        "benign_probability": round(benign_prob, 2),
        "final_verdict": final_verdict,
        "total_permissions": len(permissions)
    }
    
    # Generate JSON bytes
    json_bytes = json.dumps({
        "platform_verdict": report_data,
        "mitre_attack_tactics": tactics,
        "ai_explanation": explanation
    }, indent=2).encode("utf-8")
    
    # Generate PDF bytes
    with st.spinner("Generating beautiful PDF report..."):
        pdf_bytes = build_pdf_report(report_data, explanation, permissions, tactics)
        
    col_dl1, col_dl2 = st.columns(2)
    
    with col_dl1:
        st.download_button(
            label="⬇️ Export Diagnostic JSON Report",
            data=json_bytes,
            file_name=f"{package_name}_malware_analysis.json",
            mime="application/json",
            key="dl_json"
        )
        
    with col_dl2:
        st.download_button(
            label="⬇️ Export Certified PDF Report",
            data=pdf_bytes,
            file_name=f"{package_name}_malware_analysis.pdf",
            mime="application/pdf",
            key="dl_pdf"
        )