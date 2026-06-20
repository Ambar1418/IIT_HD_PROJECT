import os
import json
import sys
from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from pydantic import BaseModel
from fpdf import FPDF
from androguard.core.apk import APK

# Add src/ directory to path to load core modules
sys.path.append(os.path.join(os.path.dirname(__file__), "src"))
from core_analyzer import (
    calculate_risk_score, 
    load_ml_model, 
    load_feature_names, 
    predict_malware,
    get_mitre_attack_mapping
)
from llm_explainer import generate_security_explanation

app = FastAPI(
    title="Android Malware Analyzer API",
    description="Backend API wrapper supporting static APK decompilation, heuristics scoring, XGBoost classification, and Llama 3.3 analysis.",
    version="1.0.0"
)

# Enable CORS for Next.js frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # In production, restrict this to Next.js port (e.g. http://localhost:3000)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Pydantic request models
class PDFReportRequest(BaseModel):
    report_data: dict
    explanation: dict
    permissions: list
    tactics: dict

# ---------------------------
# PDF REPORT EXPORTER UTILITIES (Mirrors dashboard.py exactly)
# ---------------------------
class APKAnalysisPDF(FPDF):
    def header(self):
        self.set_font("helvetica", "B", 16)
        self.set_text_color(15, 23, 42)
        self.cell(0, 10, "Android APK Malware Analysis Report", ln=True, align="L")
        self.set_font("helvetica", "I", 9)
        self.set_text_color(100, 116, 139)
        self.cell(0, 5, "Platform Diagnostics & Artificial Intelligence Threat Assessment", ln=True, align="L")
        self.line(10, 26, 200, 26)
        self.ln(10)
        
    def footer(self):
        self.set_y(-15)
        self.set_font("helvetica", "I", 8)
        self.set_text_color(148, 163, 184)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}} | Confidential System Intelligence Diagnostic Report", align="C")

def build_pdf_report(report_data, exp_dict, permissions_list, tactics_dict):
    """Generates styled PDF report matching Streamlit exporter behavior."""
    pdf = APKAnalysisPDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    pdf.set_auto_page_break(auto=True, margin=20)
    
    # Section 1: Metadata
    pdf.set_font("helvetica", "B", 12)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 8, "1. Application Metadata", ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)
    
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(51, 65, 85)
    pdf.cell(50, 6, "Package Identifier:", border=0)
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(0, 6, str(report_data.get("package", "unknown")), border=0, ln=True)
    
    pdf.set_font("helvetica", "", 10)
    pdf.cell(50, 6, "Total Permissions Flagged:", border=0)
    pdf.cell(0, 6, str(report_data.get("total_permissions", 0)), border=0, ln=True)
    pdf.ln(4)
    
    # Section 2: Metrics
    pdf.set_font("helvetica", "B", 12)
    pdf.set_text_color(30, 41, 59)
    pdf.cell(0, 8, "2. Threat Classification & Metrics", ln=True)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(3)
    
    pdf.set_font("helvetica", "", 10)
    pdf.set_text_color(51, 65, 85)
    
    pdf.cell(50, 6, "ML Classification Verdict:", border=0)
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(0, 6, str(report_data.get("ml_prediction", "UNKNOWN")), border=0, ln=True)
    
    pdf.set_font("helvetica", "", 10)
    pdf.cell(50, 6, "Malware Confidence Score:", border=0)
    pdf.cell(0, 6, f"{report_data.get('malware_probability', 0.0):.2f}%", border=0, ln=True)
    
    pdf.cell(50, 6, "Heuristic Risk Index:", border=0)
    pdf.cell(0, 6, f"{report_data.get('risk_score', 0)}/100 ({report_data.get('severity', 'LOW')})", border=0, ln=True)
    
    pdf.cell(50, 6, "Integrated Platform Verdict:", border=0)
    pdf.set_font("helvetica", "B", 10)
    pdf.cell(0, 6, str(report_data.get("final_verdict", "BENIGN")), border=0, ln=True)
    pdf.ln(4)

    # Section 3: MITRE ATT&CK Mapping
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

    # Section 4: AI Explanation
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
# API ENDPOINTS
# ---------------------------

@app.post("/api/analyze")
async def analyze_apk(file: UploadFile = File(...)):
    """Receives APK or Manifest JSON, analyzes it, and returns combined classification payloads."""
    try:
        file_bytes = await file.read()
        file_name = file.filename.lower()
        
        if file_name.endswith(".apk"):
            apk = APK(file_bytes, raw=True)
            manifest = {
                "package": apk.get_package(),
                "permissions": list(apk.get_permissions()),
                "activities": list(apk.get_activities()),
                "services": list(apk.get_services()),
                "receivers": list(apk.get_receivers()),
                "providers": list(apk.get_providers()),
            }
        elif file_name.endswith(".json"):
            manifest = json.loads(file_bytes)
        else:
            raise HTTPException(status_code=400, detail="Unsupported file format. Please upload .apk or .json")
            
        permissions = manifest.get("permissions", [])
        services = manifest.get("services", [])
        activities = manifest.get("activities", [])
        receivers = manifest.get("receivers", [])
        providers = manifest.get("providers", [])
        package_name = manifest.get("package", "unknown.package")
        
        # Risk assessment heuristics
        score, severity, findings = calculate_risk_score(permissions, services)
        
        # Dynamic path resolution to load XGBoost
        model_path = "models/malware_model.pkl" if os.path.exists("models/malware_model.pkl") else "../models/malware_model.pkl"
        features_path = "data/drebin_features.json" if os.path.exists("data/drebin_features.json") else "../data/drebin_features.json"
        
        model = load_ml_model(model_path)
        feature_names = load_feature_names(features_path)
        
        ml_prediction, malware_prob, benign_prob, confidence = predict_malware(permissions, model, feature_names)
        
        # Integrated verdict mapping
        if score >= 50:
            final_verdict = "SUSPICIOUS APK"
        elif ml_prediction == "MALWARE" and malware_prob >= 70:
            final_verdict = "MALWARE"
        else:
            final_verdict = "BENIGN"
            
        # MITRE ATT&CK alignment
        tactics = get_mitre_attack_mapping(permissions)
        
        # AI explanation brief
        explanation = generate_security_explanation(
            package_name=package_name,
            permissions=permissions,
            risk_score=score,
            severity=severity,
            ml_prediction=ml_prediction,
            malware_prob=malware_prob,
            final_verdict=final_verdict
        )
        
        report_data = {
            "package": package_name,
            "risk_score": score,
            "severity": severity,
            "ml_prediction": ml_prediction,
            "malware_probability": round(malware_prob, 2),
            "benign_probability": round(benign_prob, 2),
            "final_verdict": final_verdict,
            "total_permissions": len(permissions),
            "activities_count": len(activities),
            "services_count": len(services),
            "receivers_count": len(receivers),
            "providers_count": len(providers)
        }
        
        return {
            "report_data": report_data,
            "tactics": tactics,
            "explanation": explanation,
            "permissions": permissions
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Diagnostic error: {str(e)}")

@app.post("/api/report/pdf")
async def generate_pdf(request: PDFReportRequest):
    """Accepts analysis payload and compiles a certified PDF diagnostic download."""
    try:
        pdf_bytes = build_pdf_report(
            report_data=request.report_data,
            exp_dict=request.explanation,
            permissions_list=request.permissions,
            tactics_dict=request.tactics
        )
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": "attachment; filename=malware_analysis.pdf",
                "Content-Type": "application/pdf"
            }
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"PDF Compilation failed: {str(e)}")
