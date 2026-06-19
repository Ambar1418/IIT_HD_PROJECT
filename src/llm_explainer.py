import os
import json
from groq import Groq

# Default model requested by user
GROQ_MODEL = "llama-3.3-70b-versatile"

def generate_security_explanation(package_name, permissions, risk_score, severity, ml_prediction, malware_prob, final_verdict, api_key=None):
    """
    Generates a structured security explanation using Groq Llama 3.3.
    If the API key is missing or the request fails, falls back to a high-quality rules-based explainer.
    """
    if not api_key:
        api_key = os.environ.get("GROQ_API_KEY")
        
    if not api_key:
        return get_fallback_explanation(package_name, permissions, risk_score, severity, ml_prediction, malware_prob, final_verdict)
        
    try:
        client = Groq(api_key=api_key)
        
        prompt = f"""
You are a Senior AI Security Engineer and expert Malware Researcher.
Analyze the following Android APK static analysis results and write an in-depth security brief.

### APK DATA
- **Package Name:** {package_name}
- **Detected Permissions:** {", ".join(permissions) if permissions else "None"}
- **Risk Score (Heuristic):** {risk_score}/100
- **Heuristic Severity Level:** {severity}
- **Machine Learning Classification:** {ml_prediction}
- **ML Malware Confidence:** {malware_prob:.2f}%
- **Integrated System Verdict:** {final_verdict}

### INSTRUCTIONS
Generate a JSON object explaining the threat profile of this APK. The output MUST contain exactly these keys and no extra text:
1. "executive_summary": A concise executive summary of the overall risk (1-2 sentences).
2. "flagged_reasons": Bullet points explaining why this APK was flagged by the ML and heuristics systems.
3. "dangerous_permissions": Breakdown of the most dangerous permissions requested and what threat vectors they unlock.
4. "threat_level_assessment": Rationale behind the final threat level classification.
5. "user_recommendation": Actionable steps for the end-user (e.g., uninstall immediately, restrict permissions, keep under audit).
6. "business_impact": Impact assessment for a corporate environment if installed on an employee's device (e.g., corporate espionage, data exfiltration, financial liability, compliance breach).

Make the analysis technical, precise, and highly professional. Ensure your output is valid JSON and contains nothing else.
"""
        response = client.chat.completions.create(
            model=GROQ_MODEL,
            messages=[
                {"role": "system", "content": "You are a professional security parser that output ONLY valid raw JSON."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            response_format={"type": "json_object"}
        )
        
        result_content = response.choices[0].message.content
        return json.loads(result_content)
        
    except Exception as e:
        # Fall back gracefully on failure so the system never crashes
        print(f"Groq API Error, falling back to heuristics explainer: {e}")
        return get_fallback_explanation(package_name, permissions, risk_score, severity, ml_prediction, malware_prob, final_verdict, error_msg=str(e))

def get_fallback_explanation(package_name, permissions, risk_score, severity, ml_prediction, malware_prob, final_verdict, error_msg=None):
    """
    Generates a rules-based mock explanation when the LLM is unavailable.
    Inspects permissions to assemble a highly relevant, customized analysis.
    """
    flagged_reasons = []
    dangerous_permissions = []
    user_recommendations = ["Do not install this APK unless from a verified developer source."]
    business_impacts = ["Potential exposure of sensitive corporate information if the device is connected to company resources."]
    
    # Analyze permissions for smart fallback text
    perms_set = set(permissions)
    
    # SMS checks
    sms_perms = {"android.permission.SEND_SMS", "android.permission.READ_SMS", "android.permission.RECEIVE_SMS"}
    has_sms = perms_set.intersection(sms_perms)
    if has_sms:
        flagged_reasons.append("Requests high-privilege SMS operations which can be exploited for premium rate fraud or interception of 2FA codes.")
        dangerous_permissions.append(f"SMS Permissions ({', '.join(has_sms)}): Enables reading or sending text messages in the background.")
        user_recommendations.append("Immediately revoke SMS permissions or uninstall the application to prevent financial fraud.")
        business_impacts.append("Compliance violation: Interception of multi-factor authentication (MFA) SMS tokens poses a direct threat to corporate account security.")

    # Location checks
    loc_perms = {"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION"}
    has_loc = perms_set.intersection(loc_perms)
    if has_loc:
        flagged_reasons.append("Requests hardware location sensors, allowing real-time tracking of the device.")
        dangerous_permissions.append(f"Location Permissions ({', '.join(has_loc)}): Enables tracking user movement and location harvesting.")
        user_recommendations.append("Disable location permissions for this application in Android System Settings.")
        business_impacts.append("Privacy breach: Tracking employee locations during work hours or inside secure zones poses a physical security risk.")

    # Audio/Video recording
    media_perms = {"android.permission.RECORD_AUDIO", "android.permission.CAMERA"}
    has_media = perms_set.intersection(media_perms)
    if has_media:
        flagged_reasons.append("Requests microphone or camera access, presenting active spyware characteristics.")
        dangerous_permissions.append(f"Media Permissions ({', '.join(has_media)}): Allows recording ambient audio or capturing video silently.")
        user_recommendations.append("Ensure microphone and camera indicator dots are not appearing unexpectedly when using this app.")
        business_impacts.append("Espionage risk: Possibility of corporate eavesdropping, unauthorized recordings of internal meetings, or leak of intellectual property.")

    # Storage access
    storage_perms = {"android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE"}
    has_storage = perms_set.intersection(storage_perms)
    if has_storage:
        flagged_reasons.append("Requests read/write privileges on external shared storage, allowing file system alterations.")
        dangerous_permissions.append(f"Storage Permissions ({', '.join(has_storage)}): Enables reading, modifying, or deleting files stored in external directories.")
        business_impacts.append("Data theft: Enables lateral scanning of the device's file system, potentially harvesting sensitive PDFs, images, or business documents.")

    # Network
    if "android.permission.INTERNET" in perms_set:
        flagged_reasons.append("Requires full internet permission, which is required to establish command and control (C2) connections or upload harvested data.")
        dangerous_permissions.append("INTERNET: Allows the application to transmit collected metadata, device telemetry, and stolen payloads to external domains.")

    # Request install packages
    if "android.permission.REQUEST_INSTALL_PACKAGES" in perms_set:
        flagged_reasons.append("Requests authority to install external applications, facilitating secondary malicious drops.")
        dangerous_permissions.append("REQUEST_INSTALL_PACKAGES: Bypasses Android's default security prompting to install additional code/APKs.")
        user_recommendations.append("Revoke the 'Install Unknown Apps' permission for this app in Android configuration.")
        business_impacts.append("Lateral movement: The app can serve as a staging point (dropper) to deliver ransomware or advanced persistent threats (APTs) on the enterprise network.")

    # Query all packages
    if "android.permission.QUERY_ALL_PACKAGES" in perms_set:
        flagged_reasons.append("Requests permission to enumerate all installed packages, facilitating reconnaissance of targeted banking or authentication applications.")
        dangerous_permissions.append("QUERY_ALL_PACKAGES: Enables scanning the device for target applications to coordinate overlay phishing attacks.")

    # If list is empty
    if not flagged_reasons:
        if risk_score > 30:
            flagged_reasons.append("Heuristic flags triggered by combination of permissions and services.")
        else:
            flagged_reasons.append("Minor permissions requested; minimal heuristic risk detected.")

    # Verdict assembly
    if final_verdict == "MALWARE":
        exec_summary = f"The application '{package_name}' has been classified as MALWARE by our machine learning classifier with {malware_prob:.2f}% confidence. The static signature matches patterns found in known malicious Android software."
        threat_level = "High-priority alert. The combination of structural permissions and machine learning flags indicates an active threat profile (e.g., remote access Trojan, dropper, or credential harvester)."
        user_recommendations.insert(0, "🔴 UNINSTALL THE APPLICATION IMMEDIATELY.")
    elif final_verdict == "SUSPICIOUS APK":
        exec_summary = f"The application '{package_name}' is marked as SUSPICIOUS due to a high heuristic risk score ({risk_score}/100) and suspicious permission combinations, although the ML model classified it as benign."
        threat_level = "Medium threat. The application possesses capabilities characteristic of malware (e.g., auto-start, internet communication, and sensitive collection), suggesting over-privileged or grayware behavior."
        user_recommendations.insert(0, "🟡 Revoke unnecessary permissions and audit the application's network traffic.")
    else:
        exec_summary = f"The application '{package_name}' is classified as BENIGN. It exhibits standard, low-risk permission behaviors with a minimal heuristic score ({risk_score}/100)."
        threat_level = "Low risk. The application does not exhibit signature behaviors associated with malware."
        user_recommendations = ["The application is safe for standard operations under default permissions."]
        business_impacts = ["No significant corporate security or compliance risks identified."]

    fallback_report = {
        "executive_summary": exec_summary,
        "flagged_reasons": flagged_reasons,
        "dangerous_permissions": dangerous_permissions,
        "threat_level_assessment": threat_level,
        "user_recommendation": user_recommendations,
        "business_impact": business_impacts
    }
    
    # Append message if the API key was missing or errored
    if error_msg:
        fallback_report["_info"] = f"Generated by local heuristics analyzer (Groq API Error: {error_msg})."
    else:
        fallback_report["_info"] = "Generated by local heuristics analyzer (GROQ_API_KEY environment variable is not configured)."

    return fallback_report

def format_explanation_markdown(exp_dict):
    """Formats the explanation dictionary into readable markdown for the dashboard."""
    md = []
    md.append(f"### 📋 Executive Summary\n{exp_dict.get('executive_summary', '')}\n")
    
    md.append("### 🚩 Flagged Risk Indicators")
    for reason in exp_dict.get("flagged_reasons", []):
        md.append(f"- {reason}")
    md.append("")
    
    md.append("### 🔑 Dangerous Capabilities Enabled")
    for perm in exp_dict.get("dangerous_permissions", []):
        md.append(f"- {perm}")
    if not exp_dict.get("dangerous_permissions"):
        md.append("No dangerous permissions identified.")
    md.append("")
    
    md.append(f"### 🚨 Threat Level Assessment\n{exp_dict.get('threat_level_assessment', '')}\n")
    
    md.append("### 💡 Recommended Actions")
    for rec in exp_dict.get("user_recommendation", []):
        md.append(f"- {rec}")
    md.append("")
    
    md.append("### 🏢 Enterprise Business Impact")
    for impact in exp_dict.get("business_impact", []):
        md.append(f"- {impact}")
    md.append("")
    
    if "_info" in exp_dict:
        md.append(f"\n*Note: {exp_dict['_info']}*")
        
    return "\n".join(md)
