import json

PERMISSION_TIERS = {
    # T3 - High risk
    "android.permission.SEND_SMS": 3,
    "android.permission.READ_SMS": 3,
    "android.permission.RECEIVE_SMS": 3,
    "android.permission.READ_CONTACTS": 3,
    "android.permission.RECORD_AUDIO": 3,
    "android.permission.CAMERA": 3,
    "android.permission.READ_CALL_LOG": 3,
    "android.permission.PROCESS_OUTGOING_CALLS": 3,
    "android.permission.SYSTEM_ALERT_WINDOW": 3,

    # T2 - Medium risk
    "android.permission.READ_EXTERNAL_STORAGE": 2,
    "android.permission.WRITE_EXTERNAL_STORAGE": 2,
    "android.permission.ACCESS_FINE_LOCATION": 2,
    "android.permission.ACCESS_COARSE_LOCATION": 2,
    "android.permission.INTERNET": 2,

    # T1 - Low risk
    "android.permission.RECEIVE_BOOT_COMPLETED": 1,
    "android.permission.POST_NOTIFICATIONS": 1,
    "android.permission.SCHEDULE_EXACT_ALARM": 1,
    "android.permission.WAKE_LOCK": 1,
    "android.permission.READ_SYNC_SETTINGS": 1,
    "android.permission.WRITE_SYNC_SETTINGS": 1,
    "android.permission.READ_SYNC_STATS": 1,
}

DANGEROUS_COMBOS = [
    ({"android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.INTERNET"}, 25),
    ({"android.permission.RECORD_AUDIO", "android.permission.INTERNET"}, 15),
    ({"android.permission.READ_CONTACTS", "android.permission.INTERNET"}, 10),
]

# Anchor score for the worst tier present, then add a small amount per extra permission
TIER_ANCHOR = {0: 5, 1: 15, 2: 40, 3: 65}
PER_EXTRA_PERM_POINTS = {0: 1, 1: 2, 2: 4, 3: 6}

def score_permissions(permissions):
    perms = set(permissions)
    breakdown = []
    max_tier = 0

    for p in perms:
        tier = PERMISSION_TIERS.get(p, 0)
        breakdown.append({"permission": p, "tier": f"T{tier}"})
        max_tier = max(max_tier, tier)

    # Anchor: score is driven mainly by the worst permission present
    base_score = TIER_ANCHOR[max_tier]

    # Small additive bump for extra permissions at that tier or below (over-privilege signal)
    extra = max(0, len(perms) - 1)
    base_score += extra * PER_EXTRA_PERM_POINTS[max_tier]

    combo_bonus = 0
    triggered_combos = []
    for combo, bonus in DANGEROUS_COMBOS:
        if combo.issubset(perms):
            combo_bonus += bonus
            triggered_combos.append(list(combo))

    final_score = min(100, base_score + combo_bonus)

    if final_score <= 30:
        band = "Low"
    elif final_score <= 60:
        band = "Medium"
    else:
        band = "High"

    return {
        "permission_risk_score": final_score,
        "band": band,
        "max_tier_found": f"T{max_tier}",
        "breakdown": breakdown,
        "dangerous_combos_triggered": triggered_combos,
    }


if __name__ == "__main__":
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    # Resolve project root based on directory structure
    if os.path.basename(current_dir) in ["src", "scripts"]:
        project_root = os.path.abspath(os.path.join(current_dir, ".."))
    else:
        project_root = os.path.abspath(current_dir)
        
    manifest_path = os.path.join(project_root, "samples", "notepad_manifest.json")
    if not os.path.exists(manifest_path):
        manifest_path = os.path.join(project_root, "notepad_manifest.json")
        
    with open(manifest_path) as f:
        manifest = json.load(f)

    result = score_permissions(manifest["permissions"])
    print(json.dumps(result, indent=2))