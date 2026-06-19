import json
import os
import sys
from androguard.core.apk import APK

# Resolve directory paths
current_dir = os.path.dirname(os.path.abspath(__file__))
if os.path.basename(current_dir) == "scripts":
    project_root = os.path.abspath(os.path.join(current_dir, ".."))
else:
    project_root = os.path.abspath(current_dir)

apk_name = "notepad.apk"
apk_path = os.path.join(project_root, "samples", apk_name)
if not os.path.exists(apk_path):
    apk_path = os.path.join(project_root, apk_name)

if not os.path.exists(apk_path):
    print(f"Error: APK file not found at {apk_path}")
    sys.exit(1)

print(f"Analyzing APK: {apk_path}")
apk = APK(apk_path)

data = {
    "package": apk.get_package(),
    "permissions": list(apk.get_permissions()),
    "activities": list(apk.get_activities()),
    "services": list(apk.get_services()),
    "receivers": list(apk.get_receivers()),
    "providers": list(apk.get_providers()),
}

manifest_path = os.path.join(project_root, "samples", "notepad_manifest.json")
os.makedirs(os.path.dirname(manifest_path), exist_ok=True)

with open(manifest_path, "w") as f:
    json.dump(data, f, indent=2)

# Save fallback to root for backward compatibility
root_manifest_path = os.path.join(project_root, "notepad_manifest.json")
with open(root_manifest_path, "w") as f:
    json.dump(data, f, indent=2)

print(f"Saved manifest to {manifest_path} and {root_manifest_path}")