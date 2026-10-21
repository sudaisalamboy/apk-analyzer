#!/usr/bin/env python3
"""
APK Analyzer — Standalone script for analyzing Android APK packages.
Performs static analysis: manifest inspection, secret scanning, security checks.

Usage:
    python3 analyze.py <apk-path> [--full-report] [--manifest-only]
"""

import sys
import os
import subprocess
import re
import json
from pathlib import Path
from datetime import datetime

# --- Config ---
DANGEROUS_PERMISSIONS = {
    "INTERNET", "ACCESS_FINE_LOCATION", "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION", "CAMERA", "RECORD_AUDIO",
    "READ_CONTACTS", "WRITE_CONTACTS", "READ_SMS", "SEND_SMS",
    "READ_EXTERNAL_STORAGE", "WRITE_EXTERNAL_STORAGE",
    "CALL_PHONE", "READ_PHONE_STATE", "READ_CALL_LOG",
    "SYSTEM_ALERT_WINDOW", "REQUEST_INSTALL_PACKAGES",
}

SECRET_PATTERNS = [
    ("Google API Key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("Stripe Secret", r"sk_live_[0-9a-zA-Z]{24,}"),
    ("GitHub Token", r"gh[pousr]_[A-Za-z0-9]{36}"),
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("Firebase Key", r"AAAA[A-Za-z0-9_\-]{35}"),
    ("JWT Token", r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
]

URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9.\-/]+")


def log(msg):
    print(f"[apk-analyzer] {msg}")


def decode_apk(apk_path, output_dir):
    log(f"Decoding {apk_path}...")
    result = subprocess.run(
        ["apktool", "d", "-f", "-o", output_dir, apk_path],
        capture_output=True, text=True, timeout=120
    )
    if result.returncode != 0:
        log(f"apktool failed: {result.stderr[:200]}")
        return False
    return True


def analyze_manifest(decoded_dir):
    manifest_path = os.path.join(decoded_dir, "AndroidManifest.xml")
    if not os.path.exists(manifest_path):
        return {"error": "AndroidManifest.xml not found"}

    with open(manifest_path, "r") as f:
        content = f.read()

    package = re.search(r'package="([^"]+)"', content)
    package = package.group(1) if package else "unknown"
    version_code = re.search(r'versionCode="(\d+)"', content)
    version_name = re.search(r'versionName="([^"]+)"', content)
    min_sdk = re.search(r'minSdkVersion="(\d+)"', content)
    target_sdk = re.search(r'targetSdkVersion="(\d+)"', content)

    permissions = re.findall(r'uses-permission android:name="([^"]+)"', content)
    permissions = [p.replace("android.permission.", "") for p in permissions]
    dangerous = [p for p in permissions if p in DANGEROUS_PERMISSIONS]
    normal = [p for p in permissions if p not in DANGEROUS_PERMISSIONS]

    exported_activities = len(re.findall(r'<activity[^>]*exported="true"', content))
    exported_services = len(re.findall(r'<service[^>]*exported="true"', content))
    exported_receivers = len(re.findall(r'<receiver[^>]*exported="true"', content))
    exported_providers = len(re.findall(r'<provider[^>]*exported="true"', content))

    debuggable = 'android:debuggable="true"' in content
    allow_backup = 'android:allowBackup="true"' in content
    cleartext = 'android:usesCleartextTraffic="true"' in content

    return {
        "package": package,
        "version_code": version_code.group(1) if version_code else "?",
        "version_name": version_name.group(1) if version_name else "?",
        "min_sdk": min_sdk.group(1) if min_sdk else "?",
        "target_sdk": target_sdk.group(1) if target_sdk else "?",
        "permissions": {"total": len(permissions), "dangerous": dangerous, "normal": normal},
        "exported": {"activities": exported_activities, "services": exported_services,
                      "receivers": exported_receivers, "providers": exported_providers},
        "security_flags": {"debuggable": debuggable, "allow_backup": allow_backup, "cleartext_traffic": cleartext},
    }


def scan_secrets(decoded_dir):
    findings = []
    smali_dirs = [d for d in Path(decoded_dir).iterdir() if d.is_dir() and d.name.startswith("smali")]
    for smali_dir in smali_dirs:
        for smali_file in smali_dir.rglob("*.smali"):
            try:
                content = smali_file.read_text(errors="ignore")
            except:
                continue
            rel_path = str(smali_file.relative_to(decoded_dir))
            for name, pattern in SECRET_PATTERNS:
                matches = re.findall(pattern, content)
                for match in matches:
                    findings.append({
                        "type": name, "value": match[:40] + "..." if len(match) > 40 else match,
                        "file": rel_path, "severity": "CRITICAL" if "Key" in name or "Token" in name else "HIGH",
                    })
    return findings


def check_signing(apk_path):
    try:
        result = subprocess.run(["keytool", "-printcert", "-jarfile", apk_path],
                                capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            owner = re.search(r"Owner:\s*(.+)", result.stdout)
            return {"signed": True, "certificate_owner": owner.group(1).strip() if owner else "unknown"}
    except:
        pass
    return {"signed": False, "certificate_owner": "unknown"}


def generate_report(manifest_data, secrets, signing, apk_name):
    report = f"""# APK Analysis Report

**Generated:** {datetime.now().strftime("%Y-%m-%d %H:%M")}
**APK:** {apk_name}

## App Identity
| Field | Value |
|-------|-------|
| Package | {manifest_data.get("package", "?")} |
| Version | {manifest_data.get("version_name", "?")} (code: {manifest_data.get("version_code", "?")}) |
| Min SDK | {manifest_data.get("min_sdk", "?")} |
| Target SDK | {manifest_data.get("target_sdk", "?")} |

## Permissions ({manifest_data.get("permissions", {}).get("total", 0)} total)
"""
    perms = manifest_data.get("permissions", {})
    if perms.get("dangerous"):
        report += f"\n### Dangerous ({len(perms['dangerous'])})\n"
        for p in perms["dangerous"]:
            report += f"- {p}\n"
    if perms.get("normal"):
        report += f"\n### Normal ({len(perms['normal'])})\n"
        for p in perms["normal"]:
            report += f"- {p}\n"

    exported = manifest_data.get("exported", {})
    sf = manifest_data.get("security_flags", {})
    report += f"""
## Exported Components
| Type | Count |
|------|-------|
| Activities | {exported.get("activities", 0)} |
| Services | {exported.get("services", 0)} |
| Receivers | {exported.get("receivers", 0)} |
| Providers | {exported.get("providers", 0)} |

## Security Flags
| Flag | Status |
|------|--------|
| Debuggable | {"⚠️ YES" if sf.get("debuggable") else "✅ No"} |
| Allow Backup | {"⚠️ YES" if sf.get("allow_backup") else "✅ No"} |
| Cleartext Traffic | {"⚠️ YES" if sf.get("cleartext_traffic") else "✅ No"} |

## Signing
- Signed: {"✅ Yes" if signing.get("signed") else "❌ No"}
- Certificate: {signing.get("certificate_owner", "unknown")}

## Secret Scan ({len(secrets)} findings)
"""
    if secrets:
        for s in secrets:
            report += f"\n### [{s['severity']}] {s['type']}\n"
            report += f"- **File:** {s['file']}\n"
            report += f"- **Evidence:** `{s['value']}`\n"
    else:
        report += "\n✅ No secrets found.\n"

    critical = len([s for s in secrets if s["severity"] == "CRITICAL"])
    high = len([s for s in secrets if s["severity"] == "HIGH"])
    risk = "Critical" if critical else "High" if high else "Low"
    report += f"""
## Summary
- Total findings: {len(secrets)}
- Critical: {critical}
- High: {high}
- Overall risk: **{risk}**

---
*Generated by APK Analyzer — Made by Sudais Alam*
"""
    return report


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 analyze.py <apk-path> [--full-report] [--manifest-only]")
        sys.exit(1)

    apk_path = sys.argv[1]
    full_report = "--full-report" in sys.argv
    manifest_only = "--manifest-only" in sys.argv

    if not os.path.exists(apk_path):
        print(f"Error: {apk_path} not found")
        sys.exit(1)

    apk_name = os.path.basename(apk_path)
    decoded_dir = f"/tmp/apk-decoded-{int(datetime.now().timestamp())}"

    if not decode_apk(apk_path, decoded_dir):
        print("Failed to decode APK. Is apktool installed?")
        sys.exit(1)

    log("Analyzing manifest...")
    manifest_data = analyze_manifest(decoded_dir)

    if manifest_only:
        print(json.dumps(manifest_data, indent=2))
        return

    secrets = []
    if full_report or not manifest_only:
        log("Scanning for secrets...")
        secrets = scan_secrets(decoded_dir)

    log("Checking signing...")
    signing = check_signing(apk_path)

    report = generate_report(manifest_data, secrets, signing, apk_name)

    report_file = f"analysis-report-{apk_name}.md"
    with open(report_file, "w") as f:
        f.write(report)

    log(f"Report saved: {report_file}")
    print("\n" + report)


if __name__ == "__main__":
    main()
