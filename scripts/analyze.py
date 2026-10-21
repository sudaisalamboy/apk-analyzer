#!/usr/bin/env python3
"""
APK Analyzer — Standalone script for analyzing Android APK packages.
Performs static analysis: manifest inspection, secret scanning, security checks.

Usage:
    python3 analyze.py <apk-path> [--full-report] [--manifest-only] [--help]
"""

import sys
import os
import subprocess
import re
import json
import shutil
import argparse
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

# Fix #8: Added missing secret patterns (Slack, Twitter, generic password)
SECRET_PATTERNS = [
    ("Google API Key", r"AIza[0-9A-Za-z_\-]{35}"),
    ("Stripe Secret", r"sk_live_[0-9a-zA-Z]{24,}"),
    ("Stripe Publishable", r"pk_live_[0-9a-zA-Z]{24,}"),
    ("GitHub Token", r"gh[pousr]_[A-Za-z0-9]{36}"),
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    ("Firebase Key", r"AAAA[A-Za-z0-9_\-]{35}"),
    ("JWT Token", r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    ("Slack Token", r"xox[baprs]-[A-Za-z0-9-]+"),
    ("Twitter Bearer", r"AAAAAAAAAAAAAAAA[A-Za-z0-9%]{40,}"),
    ("Generic Password", r'(?:password|passwd|pwd|secret)["\']?\s*[:=]\s*["\']([^"\'\s]{4,})'),
]

# Fix #1: Updated URL regex to capture query params, ports, fragments
URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9._~:/?#@!$&'()*+,;=%\-]+")


def log(msg):
    print(f"[apk-analyzer] {msg}")


# Fix #3: Handle missing apktool gracefully
def decode_apk(apk_path, output_dir):
    log(f"Decoding {apk_path}...")
    try:
        result = subprocess.run(
            ["apktool", "d", "-f", "-o", output_dir, apk_path],
            capture_output=True, text=True, timeout=120
        )
        if result.returncode != 0:
            log(f"apktool failed: {result.stderr[:200]}")
            return False
        return True
    except FileNotFoundError:
        log("ERROR: apktool is not installed.")
        log("Install it: apt install apktool  OR  download from https://ibotpeaches.github.io/Apktool/")
        return False
    except subprocess.TimeoutExpired:
        log("ERROR: apktool timed out (120s). The APK might be too large.")
        return False


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


# Fix #2: Track line numbers using enumerate
def scan_secrets(decoded_dir):
    findings = []
    smali_dirs = [d for d in Path(decoded_dir).iterdir() if d.is_dir() and d.name.startswith("smali")]
    for smali_dir in smali_dirs:
        for smali_file in smali_dir.rglob("*.smali"):
            try:
                lines = smali_file.read_text(errors="ignore").split("\n")
            except:
                continue
            rel_path = str(smali_file.relative_to(decoded_dir))
            for name, pattern in SECRET_PATTERNS:
                regex = re.compile(pattern)
                for line_num, line in enumerate(lines, 1):
                    matches = regex.findall(line)
                    for match in matches:
                        value = match if isinstance(match, str) else match[0]
                        findings.append({
                            "type": name,
                            "value": value[:50] + "..." if len(value) > 50 else value,
                            "file": rel_path,
                            "line": line_num,
                            "severity": "CRITICAL" if "Key" in name or "Token" in name else "HIGH",
                        })
            # Scan URLs
            for line_num, line in enumerate(lines, 1):
                urls = URL_PATTERN.findall(line)
                for url in set(urls):
                    if any(domain in url for domain in ["api.", "firebaseio", "googleapis", ".com/api", ".io/api"]):
                        findings.append({
                            "type": "API Endpoint",
                            "value": url[:60],
                            "file": rel_path,
                            "line": line_num,
                            "severity": "MEDIUM",
                        })
    return findings


# Fix #4: Handle missing keytool specifically
def check_signing(apk_path):
    try:
        result = subprocess.run(["keytool", "-printcert", "-jarfile", apk_path],
                                capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            owner = re.search(r"Owner:\s*(.+)", result.stdout)
            return {"signed": True, "certificate_owner": owner.group(1).strip() if owner else "unknown"}
        return {"signed": False, "certificate_owner": "not signed or keytool error"}
    except FileNotFoundError:
        return {"signed": False, "certificate_owner": "keytool not installed"}
    except Exception:
        return {"signed": False, "certificate_owner": "unknown error"}


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
            report += f"- **File:** {s['file']}:{s.get('line', '?')}\n"
            report += f"- **Evidence:** `{s['value']}`\n"
    else:
        report += "\n✅ No secrets found.\n"

    critical = len([s for s in secrets if s["severity"] == "CRITICAL"])
    high = len([s for s in secrets if s["severity"] == "HIGH"])
    medium = len([s for s in secrets if s["severity"] == "MEDIUM"])
    risk = "Critical" if critical else "High" if high else "Medium" if medium else "Low"
    report += f"""
## Summary
- Total findings: {len(secrets)}
- Critical: {critical}
- High: {high}
- Medium: {medium}
- Overall risk: **{risk}**

---
*Generated by APK Analyzer — Made by Sudais Alam*
"""
    return report


# Fix #5: Add argparse for --help
def main():
    parser = argparse.ArgumentParser(
        description="APK Analyzer — Static analysis for Android APK packages",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n  python3 analyze.py app.apk\n  python3 analyze.py app.apk --full-report\n  python3 analyze.py app.apk --manifest-only"
    )
    parser.add_argument("apk_path", help="Path to the APK file to analyze")
    parser.add_argument("--full-report", action="store_true", help="Generate full security report with secret scanning")
    parser.add_argument("--manifest-only", action="store_true", help="Only analyze the manifest (fast)")
    args = parser.parse_args()

    apk_path = args.apk_path

    if not os.path.exists(apk_path):
        print(f"Error: {apk_path} not found")
        sys.exit(1)

    apk_name = os.path.basename(apk_path)
    decoded_dir = f"/tmp/apk-decoded-{int(datetime.now().timestamp())}"

    # Fix #7: Clean up temp dirs in finally block
    try:
        if not decode_apk(apk_path, decoded_dir):
            print("Failed to decode APK. Is apktool installed?")
            sys.exit(1)

        log("Analyzing manifest...")
        manifest_data = analyze_manifest(decoded_dir)

        if args.manifest_only:
            print(json.dumps(manifest_data, indent=2))
            return

        secrets = []
        if args.full_report or not args.manifest_only:
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
    finally:
        # Fix #7: Clean up temp decoded directory
        if os.path.exists(decoded_dir):
            shutil.rmtree(decoded_dir, ignore_errors=True)
            log(f"Cleaned up temp dir: {decoded_dir}")


if __name__ == "__main__":
    main()
