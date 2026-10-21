---
name: apk-analyzer
description: Analyze Android APK packages for security research. Inspect manifests, decompile code, scan for vulnerabilities, and generate structured security reports. Use when a user provides an APK file for analysis.
metadata:
  version: "1.0.0"
  author: "Sudais Alam"
---

# APK Analyzer

Use this skill when a user provides an Android APK file for analysis. The skill performs static analysis — no dynamic execution or network calls.

## What this skill does

1. **Decodes the APK** using `apktool` (AndroidManifest, resources, smali)
2. **Inspects the manifest** for permissions, exported components, insecure flags
3. **Scans decompiled code** for hardcoded secrets (API keys, passwords, tokens)
4. **Checks signing** (v1/v2/v3 signature schemes)
5. **Generates a report** in Markdown format

## Prerequisites

Before running APK analysis, check that these tools are available:

| Tool | Check | Install |
|------|-------|--------|
| apktool | `apktool --version` | `apt install apktool` or [GitHub](https://ibotpeaches.github.io/Apktool/) |
| jadx | `jadx --version` | [GitHub releases](https://github.com/skylot/jadx/releases) |
| aapt | `aapt version` | `apt install aapt` |
| keytool | `keytool -help` | Comes with Java/JDK |
| Python 3 | `python3 --version` | `apt install python3` |

If any tool is missing, inform the user and provide the install command.

## Workflow

When a user says "analyze this APK" or provides an APK file:

### Step 1: Decode
```bash
apktool d -f -o /tmp/apk-decoded <apk-path>
```

### Step 2: Manifest Analysis
Read `AndroidManifest.xml` and extract:
- Package name, version code, version name
- Min/target SDK
- All permissions (categorize: normal, dangerous, signature)
- Exported activities, services, receivers, providers
- `android:debuggable`, `android:allowBackup`, `usesCleartextTraffic`

### Step 3: Secret Scanning
Search all smali files for:
- Hardcoded API keys (`AIza`, `sk_`, `pk_`, `ghp_`, `gho_`)
- URLs (`https?://` in const-string)
- Passwords/token patterns
- Firebase config keys

### Step 4: Signing Info
```bash
# Check signature schemes
keytool -printcert -jarfile <apk-path>
```

### Step 5: Generate Report
Create a structured Markdown report with all findings.

## Important

- **Static analysis only** — never install or run the APK
- **Passive** — no network requests, no dynamic instrumentation
- **Evidence-based** — every finding includes the file path and code snippet
- **Distinguish** between observations (facts from the APK) and inferences (deductions)

## References

- [Manifest Analysis](references/manifest-analysis.md)
- [Smali Analysis](references/smali-analysis.md)
- [Secret Scanning](references/secret-scanning.md)
- [Report Format](references/report-format.md)
