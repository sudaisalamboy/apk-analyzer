# APK Analyzer

An AI agent skill for analyzing Android APK packages — inspect manifests, decompile code, scan for vulnerabilities, and generate security reports.

> **Made by Sudais Alam**

## Preview

<img src="preview/preview.png" alt="APK Analyzer Preview" width="800" />

## Features

- 📦 **APK Inspection** — Parse AndroidManifest.xml, permissions, activities, services
- 🔍 **Code Decompiling** — Decompile DEX to readable Java (via jadx)
- 🛡️ **Vulnerability Scanning** — Detect hardcoded secrets, insecure configs, exported components
- 📊 **Security Report** — Generate a structured analysis report
- 🧩 **Skill-Based** — Designed as a reusable skill for AI coding agents

## Quick Start

```bash
git clone https://github.com/sudaisalamboy/apk-analyzer.git
cd apk-analyzer
```

### Analyze an APK

```bash
# Using the skill with an AI agent
npx skills add sudaisalamboy/apk-analyzer

# Or run standalone
python3 scripts/analyze.py path/to/app.apk
```

## Skill Structure

```
apk-analyzer/
├── skills/
│   └── apk-analyzer/
│       ├── SKILL.md                 # Skill instructions for AI agents
│       └── references/
│           ├── manifest-analysis.md  # How to read AndroidManifest
│           ├── smali-analysis.md     # Smali/Dalvik code patterns
│           ├── secret-scanning.md    # Finding hardcoded secrets
│           └── report-format.md      # Report template
├── scripts/
│   └── analyze.py                    # Standalone analysis script
├── .github/workflows/ci.yml          # CI pipeline
├── README.md
└── SETUP.md
```

## What It Detects

| Category | Examples |
|----------|---------|
| **Permissions** | Dangerous permissions (SMS, CAMERA, LOCATION) |
| **Exported Components** | Activities/Services exposed without permission |
| **Hardcoded Secrets** | API keys, passwords, tokens in code |
| **Insecure Config** | `android:debuggable`, cleartext traffic, backup enabled |
| **Native Libraries** | Architecture support, suspicious .so files |
| **Signing Info** | Signature version, certificate details |

## Tech Stack

- Python 3 (analysis script)
- aapt/apktool/jadx (external tools, documented in SETUP)
- Works with any AI agent that supports skills

## License

MIT — Made by Sudais Alam
