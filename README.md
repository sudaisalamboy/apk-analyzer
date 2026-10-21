# 🔒 APK Analyzer

> **Ethical security research tool for analyzing Android APK packages.**
> Test on YOUR OWN apps. Authorization required for third-party analysis.

> **Made by Sudais Alam**

---

## ⚠️ Legal Disclaimer

This tool is for **educational and authorized security research ONLY**.

- ✅ Analyze your **own** APKs
- ✅ Audit apps you're **authorized** to test
- ✅ Learn Android security in a controlled environment
- ❌ Do NOT use to crack, pirate, or steal from apps you don't own
- ❌ Do NOT redistribute modified APKs without consent

**By using this tool, you accept full responsibility for your actions.**

See [SECURITY.md](SECURITY.md) for the full security policy + authorization template.

---

## Preview

<img src="preview/preview.png" alt="APK Analyzer Preview" width="800" />

---

## Features

- 📦 **APK Inspection** — Parse AndroidManifest.xml, permissions, activities, services
- 🔍 **Code Decompiling** — Decompile DEX to readable Java (via jadx)
- 🛡️ **Vulnerability Scanning** — Detect hardcoded secrets, insecure configs, exported components
- 🔑 **Secret Scanning** — 10+ patterns (Google, Stripe, GitHub, AWS, Firebase, JWT, Slack, Twitter)
- 📊 **Security Report** — Structured Markdown report with severity levels (Critical/High/Medium/Low)
- 🧩 **AI Agent Skill** — Works with Claude Code, Codex, and other AI agents
- 🧹 **Auto-cleanup** — Temp directories removed after analysis

---

## 🛠️ Tools & Libraries Used

This project leverages industry-standard reverse engineering and security tools:

### Core Analysis Tools

| Tool | Purpose | Install |
|------|---------|---------|
| **apktool** | Decode APK → AndroidManifest.xml + smali (Dalvik bytecode) + resources | `apt install apktool` or [GitHub](https://ibotpeaches.github.io/Apktool/) |
| **jadx** | Decompile DEX → readable Java source code | [GitHub releases](https://github.com/skylot/jadx/releases) |
| **aapt** | Read APK badging (package, version, SDK, permissions) from binary manifest | `apt install aapt` |
| **keytool** | Check APK signing (certificate owner, signature scheme) | Comes with Java JDK |
| **unzip** | Extract raw APK contents (ZIP archive) | `apt install unzip` |

### Python Standard Library (no pip install needed)

| Module | Purpose |
|--------|---------|
| `argparse` | CLI argument parsing (`--help`, `--full-report`, `--manifest-only`) |
| `re` | Regex pattern matching for secret scanning + manifest parsing |
| `subprocess` | Run external tools (apktool, keytool) |
| `pathlib` | Cross-platform file path handling for smali scanning |
| `json` | Output manifest analysis as JSON |
| `shutil` | Cleanup of temporary decoded directories |
| `os` | File system operations |
| `datetime` | Timestamp for reports + temp dir naming |

### Secret Detection Patterns (10+)

| Pattern | What it detects | Severity |
|---------|----------------|----------|
| Google API Key | `AIza...` (35 chars) | CRITICAL |
| Stripe Secret Key | `sk_live_...` | CRITICAL |
| Stripe Publishable Key | `pk_live_...` | HIGH |
| GitHub Token | `gh[pousr]_...` (36 chars) | CRITICAL |
| AWS Access Key | `AKIA...` (16 chars) | CRITICAL |
| Firebase Key | `AAAA...` (35 chars) | CRITICAL |
| JWT Token | `eyJ...eyJ...` | HIGH |
| Slack Token | `xox[baprs]-...` | CRITICAL |
| Twitter Bearer Token | `AAAAAAAAAA...` (40+ chars) | CRITICAL |
| Generic Password | `password=...`, `secret=...` | HIGH |
| API Endpoints | URLs with `api.`, `firebaseio`, `googleapis` | MEDIUM |

### Security Checks

| Check | What it detects |
|-------|----------------|
| `android:debuggable` | App is debuggable in production (attackers can attach debuggers) |
| `android:allowBackup` | App data can be extracted via `adb backup` |
| `android:usesCleartextTraffic` | App allows HTTP (not HTTPS) — MITM risk |
| Exported Activities | Activities launchable by other apps without permission |
| Exported Services | Services bindable by other apps |
| Exported Receivers | Broadcast receivers accessible by other apps |
| Exported Providers | Content providers queryable by other apps |
| Dangerous Permissions | CAMERA, LOCATION, SMS, CONTACTS, STORAGE, PHONE |

---

## 🚀 Quick Start

```bash
git clone https://github.com/sudaisalamboy/apk-analyzer.git
cd apk-analyzer
```

### Using as an AI Agent Skill

```bash
npx skills add sudaisalamboy/apk-analyzer
```

Then ask your agent: `Analyze this APK: /path/to/app.apk`

### Using Standalone

```bash
# Full analysis with secret scanning
python3 scripts/analyze.py your-app.apk --full-report

# Just the manifest (fast)
python3 scripts/analyze.py your-app.apk --manifest-only

# See help
python3 scripts/analyze.py --help
```

---

## 📁 Project Structure

```
apk-analyzer/
├── skills/
│   └── apk-analyzer/
│       ├── SKILL.md                       # AI agent skill instructions
│       └── references/
│           ├── manifest-analysis.md       # How to read AndroidManifest
│           ├── smali-analysis.md          # Smali/Dalvik code patterns
│           ├── secret-scanning.md          # Finding hardcoded secrets
│           └── report-format.md            # Report template
├── scripts/
│   └── analyze.py                         # Standalone Python analysis script
├── .github/workflows/ci.yml               # CI pipeline (passing ✅)
├── preview/preview.png                    # Preview banner
├── SECURITY.md                            # Security policy + legal disclaimer
├── CONTRIBUTING.md                        # Contribution guide + branch strategy
├── README.md                              # This file
└── SETUP.md                               # Detailed setup instructions
```

---

## 🌿 Branch Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Stable release code |
| `develop` | Latest development changes |
| `feature/*` | New features |
| `fix/*` | Bug fixes |
| `docs/*` | Documentation updates |

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

---

## 📦 Releases

| Version | Date | Download |
|---------|------|----------|
| v1.0.0 | Oct 2026 | [apk-analyzer-skill.zip](https://github.com/sudaisalamboy/apk-analyzer/releases/download/v1.0.0/apk-analyzer-skill.zip) |

---

## 📊 CI Status

![CI](https://github.com/sudaisalamboy/apk-analyzer/actions/workflows/ci.yml/badge.svg)

---

## 📫 Contact

- GitHub: [@sudaisalamboy](https://github.com/sudaisalamboy)
- Email: sudaisalam18@gmail.com
- Security issues: See [SECURITY.md](SECURITY.md)

---

## 📄 License

MIT — Free to use for **authorized security research only**.

---

*Made with ♥ by **Sudais Alam** — Using security tools responsibly.*
