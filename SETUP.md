# Setup — APK Analyzer

## Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| Python 3 | Run analysis script | `apt install python3` |
| apktool | Decode APK resources | `apt install apktool` |
| jadx | Decompile DEX to Java | [GitHub](https://github.com/skylot/jadx) |
| aapt | Read APK manifest | `apt install aapt` |
| unzip | Extract APK contents | `apt install unzip` |

## Installation

```bash
git clone https://github.com/sudaisalamboy/apk-analyzer.git
cd apk-analyzer
```

## Using as an AI Agent Skill

```bash
# Add to your AI agent (Claude Code, Codex, etc.)
npx skills add sudaisalamboy/apk-analyzer
```

Then ask your agent:
```
Analyze this APK: /path/to/app.apk
```

## Using Standalone

```bash
# Basic analysis
python3 scripts/analyze.py app.apk

# Full report
python3 scripts/analyze.py app.apk --full-report

# Just manifest
python3 scripts/analyze.py app.apk --manifest-only
```

## Output

The tool generates:
1. **Manifest summary** — permissions, activities, services, receivers
2. **Security findings** — exported components, debuggable flag, cleartext
3. **Secret scan** — API keys, passwords found in decompiled code
4. **Full report** — Markdown file with all findings

## Project Structure

```
apk-analyzer/
├── skills/apk-analyzer/
│   ├── SKILL.md
│   └── references/
│       ├── manifest-analysis.md
│       ├── smali-analysis.md
│       ├── secret-scanning.md
│       └── report-format.md
├── scripts/analyze.py
├── .github/workflows/ci.yml
├── README.md
└── SETUP.md
```

## Troubleshooting

| Issue | Solution |
|-------|----------|
| apktool not found | `apt install apktool` or download from GitHub |
| jadx not found | Download from [jadx releases](https://github.com/skylot/jadx/releases) |
| Python error | Ensure Python 3.8+ installed |
| Permission denied | Run `chmod +x scripts/analyze.py` |

---
Made by Sudais Alam
