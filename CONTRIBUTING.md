# Contributing to APK Analyzer

Thank you for your interest in contributing!

## 🌿 Branch Strategy

| Branch | Purpose |
|--------|---------|
| `main` | Stable, production-ready code |
| `develop` | Latest development changes |
| `feature/*` | New features (e.g., `feature/qr-scan`) |
| `fix/*` | Bug fixes (e.g., `fix/regex-pattern`) |
| `docs/*` | Documentation improvements |

## 📋 How to Contribute

1. Fork the repo
2. Create a branch: `git checkout -b feature/your-feature`
3. Make your changes
4. Test: `python3 scripts/analyze.py test.apk --full-report`
5. Commit: `git commit -m "feat: add your feature"`
6. Push: `git push origin feature/your-feature`
7. Open a Pull Request

## ✅ PR Checklist
- [ ] Code follows existing style
- [ ] Python syntax valid (`python3 -c "import ast; ast.parse(open('scripts/analyze.py').read())"`)
- [ ] No hardcoded secrets in test files
- [ ] CI passes
- [ ] Updated documentation if needed

## 🧪 Testing

```bash
# Test with a real APK (your own!)
python3 scripts/analyze.py your-app.apk --full-report

# Test manifest-only mode
python3 scripts/analyze.py your-app.apk --manifest-only

# Verify --help works
python3 scripts/analyze.py --help
```

---
Made by Sudais Alam
