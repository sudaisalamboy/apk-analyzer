# Smali Analysis Reference

## What is Smali?
Smali is the human-readable representation of Dalvik bytecode (DEX). After `apktool d`, smali files are in `smali/`, `smali_classes2/`, etc.

## Key Patterns to Search

### Hardcoded Secrets
```bash
# API keys
grep -rn "AIza\|sk_live_\|sk_test_\|pk_live_\|ghp_\|gho_\|xoxb-" smali*/

# URLs (potential API endpoints)
grep -rn "https\?://" smali*/ | grep "const-string"

# Firebase config
grep -rn "firebase\|google-services\|google_api_key" smali*/

# Passwords
grep -rn "password\|passwd\|secret\|token\|api_key" smali*/ -i
```

### Dangerous Code Patterns
```bash
# Runtime code execution
grep -rn "Runtime.exec\|ProcessBuilder" smali*/

# WebView with JavaScript enabled
grep -rn "setJavaScriptEnabled\|addJavascriptInterface" smali*/

# Reflection
grep -rn "Class.forName\|Method.invoke" smali*/

# SQLite injection risk
grep -rn "rawQuery\|execSQL" smali*/ | grep "+"
```

### App Structure
- `com/<package>/` — main app code
- Third-party SDKs — Firebase, Sendbird, Razorpay, etc.
- Obfuscated classes (short names like `a.smali`, `b/c.smali`) — ProGuard/R8
