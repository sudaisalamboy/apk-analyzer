# Report Format Reference

## APK Analysis Report Template

```markdown
# APK Analysis Report

## App Identity
| Field | Value |
|-------|-------|
| Package | com.example.app |
| Version | 1.0 (code: 1) |
| App Name | Example App |
| Min SDK | 24 (Android 7.0) |
| Target SDK | 36 (Android 16) |

## Permissions (X total)
### Dangerous (Y)
- CAMERA
- ACCESS_FINE_LOCATION
...

### Normal (Z)
- INTERNET
- VIBRATE
...

## Exported Components
| Type | Name | Permission | Risk |
|------|------|-----------|------|
| Activity | MainActivity | none | Medium |
| Service | MyService | none | High |

## Security Findings

### Finding 1: [CRITICAL] Hardcoded API Key
- **File:** smali/com/example/MainActivity.smali
- **Line:** 42
- **Evidence:** `const-string v0, "AIzaSyXXXXXXXXXXXXXXXX"`
- **Impact:** API key exposed in APK

### Finding 2: [HIGH] Debuggable Enabled
- **File:** AndroidManifest.xml
- **Evidence:** `android:debuggable="true"`
- **Impact:** App can be debugged in production

## Signing
- v1: No
- v2: Yes
- v3: Yes
- Certificate: CN=Android Debug, O=Android

## Summary
- Total findings: X
- Critical: Y
- High: Z
- Overall risk: [Low/Medium/High/Critical]
```
