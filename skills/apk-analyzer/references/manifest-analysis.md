# Manifest Analysis Reference

## Key Elements to Extract

### App Identity
- `package` — package name
- `android:versionCode` — numeric version
- `android:versionName` — display version
- `android:label` — app display name

### SDK Levels
- `minSdkVersion` — minimum Android version supported
- `targetSdkVersion` — target Android version
- `compileSdkVersion` — compiled against

### Permissions (categorize by protection level)
**Dangerous** (requires user consent):
- `INTERNET`, `ACCESS_FINE_LOCATION`, `ACCESS_COARSE_LOCATION`
- `READ_CONTACTS`, `WRITE_CONTACTS`, `READ_SMS`, `SEND_SMS`
- `CAMERA`, `RECORD_AUDIO`, `READ_EXTERNAL_STORAGE`, `WRITE_EXTERNAL_STORAGE`
- `CALL_PHONE`, `READ_PHONE_STATE`, `READ_CALL_LOG`

**Normal** (auto-granted):
- `VIBRATE`, `WAKE_LOCK`, `ACCESS_NETWORK_STATE`, `ACCESS_WIFI_STATE`
- `FOREGROUND_SERVICE`, `POST_NOTIFICATIONS`, `RECEIVE_BOOT_COMPLETED`

### Exported Components (security risk)
Check for `android:exported="true"` on:
- `<activity>` — can be launched by other apps
- `<service>` — can be started/bound by other apps
- `<receiver>` — can receive broadcasts from other apps
- `<provider>` — can be queried by other apps

Flag exported components that don't have `android:permission` set.

### Insecure Flags
- `android:debuggable="true"` — app is debuggable (production risk)
- `android:allowBackup="true"` — data can be extracted via adb
- `android:usesCleartextTraffic="true"` — allows HTTP (not HTTPS)
- `android:networkSecurityConfig` missing — uses platform defaults
