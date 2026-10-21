# Secret Scanning Reference

## Patterns to Detect

### API Keys
| Pattern | Regex | Service |
|---------|-------|---------|
| Google API | `AIza[0-9A-Za-z_-]{35}` | Google Cloud |
| Stripe Secret | `sk_live_[0-9a-zA-Z]{24,}` | Stripe |
| Stripe Publishable | `pk_live_[0-9a-zA-Z]{24,}` | Stripe |
| GitHub Token | `gh[pousr]_[A-Za-z0-9]{36}` | GitHub |
| Slack Token | `xox[baprs]-[A-Za-z0-9-]+` | Slack |
| AWS Access Key | `AKIA[0-9A-Z]{16}` | AWS |
| Twitter Bearer | `AAAAAAAAAAAAAAAA[A-Za-z0-9%]{40,}` | Twitter/X |
| Firebase Key | `AAAA[A-Za-z0-9_-]{35}` | Firebase |

### Passwords & Tokens
Search for:
- `const-string.*"password"` / `"passwd"` / `"pwd"`
- `const-string.*"secret"` / `"token"` / `"api_key"`
- `const-string.*"Bearer "` / `"Basic "`
- JWT patterns: `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`

### URLs
- `https?://` in `const-string` (potential API endpoints)
- Firebase URLs: `*.firebaseio.com`
- Google APIs: `*.googleapis.com`
- Payment gateways: `razorpay.com`, `stripe.com`, `paypal.com`

### Files
- `google-services.json` (in assets/)
- `.env` files
- Config files with credentials

## Severity Levels
- **CRITICAL** — Live API keys, AWS credentials, private keys
- **HIGH** — Hardcoded passwords, Firebase config with secrets
- **MEDIUM** — API endpoints, internal URLs
- **LOW** — Public keys, test credentials, placeholder values
