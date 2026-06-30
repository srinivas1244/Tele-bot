#  Assessment Telegram Bot

A safe, authorized-only Telegram bot that performs non-destructive website and API security assessments and generates AI-powered reports using Claude.

---

## ⚠️ Legal & Ethical Requirements

> **This tool must only be used on assets you own or have explicit written permission to test.**
> Unauthorized scanning is illegal under computer fraud laws in most jurisdictions (e.g., CFAA, Computer Misuse Act).
> The authors accept no liability for misuse.

---

## Features

| Module | What it checks |
|---|---|
| **Port Scan** | 11 common TCP ports — open/closed, service, risk |
| **TLS/SSL** | Certificate validity, expiry, hostname, TLS version, HTTPS redirect |
| **Security Headers** | CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, CORP, COEP |
| **Cookies** | Secure, HttpOnly, SameSite, SameSite=None+Secure |
| **CORS** | Wildcard origins, reflected origins, null origin |
| **Sensitive Files** | `.env`, `.git`, backups, configs, DB dumps, admin panels, directory listing |
| **CMS Detection** | WordPress, Drupal, Joomla, Laravel, Django, Rails, Shopify, Magento |
| **Dependencies** | Frontend JS library detection + NVD CVE lookup |
| **API Security** | Swagger/OpenAPI exposure, HTTP methods, error messages, rate limits |
| **Open Redirects** | Safe parameter-based redirect detection |
| **Web Checks** | Mixed content, JS source maps, version comments, stack traces |
| **AI Report** | Claude-generated plain-language analysis with prioritized remediation roadmap |

---

## Architecture

```
├── main.py                  # Entry point
├── config.py                # All configuration constants
├── .env                     # Your credentials (never commit this)
├── bot/
│   ├── handlers.py          # Telegram conversation flow + scan dispatch
│   ├── messages.py          # Message templates
│   └── rate_limit.py        # Per-user sliding-window rate limiter
├── scanner/
│   ├── core.py              # Orchestrates all scan modules
│   ├── models.py            # Pydantic data models (Finding, ScanResult, etc.)
│   ├── ports.py             # TCP port check
│   ├── headers.py           # Security header analysis
│   ├── tls.py               # SSL/TLS certificate inspection
│   ├── cookies.py           # Cookie attribute audit
│   ├── cors.py              # CORS misconfiguration detection
│   ├── files.py             # Sensitive file + admin panel + directory listing
│   ├── cms.py               # CMS/framework fingerprinting
│   ├── dependencies.py      # Frontend library CVE detection
│   ├── api.py               # API security checks
│   ├── redirects.py         # Open redirect detection
│   ├── web.py               # General web checks
│   └── cve_lookup.py        # NVD API CVE lookup
├── report/
│   ├── ai_report.py         # Claude AI report generation
│   ├── json_report.py       # JSON export
│   └── pdf_report.py        # PDF report (ReportLab)
├── storage/                 # SQLite DB (auto-created)
├── reports/                 # Output reports (auto-created)
└── requirements.txt
```

---

## Setup

### 1. Prerequisites

- Python 3.11+
- A Telegram Bot Token (from [@BotFather](https://t.me/BotFather))
- An Anthropic API Key (from [console.anthropic.com](https://console.anthropic.com/))

### 2. Install dependencies

```bash
pip install -r requirements.txt
```

### 3. Configure environment

```bash
cp .env.example .env
# Edit .env and fill in your TELEGRAM_BOT_TOKEN and ANTHROPIC_API_KEY
```

### 4. Run the bot

```bash
python main.py
```

---

## Configuration Reference

| Variable | Default | Description |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | — | **Required.** From @BotFather |
| `ANTHROPIC_API_KEY` | — | **Required** for AI reports. Falls back to structured report if missing. |
| `CLAUDE_MODEL` | `claude-sonnet-4-6` | Claude model for AI report generation |
| `AUTHORIZED_USER_IDS` | _(empty = all users)_ | Comma-separated Telegram user IDs allowed to use the bot |
| `MAX_SCANS_PER_USER_PER_HOUR` | `3` | Rate limit per user |
| `PORT_SCAN_TIMEOUT` | `2.0` | Seconds per port TCP connect attempt |
| `HTTP_TIMEOUT` | `12.0` | HTTP request timeout in seconds |
| `REPORT_DIR` | `reports` | Directory for JSON/PDF output |

---

## Severity Model

| Level | Criteria |
|---|---|
| **Critical** | Exposed secrets, unauthenticated DB/admin, actively exploited CVE, expired cert |
| **High** | Dangerous CORS, exposed admin panels, open redirect confirmed, weak TLS, no HTTPS |
| **Medium** | Missing important headers, version disclosure, API error leakage, insecure cookies |
| **Low** | Missing optional headers, robots.txt disclosure, minor info leakage |
| **Informational** | Technology detected, expected open ports, CDN/WAF detected |

---

## Safety Design

- **No exploit code** anywhere in the codebase.
- **No offensive payloads** — input reflection tested with a harmless alphanumeric marker only.
- **Non-destructive** — read-only HTTP GET requests, TCP connect probes only (no SYN scan, no UDP, no fuzzing).
- **Rate-limited** — 3 scans/user/hour by default; configurable.
- **Authorization confirmation** — user must explicitly confirm ownership before any scan.
- **Concurrency cap** — one active scan per user at a time.
- **AI report safety** — Claude prompt explicitly prohibits exploit instructions.

---

## Extending the Bot

To add a new scanner module:

1. Create `scanner/mymodule.py` with an `async def check_mymodule(url, client) -> list[Finding]` function.
2. Import and call it in `scanner/core.py` inside `run_scan()`.
3. Add a progress line to `bot/messages.py` `SCAN_STARTED_MESSAGE`.

---

## Deployment

### Systemd (Linux)

```ini
[Unit]
Description=Security Assessment Telegram Bot
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/secbot
ExecStart=/opt/secbot/venv/bin/python main.py
Restart=always
RestartSec=10
EnvironmentFile=/opt/secbot/.env
User=secbot

[Install]
WantedBy=multi-user.target
```

### Docker

```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
CMD ["python", "main.py"]
```

```bash
docker build -t secbot .
docker run -d --env-file .env --name secbot secbot
```

---

## Legal Precautions

1. Only deploy this bot with access restricted to authorized users (`AUTHORIZED_USER_IDS`).
2. Log all scan requests with user ID, timestamp, and target for audit purposes.
3. Display the legal confirmation message before every scan.
4. Do not use this tool against systems you do not own or have written permission to test.
5. Store `.env` credentials securely — never commit them to version control.
6. Review your local laws regarding authorized penetration testing before use.

---

## License

For authorized security testing use only. See LICENSE file.
