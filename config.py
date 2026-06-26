import os
from dotenv import load_dotenv

load_dotenv()

# ── Credentials ──────────────────────────────────────────────────────────────
TELEGRAM_BOT_TOKEN: str = os.getenv("TELEGRAM_BOT_TOKEN", "")

# ── AI Report Provider (free options) ────────────────────────────────────────
# Options: "ollama" | "groq" | "none"
# "none"   → structured rule-based report, no AI needed (default)
# "ollama" → local LLM via Ollama (https://ollama.com) — completely free
# "groq"   → Groq cloud API free tier (https://console.groq.com) — free API key
AI_PROVIDER: str = os.getenv("AI_PROVIDER", "none")

# Ollama settings (used when AI_PROVIDER=ollama)
OLLAMA_URL: str = os.getenv("OLLAMA_URL", "http://localhost:11434")
OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "llama3.1")

# Groq settings (used when AI_PROVIDER=groq)
# Free API key from: https://console.groq.com — no credit card required
GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
GROQ_MODEL: str = os.getenv("GROQ_MODEL", "llama-3.1-8b-instant")

# ── Rate limiting ─────────────────────────────────────────────────────────────
MAX_SCANS_PER_USER_PER_HOUR: int = int(os.getenv("MAX_SCANS_PER_USER_PER_HOUR", "3"))
MAX_CONCURRENT_SCANS: int = int(os.getenv("MAX_CONCURRENT_SCANS", "5"))

# ── Timeouts ──────────────────────────────────────────────────────────────────
PORT_SCAN_TIMEOUT: float = float(os.getenv("PORT_SCAN_TIMEOUT", "2.0"))
HTTP_TIMEOUT: float = float(os.getenv("HTTP_TIMEOUT", "12.0"))
HTTP_MAX_REDIRECTS: int = int(os.getenv("HTTP_MAX_REDIRECTS", "5"))

# ── Port scanning ─────────────────────────────────────────────────────────────
COMMON_PORTS: list[int] = [21, 22, 25, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200]

PORT_SERVICES: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    25: "SMTP",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
}

PORT_RISKS: dict[int, str] = {
    21: "FTP transmits credentials in plaintext; prefer SFTP/SCP.",
    22: "SSH exposed to internet; restrict via firewall or fail2ban.",
    25: "SMTP may allow relay abuse if misconfigured.",
    80: "Plain HTTP; enforce HTTPS redirect.",
    443: "Expected for HTTPS; verify certificate is valid.",
    3306: "MySQL should not be internet-facing; restrict to localhost.",
    5432: "PostgreSQL should not be internet-facing; restrict to localhost.",
    6379: "Redis has no auth by default; never expose publicly.",
    8080: "HTTP alternative port; may expose dev/staging services.",
    8443: "HTTPS alternative port; verify certificate.",
    9200: "Elasticsearch REST API; unauthenticated access is Critical.",
}

# ── Sensitive files ───────────────────────────────────────────────────────────
SENSITIVE_FILES: list[str] = [
    ".env", ".env.local", ".env.production", ".env.staging", ".env.backup",
    ".git/config", ".git/HEAD", ".git/COMMIT_EDITMSG",
    "config.php", "config.yaml", "config.yml", "config.json",
    "wp-config.php", "wp-config.php.bak", "wp-config.php~",
    "database.yml", "database.php", "database.json",
    "settings.py", "settings.php", "local_settings.py",
    "application.properties", "application.yml", "appsettings.json",
    "backup.sql", "dump.sql", "db.sql", "database.sql",
    "backup.zip", "backup.tar.gz", "site.zip", "site.tar.gz",
    "www.zip", "html.zip", "public.zip",
    ".htaccess", "web.config",
    "phpinfo.php", "info.php", "test.php", "debug.php",
    "composer.json", "package.json", "Gemfile", "requirements.txt",
    "README.md", "CHANGELOG.md", "INSTALL.md",
    "logs/error.log", "logs/access.log", "logs/debug.log",
    "error_log", "access.log", "debug.log",
    "server-status", "server-info",
    "crossdomain.xml", "clientaccesspolicy.xml",
]

# ── Admin paths ───────────────────────────────────────────────────────────────
ADMIN_PATHS: list[str] = [
    "/admin", "/admin/", "/admin/login", "/admin/dashboard",
    "/wp-admin/", "/wp-login.php",
    "/administrator/", "/administrator/index.php",
    "/phpmyadmin/", "/pma/", "/phpMyAdmin/",
    "/cpanel/", "/cPanel/", "/whm/",
    "/manager/", "/management/",
    "/dashboard/", "/controlpanel/",
    "/console/", "/adminer/", "/adminer.php",
    "/panel/", "/admin-panel/",
    "/backend/", "/cms/",
    "/login", "/signin", "/auth/login",
]

# ── API discovery paths ───────────────────────────────────────────────────────
API_DISCOVERY_PATHS: list[str] = [
    "/swagger.json", "/swagger.yaml", "/swagger/",
    "/api/swagger.json", "/api/swagger.yaml",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/api-docs/", "/api-docs.json",
    "/api/docs", "/api/v1/docs", "/api/v2/docs", "/api/v3/docs",
    "/.well-known/openapi",
    "/redoc", "/redoc/",
    "/graphql",
    "/api/schema", "/api/schema.json",
    "/v1/swagger.json", "/v2/swagger.json",
]

# ── Storage / output ──────────────────────────────────────────────────────────
DATABASE_PATH: str = os.getenv("DATABASE_PATH", "storage/scans.db")
REPORT_DIR: str = os.getenv("REPORT_DIR", "reports")

# ── HTTP headers ──────────────────────────────────────────────────────────────
USER_AGENT: str = "SecurityAssessmentBot/1.0 (Authorized-Only; +https://github.com/your-org/secbot)"

# ── Authorization ─────────────────────────────────────────────────────────────
# If populated, only these Telegram user IDs may use the bot.
AUTHORIZED_USER_IDS: list[int] = [
    int(uid.strip())
    for uid in os.getenv("AUTHORIZED_USER_IDS", "").split(",")
    if uid.strip().isdigit()
]

# ── Security headers to audit ─────────────────────────────────────────────────
SECURITY_HEADERS: dict[str, dict] = {
    "content-security-policy": {
        "name": "Content-Security-Policy",
        "severity": "High",
        "description": "Prevents XSS and data injection by restricting resource origins.",
        "recommendation": "Define a strict CSP policy; start with default-src 'self'.",
    },
    "strict-transport-security": {
        "name": "Strict-Transport-Security",
        "severity": "Medium",
        "description": "Forces HTTPS connections; prevents protocol downgrade attacks.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "x-frame-options": {
        "name": "X-Frame-Options",
        "severity": "Medium",
        "description": "Prevents clickjacking by restricting iframe embedding.",
        "recommendation": "Add: X-Frame-Options: DENY or SAMEORIGIN",
    },
    "x-content-type-options": {
        "name": "X-Content-Type-Options",
        "severity": "Low",
        "description": "Prevents MIME-type sniffing attacks.",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "name": "Referrer-Policy",
        "severity": "Low",
        "description": "Controls how much referrer information is shared.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "name": "Permissions-Policy",
        "severity": "Low",
        "description": "Controls browser feature access (camera, microphone, geolocation).",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
    "cross-origin-opener-policy": {
        "name": "Cross-Origin-Opener-Policy",
        "severity": "Low",
        "description": "Isolates browsing context from cross-origin documents.",
        "recommendation": "Add: Cross-Origin-Opener-Policy: same-origin",
    },
    "cross-origin-resource-policy": {
        "name": "Cross-Origin-Resource-Policy",
        "severity": "Low",
        "description": "Controls which origins can load the resource.",
        "recommendation": "Add: Cross-Origin-Resource-Policy: same-site",
    },
    "cross-origin-embedder-policy": {
        "name": "Cross-Origin-Embedder-Policy",
        "severity": "Low",
        "description": "Prevents loading cross-origin resources without explicit permission.",
        "recommendation": "Add: Cross-Origin-Embedder-Policy: require-corp",
    },
}
