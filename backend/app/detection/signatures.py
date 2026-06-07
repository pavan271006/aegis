"""Signature rules for known attack payloads, matched against the URL-decoded
request path. Conservative patterns to keep false positives low."""
import re

SIGNATURES = {
    "sql_injection": [
        r"union\s+select", r"select\s+.+\s+from\s", r"'\s*or\s*'?\d+'?\s*=\s*'?\d",
        r"information_schema", r";\s*drop\s+table", r"sleep\(\d", r"benchmark\(", r"--\s",
    ],
    "xss": [
        r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
        r"<img[^>]+src", r"document\.cookie", r"<svg[^>]+onload",
    ],
    "path_traversal": [
        r"\.\./", r"\.\.%2f", r"/etc/passwd", r"/etc/shadow", r"boot\.ini", r"win\.ini",
    ],
    "malware_upload": [
        r"\.php[345]?$", r"\.jsp$", r"\.aspx?$", r"\.exe$", r"\.sh$", r"webshell", r"c99\.php", r"r57\.php",
    ],
}

COMPILED = {k: [re.compile(p, re.IGNORECASE) for p in v] for k, v in SIGNATURES.items()}

# Base severity per detected type
SEVERITY = {
    "sql_injection": "high", "xss": "high", "path_traversal": "high",
    "command_injection": "high", "malware_upload": "high",
    "credential_stuffing": "high", "brute_force": "high",
    "bot_attack": "medium", "scanning": "medium", "api_abuse": "medium",
    "ddos_pattern": "high", "rate_anomaly": "medium",
    "suspicious_login": "medium", "honeypot": "high",
}

THREAT_LABEL = {
    "sql_injection": "SQL Injection", "xss": "Cross-Site Scripting (XSS)",
    "path_traversal": "Path Traversal", "command_injection": "Command Injection",
    "malware_upload": "Malware Upload Attempt", "credential_stuffing": "Credential Stuffing",
    "brute_force": "Brute Force", "bot_attack": "Bot Attack", "scanning": "Scanning / Enumeration",
    "api_abuse": "API Abuse", "ddos_pattern": "DDoS Pattern", "rate_anomaly": "Abnormal Request Rate",
    "suspicious_login": "Suspicious Login Behavior", "honeypot": "Honeypot Trigger",
}

PREVENTION = {
    "sql_injection": "Use parameterized queries; enable Cloudflare managed WAF SQLi ruleset.",
    "xss": "Encode output, set a Content-Security-Policy header; enable WAF XSS ruleset.",
    "path_traversal": "Validate/normalize file paths; never pass user input to the filesystem.",
    "command_injection": "Never pass user input to a shell; use safe library calls.",
    "malware_upload": "Validate file type/size; scan uploads; store outside the webroot.",
    "credential_stuffing": "Add login rate-limiting + 2FA; enable Cloudflare Bot Fight Mode.",
    "brute_force": "Add login rate-limiting, lockouts, and 2FA.",
    "bot_attack": "Enable bot management / Turnstile; rate-limit by fingerprint.",
    "scanning": "Hide internal paths; rate-limit; remove exposed sensitive endpoints.",
    "api_abuse": "Enforce per-key rate limits and schema validation on the API.",
    "ddos_pattern": "Enable Cloudflare rate-limiting and caching to absorb spikes.",
    "rate_anomaly": "Enable Cloudflare rate-limiting rules and caching.",
    "suspicious_login": "Require 2FA; alert users to logins from new locations.",
    "honeypot": "No legitimate user hits these paths; block the source immediately.",
}
