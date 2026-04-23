"""
config/settings.py
Loads all configuration from environment variables / .env file.
"""

import os
from dotenv import load_dotenv

# Load .env if present
load_dotenv()

def _int(key, default):   return int(os.getenv(key, default))
def _float(key, default): return float(os.getenv(key, default))
def _str(key, default):   return os.getenv(key, default)

# ── DVWA Target ──────────────────────────────────────────────────────────────
DVWA_URL            = _str("DVWA_URL",      "http://localhost/dvwa")
DVWA_USERNAME       = _str("DVWA_USERNAME", "admin")
DVWA_PASSWORD       = _str("DVWA_PASSWORD", "password")
DVWA_SECURITY_LEVEL = _str("DVWA_SECURITY_LEVEL", "low")

# Derived DVWA endpoints
DVWA_LOGIN_URL      = f"{DVWA_URL}/login.php"
DVWA_SETUP_URL      = f"{DVWA_URL}/setup.php"
DVWA_SECURITY_URL   = f"{DVWA_URL}/security.php"
DVWA_SQLI_URL       = f"{DVWA_URL}/vulnerabilities/sqli/"
DVWA_XSS_URL        = f"{DVWA_URL}/vulnerabilities/xss_r/"
DVWA_XSS_STORED_URL = f"{DVWA_URL}/vulnerabilities/xss_s/"
DVWA_CMD_URL        = f"{DVWA_URL}/vulnerabilities/exec/"
DVWA_FI_URL         = f"{DVWA_URL}/vulnerabilities/fi/"
DVWA_BRUTE_URL      = f"{DVWA_URL}/vulnerabilities/brute/"
DVWA_UPLOAD_URL     = f"{DVWA_URL}/vulnerabilities/upload/"
DVWA_CSRF_URL       = f"{DVWA_URL}/vulnerabilities/csrf/"

# ── Training ─────────────────────────────────────────────────────────────────
MAX_EPISODES         = _int("MAX_EPISODES",          300)
MAX_STEPS_PER_EP     = _int("MAX_STEPS_PER_EPISODE",  25)
LEARNING_RATE        = _float("LEARNING_RATE",       0.1)
DISCOUNT_FACTOR      = _float("DISCOUNT_FACTOR",     0.95)
EPSILON_START        = _float("EPSILON_START",       1.0)
EPSILON_MIN          = _float("EPSILON_MIN",         0.05)
EPSILON_DECAY        = _float("EPSILON_DECAY",       0.995)

# ── Rewards ───────────────────────────────────────────────────────────────────
REWARD_ATTACK_SUCCESS  = _int("REWARD_ATTACK_SUCCESS",  10)
REWARD_ATTACK_FAIL     = _int("REWARD_ATTACK_FAIL",     -2)
REWARD_DEFEND_SUCCESS  = _int("REWARD_DEFEND_SUCCESS",  10)
REWARD_DEFEND_FAIL     = _int("REWARD_DEFEND_FAIL",     -5)
REWARD_FALSE_POSITIVE  = _int("REWARD_FALSE_POSITIVE",  -1)

# ── Attack / Defend action spaces ────────────────────────────────────────────
ATTACK_ACTIONS = [
    "sqli_union",           # DVWA SQLi — UNION-based extraction
    "sqli_boolean_blind",   # DVWA SQLi — Boolean blind
    "xss_reflected",        # DVWA XSS reflected — script injection
    "xss_stored",           # DVWA XSS stored — persistent payload
    "cmd_injection",        # DVWA Command Execution — shell commands
    "file_inclusion",       # DVWA File Inclusion — path traversal / LFI
    "brute_force",          # DVWA Brute Force — credential stuffing
    "csrf_probe",           # DVWA CSRF — token-less form submission
]

DEFEND_ACTIONS = [
    "allow",                # Take no action — observe only
    "block_ip",             # Simulate IP blacklist (log + skip)
    "rate_limit",           # Slow request cadence (sleep)
    "honeypot_redirect",    # Log and stop — treat as caught
    "waf_rule_sqli",        # Apply SQLi-specific WAF pattern
    "waf_rule_xss",         # Apply XSS-specific WAF pattern
    "reset_session",        # Invalidate DVWA session (re-login)
    "alert_only",           # Log threat without intervention
]

# ── Paths ─────────────────────────────────────────────────────────────────────
LOG_DIR         = _str("LOG_DIR",    "logs")
REPORT_DIR      = _str("REPORT_DIR", "reports")
MODEL_DIR       = "models"
BATTLE_LOG      = f"{LOG_DIR}/battle.jsonl"
FORENSIC_REPORT = f"{REPORT_DIR}/forensics_report.json"

# ── Dashboard ─────────────────────────────────────────────────────────────────
DASHBOARD_PORT  = _int("DASHBOARD_PORT", 8080)
