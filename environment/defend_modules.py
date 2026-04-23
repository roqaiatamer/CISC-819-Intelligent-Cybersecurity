"""
environment/defend_modules.py

Defensive countermeasures applied BEFORE or AFTER each attacker action.
Returns a DefendResult showing what was done and whether it would stop the attack.
"""

import re
import time
import sys
import os
from dataclasses import dataclass
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config.settings import DVWA_URL
from utils.logger import get_logger

log = get_logger("Defender")

# WAF pattern libraries
WAF_SQLI_PATTERNS = [
    r"(?i)(union\s+select)",
    r"(?i)(or\s+1\s*=\s*1)",
    r"(?i)(and\s+1\s*=\s*[12])",
    r"'.*--",
    r";\s*drop",
    r";\s*insert",
    r";\s*select",
    r"xp_cmdshell",
    r"information_schema",
]
WAF_XSS_PATTERNS = [
    r"(?i)<script[\s>]",
    r"(?i)javascript:",
    r"(?i)on\w+\s*=",
    r"(?i)<iframe",
    r"(?i)document\.cookie",
    r"(?i)eval\s*\(",
]
WAF_CMD_PATTERNS = [
    r";\s*(id|whoami|ls|cat|pwd|uname)",
    r"\|\s*(id|whoami|bash|sh)",
    r"&&\s*(id|whoami)",
    r"`[^`]+`",
    r"\$\([^)]+\)",
]
WAF_LFI_PATTERNS = [
    r"\.\./",
    r"\.\.\\",
    r"etc/passwd",
    r"etc/shadow",
    r"proc/self",
]


@dataclass
class DefendResult:
    action:       str
    would_block:  bool          # True → attack payload would be stopped
    method:       str           # description of how
    details:      str
    duration_ms:  float


def _timer():
    return time.perf_counter()

def _elapsed(t0) -> float:
    return round((time.perf_counter() - t0) * 1000, 2)

def _waf_check(payload: str, patterns: list) -> bool:
    return any(re.search(p, payload) for p in patterns)


# ─────────────────────────────────────────────────────────────────────────────
# Individual defend actions
# ─────────────────────────────────────────────────────────────────────────────

def defend_allow(context: dict) -> DefendResult:
    """Do nothing — passive observation."""
    t0 = _timer()
    return DefendResult("allow", False, "Passive", "No action taken", _elapsed(t0))


def defend_block_ip(context: dict) -> DefendResult:
    """
    Simulates IP block — in a real deployment this would add a firewall rule.
    Here: marks attacker IP as blocked in shared state so env skips the request.
    """
    t0 = _timer()
    context.get("state", {})["ip_blocked"] = True
    log.info("[DEFENDER] IP blocked (simulated firewall rule)")
    return DefendResult(
        "block_ip", True,
        "Firewall / iptables",
        f"Attacker IP flagged — subsequent requests dropped",
        _elapsed(t0)
    )


def defend_rate_limit(context: dict) -> DefendResult:
    """Slow down attack by introducing delay (simulates rate-limiter)."""
    t0 = _timer()
    time.sleep(1.5)   # 1.5s throttle
    context.get("state", {})["rate_limited"] = True
    return DefendResult(
        "rate_limit", False,
        "Rate limiter",
        "1.5s throttle applied — requests slowed",
        _elapsed(t0)
    )


def defend_honeypot_redirect(context: dict) -> DefendResult:
    """
    Marks session as honeypotted — attacker believes they're in real system
    but all results are fake. In sim: marks as honeypot, blocks real actions.
    """
    t0 = _timer()
    context.get("state", {})["in_honeypot"] = True
    return DefendResult(
        "honeypot_redirect", True,
        "Honeypot",
        "Session redirected to decoy — attacker isolated",
        _elapsed(t0)
    )


def defend_waf_sqli(context: dict) -> DefendResult:
    """Apply SQLi WAF rules to the current attack payload."""
    t0 = _timer()
    payload = context.get("payload", "")
    blocked = _waf_check(payload, WAF_SQLI_PATTERNS)
    method  = "WAF — SQLi ruleset"
    detail  = f"Payload {'BLOCKED' if blocked else 'passed'} SQLi pattern check"
    if blocked:
        log.info(f"[WAF-SQLI] Blocked payload: {payload[:60]}")
    return DefendResult("waf_rule_sqli", blocked, method, detail, _elapsed(t0))


def defend_waf_xss(context: dict) -> DefendResult:
    """Apply XSS WAF rules to the current attack payload."""
    t0 = _timer()
    payload = context.get("payload", "")
    blocked = _waf_check(payload, WAF_XSS_PATTERNS)
    detail  = f"Payload {'BLOCKED' if blocked else 'passed'} XSS pattern check"
    if blocked:
        log.info(f"[WAF-XSS] Blocked payload: {payload[:60]}")
    return DefendResult("waf_rule_xss", blocked, "WAF — XSS ruleset", detail, _elapsed(t0))


def defend_reset_session(context: dict) -> DefendResult:
    """Disabled — session reset causes login loops. Acts as alert_only instead."""
    t0 = _timer()
    payload = context.get("payload", "unknown")
    action  = context.get("attack_action", "unknown")
    log.warning(f"[ALERT] Threat detected: action={action} payload={payload[:80]}")
    return DefendResult(
        "reset_session", False,
        "IDS Alert (session reset disabled)",
        f"Threat logged: {action} — reset_session replaced with alert",
        _elapsed(t0)
    )


def defend_alert_only(context: dict) -> DefendResult:
    """Log the threat but take no blocking action."""
    t0 = _timer()
    payload = context.get("payload", "unknown")
    action  = context.get("attack_action", "unknown")
    log.warning(f"[ALERT] Threat detected: action={action} payload={payload[:80]}")
    return DefendResult(
        "alert_only", False,
        "IDS Alert",
        f"Threat logged: {action} — no block applied",
        _elapsed(t0)
    )


# ─────────────────────────────────────────────────────────────────────────────
# Dispatcher
# ─────────────────────────────────────────────────────────────────────────────
DEFEND_DISPATCH = {
    "allow":              defend_allow,
    "block_ip":           defend_block_ip,
    "rate_limit":         defend_rate_limit,
    "honeypot_redirect":  defend_honeypot_redirect,
    "waf_rule_sqli":      defend_waf_sqli,
    "waf_rule_xss":       defend_waf_xss,
    "reset_session":      defend_reset_session,
    "alert_only":         defend_alert_only,
}

def execute_defense(action_name: str, context: dict) -> DefendResult:
    fn = DEFEND_DISPATCH.get(action_name)
    if fn is None:
        return DefendResult(action_name, False, "Unknown", "Action not found", 0.0)
    return fn(context)
