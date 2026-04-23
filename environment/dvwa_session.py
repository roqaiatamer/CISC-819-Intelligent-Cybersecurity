"""
environment/dvwa_session.py

Manages an authenticated requests.Session against a live DVWA instance.
Handles:
  - Login + CSRF token extraction
  - Security level setting
  - Session keep-alive / re-auth
  - Health-check before training starts
"""

import requests
import time
import sys
import os
from bs4 import BeautifulSoup

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from config.settings import (
    DVWA_URL, DVWA_SECURITY_URL,
    DVWA_USERNAME, DVWA_PASSWORD, DVWA_SECURITY_LEVEL,
)
from utils.logger import get_logger

log = get_logger("DVWASession")


class DVWASession:
    """
    Authenticated persistent session to DVWA.
    All attack modules share one instance.
    """

    def __init__(self, base_url: str = DVWA_URL,
                 username: str = DVWA_USERNAME,
                 password: str = DVWA_PASSWORD,
                 security: str = DVWA_SECURITY_LEVEL):
        self.base_url  = base_url.rstrip("/")
        self.username  = username
        self.password  = password
        self.security  = security
        self.session   = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                          "AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        })
        self.logged_in = False
        self._csrf_cache: dict = {}

    # ── Public API ────────────────────────────────────────────────────────────

    def connect(self, retries: int = 8, delay: float = 3.0) -> bool:
        """Login to DVWA, set security level. Retry on failure."""
        for attempt in range(1, retries + 1):
            try:
                log.info(f"Connecting to DVWA at {self.base_url} (attempt {attempt}/{retries})")
                if self._login():
                    self._set_security_level()
                    log.info(f"Connected! Security level → {self.security.upper()}")
                    self.logged_in = True
                    return True
            except requests.exceptions.ConnectionError:
                log.warning(f"DVWA not reachable — retrying in {delay}s …")
                time.sleep(delay)
            except Exception as e:
                log.error(f"Connection error: {e}")
                time.sleep(delay)
        log.error("Could not connect to DVWA after all retries.")
        return False

    def health_check(self) -> bool:
        """Return True if DVWA is reachable and session is valid."""
        try:
            r = self.session.get(f"{self.base_url}/index.php", timeout=5)
            if "login" in r.url.lower():
                log.warning("Session expired — re-authenticating …")
                return self._login()
            return r.status_code == 200
        except Exception:
            return False

    def get(self, url: str, **kwargs) -> requests.Response:
        self._ensure_logged_in()
        return self.session.get(url, timeout=10, **kwargs)

    def post(self, url: str, **kwargs) -> requests.Response:
        self._ensure_logged_in()
        return self.session.post(url, timeout=10, **kwargs)

    def get_csrf_token(self, url: str) -> str:
        """Extract user_token from a DVWA page (cached per URL)."""
        try:
            r = self.session.get(url, timeout=8)
            soup = BeautifulSoup(r.text, "lxml")
            token_input = soup.find("input", {"name": "user_token"})
            if token_input:
                token = token_input.get("value", "")
                self._csrf_cache[url] = token
                return token
        except Exception as e:
            log.debug(f"CSRF token fetch failed for {url}: {e}")
        return self._csrf_cache.get(url, "")

    # ── Private helpers ───────────────────────────────────────────────────────

    def _login(self) -> bool:
        login_url = f"{self.base_url}/login.php"
        try:
            # 1. GET login page and extract CSRF token
            r = self.session.get(login_url, timeout=8)
            soup = BeautifulSoup(r.text, "lxml")
            token_input = soup.find("input", {"name": "user_token"})
            user_token  = token_input["value"] if token_input else ""

            # 2. POST credentials
            payload = {
                "username":   self.username,
                "password":   self.password,
                "Login":      "Login",
                "user_token": user_token,
            }
            r2 = self.session.post(
                login_url, data=payload,
                timeout=8, allow_redirects=True
            )

            # 3. Check success using multiple indicators
            # Success = redirected away from login page
            if "login.php" not in r2.url:
                log.debug("Login successful — redirected away from login page")
                return True
            # Success = logout link visible (means user is logged in)
            if "logout" in r2.text.lower():
                log.debug("Login successful — logout link found")
                return True
            # Success = welcome message on page
            if "welcome" in r2.text.lower():
                log.debug("Login successful — welcome text found")
                return True
            # Success = DVWA vulnerability menu visible
            if "vulnerability" in r2.text.lower():
                log.debug("Login successful — vulnerability menu found")
                return True
            # Success = DVWA setup page content (some versions)
            if "dvwa" in r2.text.lower() and "login" not in r2.text.lower():
                log.debug("Login successful — DVWA content found")
                return True

            log.error("Login failed — check DVWA_USERNAME / DVWA_PASSWORD in .env")
            return False

        except Exception as e:
            log.error(f"Login exception: {e}")
            return False

    def _set_security_level(self):
        sec_url = f"{self.base_url}/security.php"
        token   = self.get_csrf_token(sec_url)
        self.session.post(sec_url, data={
            "seclev_submit": "Submit",
            "security":      self.security,
            "user_token":    token,
        }, timeout=8)
        log.debug(f"Security level set to {self.security}")

    def _ensure_logged_in(self):
        if not self.logged_in:
            raise RuntimeError("DVWASession: not connected. Call connect() first.")