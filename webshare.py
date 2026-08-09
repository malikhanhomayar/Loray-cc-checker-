#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
webshare.py — Automated webshare.io proxy fetcher
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
reCAPTCHA solving strategy (tried in order):
  1. NoPeCHA  (4 keys, auto-rotate on out-of-credit / expired)
  2. Direct recaptcha.net API bypass (no third-party solver needed)

Advanced TLS fingerprinting: curl_cffi chrome131 on every request.
Debug logging on EVERY request → webshare_debug.log

Standalone:  python webshare.py
Module:      from webshare import get_free_proxies
             proxies = await get_free_proxies(10)
"""
import sys, io
if hasattr(sys.stdout, "buffer"):
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "buffer"):
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

import asyncio
import base64
import json
import logging
import os
import random
import re
import string
import time
from pathlib import Path

from curl_cffi.requests import AsyncSession

# ══════════════════════════════════════════════════════════════
#  Logging
# ══════════════════════════════════════════════════════════════
_log_fmt = "%(asctime)s | %(levelname)-7s | %(message)s"
logging.basicConfig(level=logging.DEBUG, format=_log_fmt, handlers=[logging.StreamHandler()])
_fh = logging.FileHandler(Path(__file__).parent / "webshare_debug.log", encoding="utf-8")
_fh.setFormatter(logging.Formatter(_log_fmt))
logging.getLogger().addHandler(_fh)
log = logging.getLogger("webshare")

# ══════════════════════════════════════════════════════════════
#  NoPeCHA API keys (auto-rotated on credit exhaustion)
# ══════════════════════════════════════════════════════════════
NOPECHA_KEYS: list[str] = [
    "sub_1TdbHzCtAkNUqyep",
]
# Keys with credit code-16 errors — permanently skip for this process lifetime
_credit_exhausted_keys: set[str] = set()
# Keys temporarily skipped for the current solve attempt (reset between registration attempts)
_attempt_failed_keys: set[str] = set()

# Serialize ALL registration attempts — prevents concurrent /freeproxy calls
# from flooding NoPeCHA with simultaneous solve jobs and exhausting keys.
_REG_LOCK: asyncio.Lock | None = None

def _get_reg_lock() -> asyncio.Lock:
    """Lazily create the registration lock (requires a running event loop)."""
    global _REG_LOCK
    if _REG_LOCK is None:
        _REG_LOCK = asyncio.Lock()
    return _REG_LOCK

NOPECHA_URL   = "https://api.nopecha.com/v1"

# ══════════════════════════════════════════════════════════════
#  webshare.io constants
# ══════════════════════════════════════════════════════════════
WEBSHARE_RECAPTCHA_SITEKEY = "6LeHZ6UUAAAAAKat_YS--O2tj_by3gv3r_l03j9d"
WEBSHARE_REGISTER_URL      = "https://proxy.webshare.io/register"
# CO = base64url(b"https://proxy.webshare.io:443")  for recaptcha.net bypass
WEBSHARE_RECAPTCHA_CO      = base64.urlsafe_b64encode(b"https://proxy.webshare.io:443").decode().rstrip("=")

API_BASE      = "https://proxy.webshare.io/api/v2"
IMPERSONATE   = "chrome131"
MAX_REG_TRIES = 3

# Only the most trusted domains — webshare.io rejects "suspicious" ones like live.com/zoho/aol
EMAIL_DOMAINS = ["gmail.com", "outlook.com", "gmail.com", "gmail.com"]  # weighted toward gmail

# Common first/last names for realistic usernames
_FIRST_NAMES = [
    "james","john","robert","michael","william","david","richard","joseph","thomas","charles",
    "christopher","daniel","matthew","anthony","mark","donald","steven","paul","andrew","joshua",
    "emma","olivia","ava","isabella","sophia","mia","charlotte","amelia","harper","evelyn",
    "emily","abigail","ella","elizabeth","camila","luna","sofia","avery","mila","aria",
]
_LAST_NAMES = [
    "smith","johnson","williams","brown","jones","garcia","miller","davis","wilson","moore",
    "taylor","anderson","thomas","jackson","white","harris","martin","thompson","young","allen",
    "king","wright","scott","torres","nguyen","hill","flores","green","adams","nelson",
]

# ══════════════════════════════════════════════════════════════
#  Account file helpers
# ══════════════════════════════════════════════════════════════
BASE_DIR          = Path(__file__).parent
ACCOUNTS_FILE     = BASE_DIR / "webshare_accounts.json"
REG_COOLDOWN_FILE = BASE_DIR / "webshare_reg_cooldown.json"

def load_accounts() -> dict:
    """
    Returns the accounts store.
    Structure:
      {
        "accounts": [...],          # legacy global pool (kept for compat)
        "user_accounts": {          # per-user accounts keyed by str(user_id)
          "123456": {"email":..., "token":..., ...}
        }
      }
    """
    if ACCOUNTS_FILE.exists():
        try:
            data = json.loads(ACCOUNTS_FILE.read_text(encoding="utf-8"))
            if "user_accounts" not in data:
                data["user_accounts"] = {}
            return data
        except Exception as exc:
            log.warning(f"[ACCOUNTS] Load failed: {exc}")
    return {"accounts": [], "user_accounts": {}}

def save_accounts(data: dict) -> None:
    ACCOUNTS_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
    ua = len(data.get("user_accounts", {}))
    log.debug(f"[ACCOUNTS] Saved {len(data.get('accounts', []))} global + {ua} user accounts")

def _reg_cooldown_until() -> float:
    """Returns UNIX timestamp until which registration is rate-limited (or 0 if clear)."""
    try:
        d = json.loads(REG_COOLDOWN_FILE.read_text(encoding="utf-8"))
        return float(d.get("until", 0))
    except Exception:
        return 0.0

def _set_reg_cooldown(seconds: int) -> None:
    until = time.time() + seconds + 10  # 10s buffer
    REG_COOLDOWN_FILE.write_text(json.dumps({"until": until}), encoding="utf-8")
    log.warning(f"[REG-COOLDOWN] Registration rate-limited for {seconds}s — until {time.ctime(until)}")

# ══════════════════════════════════════════════════════════════
#  Random credential generators
# ══════════════════════════════════════════════════════════════
def _gen_gmail_username() -> str:
    """Generate a human-looking Gmail username (no domain)."""
    first  = random.choice(_FIRST_NAMES)
    last   = random.choice(_LAST_NAMES)
    sep    = random.choice([".", "_", ""])
    suffix = random.choice(["", str(random.randint(1, 99)), str(random.randint(1970, 2005))])
    return f"{first}{sep}{last}{suffix}"

def gen_email() -> str:
    """Generate a human-looking gmail.com address."""
    return f"{_gen_gmail_username()}@gmail.com"

def gen_password() -> str:
    chars = (
        random.choices(string.ascii_uppercase, k=3)
        + random.choices(string.ascii_lowercase, k=random.randint(6, 8))
        + random.choices(string.digits, k=3)
        + random.choices("!@#$%^*()", k=2)
    )
    random.shuffle(chars)
    return "".join(chars)

# ══════════════════════════════════════════════════════════════
#  Gmail existence check
#  Google's MX server (aspmx.l.google.com:25) responds to
#  RCPT TO with 250 = exists, 550 = does not exist.
#  HTTP fallback: mail.google.com/mail/gxlu?email=
# ══════════════════════════════════════════════════════════════
import smtplib

def _smtp_check_gmail(email: str) -> bool | None:
    """
    Blocking SMTP check — run in a thread.
    Returns True (exists), False (doesn't exist), None (inconclusive / port blocked).
    """
    try:
        with smtplib.SMTP("aspmx.l.google.com", 25, timeout=3) as smtp:
            smtp.ehlo("check.example.com")
            smtp.mail("")
            code, msg = smtp.rcpt(str(email))
            log.debug(f"[GMAIL-SMTP] {email}: code={code} msg={msg[:80]}")
            return code == 250
    except (smtplib.SMTPConnectError, ConnectionRefusedError, OSError) as exc:
        # Port 25 blocked by ISP or firewall — inconclusive
        log.debug(f"[GMAIL-SMTP] Port 25 blocked/unavailable: {exc}")
        return None
    except smtplib.SMTPServerDisconnected as exc:
        log.debug(f"[GMAIL-SMTP] Server disconnected: {exc}")
        return None
    except Exception as exc:
        log.debug(f"[GMAIL-SMTP] Unexpected exception: {type(exc).__name__}: {exc}")
        return None

async def _http_check_gmail(session: AsyncSession, email: str) -> bool | None:
    """
    HTTP check via Google's gxlu endpoint.
    200 = account exists, 404 = doesn't exist, else inconclusive.
    """
    log.debug(f"[GMAIL-HTTP] Checking {email} via gxlu...")
    t0 = time.monotonic()
    try:
        resp = await session.get(
            "https://mail.google.com/mail/gxlu",
            params={"email": email},
            headers={
                "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                              "AppleWebKit/537.36 (KHTML, like Gecko) "
                              "Chrome/131.0.0.0 Safari/537.36",
                "Accept": "text/html,application/xhtml+xml,*/*",
            },
            allow_redirects=False,
            timeout=8,
        )
        elapsed = time.monotonic() - t0
        log.debug(f"[GMAIL-HTTP] {email}: status={resp.status_code} elapsed={elapsed:.2f}s")
        # 200/204 = account exists (204 = no content but confirmed)
        if resp.status_code in (200, 204):
            return True
        # 404 = account doesn't exist
        if resp.status_code == 404:
            return False
        # 302 redirect without location is often "exists" too
        if resp.status_code == 302:
            return True
        return None  # inconclusive
    except Exception as exc:
        log.debug(f"[GMAIL-HTTP] Exception: {exc}")
        return None

async def check_gmail_exists(session: AsyncSession, email: str) -> bool:
    """
    Verify a Gmail address is a real, active account.

    Strategy:
    1. SMTP RCPT TO query to aspmx.l.google.com:25 (most definitive)
    2. HTTP fallback via mail.google.com/mail/gxlu (if port 25 blocked)
    3. If both inconclusive → assume exists (try registration anyway)
    """
    log.info(f"[GMAIL-CHECK] Verifying {email}...")

    # SMTP check (run in thread to keep async loop unblocked)
    smtp_result = await asyncio.to_thread(_smtp_check_gmail, email)
    if smtp_result is not None:
        log.info(f"[GMAIL-CHECK] SMTP result for {email}: exists={smtp_result}")
        return smtp_result

    # HTTP fallback
    http_result = await _http_check_gmail(session, email)
    if http_result is not None:
        log.info(f"[GMAIL-CHECK] HTTP result for {email}: exists={http_result}")
        return http_result

    # Both inconclusive — optimistically assume exists, let webshare decide
    log.warning(f"[GMAIL-CHECK] Could not verify {email} — assuming exists")
    return True

async def find_valid_gmail(session: AsyncSession, max_tries: int = 20) -> str:
    """
    Generate Gmail usernames and return the first one that actually exists.
    Tries up to max_tries candidates.
    """
    for i in range(max_tries):
        candidate = f"{_gen_gmail_username()}@gmail.com"
        log.info(f"[GMAIL-FIND] Candidate {i+1}/{max_tries}: {candidate}")
        if await check_gmail_exists(session, candidate):
            log.info(f"[GMAIL-FIND] Found valid Gmail: {candidate}")
            return candidate
        log.info(f"[GMAIL-FIND] {candidate} does not exist — trying next")
        await asyncio.sleep(0.3)  # brief pause to avoid hammering Google

    # Exhausted candidates — fall back to random gmail (let webshare validate)
    fallback = gen_email()
    log.warning(f"[GMAIL-FIND] Exhausted {max_tries} candidates — using fallback {fallback}")
    return fallback


# ══════════════════════════════════════════════════════════════
#  HTTP Session
# ══════════════════════════════════════════════════════════════
def _make_session(proxy_url: str | None = None) -> AsyncSession:
    log.debug(f"[SESSION] AsyncSession impersonate={IMPERSONATE} proxy={proxy_url or 'direct'}")
    if proxy_url:
        return AsyncSession(
            impersonate=IMPERSONATE,
            proxies={"http": proxy_url, "https": proxy_url},
        )
    return AsyncSession(impersonate=IMPERSONATE)

# ══════════════════════════════════════════════════════════════
#  User-proxy helpers (proxy.json fallback for rate-limited reg)
# ══════════════════════════════════════════════════════════════
PROXY_JSON_FILE = BASE_DIR / "proxy.json"

def _proxy_dict_to_url(p: dict) -> str | None:
    """Convert a proxy dict {ip, port, username, password} to an http:// URL."""
    ip   = str(p.get("ip")       or "").strip()
    port = str(p.get("port")     or "").strip()
    user = str(p.get("username") or "").strip()
    pw   = str(p.get("password") or "").strip()
    if not ip or not port:
        return None
    if user and pw:
        # URL-encode special chars in credentials
        import urllib.parse
        return f"http://{urllib.parse.quote(user, safe='')}:{urllib.parse.quote(pw, safe='')}@{ip}:{port}"
    return f"http://{ip}:{port}"

def _load_all_user_proxies() -> list[str]:
    """
    Read proxy.json and return a deduplicated, shuffled list of proxy URLs
    (http://user:pass@ip:port) collected from ALL users' stored proxies.
    """
    try:
        data = json.loads(PROXY_JSON_FILE.read_text(encoding="utf-8"))
    except Exception as exc:
        log.debug(f"[PROXY-POOL] Could not read proxy.json: {exc}")
        return []

    seen: set[str] = set()
    urls: list[str] = []
    for uid, proxies in data.items():
        if not isinstance(proxies, list):
            continue
        for p in proxies:
            # normalise string format ip:port:user:pass → dict
            if isinstance(p, str):
                parts = p.strip().split(":")
                if len(parts) >= 4:
                    p = {"ip": parts[0], "port": parts[1], "username": parts[2], "password": parts[3]}
                elif len(parts) == 2:
                    p = {"ip": parts[0], "port": parts[1], "username": "", "password": ""}
                else:
                    continue
            if not isinstance(p, dict):
                continue
            url = _proxy_dict_to_url(p)
            if url and url not in seen:
                seen.add(url)
                urls.append(url)

    random.shuffle(urls)
    log.info(f"[PROXY-POOL] Loaded {len(urls)} unique user proxies from proxy.json")
    return urls

def _api_headers(token: str = "", referer: str = "https://proxy.webshare.io/register") -> dict:
    h = {
        "Accept":             "application/json, text/plain, */*",
        "Accept-Language":    "en-US,en;q=0.9",
        "Accept-Encoding":    "gzip, deflate, br, zstd",
        "Content-Type":       "application/json",
        "Origin":             "https://proxy.webshare.io",
        "Referer":            referer,
        "sec-ch-ua":          '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        "sec-ch-ua-mobile":   "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest":     "empty",
        "sec-fetch-mode":     "cors",
        "sec-fetch-site":     "same-origin",
    }
    if token:
        h["Authorization"] = f"Token {token}"
    return h

# ══════════════════════════════════════════════════════════════
#  NoPeCHA solver
# ══════════════════════════════════════════════════════════════
def _active_nopecha_key() -> str | None:
    """Return first key not in credit_exhausted or attempt_failed, or None."""
    for k in NOPECHA_KEYS:
        if k not in _credit_exhausted_keys and k not in _attempt_failed_keys:
            return k
    log.error("[NOPECHA] All keys exhausted for this solve attempt")
    return None

def _nopecha_auth(key: str) -> dict:
    return {
        "Authorization": f"Basic {key}",
        "Content-Type":  "application/json",
    }

async def _nopecha_check_key(session: AsyncSession, key: str) -> bool:
    """Return True if key is Active with credit > 0."""
    log.debug(f"[NOPECHA] GET {NOPECHA_URL}/status key={key[:20]}...")
    t0 = time.monotonic()
    try:
        resp = await session.get(
            f"{NOPECHA_URL}/status",
            headers=_nopecha_auth(key),
            timeout=10,
        )
        elapsed = time.monotonic() - t0
        log.debug(f"[NOPECHA] status={resp.status_code} elapsed={elapsed:.2f}s body={resp.text[:200]}")
        if resp.status_code == 200:
            data   = resp.json()
            active = data.get("status", "").lower() == "active"
            credit = data.get("credit", 0)
            log.info(f"[NOPECHA] key={key[:20]}... status={data.get('status')} credit={credit}")
            return active and credit > 0
    except Exception as exc:
        log.debug(f"[NOPECHA] status check exception: {exc}")
    return False

async def _nopecha_submit(session: AsyncSession, key: str) -> str | None:
    """Submit reCAPTCHA v2 job. Returns job_id or None. Marks key exhausted on code 16."""
    payload = {
        "sitekey": WEBSHARE_RECAPTCHA_SITEKEY,
        "url":     WEBSHARE_REGISTER_URL,
    }
    log.info(f"[NOPECHA] POST {NOPECHA_URL}/token/recaptcha2 | key={key[:20]}...")
    log.debug(f"[NOPECHA] payload={payload}")
    t0 = time.monotonic()
    try:
        resp = await session.post(
            f"{NOPECHA_URL}/token/recaptcha2",
            json=payload,
            headers=_nopecha_auth(key),
            timeout=15,
        )
        elapsed = time.monotonic() - t0
        log.debug(f"[NOPECHA] submit status={resp.status_code} elapsed={elapsed:.2f}s body={resp.text[:300]}")

        if resp.status_code == 200:
            data   = resp.json()
            job_id = data.get("data", "")
            if job_id:
                log.info(f"[NOPECHA] Job submitted: {job_id}")
                return str(job_id)
            log.error(f"[NOPECHA] No job_id in response: {data}")
            return None

        elif resp.status_code == 403:
            data = resp.json()
            code = data.get("code", 0)
            if code == 16:
                log.warning(f"[NOPECHA] key={key[:20]}... OUT OF CREDIT (code 16) — marking exhausted")
                _credit_exhausted_keys.add(key)
            else:
                log.warning(f"[NOPECHA] 403 code={code}: {data}")
        elif resp.status_code == 429:
            log.warning(f"[NOPECHA] 429 rate-limited on key={key[:20]}... — marking exhausted for now")
            _credit_exhausted_keys.add(key)
        else:
            log.warning(f"[NOPECHA] {resp.status_code}: {resp.text[:200]}")

    except Exception as exc:
        log.error(f"[NOPECHA] submit exception: {exc}")
    return None

async def _nopecha_poll(session: AsyncSession, key: str, job_id: str, max_wait: int = 40) -> str | None:
    """Poll for solved token. Returns token string or None."""
    log.info(f"[NOPECHA] Polling job={job_id} (max {max_wait}s)")
    deadline = time.monotonic() + max_wait
    interval = 4.0

    while time.monotonic() < deadline:
        await asyncio.sleep(interval)
        t0 = time.monotonic()
        try:
            resp = await session.get(
                f"{NOPECHA_URL}/token/recaptcha2",
                params={"id": job_id},
                headers=_nopecha_auth(key),
                timeout=15,
            )
            elapsed = time.monotonic() - t0
            log.debug(f"[NOPECHA] poll status={resp.status_code} elapsed={elapsed:.2f}s body={resp.text[:200]}")

            if resp.status_code == 200:
                data  = resp.json()
                token = data.get("data", "")
                if token and len(token) > 30:
                    log.info(f"[NOPECHA] Solved! token={token[:50]}...")
                    return token
                log.debug(f"[NOPECHA] Still processing job={job_id}")
                interval = min(interval * 1.10, 7.0)

            elif resp.status_code == 409:
                # Incomplete job — still being processed, keep waiting
                log.debug(f"[NOPECHA] 409 Incomplete job — still processing")
                interval = min(interval * 1.10, 7.0)

            elif resp.status_code == 403:
                code = resp.json().get("code", 0)
                if code == 16:
                    # Credit exhausted — mark key and abort poll
                    _credit_exhausted_keys.add(key)
                log.error(f"[NOPECHA] poll 403 code={code} — aborting poll")
                return None
            else:
                log.warning(f"[NOPECHA] poll {resp.status_code}: {resp.text[:100]}")
                interval = 6.0

        except Exception as exc:
            log.error(f"[NOPECHA] poll exception: {exc}")
            interval = 6.0

    # Timeout — don't mark key exhausted, just means this job was slow
    log.warning(f"[NOPECHA] Timeout polling job={job_id} — key still valid, try next key")
    return None

async def solve_via_nopecha(session: AsyncSession) -> str | None:
    """
    Try each available NoPeCHA key in order.
    Returns reCAPTCHA token or None if all keys fail.
    """
    for attempt in range(len(NOPECHA_KEYS)):
        key = _active_nopecha_key()
        if not key:
            break

        log.info(f"[NOPECHA] Using key={key[:20]}... (attempt {attempt+1})")
        job_id = await _nopecha_submit(session, key)
        if not job_id:
            # Only mark permanently exhausted if _nopecha_submit flagged it (code 16/429)
            # Otherwise just skip for this attempt
            if key not in _credit_exhausted_keys:
                log.warning(f"[NOPECHA] Submit failed on key={key[:20]}... — skipping for this attempt")
                _attempt_failed_keys.add(key)
            continue

        token = await _nopecha_poll(session, key, job_id)
        if token:
            return token

        # Poll failed (timeout or bad job) — don't exhaust the key unless it was a credit error
        # (credit errors are already marked inside _nopecha_poll/_nopecha_submit)
        log.warning(f"[NOPECHA] Poll returned no token on key={key[:20]}... — trying next key")
        _attempt_failed_keys.add(key)  # skip for this solve attempt only

    log.error("[NOPECHA] All keys exhausted or failed")
    return None

# ══════════════════════════════════════════════════════════════
#  Direct recaptcha.net bypass (free fallback, no solver)
# ══════════════════════════════════════════════════════════════
# Module-level version cache — api.js changes rarely; reuse across registrations
_rcaptcha_version:    str   = ""
_rcaptcha_version_ts: float = 0.0
_RCAPTCHA_VERSION_TTL = 3600.0  # 1 hour

async def _get_rcaptcha_version(session: AsyncSession) -> str | None:
    """
    Fetch and cache the reCAPTCHA version string from api.js.
    Returns the cached value if it was fetched within TTL.
    """
    global _rcaptcha_version, _rcaptcha_version_ts
    now = time.monotonic()
    if _rcaptcha_version and (now - _rcaptcha_version_ts) < _RCAPTCHA_VERSION_TTL:
        log.debug(f"[DIRECT] reCAPTCHA version from cache: {_rcaptcha_version}")
        return _rcaptcha_version

    base       = "https://www.recaptcha.net"
    sitekey    = WEBSHARE_RECAPTCHA_SITEKEY
    api_js_url = f"{base}/recaptcha/api.js?render={sitekey}"
    log.debug(f"[DIRECT] GET {api_js_url} (cache miss)")
    t0 = time.monotonic()
    try:
        resp = await session.get(
            api_js_url,
            headers={"Referer": WEBSHARE_REGISTER_URL},
            timeout=12,
        )
        elapsed = time.monotonic() - t0
        log.debug(f"[DIRECT] api.js status={resp.status_code} elapsed={elapsed:.2f}s len={len(resp.text)}")
        v_match = re.search(r"releases/([^/]+)/recaptcha", resp.text)
        if not v_match:
            log.warning("[DIRECT] Could not extract reCAPTCHA version from api.js")
            return None
        _rcaptcha_version    = v_match.group(1)
        _rcaptcha_version_ts = time.monotonic()
        log.info(f"[DIRECT] reCAPTCHA version={_rcaptcha_version} (cached for {_RCAPTCHA_VERSION_TTL/60:.0f}m)")
        return _rcaptcha_version
    except Exception as exc:
        log.error(f"[DIRECT] api.js exception: {exc}")
        return None

async def solve_via_direct(session: AsyncSession) -> str | None:
    """
    Bypass reCAPTCHA v2 invisible by talking directly to recaptcha.net:
      1. GET recaptcha api.js  → extract version (cached for 1h — free)
      2. GET anchor endpoint   → extract anchor token (c=)
      3. POST reload endpoint  → extract final rresp token
    This works for invisible reCAPTCHA on some sites without solver credits.
    """
    sitekey = WEBSHARE_RECAPTCHA_SITEKEY
    co      = WEBSHARE_RECAPTCHA_CO
    base    = "https://www.recaptcha.net"

    log.info("[DIRECT] Attempting direct recaptcha.net bypass...")

    # ── Step 1: Get reCAPTCHA version (cached) ─────────────────────────────────
    version = await _get_rcaptcha_version(session)
    if not version:
        return None

    # ── Step 2: Get anchor token ───────────────────────────────────────────────
    anchor_url = (
        f"{base}/recaptcha/api2/anchor"
        f"?ar=1&k={sitekey}&co={co}&hl=en&v={version}&size=invisible"
    )
    log.debug(f"[DIRECT] GET {anchor_url}")
    t0 = time.monotonic()
    try:
        resp = await session.get(
            anchor_url,
            headers={"Referer": WEBSHARE_REGISTER_URL},
            timeout=12,
        )
        elapsed = time.monotonic() - t0
        log.debug(f"[DIRECT] anchor status={resp.status_code} elapsed={elapsed:.2f}s len={len(resp.text)}")
        anchor_match = re.search(r'id="recaptcha-token"\s+value="([^"]+)"', resp.text)
        if not anchor_match:
            log.warning("[DIRECT] Could not extract anchor token from anchor page")
            log.debug(f"[DIRECT] anchor body preview: {resp.text[:400]}")
            return None
        anchor_token = anchor_match.group(1)
        log.info(f"[DIRECT] anchor_token={anchor_token[:40]}...")
    except Exception as exc:
        log.error(f"[DIRECT] anchor exception: {exc}")
        return None

    # ── Step 3: Get final rresp token ──────────────────────────────────────────
    reload_url = f"{base}/recaptcha/api2/reload?k={sitekey}"
    reload_data = {
        "v":    version,
        "reason": "q",
        "c":    anchor_token,
        "k":    sitekey,
        "co":   co,
        "hl":   "en",
        "size": "invisible",
        "chr":  "%5B89%2C64%2C27%5D",
        "vh":   "13599012192",
        "bg":   "",
    }
    log.debug(f"[DIRECT] POST {reload_url}")
    log.debug(f"[DIRECT] reload payload keys: {list(reload_data.keys())}")
    t0 = time.monotonic()
    try:
        resp = await session.post(
            reload_url,
            data=reload_data,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer":      anchor_url,
                "Origin":       base,
            },
            timeout=15,
        )
        elapsed = time.monotonic() - t0
        log.debug(f"[DIRECT] reload status={resp.status_code} elapsed={elapsed:.2f}s body={resp.text[:300]}")
        rr_match = re.search(r'\["rresp","([^"]+)"', resp.text)
        if rr_match:
            token = rr_match.group(1)
            log.info(f"[DIRECT] Got rresp token: {token[:50]}...")
            return token
        log.warning("[DIRECT] Could not find rresp token in reload response")
        log.debug(f"[DIRECT] reload body: {resp.text[:500]}")
    except Exception as exc:
        log.error(f"[DIRECT] reload exception: {exc}")

    return None

# ══════════════════════════════════════════════════════════════
#  Combined captcha solver — NoPeCHA only
#  (direct recaptcha.net bypass is disabled: webshare.io rejects
#   those rresp tokens server-side every time)
# ══════════════════════════════════════════════════════════════
async def solve_recaptcha(session: AsyncSession) -> str | None:
    """
    Solve webshare.io reCAPTCHA v2 invisible via NoPeCHA.

    NOTE: The free recaptcha.net direct bypass was removed — webshare.io
    validates tokens with Google server-side and rejects the rresp tokens
    produced by the api2/reload trick with code 'captcha_invalid'.
    NoPeCHA returns properly solved tokens that pass server-side validation.
    """
    log.info("[SOLVER] Starting reCAPTCHA solve via NoPeCHA...")
    active_key = _active_nopecha_key()
    if not active_key:
        log.error("[SOLVER] No NoPeCHA keys available — all exhausted or failed")
        return None

    token = await solve_via_nopecha(session)
    if token:
        log.info("[SOLVER] NoPeCHA succeeded")
        return token

    log.error("[SOLVER] NoPeCHA failed — no token available")
    return None

# ══════════════════════════════════════════════════════════════
#  webshare.io registration
# ══════════════════════════════════════════════════════════════
class _RateLimitedError(Exception):
    def __init__(self, wait_seconds: int):
        self.wait_seconds = wait_seconds
        super().__init__(f"Rate limited for {wait_seconds}s")

class _AlreadyRegisteredError(Exception):
    """webshare.io returned 'email already exists' — try a different email."""

class _SuspiciousEmailError(Exception):
    """webshare.io flagged the email as suspicious — try a different email."""

async def _register_once(
    session: AsyncSession,
    email: str,
    reg_proxy_url: str | None = None,
) -> dict | None:
    """
    Single registration attempt for a pre-validated email address.

    reg_proxy_url: when set, the Webshare registration POST is routed through
    this proxy (to dodge the VPS IP rate-limit). NoPeCHA and Gmail checks always
    use the direct session — proxies may block TLS to third-party APIs.
    """
    password = gen_password()

    log.info(f"[REGISTER] Solving reCAPTCHA for {email}...")
    recaptcha_token = await solve_recaptcha(session)   # always direct — no proxy
    if not recaptcha_token:
        log.error("[REGISTER] No captcha token — aborting attempt")
        return None

    payload = {
        "email":                    email,
        "password":                 password,
        "recaptcha":                recaptcha_token,
        "tos_accepted":             True,
        "marketing_email_accepted": False,
    }
    log.info(
        f"[REGISTER] POST {API_BASE}/register/ email={email}"
        + (f" via proxy {reg_proxy_url[:40]}..." if reg_proxy_url else "")
    )
    log.debug(f"[REGISTER] payload (password hidden): {dict(payload, password='****', recaptcha=recaptcha_token[:40]+'...')}")

    post_kwargs: dict = {
        "json":    payload,
        "headers": _api_headers(),
        "timeout": 25,
    }
    if reg_proxy_url:
        post_kwargs["proxies"] = {"http": reg_proxy_url, "https": reg_proxy_url}

    t0 = time.monotonic()
    try:
        resp = await session.post(
            f"{API_BASE}/register/",
            **post_kwargs,
        )
        elapsed = time.monotonic() - t0
        log.debug(f"[REGISTER] status={resp.status_code} elapsed={elapsed:.2f}s body={resp.text[:400]}")

        if resp.status_code in (200, 201):
            try:
                data = resp.json()
            except Exception:
                log.error(f"[REGISTER] Non-JSON: {resp.text[:200]}")
                return None
            token = data.get("token") or data.get("api_key") or data.get("key") or ""
            if not token:
                log.error(f"[REGISTER] No token in response: {data}")
                return None
            acc = {
                "email":         email,
                "password":      password,
                "token":         token,
                "registered_at": int(time.time()),
                "last_used":     0,
                "proxy_count":   0,
            }
            log.info(f"[REGISTER] OK: {email} token={token[:24]}...")
            return acc

        elif resp.status_code == 400:
            body = resp.text.lower()
            log.warning(f"[REGISTER] 400 validation: {resp.text[:400]}")
            if "already" in body or "exists" in body or "taken" in body:
                raise _AlreadyRegisteredError()
            if "suspicious" in body:
                raise _SuspiciousEmailError()
            if "recaptcha" in body:
                log.warning("[REGISTER] reCAPTCHA token rejected — solver token may be stale")
        elif resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After", "")
            wait = int(retry_after) if retry_after.isdigit() else 700
            _set_reg_cooldown(wait)
            # Don't retry — signal the caller with a special sentinel
            raise _RateLimitedError(wait)
        elif resp.status_code in (403, 503):
            log.warning(f"[REGISTER] {resp.status_code} (Cloudflare?) body={resp.text[:200]}")
        else:
            log.warning(f"[REGISTER] {resp.status_code} body={resp.text[:300]}")

    except (_RateLimitedError, _AlreadyRegisteredError, _SuspiciousEmailError):
        raise  # let register_account handle these specifically
    except Exception as exc:
        elapsed = time.monotonic() - t0
        log.error(f"[REGISTER] Exception {type(exc).__name__}: {exc} elapsed={elapsed:.2f}s")
    return None

async def register_account(
    session: AsyncSession,
    skip_cooldown: bool = False,
    proxy_url: str | None = None,
) -> dict | None:
    """
    Register a new webshare.io account.

    Flow per attempt:
    1. Find a valid Gmail (SMTP/HTTP verified to actually exist)
    2. Solve reCAPTCHA via NoPeCHA (key rotation) -> direct bypass fallback
    3. POST to /api/v2/register/
    4. If "already registered" or "suspicious" -> skip email, find next valid Gmail
    5. If 429 rate-limited -> save cooldown, abort immediately
    Retries up to MAX_REG_TRIES times total.

    skip_cooldown=True : bypass the IP-based rate-limit guard.
    proxy_url         : route only the Webshare registration POST through this proxy
                        (NoPeCHA / Gmail checks still use the direct session).

    Serialised by _REG_LOCK — only one registration runs at a time globally so
    concurrent /freeproxy calls don't flood NoPeCHA and exhaust all keys.
    """
    async with _get_reg_lock():
        # Re-check cooldown after waiting on the lock — a previous caller may
        # have just triggered a 429 and set the cooldown while we waited.
        if not skip_cooldown:
            cooldown_until = _reg_cooldown_until()
            if cooldown_until > time.time():
                remaining = int(cooldown_until - time.time())
                log.error(
                    f"[REGISTER] IP rate-limited — {remaining}s remaining "
                    f"(clears at {time.ctime(cooldown_until)})"
                )
                return None

        for attempt in range(1, MAX_REG_TRIES + 1):
            log.info(f"[REGISTER] Attempt {attempt}/{MAX_REG_TRIES}")
            _attempt_failed_keys.clear()  # safe: no concurrent registrations inside lock

            # Find a real, existing Gmail address (always direct — no proxy)
            email = await find_valid_gmail(session)

            try:
                acc = await _register_once(session, email, reg_proxy_url=proxy_url)
            except _RateLimitedError as rle:
                log.error(f"[REGISTER] 429 — aborting all retries (wait {rle.wait_seconds}s)")
                return None
            except (_AlreadyRegisteredError, _SuspiciousEmailError) as e:
                log.warning(f"[REGISTER] {email} rejected ({type(e).__name__}) — finding new Gmail")
                continue  # no backoff; immediately try a different email

            if acc:
                return acc

            if attempt < MAX_REG_TRIES:
                delay = attempt * 5 + random.uniform(2.0, 4.0)
                log.info(f"[REGISTER] Backoff {delay:.1f}s...")
                await asyncio.sleep(delay)

        log.error("[REGISTER] All attempts exhausted")
        return None

# ══════════════════════════════════════════════════════════════
#  Token validation
# ══════════════════════════════════════════════════════════════
async def validate_token(session: AsyncSession, token: str) -> bool:
    log.debug(f"[VALIDATE] token={token[:24]}...")
    t0 = time.monotonic()
    try:
        resp = await session.get(
            f"{API_BASE}/proxy/list/",
            params={"mode": "direct", "page": 1, "page_size": 1},
            headers=_api_headers(token, referer="https://proxy.webshare.io/proxy/list"),
            timeout=12,
        )
        elapsed = time.monotonic() - t0
        ok = resp.status_code == 200
        log.debug(f"[VALIDATE] status={resp.status_code} elapsed={elapsed:.2f}s valid={ok}")
        return ok
    except Exception as exc:
        log.debug(f"[VALIDATE] Exception: {exc}")
        return False

# ══════════════════════════════════════════════════════════════
#  Proxy fetching (JSON endpoint)
# ══════════════════════════════════════════════════════════════
async def fetch_proxies(session: AsyncSession, token: str, count: int = 10) -> list[str]:
    page_size = max(count, 25)
    url       = f"{API_BASE}/proxy/list/"
    log.info(f"[FETCH] GET {url} count={count} page_size={page_size} token={token[:24]}...")
    t0 = time.monotonic()
    try:
        resp = await session.get(
            url,
            params={"mode": "direct", "page": 1, "page_size": page_size},
            headers=_api_headers(token, referer="https://proxy.webshare.io/proxy/list"),
            timeout=20,
        )
        elapsed = time.monotonic() - t0
        log.debug(f"[FETCH] status={resp.status_code} elapsed={elapsed:.2f}s")
        if resp.status_code == 200:
            data    = resp.json()
            results = data.get("results", [])
            total   = data.get("count", len(results))
            log.info(f"[FETCH] {len(results)}/{total} results")
            proxies = []
            for idx, p in enumerate(results):
                user, pw   = p.get("username", ""), p.get("password", "")
                host, port = p.get("proxy_address", ""), p.get("port", 80)
                country    = p.get("country_code", "??")
                valid      = p.get("valid", True)
                log.debug(f"[PROXY #{idx+1:02d}] {country} {host}:{port} user={user} valid={valid}")
                if user and pw and host and port:
                    proxies.append(f"{host}:{port}:{user}:{pw}")
                if len(proxies) >= count:
                    break
            log.info(f"[FETCH] Built {len(proxies)} proxy strings (format: ip:port:user:pass)")
            return proxies
        elif resp.status_code == 401:
            log.warning("[FETCH] 401 — token expired")
        else:
            log.warning(f"[FETCH] {resp.status_code} body={resp.text[:300]}")
    except Exception as exc:
        log.error(f"[FETCH] Exception: {exc}")
    return []

# ══════════════════════════════════════════════════════════════
#  Download-token fallback
# ══════════════════════════════════════════════════════════════
async def fetch_proxies_download(session: AsyncSession, token: str, count: int = 10) -> list[str]:
    log.debug(f"[FETCH-DL] Getting download token from {API_BASE}/proxy/config/")
    t0 = time.monotonic()
    try:
        resp = await session.get(f"{API_BASE}/proxy/config/", headers=_api_headers(token), timeout=12)
        elapsed = time.monotonic() - t0
        log.debug(f"[FETCH-DL] config status={resp.status_code} elapsed={elapsed:.2f}s body={resp.text[:200]}")
        dl_token = (resp.json().get("proxy_list_download_token", "") if resp.status_code == 200 else "")
    except Exception as exc:
        log.error(f"[FETCH-DL] config exception: {exc}")
        return []

    if not dl_token:
        log.warning("[FETCH-DL] No download token")
        return []

    dl_url = f"{API_BASE}/proxy/list/download/{dl_token}/-/any/username/direct/-/"
    log.info(f"[FETCH-DL] GET {dl_url}")
    t0 = time.monotonic()
    try:
        resp = await session.get(dl_url, headers=_api_headers(token), timeout=20)
        elapsed = time.monotonic() - t0
        log.debug(f"[FETCH-DL] status={resp.status_code} elapsed={elapsed:.2f}s len={len(resp.text)}")
        if resp.status_code == 200:
            proxies = []
            for line in resp.text.splitlines():
                parts = line.strip().split(":")
                if len(parts) == 4:
                    ip, port, user, pw = parts
                    proxies.append(f"{ip}:{port}:{user}:{pw}")
                    if len(proxies) >= count:
                        break
            log.info(f"[FETCH-DL] Parsed {len(proxies)} proxies (format: ip:port:user:pass)")
            return proxies
    except Exception as exc:
        log.error(f"[FETCH-DL] Exception: {exc}")
    return []

# ══════════════════════════════════════════════════════════════
#  Main entry point
# ══════════════════════════════════════════════════════════════
async def _fetch_with_retry(
    session: AsyncSession, token: str, count: int, retries: int = 3, delay: float = 3.0
) -> list[str]:
    """Fetch proxies with retry — new accounts sometimes need a moment to populate."""
    for attempt in range(1, retries + 1):
        proxies = await fetch_proxies(session, token, count)
        if not proxies:
            proxies = await fetch_proxies_download(session, token, count)
        if proxies:
            return proxies
        if attempt < retries:
            log.info(f"[FETCH-RETRY] 0 proxies on attempt {attempt}/{retries} — waiting {delay}s")
            await asyncio.sleep(delay)
    return []


async def get_free_proxies(count: int = 10, user_id: int | None = None) -> list[str]:
    """
    Fetch `count` proxy strings (ip:port:user:pass) for a specific user.

    Flow:
    1. If user_id given — check for their personal account first (gives unique proxies).
    2. If no personal account or token invalid — register a fresh account for them.
    3. If IP rate-limited — fall back to their existing personal account (re-fetch) or
       any valid global pool account as last resort.

    Each user gets their own webshare account so proxy credentials are unique per user.
    """
    if _credit_exhausted_keys and _credit_exhausted_keys.issuperset(NOPECHA_KEYS):
        log.warning("[MAIN] All NoPeCHA keys credit-exhausted — resetting")
        _credit_exhausted_keys.clear()

    uid_key = str(user_id) if user_id else None
    log.info(f"[MAIN] get_free_proxies(count={count}, user_id={user_id})")

    accounts_data  = load_accounts()
    user_accounts  = accounts_data.setdefault("user_accounts", {})
    global_pool    = accounts_data.get("accounts", [])

    async with _make_session() as session:
        # ── Step 1: Try this user's personal account ───────────────────────────
        if uid_key and uid_key in user_accounts:
            acc   = user_accounts[uid_key]
            token = acc.get("token", "")
            email = acc.get("email", "?")
            log.info(f"[MAIN] Found personal account for user {uid_key}: {email}")
            if token and await validate_token(session, token):
                proxies = await _fetch_with_retry(session, token, count)
                if proxies:
                    acc["last_used"]   = int(time.time())
                    acc["proxy_count"] = len(proxies)
                    save_accounts(accounts_data)
                    log.info(f"[MAIN] OK: {len(proxies)} proxies from personal account {email}")
                    return proxies
                log.warning(f"[MAIN] Personal account {email} valid but returned 0 proxies — re-registering")
            else:
                log.warning(f"[MAIN] Personal account {email} token invalid — re-registering")

        # ── Step 2: Register a fresh account for this user ────────────────────
        cooldown_until = _reg_cooldown_until()
        if cooldown_until <= time.time():
            log.info(f"[MAIN] Registering fresh account for user {uid_key}...")
            new_acc = await register_account(session)
            # Another concurrent caller may have registered while we waited on
            # _REG_LOCK — re-load accounts and use their new account if present.
            if new_acc is None and uid_key:
                fresh = load_accounts().get("user_accounts", {}).get(uid_key)
                if fresh and fresh.get("token"):
                    log.info(f"[MAIN] Found account created by concurrent call — using it")
                    new_acc = fresh
            if new_acc:
                await asyncio.sleep(3.0)
                proxies = await _fetch_with_retry(session, new_acc["token"], count)
                new_acc["last_used"]   = int(time.time())
                new_acc["proxy_count"] = len(proxies)
                # Save as this user's personal account
                if uid_key:
                    user_accounts[uid_key] = new_acc
                else:
                    global_pool.append(new_acc)
                    accounts_data["accounts"] = global_pool[-20:]
                save_accounts(accounts_data)
                if proxies:
                    log.info(f"[MAIN] OK: {len(proxies)} proxies from new account {new_acc['email']}")
                    return proxies
                log.warning("[MAIN] Registered but 0 proxies — falling back to global pool")
        else:
            remaining = int(cooldown_until - time.time())
            log.warning(f"[MAIN] IP rate-limited for {remaining}s — attempting proxy-based registration")

            # ── Step 2b: Register through a random user proxy to dodge VPS IP ban ──
            # IMPORTANT: session (direct) is reused for NoPeCHA + Gmail so that
            # cheap HTTP proxies don't break TLS to third-party services.
            # The proxy is injected ONLY into the Webshare registration POST.
            user_proxy_urls = _load_all_user_proxies()
            if user_proxy_urls:
                max_proxy_attempts = min(5, len(user_proxy_urls))
                for attempt_idx, p_url in enumerate(user_proxy_urls[:max_proxy_attempts], 1):
                    log.info(
                        f"[MAIN] Proxy-reg attempt {attempt_idx}/{max_proxy_attempts}: "
                        f"{p_url[:50]}..."
                    )
                    try:
                        new_acc = await register_account(
                            session,
                            skip_cooldown=True,
                            proxy_url=p_url,
                        )
                        if new_acc:
                            await asyncio.sleep(3.0)
                            proxies = await _fetch_with_retry(session, new_acc["token"], count)
                            new_acc["last_used"]   = int(time.time())
                            new_acc["proxy_count"] = len(proxies)
                            if uid_key:
                                user_accounts[uid_key] = new_acc
                            else:
                                global_pool.append(new_acc)
                                accounts_data["accounts"] = global_pool[-20:]
                            save_accounts(accounts_data)
                            if proxies:
                                log.info(
                                    f"[MAIN] OK: {len(proxies)} proxies via proxy-reg "
                                    f"{new_acc['email']}"
                                )
                                return proxies
                            log.warning(
                                "[MAIN] Proxy-reg succeeded but 0 proxies — trying next proxy"
                            )
                    except Exception as pexc:
                        log.warning(
                            f"[MAIN] Proxy-reg attempt {attempt_idx} failed "
                            f"({type(pexc).__name__}: {pexc}) — trying next"
                        )
                log.warning("[MAIN] All proxy-reg attempts exhausted — falling back to pool")
            else:
                log.warning("[MAIN] No user proxies in proxy.json — falling back to pool")

        # ── Step 3: Fall back to any valid global pool account ─────────────────
        log.info(f"[MAIN] Trying {len(global_pool)} global pool accounts as fallback...")
        for idx, acc in enumerate(
            sorted(global_pool, key=lambda a: a.get("last_used", 0), reverse=True)
        ):
            token = acc.get("token", "")
            email = acc.get("email", "?")
            log.info(f"[MAIN] Trying pool account #{idx+1}: {email}")
            if not token:
                continue
            if not await validate_token(session, token):
                log.warning(f"[MAIN] {email} — token invalid, skipping")
                continue
            proxies = await _fetch_with_retry(session, token, count, retries=2, delay=2.0)
            if proxies:
                acc["last_used"]   = int(time.time())
                acc["proxy_count"] = len(proxies)
                save_accounts(accounts_data)
                log.info(f"[MAIN] OK: {len(proxies)} proxies from pool {email}")
                return proxies
            log.warning(f"[MAIN] {email} valid but 0 proxies")

    log.error("[MAIN] Failed to get any proxies")
    return []

# ══════════════════════════════════════════════════════════════
#  CLI test runner
# ══════════════════════════════════════════════════════════════
async def _cli_main():
    print()
    print("=" * 62)
    print("  webshare.io Automated Proxy Fetcher — Local Test")
    print("=" * 62)
    print(f"  NoPeCHA keys loaded: {len(NOPECHA_KEYS)}")
    for i, k in enumerate(NOPECHA_KEYS, 1):
        print(f"    {i}. {k[:20]}...")
    print(f"  reCAPTCHA sitekey : {WEBSHARE_RECAPTCHA_SITEKEY}")
    print(f"  recaptcha.net CO  : {WEBSHARE_RECAPTCHA_CO}")
    print()

    t0 = time.monotonic()
    proxies = await get_free_proxies(10)
    elapsed = time.monotonic() - t0

    print()
    print("=" * 62)
    if proxies:
        print(f"  OK: {len(proxies)} proxies in {elapsed:.1f}s\n")
        for i, p in enumerate(proxies, 1):
            print(f"  {i:2}. {p}")
    else:
        print(f"  FAIL: No proxies in {elapsed:.1f}s")
        print("  -> Check webshare_debug.log for details")
    print("=" * 62)
    print()

if __name__ == "__main__":
    asyncio.run(_cli_main())
