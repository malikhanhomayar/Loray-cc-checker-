"""
helpers.py — BIN Lookup, Proxy Parsing, Proxy Testing
"""

import re
import asyncio
import aiohttp
from cachetools import TTLCache

# ── BIN lookup cache (24hr, avoids hammering APIs for same BIN) ───────────────
_bin_lookup_cache: TTLCache = TTLCache(maxsize=5000, ttl=86400)

# ── Browser-like headers (required by BIN APIs to not block us) ───────────────
_DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
    "Accept": "application/json, text/plain, */*",
    "Accept-Language": "en-US,en;q=0.9",
}

# ── Shared aiohttp session (proxy tests, general use) ────────────────────────
_session: aiohttp.ClientSession | None = None

async def get_session() -> aiohttp.ClientSession:
    global _session
    if _session is None or _session.closed:
        _session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=300, ssl=False),
            timeout=aiohttp.ClientTimeout(total=15),
            headers=_DEFAULT_HEADERS,
        )
    return _session

# ── Dedicated BIN lookup session (never starved by proxy/checker traffic) ─────
_bin_session: aiohttp.ClientSession | None = None

async def _get_bin_session() -> aiohttp.ClientSession:
    global _bin_session
    if _bin_session is None or _bin_session.closed:
        _bin_session = aiohttp.ClientSession(
            connector=aiohttp.TCPConnector(limit=80, ssl=False),
            timeout=aiohttp.ClientTimeout(total=10),
            headers=_DEFAULT_HEADERS,
        )
    return _bin_session

async def close_session():
    global _session, _bin_session
    if _session and not _session.closed:
        await _session.close()
        _session = None
    if _bin_session and not _bin_session.closed:
        await _bin_session.close()
        _bin_session = None

async def bin_lookup(bin_number: str) -> dict:
    """
    Lookup BIN info via 3 APIs in parallel, first success wins immediately.
    Uses a dedicated session so checker/proxy traffic can't starve it.
    """
    _FALLBACK = {"brand": "-", "type": "-", "level": "-", "bank": "-", "country": "-", "flag": "🏳️"}

    bin_number = bin_number.strip().replace(" ", "")[:6]
    if len(bin_number) < 6:
        return _FALLBACK

    if bin_number in _bin_lookup_cache:
        return _bin_lookup_cache[bin_number]

    session = await _get_bin_session()
    _t = aiohttp.ClientTimeout(total=8)

    async def _try_antipublic():
        async with session.get(
            f"https://bins.antipublic.cc/bins/{bin_number}", timeout=_t
        ) as res:
            if res.status == 200:
                data = await res.json(content_type=None)
                if isinstance(data, dict) and data.get('brand'):
                    return {
                        "brand": data.get('brand', '-') or '-',
                        "type": data.get('type', '-') or '-',
                        "level": data.get('level', '-') or '-',
                        "bank": data.get('bank', '-') or '-',
                        "country": data.get('country_name', '-') or '-',
                        "flag": data.get('country_flag', '🏳️') or '🏳️',
                    }

    async def _try_hexunit():
        async with session.get(
            f"https://bin.hex-unit.com/{bin_number}", timeout=_t
        ) as res:
            if res.status == 200:
                data = await res.json(content_type=None)
                if isinstance(data, dict) and data.get('brand'):
                    return {
                        "brand": data.get('brand', '-') or '-',
                        "type": data.get('type', '-') or '-',
                        "level": data.get('level', '-') or '-',
                        "bank": data.get('bank', '-') or '-',
                        "country": data.get('country_name', '-') or '-',
                        "flag": data.get('country_flag', '🏳️') or '🏳️',
                    }

    async def _try_binlist():
        async with session.get(
            f"https://lookup.binlist.net/{bin_number}",
            headers={"Accept-Version": "3"}, timeout=_t
        ) as res:
            if res.status == 200:
                data = await res.json(content_type=None)
                if isinstance(data, dict):
                    return {
                        "brand": (data.get('scheme') or '-').upper(),
                        "type": (data.get('type') or '-').upper(),
                        "level": (data.get('brand') or '-'),
                        "bank": (data.get('bank') or {}).get('name', '-') or '-',
                        "country": (data.get('country') or {}).get('name', '-') or '-',
                        "flag": (data.get('country') or {}).get('emoji', '🏳️') or '🏳️',
                    }

    # Fire all 3, return as soon as the FIRST one succeeds — cancel the rest
    tasks = [
        asyncio.create_task(_try_antipublic()),
        asyncio.create_task(_try_hexunit()),
        asyncio.create_task(_try_binlist()),
    ]
    try:
        done = set()
        pending = set(tasks)
        while pending:
            finished, pending = await asyncio.wait(
                pending, return_when=asyncio.FIRST_COMPLETED
            )
            for t in finished:
                done.add(t)
                try:
                    r = t.result()
                    if r:
                        _bin_lookup_cache[bin_number] = r
                        return r
                except Exception:
                    pass
    finally:
        for t in tasks:
            if not t.done():
                t.cancel()

    return _FALLBACK


# ══════════════════════════════════════════════════════════════════════════════
#  PROXY FORMAT PARSER
# ══════════════════════════════════════════════════════════════════════════════

def parse_proxy_format(proxy: str) -> dict | None:
    """
    Parse many proxy formats into a normalised dict.
    Supports: socks5://user:pass@host:port, host:port:user:pass,
              user:pass@host:port, host:port, etc.
    Returns {ip, port, username, password, proxy_url, type} or None.
    """
    proxy = proxy.strip().strip("`'\"")
    if not proxy:
        return None

    proxy_type = 'http'

    protocol_match = re.match(r'^(socks5|socks4|http|https)://(.+)$', proxy, re.IGNORECASE)
    if protocol_match:
        proxy_type = protocol_match.group(1).lower()
        proxy = protocol_match.group(2)

    host = ''
    port = ''
    username = ''
    password = ''

    # Format: username:password@host:port
    match = re.match(r'^([^@:]+):([^@]+)@([^:@]+):(\d+)$', proxy)
    if match:
        username, password, host, port = match.groups()

    # Format: host:port@username:password
    elif re.match(r'^([a-zA-Z0-9.\-]+):(\d+)@([^:]+):(.+)$', proxy):
        match = re.match(r'^([a-zA-Z0-9.\-]+):(\d+)@([^:]+):(.+)$', proxy)
        host, port, username, password = match.groups()

    # Format: host:port:username:password
    elif re.match(r'^([^:]+):(\d+):([^:]+):(.+)$', proxy):
        match = re.match(r'^([^:]+):(\d+):([^:]+):(.+)$', proxy)
        potential_host, potential_port, potential_user, potential_pass = match.groups()
        if 0 < int(potential_port) <= 65535:
            host, port, username, password = potential_host, potential_port, potential_user, potential_pass

    # Format: host:port
    elif re.match(r'^([^:@]+):(\d+)$', proxy):
        match = re.match(r'^([^:@]+):(\d+)$', proxy)
        host, port = match.groups()

    # Fallback: last @ wins
    elif '@' in proxy:
        at_pos = proxy.rfind('@')
        auth_part = proxy[:at_pos]
        host_part = proxy[at_pos + 1:]
        host_parts = host_part.split(':')
        if len(host_parts) >= 2:
            host = host_parts[0]
            port = host_parts[1]
            auth_parts = auth_part.split(':', 1)
            if len(auth_parts) == 2:
                username, password = auth_parts
    else:
        return None

    if not host or not port:
        return None
    try:
        port_num = int(port)
        if port_num <= 0 or port_num > 65535:
            return None
    except ValueError:
        return None

    # Build proxy URL
    if username and password:
        if proxy_type in ['socks5', 'socks4']:
            proxy_url = f'{proxy_type}://{username}:{password}@{host}:{port}'
        else:
            proxy_url = f'http://{username}:{password}@{host}:{port}'
    else:
        if proxy_type in ['socks5', 'socks4']:
            proxy_url = f'{proxy_type}://{host}:{port}'
        else:
            proxy_url = f'http://{host}:{port}'

    return {
        'ip': host,
        'port': port,
        'username': username if username else None,
        'password': password if password else None,
        'proxy_url': proxy_url,
        'type': proxy_type
    }


def proxy_dict_to_url(proxy_data: dict | None) -> str | None:
    """Convert a parsed proxy dict (from proxy.json) to a curl/requests proxy URL."""
    if not proxy_data:
        return None
    if isinstance(proxy_data, str):
        return proxy_data.strip() or None

    existing = proxy_data.get("proxy_url")
    if existing and isinstance(existing, str) and existing.strip():
        return existing.strip()

    ip = str(proxy_data.get("ip") or "").strip()
    port = str(proxy_data.get("port") or "").strip()
    user = proxy_data.get("username")
    pw = proxy_data.get("password")
    ptype = (proxy_data.get("type") or "http").lower()
    if not ip or not port:
        return None
    if ptype == "https":
        ptype = "http"
    from urllib.parse import quote
    if user and pw:
        auth = f"{quote(str(user), safe='')}:{quote(str(pw), safe='')}"
        return f"{ptype}://{auth}@{ip}:{port}"
    return f"{ptype}://{ip}:{port}"


def proxy_dict_to_requests(proxy_data: dict | None) -> dict[str, str] | None:
    """Convert a parsed proxy dict to requests/curl proxies format."""
    url = proxy_dict_to_url(proxy_data)
    if not url:
        return None
    return {"http": url, "https": url}


# ══════════════════════════════════════════════════════════════════════════════
#  PROXY CONNECTIVITY TEST
# ══════════════════════════════════════════════════════════════════════════════

async def test_proxy(proxy_url: str) -> tuple:
    """
    Test if proxy is working and detect rotating vs static.
    Returns (True, ip, 'Rotating'|'Static') or (False, error_str, None).
    """
    try:
        session = await get_session()
        proxy_timeout = aiohttp.ClientTimeout(total=15)
        # First request
        async with session.get('http://api.ipify.org?format=json', proxy=proxy_url, timeout=proxy_timeout) as res:
            if res.status != 200:
                return False, f"HTTP {res.status}", None
            data = await res.json()
            ip1 = data.get('ip', 'Unknown')
        # Second request to detect rotation
        try:
            async with session.get('http://api.ipify.org?format=json', proxy=proxy_url, timeout=proxy_timeout) as res2:
                if res2.status == 200:
                    data2 = await res2.json()
                    ip2 = data2.get('ip', 'Unknown')
                    rotation = 'Rotating' if ip1 != ip2 else 'Static'
                else:
                    rotation = 'Static'
        except Exception:
            rotation = 'Static'
        return True, ip1, rotation
    except Exception as e:
        return False, str(e), None


# ══════════════════════════════════════════════════════════════════════════════
#  CC REGEX EXTRACTOR
# ══════════════════════════════════════════════════════════════════════════════

CC_PATTERN = re.compile(
    r'(\d{15,16})\s*[|/]\s*(\d{1,2})\s*[|/]\s*(\d{2,4})\s*[|/]\s*(\d{3,4})'
)

def extract_cc(text: str) -> str | None:
    """Extract a CC in format number|mm|yy|cvv from text. Returns pipe-separated string or None."""
    m = CC_PATTERN.search(text)
    if m:
        return f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
    return None


# ══════════════════════════════════════════════════════════════════════════════
#  GATE OUTCOME CLASSIFICATION (bt1 / st1 / shopify-style responses)
# ══════════════════════════════════════════════════════════════════════════════

_GATE_ERROR_CODES = frozenset({
    "proxy_error", "connection_error", "timeout", "captcha_required", "cart_fail",
    "bt_token_fail", "upstream_5xx", "exception", "bad_json", "empty", "failed",
})

_GATE_CHARGED_SIGNALS = (
    "charged",
    "payment success",
    "payment successful",
    "payment complete",
    "payment completed",
    "order success",
    "order successful",
    "order completed",
    "order placed",
    "order_placed",
    "order received",
    "order confirmed",
    "processedreceipt",
    "successfulreceipt",
    "thank you for your order",
    "thank you",
    "transaction successful",
    "successfully charged",
    "captured",
    "authorized",
    "woocommerce_order",
    '"success":true',
    '"success": true',
    '"result":"success"',
    "result\":\"success\"",
    "checkout success",
    "payment_id",
    "order_id",
    "razorpay_payment_id",
)

_GATE_CCN_SIGNALS = (
    "incorrect cvv",
    "incorrect cvc",
    "invalid cvv",
    "invalid cvc",
    "invalid security",
    "security code",
    "card security code",
    "cvv mismatch",
    "cvc mismatch",
    "wrong cvv",
    "wrong cvc",
    "ccn",
    "incorrect_cvc",
    "invalid_cvc",
    "verification number",
)

_GATE_LIMIT_SIGNALS = (
    "insufficient",
    "insufficient funds",
    "not enough fund",
    "balance",
    "limit exceeded",
    "maximum transaction",
    "over limit",
    "exceeds limit",
    "account balance",
)

_GATE_3DS_SIGNALS = (
    "3ds",
    "3d secure",
    "requires_action",
    "authentication required",
    "challenge_required",
    "challenge required",
    "otp",
    "verify your card",
)

_GATE_DECLINED_SIGNALS = (
    "declined",
    "rejected",
    "denied",
    "do not honour",
    "pick up",
    "lost card",
    "stolen",
    "expired card",
    "fraud",
    "not permitted",
    "restricted card",
)


def classify_gate_response(
    text: str = "",
    status_hint: str = "",
    code_hint: str = "",
) -> tuple[str, str, str]:
    """
    Normalize any gate response to (status, message, code).
    status: charged | approved | declined | error
    """
    raw_msg = (text or "").strip()
    if len(raw_msg) > 300:
        raw_msg = raw_msg[:300]
    low = f"{raw_msg} {status_hint} {code_hint}".lower()
    out_msg = raw_msg[:120] if raw_msg else (code_hint or status_hint or "")[:120]

    cd = (code_hint or "").lower()
    st = (status_hint or "").lower()

    if cd in _GATE_ERROR_CODES or st == "error":
        return "error", out_msg, cd or "error"

    if any(k in low for k in ("proxy dead", "proxy error", "tunnel", "connection refused", "connection error")):
        return "error", out_msg, "proxy_error"
    if "timed out" in low or "timeout" in low and "challenge" not in low:
        return "error", out_msg, "timeout"

    if st == "charged" or cd == "charged":
        return "charged", out_msg or "Charged", "charged"

    if any(sig in low for sig in _GATE_CHARGED_SIGNALS):
        if not any(x in low for x in ("declined", "rejected", "failed", "unsuccessful", "not success", "was not")):
            return "charged", out_msg or "Payment / order success", "charged"

    if cd in ("ccn", "cvv_approved") or any(sig in low for sig in _GATE_CCN_SIGNALS):
        return "approved", out_msg or "CCN / CVV", "ccn"

    if cd in ("live_limit",) or any(sig in low for sig in _GATE_LIMIT_SIGNALS):
        return "approved", out_msg or "Insufficient / limit", "live_limit"

    if cd in ("3ds", "3ds_required", "challenge_3d", "3ds_or_otp") or any(sig in low for sig in _GATE_3DS_SIGNALS):
        if "passed" not in low and "authenticate_successful" not in low:
            return "approved", out_msg or "3DS / OTP", "3ds"

    if st == "approved" or cd == "approved":
        return "approved", out_msg or "Approved", "approved"

    if cd == "declined" or st == "declined" or any(sig in low for sig in _GATE_DECLINED_SIGNALS):
        return "declined", out_msg or "Declined", "declined"

    if "success" in low and any(k in low for k in ("payment", "order", "checkout", "complete", "approved")):
        return "charged", out_msg or "Success", "charged"

    return "declined", out_msg or "declined", "declined"


def gate_is_charged(status: str, code: str, msg: str = "") -> bool:
    st, _, _ = classify_gate_response(msg, status_hint=status, code_hint=code)
    return st == "charged"


def gate_is_approved(status: str, code: str, msg: str = "") -> bool:
    st, _, _ = classify_gate_response(msg, status_hint=status, code_hint=code)
    return st == "approved"
