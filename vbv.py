"""Braintree VBV — hosted API (2D / 3D check)."""

from __future__ import annotations

import json
import logging
import re
import urllib.parse
from typing import Any

from curl_cffi import requests as curl_requests

logger = logging.getLogger(__name__)

VBV_API_URL = "https://ravenxkiller.site/vbv.php"
_HTTP_TIMEOUT = 60


def _normalize_cc_line(cc_str: str) -> str:
    parts = cc_str.replace("/", "|").split("|")
    if len(parts) < 4:
        raise ValueError("invalid_cc_format")
    cc, mm, yy, cvv = [p.strip() for p in parts[:4]]
    if len(yy) == 2:
        yy = "20" + yy[-2:]
    return f"{cc}|{mm.zfill(2)}|{yy}|{cvv}"


def check_card_str(cc_str: str, timeout: float = 55.0) -> tuple[str, str, str, dict[str, Any]]:
    """
    Call vbv.php?lista=cc|mm|yy|cvv

    Returns (api_status, api_message, code, dbg).
    code: passed | challenge_3d | rejected | error
    """
    try:
        lista = _normalize_cc_line(cc_str)
    except ValueError:
        return "Error", "invalid_cc_format", "bad_format", {}

    url = VBV_API_URL + "?" + urllib.parse.urlencode({"lista": lista})
    dbg: dict[str, Any] = {"lista": lista, "hosted_api": True}

    try:
        resp = curl_requests.get(
            url,
            impersonate="chrome120",
            timeout=min(float(timeout), _HTTP_TIMEOUT),
            verify=False,
        )
        dbg["http_status"] = resp.status_code
        text = (resp.text or "").strip()
    except Exception as e:
        logger.warning("vbv api failed: %s", e)
        return "Error", str(e)[:120], "connection_error", dbg

    if not text:
        return "Error", f"empty_response_http_{resp.status_code}", "empty", dbg

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        snippet = re.sub(r"\s+", " ", text)[:200]
        return "Error", snippet or "invalid_json", "bad_json", dbg

    if not isinstance(data, dict):
        return "Error", "invalid_api_response", "bad_json", dbg

    api_status = str(data.get("status") or "")
    api_message = str(data.get("message") or "")
    dbg["gate"] = data.get("gate")
    dbg["card"] = data.get("card")
    dbg["raw"] = data

    low_status = api_status.lower()
    low_msg = api_message.lower()

    if "passed" in low_status or "✅" in api_status:
        return api_status, api_message, "passed", dbg
    if "challenge" in low_msg or "3ds" in low_msg or "3d" in low_msg:
        return api_status, api_message, "challenge_3d", dbg
    if "rejected" in low_status or "❌" in api_status:
        return api_status, api_message, "rejected", dbg
    return api_status, api_message, "unclassified", dbg
