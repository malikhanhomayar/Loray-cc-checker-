import re
import json
import base64
import requests
from datetime import datetime
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# ---------- Adyen API Endpoints ----------
ADYEN_CLIENT_KEY_URL = "https://checkoutshopper-live.adyen.com/checkoutshopper/v1/clientKeys"
ADYEN_PAYMENT_URL = "https://checkoutshopper-live.adyen.com/checkoutshopper/v1/payments"
ADYEN_SESSIONS_URL = "https://checkoutshopper-live.adyen.com/checkoutshopper/v1/sessions"
ADYEN_VERSION = "v71"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

# ---------- Helper Functions ----------
def _extract_session_id(url: str) -> str:
    """Extracts session ID from a given Adyen checkout or payment link."""
    # Patterns: .../sessions/?..., .../payments//...
    patterns = [
        r'/sessions/([A-Za-z0-9_\-]+)',
        r'/payments/([A-Za-z0-9_\-]+)',
        r'sessionId=([A-Za-z0-9_\-]+)',
    ]
    for pat in patterns:
        match = re.search(pat, url)
        if match:
            return match.group(1)
    raise ValueError(f"Could not extract session ID from URL: {url}")

def _fetch_public_key(session: requests.Session, proxy: dict = None) -> str:
    """Gets Adyen's public key for client-side encryption."""
    resp = session.post(ADYEN_CLIENT_KEY_URL, json={"version": ADYEN_VERSION}, proxies=proxy, timeout=15)
    resp.raise_for_status()
    return resp.json()["publicKey"]

def _encrypt_card_data(cc: str, exp_month: str, exp_year: str, cvc: str, public_key_str: str) -> dict:
    """
    Encrypts card details using Adyen's client-side encryption method.
    Returns a dict with encryptedCardNumber, encryptedExpiryMonth, encryptedExpiryYear, encryptedSecurityCode.
    """
    # Load public key
    public_key = serialization.load_pem_public_key(public_key_str.encode(), backend=default_backend())

    def encrypt_field(value: str) -> str:
        ciphertext = public_key.encrypt(
            value.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(ciphertext).decode()

    return {
        "encryptedCardNumber": encrypt_field(cc.replace(" ", "")),
        "encryptedExpiryMonth": encrypt_field(exp_month.zfill(2)),
        "encryptedExpiryYear": encrypt_field(exp_year[-2:]),
        "encryptedSecurityCode": encrypt_field(cvc),
    }

def _parse_cc(cc_str: str) -> tuple:
    """Parses cc string like '4000000000000000|12|2025|123' into components."""
    parts = cc_str.split("|")
    if len(parts) != 4:
        raise ValueError("Invalid CC format. Use: number|MM|YYYY|CVV")
    return parts[0].strip(), parts[1].strip(), parts[2].strip(), parts[3].strip()

def _build_payment_request(session_id: str, encrypted_data: dict, browser_info: dict = None) -> dict:
    """Constructs the payment completion request body."""
    payload = {
        "sessionId": session_id,
        "paymentMethod": {
            "type": "scheme",
            **encrypted_data,
            "holderName": "John Doe"
        },
        "browserInfo": browser_info or {
            "userAgent": USER_AGENT,
            "acceptHeader": "*/*",
            "language": "en-US",
            "colorDepth": 24,
            "screenHeight": 1080,
            "screenWidth": 1920,
            "timeZoneOffset": -60,
            "javaEnabled": True
        }
    }
    return payload

# ---------- Main Function ----------
async def process_payment(adyen_link: str, cc_str: str, proxy: dict = None) -> dict:
    """
    Completes an Adyen payment session using the given card details and proxy.
    Args:
        adyen_link: Full Adyen checkout URL (contains sessionId).
        cc_str: Card details in format "number|MM|YYYY|CVV".
        proxy: Dict with proxy settings, e.g. {"http": "http://user:pass@ip:port", "https": ...}
    Returns:
        dict: Either {'status': 'approved', 'response': gateway_response} or {'error': '...'}
    """
    try:
        # 1. Extract session ID
        session_id = _extract_session_id(adyen_link)

        # 2. Create a requests Session for cookie persistence
        sess = requests.Session()
        sess.headers.update({"User-Agent": USER_AGENT})

        # 3. Fetch Adyen public key
        pub_key = _fetch_public_key(sess, proxy)

        # 4. Parse card data and encrypt
        cc_num, exp_mm, exp_yy, cvc = _parse_cc(cc_str)
        encrypted = _encrypt_card_data(cc_num, exp_mm, exp_yy, cvc, pub_key)

        # 5. Build and send payment request
        payload = _build_payment_request(session_id, encrypted)
        resp = sess.post(
            ADYEN_PAYMENT_URL,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "Origin": "https://checkoutshopper-live.adyen.com",
                "Referer": adyen_link
            },
            proxies=proxy,
            timeout=30
        )
        resp_json = resp.json()

        # 6. Interpret response
        if resp.status_code in (200, 201, 202):
            result_code = resp_json.get("resultCode", "Unknown")
            refusal_reason = resp_json.get("refusalReason", "")
            # Classify response
            if result_code == "Authorised":
                return {"status": "approved", "response": "Authorised", "cc": cc_str}
            elif result_code == "Refused":
                return {"status": "declined", "response": refusal_reason or "Refused", "cc": cc_str}
            else:
                return {"status": result_code.lower(), "response": resp_json.get("message", ""), "cc": cc_str}
        else:
            error_msg = resp_json.get("message", f"HTTP {resp.status_code}")
            return {"error": error_msg[:100], "cc": cc_str}

    except Exception as e:
        return {"error": str(e)[:100], "cc": cc_str}
