"""
checker_bridge.py — Async HTTP load balancer across VPS checker nodes.

Each node runs sh_checker.py (aiohttp.web on :8181) with gunicorn async workers.
Routing uses least-connections + circuit-breaker; every request is retried on
the next healthy node on failure — nothing is dropped while any node lives.

Node specs: 8 CPU cores, 32 GB RAM → 16 gunicorn workers each → 96 total workers
across 6 nodes.  Handles 2 000+ users; /ran fires 100 parallel requests spread
evenly across all 6 nodes.

Active nodes (6):
  2.25.68.50 | 2.25.68.55 | 187.77.137.114
  187.127.214.93 | 187.127.214.92
"""

import asyncio
import aiohttp
import time
import logging
from urllib.parse import quote as _urlquote

log = logging.getLogger("checker_bridge")
log.setLevel(logging.DEBUG)

# ── Node list (6 nodes × 16 workers = 96 total async workers) ────────────────
NODES = [
    "http://2.25.68.50:8181",
    "http://2.25.68.55:8181",
    "http://187.77.137.114:8181",
    "http://187.127.214.93:8181",
    "http://187.127.214.92:8181",
]

# ── Manually disabled nodes (via /api command) ────────────────────────────────
_disabled_nodes: set = set()

# ── Per-node runtime state ────────────────────────────────────────────────────
_state: dict = {
    url: {
        "in_flight":    0,
        "consec_fails": 0,
        "healthy":      True,
        "unhealthy_at": 0.0,
        "avg_ms":       3000.0,
        "total_ok":     0,
    }
    for url in NODES
}

# Circuit breaker: only real node errors open the circuit, NOT proxy-side failures
_CIRCUIT_FAIL_THRESHOLD = 5        # more lenient — proxy burns ≠ node down
_CIRCUIT_RESET_SECS     = 20.0     # fast recovery
_REQUEST_TIMEOUT        = 120      # per-check hard cap (reduced from 240)
_CONNECT_TIMEOUT        = 5
_HEALTH_PING_INTERVAL   = 15

# Responses that mean proxy is burned — don't penalise the node for these
_PROXY_BURNED_INDICATORS = (
    "proxy burned", "change your proxy", "proxy error",
    "authentication failed", "could not connect",
)

# ── Persistent aiohttp session ────────────────────────────────────────────────
_session: aiohttp.ClientSession | None = None

async def _get_session() -> aiohttp.ClientSession:
    global _session
    if _session is None or _session.closed:
        conn = aiohttp.TCPConnector(
            limit=8000,           # total concurrent connections across all nodes
            limit_per_host=2000,  # per node — 32 workers × many concurrent checks
            ttl_dns_cache=300,
            keepalive_timeout=60,
            enable_cleanup_closed=True,
        )
        _session = aiohttp.ClientSession(
            connector=conn,
            timeout=aiohttp.ClientTimeout(
                total=_REQUEST_TIMEOUT,
                connect=_CONNECT_TIMEOUT,
            ),
        )
    return _session


# ── Circuit-breaker helpers ───────────────────────────────────────────────────

def _maybe_reset(url: str) -> None:
    s = _state[url]
    if not s["healthy"] and (time.monotonic() - s["unhealthy_at"]) >= _CIRCUIT_RESET_SECS:
        s["healthy"] = True
        s["consec_fails"] = 0
        log.info(f"[lb] circuit RESET → {url}")


def _pick_node(exclude: set | None = None) -> str | None:
    exclude = exclude or set()
    for url in _state:
        _maybe_reset(url)

    cands  = [(u, s) for u, s in _state.items()
              if u not in exclude and u not in _disabled_nodes]
    if not cands:
        return None
    healthy = [(u, s) for u, s in cands if s["healthy"]]
    pool    = healthy if healthy else cands
    # primary: fewest in-flight  |  tiebreak: fastest recent response
    pool.sort(key=lambda x: (x[1]["in_flight"], x[1]["avg_ms"]))
    return pool[0][0]


# ── Single node HTTP call ─────────────────────────────────────────────────────

async def _call_node(node: str, cc: str, proxy: str, site: str) -> dict:
    s    = _state[node]
    t0   = time.monotonic()
    cc4  = cc.split("|")[0][-4:] if "|" in cc else cc[-4:]
    s["in_flight"] += 1
    log.debug(f"[lb] → {node} | cc=...{cc4} | in_flight={s['in_flight']} | proxy={proxy[:30]}...")
    try:
        sess   = await _get_session()
        # site omitted — sh_checker.py fetches it from UCP MCP automatically
        params = {"cc": cc, "proxy": proxy}

        async with sess.get(
            f"{node}/check",
            params=params,
            timeout=aiohttp.ClientTimeout(
                total=_REQUEST_TIMEOUT, connect=_CONNECT_TIMEOUT,
            ),
        ) as resp:
            if resp.status != 200:
                raise RuntimeError(f"HTTP {resp.status}")
            data = await resp.json(content_type=None)

        elapsed           = (time.monotonic() - t0) * 1000
        s["consec_fails"] = 0
        s["healthy"]      = True
        s["avg_ms"]       = 0.75 * s["avg_ms"] + 0.25 * elapsed
        s["total_ok"]    += 1
        log.debug(f"[lb] ✓ {node} | {elapsed:.0f}ms | resp={str(data.get('Response',''))[:60]}")
        return data

    except (asyncio.TimeoutError, TimeoutError) as e:
        elapsed = (time.monotonic() - t0) * 1000
        # Timeout when bridge→node times out = node overloaded/down, count as node fail
        s["consec_fails"] += 1
        log.warning(f"[lb] TIMEOUT {node} | {elapsed:.0f}ms | fails={s['consec_fails']}")
        if s["consec_fails"] >= _CIRCUIT_FAIL_THRESHOLD:
            s["healthy"] = False
            s["unhealthy_at"] = time.monotonic()
            log.warning(f"[lb] OPEN (timeout) → {node}")
        raise

    except Exception as e:
        elapsed  = (time.monotonic() - t0) * 1000
        err_str  = str(e)[:80]
        err_type = type(e).__name__
        # Don't open circuit if the node responded OK but the user's proxy was burned
        proxy_side = any(ind in err_str.lower() for ind in _PROXY_BURNED_INDICATORS)
        if not proxy_side:
            s["consec_fails"] += 1
            if s["consec_fails"] >= _CIRCUIT_FAIL_THRESHOLD:
                s["healthy"] = False
                s["unhealthy_at"] = time.monotonic()
                log.warning(f"[lb] OPEN ({err_type}) → {node}")
        log.warning(f"[lb] ERROR {node} | {elapsed:.0f}ms | {err_type}: {err_str} | proxy_side={proxy_side}")
        raise

    finally:
        s["in_flight"] = max(0, s["in_flight"] - 1)


# ── Background health pinger ──────────────────────────────────────────────────

async def _health_loop() -> None:
    while True:
        await asyncio.sleep(_HEALTH_PING_INTERVAL)
        for url in list(_state):
            try:
                sess = await _get_session()
                async with sess.get(
                    f"{url}/health",
                    timeout=aiohttp.ClientTimeout(total=6, connect=4),
                ) as r:
                    if r.status == 200:
                        if not _state[url]["healthy"]:
                            log.info(f"[lb] RESTORED → {url}")
                        _state[url]["healthy"] = True
                        _state[url]["consec_fails"] = 0
            except Exception:
                pass

_health_task: asyncio.Task | None = None

def _ensure_health_loop() -> None:
    global _health_task
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running() and (_health_task is None or _health_task.done()):
            _health_task = loop.create_task(_health_loop())
    except Exception:
        pass


# ── Proxy helpers (mirrors helpers.py proxy_dict_to_url) ─────────────────────

def _proxy_data_to_proxy_str(proxy_data: dict | None) -> str | None:
    if not proxy_data:
        return None
    # prefer fully-built proxy_url from proxy.json
    existing = proxy_data.get("proxy_url")
    if existing and isinstance(existing, str) and existing.strip():
        return existing.strip()
    ip    = str(proxy_data.get("ip")   or "").strip()
    port  = str(proxy_data.get("port") or "").strip()
    user  = proxy_data.get("username")
    pw    = proxy_data.get("password")
    ptype = (proxy_data.get("type") or "http").lower()
    if not ip or not port:
        return None
    if ptype == "https":
        ptype = "http"
    if user and pw:
        u = _urlquote(str(user), safe="")
        p = _urlquote(str(pw),   safe="")
        return f"{ptype}://{u}:{p}@{ip}:{port}"
    return f"{ptype}://{ip}:{port}"


# ── Result normalisation ──────────────────────────────────────────────────────

def _map_result(raw: dict, cc_str: str, site_url: str) -> dict:
    response = raw.get("Response", "Unknown")
    price    = raw.get("Price", "-")
    gate     = raw.get("Gate", "Shopify")

    rl = response.lower()
    if "order_placed" in rl or "order completed" in rl or "💎" in response:
        status = "Charged"
    elif any(k in rl for k in [
        "invalid_cvv", "incorrect_cvv", "insufficient_funds",
        "approved", "invalid_cvc", "incorrect_cvc",
        "incorrect_zip", "insufficient funds",
    ]):
        status = "Approved"
    else:
        status = response

    result = {
        "Response": response,
        "Price":    price,
        "Gate":     gate,
        "Status":   status,
        "CC":       raw.get("CC", cc_str),
        "Site":     raw.get("Site", site_url),
    }
    p = str(result["Price"])
    if p not in ("-", "", "0.00") and not p.startswith("$"):
        result["Price"] = f"${p}"
    return result


# ── Dead-response detection ───────────────────────────────────────────────────

_DEAD_INDICATORS = (
    'receipt id is empty', 'handle is empty', 'product id is empty',
    'tax amount is empty', 'payment method identifier is empty',
    'invalid url', 'error in 1st req', 'cloudflare', 'connection failed',
    'timed out', 'access denied', 'tlsv1 alert', 'ssl routines',
    'could not resolve', 'name or service not known', 'openssl ssl_connect',
    'empty reply from server', 'http error', 'timeout', 'unreachable',
    '502', '503', '504', 'bad gateway', 'service unavailable',
    'gateway timeout', 'network error', 'connection reset',
    'failed to detect product', 'failed to create checkout',
    'failed to tokenize card', 'failed to get proposal data',
    'submit rejected', 'http 404', 'url rejected', 'malformed input',
    'amount_too_small', 'site dead', 'captcha_required', 'site errors',
    'all products sold out', 'no_session_token', 'tokenize_fail',
    'all nodes failed',
)

def _is_dead(response_text: str) -> bool:
    if not response_text:
        return True
    rl = response_text.lower()
    return any(ind in rl for ind in _DEAD_INDICATORS)


# ── Public API ────────────────────────────────────────────────────────────────

async def check_card_site(cc_str: str, site_url: str, proxy_data: dict | None) -> dict:
    """
    Main async entry point called by bot.py for every CC check.

    Sends the request to the least-loaded healthy node.  On any node error
    the request is immediately retried on the next available node.
    Concurrent /ran batches of 100 are spread across all 8 nodes automatically.
    """
    _ensure_health_loop()

    proxy_str = _proxy_data_to_proxy_str(proxy_data)
    if not proxy_str:
        return {
            "Response": "No proxy – add one with /addpxy",
            "Price": "-", "Gate": "-", "Status": "No proxy",
            "CC": cc_str, "Site": site_url,
        }

    if site_url and not site_url.startswith("http"):
        site_url = f"https://{site_url}"
    site_url = (site_url or "").rstrip("/")

    tried:    set  = set()
    last_err: str  = "All nodes failed"
    t_start = time.monotonic()
    cc4 = cc_str.split('|')[0][-4:] if '|' in cc_str else cc_str[-4:]

    log.info(f"[bridge] check_card_site | cc=...{cc4} | proxy={proxy_str[:25] if proxy_str else 'NONE'}...")

    while True:
        node = _pick_node(exclude=tried)
        if node is None:
            break
        tried.add(node)
        try:
            raw    = await _call_node(node, cc_str, proxy_str, site_url)
            result = _map_result(raw, cc_str, site_url)
            log.info(
                f"[bridge] done | node={node} | {(time.monotonic()-t_start)*1000:.0f}ms"
                f" | status={result.get('Status')} | resp={result.get('Response','')[:60]}"
            )
            # If the checker itself returned "proxy burned", surface it immediately
            # — no point retrying other nodes with the same burned proxy
            resp_l = result.get("Response", "").lower()
            if any(ind in resp_l for ind in _PROXY_BURNED_INDICATORS):
                return {
                    "Response": "Proxy burned - change your proxy",
                    "Price": "-", "Gate": "Shopify", "Status": "Error",
                    "CC": cc_str, "Site": site_url,
                }
            return result
        except Exception as e:
            last_err = f"{type(e).__name__}: {str(e)[:80]}"
            log.warning(f"[lb] node {node} failed — {last_err}")
            if len(tried) >= len(NODES):
                break
            await asyncio.sleep(0.05)

    # All nodes failed
    err_l = last_err.lower()
    if any(ind in err_l for ind in _PROXY_BURNED_INDICATORS):
        final_resp = "Proxy burned - change your proxy"
    else:
        final_resp = f"All nodes failed: {last_err}"

    return {
        "Response": final_resp,
        "Price": "-", "Gate": "-", "Status": "Error",
        "CC": cc_str, "Site": site_url,
    }


async def test_site(
    site_url:   str,
    proxy_data: dict | None,
    test_card:  str = "4031630422575208|01|2030|280",
) -> dict:
    raw           = await check_card_site(test_card, site_url, proxy_data)
    response_text = raw.get("Response", "")
    price         = raw.get("Price", "-")
    status        = "working"
    if "proxy dead" in response_text.lower():
        status = "proxy_dead"
    elif _is_dead(response_text):
        status = "dead"
    return {"status": status, "response": response_text, "site": site_url, "price": price}


# ── /api management helpers (used by bot.py) ──────────────────────────────────

def get_all_nodes() -> list[str]:
    """Return the full node list (all, including disabled)."""
    return list(NODES)


async def check_node_health(node: str) -> bool:
    """Ping a single node's /health endpoint. Returns True if alive."""
    try:
        sess = await _get_session()
        async with sess.get(
            f"{node}/health",
            timeout=aiohttp.ClientTimeout(total=6, connect=4),
        ) as r:
            return r.status == 200
    except Exception:
        return False


def is_node_disabled(node: str) -> bool:
    return node in _disabled_nodes


def disable_node(node: str) -> None:
    _disabled_nodes.add(node)
    log.info(f"[api] node DISABLED: {node}")


def enable_node(node: str) -> None:
    _disabled_nodes.discard(node)
    # also reset circuit-breaker state so it gets traffic immediately
    if node in _state:
        _state[node]["healthy"]      = True
        _state[node]["consec_fails"] = 0
    log.info(f"[api] node ENABLED: {node}")
