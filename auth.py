"""auth.py — User authentication, premium access, key generation, admin & ban management."""

import json
import os
import time
import string
import random

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE   = os.path.join(BASE_DIR, "users.txt")
ADMINS_FILE  = os.path.join(BASE_DIR, "admins.json")
PREMIUM_FILE = os.path.join(BASE_DIR, "premium.json")
KEYS_FILE    = os.path.join(BASE_DIR, "keys.json")
BANNED_FILE   = os.path.join(BASE_DIR, "banned.json")
CHARGED_FILE  = os.path.join(BASE_DIR, "charged.txt")
NOPECHA_FILE  = os.path.join(BASE_DIR, "nopecha.json")   # {str(user_id): api_key}

OWNER_ID          = 8661200480
FREE_GROUP_ID     = -1003742612622

# ── CC limits per role ────────────────────────────────────────────────────────
CC_LIMITS = {
    "owner":   20000,
    "admin":   15000,
    "premium": 10000,
    "free":    200,
}

# ── mtime-based cache for hot permission files ────────────────────────────────
# is_premium / is_admin / is_banned run on every command.  With 3K users that
# means thousands of synchronous open→read→json.load per second.  This cache
# returns the already-parsed dict/list as long as the file's mtime hasn't
# changed, turning repeated reads into a single os.stat().
_json_cache: dict[str, dict | list] = {}
_json_mtime: dict[str, float] = {}

def _load_json_cached(path: str):
    """Return cached parse of *path* unless the file was modified on disk."""
    try:
        mt = os.path.getmtime(path)
    except OSError:
        return {}
    prev = _json_mtime.get(path)
    if prev is not None and prev == mt and path in _json_cache:
        return _json_cache[path]
    data = _load_json(path)
    _json_cache[path] = data
    _json_mtime[path] = mt
    return data


# ══════════════════════════════════════════════════════════════════════════════
#  GENERIC JSON HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _load_json(path: str) -> dict:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def _save_json(path: str, data: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    _json_cache[path] = data
    try:
        _json_mtime[path] = os.path.getmtime(path)
    except OSError:
        _json_mtime.pop(path, None)


# ══════════════════════════════════════════════════════════════════════════════
#  USERS  (users.txt — append-only log)
# ══════════════════════════════════════════════════════════════════════════════

def save_user(user_id: int, username: str, full_name: str) -> bool:
    """Append user to users.txt if not already recorded. Returns True for new users."""
    uid = str(user_id)
    existing = set()
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r", encoding="utf-8") as f:
            for line in f:
                parts = line.strip().split("|")
                if parts:
                    existing.add(parts[0])

    if uid not in existing:
        with open(USERS_FILE, "a", encoding="utf-8") as f:
            f.write(f"{user_id}|{username or 'none'}|{full_name or 'Unknown'}|{int(time.time())}\n")
        return True
    return False

def get_total_users() -> int:
    if not os.path.exists(USERS_FILE):
        return 0
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        return sum(1 for line in f if line.strip())

def get_all_user_ids() -> list[int]:
    """Return all registered user IDs from users.txt."""
    ids = []
    if not os.path.exists(USERS_FILE):
        return ids
    with open(USERS_FILE, "r", encoding="utf-8") as f:
        for line in f:
            parts = line.strip().split("|")
            if parts and parts[0].isdigit():
                ids.append(int(parts[0]))
    return ids


# ══════════════════════════════════════════════════════════════════════════════
#  OWNER
# ══════════════════════════════════════════════════════════════════════════════

def is_owner(user_id: int) -> bool:
    return user_id == OWNER_ID


# ══════════════════════════════════════════════════════════════════════════════
#  ADMINS  (admins.json)
# ══════════════════════════════════════════════════════════════════════════════

def load_admins() -> list:
    data = _load_json_cached(ADMINS_FILE)
    return data.get("admins", [])

def save_admins(admins: list):
    _save_json(ADMINS_FILE, {"admins": admins})

def add_admin(user_id: int) -> bool:
    admins = load_admins()
    if user_id not in admins:
        admins.append(user_id)
        save_admins(admins)
        return True
    return False

def remove_admin(user_id: int) -> bool:
    admins = load_admins()
    if user_id in admins:
        admins.remove(user_id)
        save_admins(admins)
        return True
    return False

def is_admin(user_id: int) -> bool:
    return user_id in load_admins() or is_owner(user_id)


# ══════════════════════════════════════════════════════════════════════════════
#  PREMIUM  (premium.json)
# ══════════════════════════════════════════════════════════════════════════════

def load_premium() -> dict:
    return _load_json_cached(PREMIUM_FILE)

def save_premium(data: dict):
    _save_json(PREMIUM_FILE, data)

def auth_user(user_id: int, days: int = 0, by: int = 0):
    """Grant premium. days=0 → lifetime."""
    data = load_premium()
    expires = 0 if days == 0 else int(time.time()) + (days * 86400)
    data[str(user_id)] = {
        "expires": expires,
        "authorized_by": by,
        "authorized_at": int(time.time()),
    }
    save_premium(data)

def unauth_user(user_id: int) -> bool:
    data = load_premium()
    if str(user_id) in data:
        del data[str(user_id)]
        save_premium(data)
        return True
    return False

def is_premium(user_id: int) -> bool:
    if is_owner(user_id) or user_id in load_admins():
        return True
    data = load_premium()
    entry = data.get(str(user_id))
    if not entry:
        return False
    expires = entry.get("expires", 0)
    if expires == 0:
        return True   # lifetime
    return time.time() < expires

def get_premium_expiry(user_id: int) -> str:
    """Human-readable expiry string."""
    if is_owner(user_id):
        return "Owner (Lifetime)"
    if user_id in load_admins():
        return "Admin (Lifetime)"
    data = load_premium()
    entry = data.get(str(user_id))
    if not entry:
        return "None"
    expires = entry.get("expires", 0)
    if expires == 0:
        return "Lifetime"
    remaining = expires - time.time()
    if remaining <= 0:
        return "Expired"
    days = int(remaining // 86400)
    hours = int((remaining % 86400) // 3600)
    return f"{days}d {hours}h"


# ══════════════════════════════════════════════════════════════════════════════
#  KEYS  (keys.json)
# ══════════════════════════════════════════════════════════════════════════════

def load_keys() -> dict:
    return _load_json(KEYS_FILE)

def save_keys(data: dict):
    _save_json(KEYS_FILE, data)

def generate_keys(max_users: int, days: int, created_by: int = 0) -> list[str]:
    """Generate ONE key redeemable by up to `max_users` people for `days` each.

    Example: generate_keys(10, 1) → one ALI-SINDHI-… key, 10 users can /redeem it,
    each gets 1 day premium.
    """
    data = load_keys()
    charset = string.ascii_letters + string.digits
    rand_part = "".join(random.choices(charset, k=20))
    key = f"ALI-SINDHI-{rand_part}"
    data[key] = {
        "days": days,
        "created_by": created_by,
        "created_at": int(time.time()),
        "max_uses": max(1, int(max_users)),
        "redeemed_by": [],  # list of user ids who redeemed
    }
    save_keys(data)
    return [key]


def redeem_key(user_id: int, key: str) -> tuple[bool, str]:
    """Try to redeem a key. Returns (success, info_message).

    Supports:
      - New multi-use keys: redeemed_by=list, max_uses=N
      - Legacy single-use keys: redeemed_by=user_id|None
    """
    data = load_keys()
    if key not in data:
        return False, "Invalid key"
    entry = data[key]
    days = entry.get("days", 0)
    redeemed = entry.get("redeemed_by")

    # Legacy single-use key (redeemed_by was a lone int / None)
    if redeemed is not None and not isinstance(redeemed, list):
        return False, "Key already redeemed"

    if isinstance(redeemed, list):
        redeemers = list(redeemed)
        max_uses = int(entry.get("max_uses") or 1)
    else:
        # Unused legacy key (None) → treat as 1-slot
        redeemers = []
        max_uses = int(entry.get("max_uses") or 1)

    if user_id in redeemers:
        return False, "You already redeemed this key"

    if len(redeemers) >= max_uses:
        return False, "Key fully redeemed (no slots left)"

    redeemers.append(user_id)
    entry["redeemed_by"] = redeemers
    entry["redeemed_at"] = int(time.time())
    entry["max_uses"] = max_uses
    save_keys(data)
    auth_user(user_id, days=days, by=0)
    left = max_uses - len(redeemers)
    return True, f"{days} days ({left}/{max_uses} slots left)"


# ══════════════════════════════════════════════════════════════════════════════
#  BANNED  (banned.json)
# ══════════════════════════════════════════════════════════════════════════════

def load_banned() -> list:
    data = _load_json_cached(BANNED_FILE)
    # Handle both {"banned": [...]} and a bare list (corrupted file)
    if isinstance(data, list):
        return data
    return data.get("banned", [])

def save_banned(banned: list):
    _save_json(BANNED_FILE, {"banned": banned})

def ban_user(user_id: int) -> bool:
    banned = load_banned()
    if user_id not in banned:
        banned.append(user_id)
        save_banned(banned)
        return True
    return False

def unban_user(user_id: int) -> bool:
    banned = load_banned()
    if user_id in banned:
        banned.remove(user_id)
        save_banned(banned)
        return True
    return False

def is_banned(user_id: int) -> bool:
    return user_id in load_banned()


# ══════════════════════════════════════════════════════════════════════════════
#  ROLE HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def get_user_role(user_id: int) -> str:
    if is_owner(user_id):
        return "owner"
    if user_id in load_admins():
        return "admin"
    if is_premium(user_id):
        return "premium"
    return "free"

def get_cc_limit(user_id: int) -> int:
    role = get_user_role(user_id)
    return CC_LIMITS.get(role, CC_LIMITS["free"])

def has_premium_access(user_id: int, chat_id: int = 0) -> bool:
    """Check if user can use premium commands (/sh, /msh, /ran)."""
    if is_owner(user_id):
        return True
    if is_admin(user_id):
        return True
    if is_premium(user_id):
        return True
    # Free access inside the free group only
    if chat_id == FREE_GROUP_ID:
        return True
    return False




# ══════════════════════════════════════════════════════════════════════════════
#  CHARGED CC LOG  (charged.txt)
# ══════════════════════════════════════════════════════════════════════════════

def save_charged_cc(cc_str: str, user_id: int, user_name: str, gate: str = "-", price: str = "-"):
    """Append a charged CC to charged.txt."""
    with open(CHARGED_FILE, "a", encoding="utf-8") as f:
        ts = int(time.time())
        f.write(f"{cc_str}|{gate}|{price}|{user_id}|{user_name}|{ts}\n")


# ══════════════════════════════════════════════════════════════════════════════
#  NOPECHA API KEY  (nopecha.json — per-user captcha solver key)
# ══════════════════════════════════════════════════════════════════════════════

def get_nopecha_key(user_id: int) -> str:
    """Return the NopeCHA API key set by this user, or '' if none."""
    return _load_json(NOPECHA_FILE).get(str(user_id), "")


def set_nopecha_key(user_id: int, key: str) -> None:
    """Save (or clear if key=='') a NopeCHA API key for a user."""
    data = _load_json(NOPECHA_FILE)
    uid = str(user_id)
    if key:
        data[uid] = key
    else:
        data.pop(uid, None)
    _save_json(NOPECHA_FILE, data)

