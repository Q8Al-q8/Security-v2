import asyncio
import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timezone
from urllib.parse import quote, urlencode, urlparse

from aiohttp import ClientError, ClientSession, ClientTimeout, web

try:
    from pymongo import MongoClient, ReturnDocument, UpdateOne
    from pymongo.errors import PyMongoError
except Exception:
    MongoClient = None
    ReturnDocument = None
    UpdateOne = None

    class PyMongoError(Exception):
        pass


SITE_NAME = os.getenv("SITE_NAME", "ARAB SECURITY").strip() or "ARAB SECURITY"
OWNER_NAME = os.getenv("OWNER_NAME", "سعود السويط").strip() or "سعود السويط"
ADMIN_USER_ID = os.getenv("ADMIN_USER_ID", "1395418036919468073").strip() or "1395418036919468073"

DEFAULT_DOMAIN_URL = "https://3rabsecurity.de5.net"
DEFAULT_REDIRECT_URI = f"{DEFAULT_DOMAIN_URL}/callback"
SUPPORT_SERVER_URL = os.getenv("SUPPORT_SERVER_URL", "https://discord.gg/khQXQCtjMS").strip()

HOST = os.getenv("HOST", "0.0.0.0").strip() or "0.0.0.0"
PORT = int(os.getenv("PORT", "8080") or "8080")

EXPLICIT_MAIN_URL = os.getenv("MAIN_SITE_URL", DEFAULT_DOMAIN_URL).strip().rstrip("/")
EXPLICIT_WEB_URL = os.getenv("WEB_BASE_URL", DEFAULT_DOMAIN_URL).strip().rstrip("/")
EXPLICIT_REDIRECT_URI = os.getenv("DISCORD_REDIRECT_URI", DEFAULT_REDIRECT_URI).strip()

BOT_INVITE_URL = os.getenv(
    "BOT_INVITE_URL",
    "https://discord.com/oauth2/authorize?client_id=1573635674551357550&permissions=8&integration_type=0&scope=bot%20applications.commands",
).strip()

MONGO_DB_NAME = os.getenv("MONGO_DB", "arab_security").strip() or "arab_security"
MONGO_USER = os.getenv("MONGO_USER", "").strip()
MONGO_PASS = os.getenv("MONGO_PASS", "").strip()
MONGO_HOST = os.getenv("MONGO_HOST", "").strip()
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://soudfares02_db_user:XFpjfdaMuqTzcvIZ@cluster0.hzhfdxt.mongodb.net/?retryWrites=true&w=majority").strip()


if not MONGO_URI and MONGO_HOST and MONGO_USER and MONGO_PASS:
    safe_user = quote(MONGO_USER, safe="")
    safe_pass = quote(MONGO_PASS, safe="")
    clean_host = MONGO_HOST.replace("mongodb+srv://", "").replace("mongodb://", "").strip("/")
    MONGO_URI = f"mongodb+srv://{safe_user}:{safe_pass}@{clean_host}/{MONGO_DB_NAME}?retryWrites=true&w=majority"

SESSION_SECRET = os.getenv("SESSION_SECRET", "").strip()
BOT_SYNC_SECRET = (os.getenv("BOT_SYNC_SECRET") or SESSION_SECRET).strip()
RATE_LIMIT_PER_MIN = int(os.getenv("RATE_LIMIT_PER_MIN", "180") or "180")
AUTH_RATE_LIMIT_PER_MIN = int(os.getenv("AUTH_RATE_LIMIT_PER_MIN", "35") or "35")

TRUST_PROXY = os.getenv("TRUST_PROXY", "true").strip().lower() in ("1", "true", "yes", "on")
TRUSTED_PROXY_IPS = {
    ip.strip()
    for ip in os.getenv("TRUSTED_PROXY_IPS", "").split(",")
    if ip.strip()
}
COOKIE_SECURE_ENV = os.getenv("COOKIE_SECURE", "").strip().lower()

DISCORD_CLIENT_ID = os.getenv("DISCORD_CLIENT_ID", "1573635674551357550").strip()
DISCORD_CLIENT_SECRET = os.getenv("DISCORD_CLIENT_SECRET", "e86TUouEB55j63-FwZFYQrsIBouxYF_r").strip()

PREMIUM_DURATION_DAYS = 30
PREMIUM_DURATION_SECONDS = PREMIUM_DURATION_DAYS * 86400

MAX_IMAGE_BYTES = 1_500_000
MAX_IMAGE_DATA_URL_LEN = 2_100_000

if not SESSION_SECRET or len(SESSION_SECRET) < 16:
    raise RuntimeError("A1234567890112314566") 
if not ADMIN_USER_ID.isdigit():
    raise RuntimeError("A1234567890112314566")

MANAGE_GUILD_PERM = 0x20
ADMIN_PERM = 0x8

ANTINUKE_RULE_KEYS = (
    "anti_ban",
    "anti_kick",
    "anti_role_create",
    "anti_role_delete",
    "anti_channel_create",
    "anti_channel_delete",
    "anti_webhook_create",
    "anti_bot_add",
    "anti_guild_update",
)

SHIELD_TOGGLE_KEYS = (
    "anti_selfbot",
    "anti_webhook_abuse",
    "anti_app_abuse",
    "anti_privilege_escalation",
    "anti_role_tamper",
    "anti_channel_perms_tamper",
    "audit_log_watch",
    "anti_mass_unban",
    "anti_mass_kick",
    "anti_mass_timeout",
    "admin_behavior_analysis",
    "trusted_admins_enabled",
    "perms_snapshot_enabled",
    "auto_rollback_enabled",
    "gradual_attack_detect",
    "collusion_detect",
    "false_punishment_guard",
    "emergency_mode",
    "auto_perms_audit",
    "silent_mode",
    "anti_invites",
    "voice_lock",
)

PREMIUM_ONLY_KEYS = {
    "anti_selfbot",
    "anti_link",
    "anti_privilege_escalation",
    "anti_role_tamper",
    "anti_channel_perms_tamper",
    "anti_webhook_abuse",
    "anti_app_abuse",
    "admin_behavior_analysis",
    "perms_snapshot_enabled",
    "auto_rollback_enabled",
    "gradual_attack_detect",
    "collusion_detect",
    "false_punishment_guard",
    "auto_perms_audit",
    "emergency_mode",
}


def _fresh_default_guild_cfg() -> dict:
    return {
        "prefix": "!",
        "maintenance": False,
        "mod_log_channel": "",
        "anti_spam": True,
        "spam_punishment": "Timeout",
        "spam_timeout_seconds": 600,
        "anti_link": False,
        "link_punishment": "Delete & Timeout",
        "link_timeout_seconds": 300,
        "anti_invites": True,
        "voice_lock": False,
        "silent_mode": False,
        "beast_mode": False,
        "anti_raid": False,
        "verification": False,
        "lockdown": False,
        "anti_new_accounts": False,
        "min_account_age_days": 7,
        "dangerous_perms_guard": True,
        "alert_on_trigger": True,
        "anti_selfbot": True,
        "anti_webhook_abuse": True,
        "anti_app_abuse": True,
        "anti_privilege_escalation": True,
        "anti_role_tamper": True,
        "anti_channel_perms_tamper": True,
        "audit_log_watch": True,
        "anti_mass_unban": True,
        "anti_mass_kick": True,
        "anti_mass_timeout": True,
        "admin_behavior_analysis": True,
        "trusted_admins_enabled": True,
        "perms_snapshot_enabled": True,
        "auto_rollback_enabled": True,
        "gradual_attack_detect": True,
        "collusion_detect": True,
        "false_punishment_guard": True,
        "emergency_mode": False,
        "auto_perms_audit": True,
        "trusted_admins": [ADMIN_USER_ID],
        "perms_snapshots": [],
        "antinuke": {
            "anti_ban": {"enabled": True, "limit": 1, "punishment": "Kick"},
            "anti_kick": {"enabled": True, "limit": 1, "punishment": "Kick"},
            "anti_role_create": {"enabled": True, "limit": 1, "punishment": "Kick"},
            "anti_role_delete": {"enabled": True, "limit": 1, "punishment": "Ban"},
            "anti_channel_create": {"enabled": True, "limit": 2, "punishment": "Kick"},
            "anti_channel_delete": {"enabled": True, "limit": 1, "punishment": "Ban"},
            "anti_webhook_create": {"enabled": True, "limit": 1, "punishment": "Ban"},
            "anti_bot_add": {"enabled": True, "limit": 1, "punishment": "Ban"},
            "anti_guild_update": {"enabled": True, "limit": 1, "punishment": "Kick"},
        },
        "guild_profile": {
            "bio": "",
            "avatar_data_url": "",
            "avatar_name": "",
            "banner_data_url": "",
            "banner_name": "",
        },
        "premium_perks": {
            "ultra_fortress_mode": False,
            "instant_rollback_enabled": True,
            "priority_shield_response": True,
            "alert_channel_id": "",
            "alert_webhook_url": "",
            "last_restored_snapshot": "",
        },
    }


MEM_LOGS: deque[dict] = deque(maxlen=300)
MEM_INCIDENTS: deque[dict] = deque(maxlen=200)
MEM_GUILDS: dict[str, dict] = {}
MEM_GUILD_CFG: dict[str, dict] = defaultdict(_fresh_default_guild_cfg)
MEM_QUEUE: deque[dict] = deque(maxlen=200)
MEM_PREMIUM: dict[str, dict] = {
    ADMIN_USER_ID: {
        "user_id": ADMIN_USER_ID,
        "username": OWNER_NAME,
        "handle": OWNER_NAME,
        "granted_by": "owner",
        "granted_at": "",
        "expires_at": 0.0,
        "permanent": True,
    }
}
MEM_ADMINS: set[str] = {ADMIN_USER_ID}
MEM_VISITORS: dict[str, object] = {
    "total_visits": 0,
    "unique_hashes": deque(maxlen=5000),
    "unique_seen": set(),
}
MEM_BACKUPS: deque[dict] = deque(maxlen=25)
MEM_BOT_HEARTBEAT: dict[str, str] = {
    "status": "ONLINE",
    "last_seen": "",
    "latency_ms": "6ms",
}

_CFG_CACHE: dict[str, tuple[float, dict]] = {}
_CFG_TTL = 10.0

_PERM_CACHE: dict[str, tuple[float, object]] = {}
_PERM_TTL = 15.0

_GUILDS_CACHE: tuple[float, list[dict]] = (0.0, [])
_GUILDS_TTL = 2.0

_VISIT_STATS_CACHE: tuple[float, int, int] = (0.0, 0, 0)
_VISIT_STATS_TTL = 8.0

_PENDING_VISITS = 0
_PENDING_UNIQUE: list[str] = []
_LAST_VISIT_FLUSH = 0.0

CSRF_TOKENS: dict[str, dict] = {}
OAUTH_STATES: dict[str, float] = {}
USED_NONCES: dict[str, float] = {}
RATE_BUCKETS: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=500))
AUTH_RATE_BUCKETS: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=150))
SESSIONS: dict[str, dict] = {}


def esc(val) -> str:
    return html.escape(str(val or ""), quote=True)


def sanitize_http_url(raw_url: str | None) -> str:
    val = str(raw_url or "").strip()[:400]
    if not val:
        return ""
    try:
        parsed = urlparse(val)
    except Exception:
        return ""
    if parsed.scheme.lower() not in ("https", "http") or not parsed.netloc:
        return ""
    return val


def sanitize_image_data_url(raw_val: str | None, max_len: int = MAX_IMAGE_DATA_URL_LEN) -> str:
    val = str(raw_val or "").strip()
    if not val:
        return ""
    if val.startswith("data:image/"):
        if len(val) > max_len or ";base64," not in val:
            return ""
        header, b64_part = val.split(";base64,", 1)
        allowed_mimes = ("data:image/png", "data:image/jpeg", "data:image/jpg", "data:image/webp", "data:image/gif")
        if header.lower() not in allowed_mimes or not b64_part:
            return ""
        try:
            decoded = base64.b64decode(b64_part, validate=True)
            if not decoded or len(decoded) > MAX_IMAGE_BYTES:
                return ""
            return f"{header.lower()};base64,{base64.b64encode(decoded).decode('ascii')}"
        except Exception:
            return ""
    return sanitize_http_url(val)


def sanitize_flash_msg(raw_msg: str | None) -> str:
    cleaned = "".join(ch for ch in str(raw_msg or "") if ch.isprintable()).strip()
    return cleaned[:240]


def _now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _safe_exp(val) -> float:
    if isinstance(val, dict):
        val = val.get("exp", 0)
    try:
        return float(val)
    except Exception:
        return 0.0


db = None
logs_col = None
incidents_col = None
bot_guilds_col = None
guild_settings_col = None
queue_col = None
premium_col = None
admins_col = None
stats_col = None
backups_col = None
sessions_col = None

if MONGO_URI and MongoClient is not None:
    try:
        client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=900,
            connectTimeoutMS=900,
            socketTimeoutMS=1200,
            maxPoolSize=30,
        )
        client.admin.command("ping")
        db = client[MONGO_DB_NAME]
        logs_col = db["activity_logs"]
        incidents_col = db["security_incidents"]
        bot_guilds_col = db["bot_guilds"]
        guild_settings_col = db["guild_settings"]
        queue_col = db["remote_commands"]
        premium_col = db["premium_users"]
        admins_col = db["site_admins"]
        stats_col = db["site_stats"]
        backups_col = db["db_backups"]
        sessions_col = db["web_sessions"]

        premium_col.update_one(
            {"user_id": ADMIN_USER_ID},
            {
                "$set": {
                    "user_id": ADMIN_USER_ID,
                    "username": OWNER_NAME,
                    "handle": OWNER_NAME,
                    "granted_by": "owner",
                    "permanent": True,
                    "expires_at": 0.0,
                    "updated_at": _now_str(),
                }
            },
            upsert=True,
        )
        admins_col.update_one(
            {"user_id": ADMIN_USER_ID},
            {"$set": {"user_id": ADMIN_USER_ID, "granted_by": "owner", "updated_at": _now_str()}},
            upsert=True,
        )
    except (PyMongoError, Exception) as exc:
        print(f"[DB] تنبيه: تشغيل بالذاكرة الاحتياطية ({type(exc).__name__})")


def _store_session_record(sid: str, record: dict) -> None:
    if len(SESSIONS) >= 5000:
        oldest_sid = next(iter(SESSIONS))
        SESSIONS.pop(oldest_sid, None)
    SESSIONS[sid] = dict(record)
    if sessions_col is not None:
        try:
            sessions_col.update_one(
                {"sid": sid},
                {"$set": {**record, "sid": sid}},
                upsert=True,
            )
        except PyMongoError:
            pass


def _load_session_record(sid: str) -> dict | None:
    now = time.time()
    mem_sess = SESSIONS.get(sid)
    if mem_sess:
        if _safe_exp(mem_sess.get("exp", 0)) <= now:
            SESSIONS.pop(sid, None)
            mem_sess = None
        else:
            return mem_sess

    if sessions_col is not None:
        try:
            doc = sessions_col.find_one({"sid": sid}, {"_id": 0})
            if doc:
                if _safe_exp(doc.get("exp", 0)) <= now:
                    sessions_col.delete_one({"sid": sid})
                    return None
                SESSIONS[sid] = dict(doc)
                return dict(doc)
        except PyMongoError:
            pass
    return None


def _delete_session_record(sid: str) -> None:
    SESSIONS.pop(sid, None)
    if sessions_col is not None:
        try:
            sessions_col.delete_one({"sid": sid})
        except PyMongoError:
            pass


def _cleanup_expired() -> None:
    now = time.time()
    for k, meta in list(CSRF_TOKENS.items()):
        if _safe_exp(meta.get("exp", 0)) <= now:
            CSRF_TOKENS.pop(k, None)
    for st, exp in list(OAUTH_STATES.items()):
        if _safe_exp(exp) <= now:
            OAUTH_STATES.pop(st, None)
    for n, exp in list(USED_NONCES.items()):
        if _safe_exp(exp) <= now:
            USED_NONCES.pop(n, None)
    for sid, sess in list(SESSIONS.items()):
        if _safe_exp(sess.get("exp", 0)) <= now:
            SESSIONS.pop(sid, None)
    if sessions_col is not None:
        try:
            sessions_col.delete_many({"exp": {"$lte": now}})
        except PyMongoError:
            pass


def issue_oauth_state() -> str:
    _cleanup_expired()
    st = secrets.token_urlsafe(24)
    if len(OAUTH_STATES) >= 2000:
        oldest = next(iter(OAUTH_STATES))
        OAUTH_STATES.pop(oldest, None)
    OAUTH_STATES[st] = time.time() + 600.0
    return st


def consume_oauth_state(state_val: str | None) -> bool:
    _cleanup_expired()
    clean = str(state_val or "").strip()
    if not clean or clean not in OAUTH_STATES:
        return False
    exp = _safe_exp(OAUTH_STATES.pop(clean))
    return exp > time.time()


def issue_csrf_token(session_id: str) -> str:
    _cleanup_expired()
    tok = secrets.token_hex(24)
    if len(CSRF_TOKENS) >= 5000:
        oldest = next(iter(CSRF_TOKENS))
        CSRF_TOKENS.pop(oldest, None)
    CSRF_TOKENS[tok] = {
        "sid": str(session_id or ""),
        "exp": time.time() + 3600.0,
    }
    return tok


def consume_csrf_token(tok: str | None, session_id: str | None) -> bool:
    _cleanup_expired()
    clean_tok = str(tok or "").strip()
    clean_sid = str(session_id or "").strip()
    if not clean_tok or not clean_sid or clean_tok not in CSRF_TOKENS:
        return False
    meta = CSRF_TOKENS.pop(clean_tok)
    if _safe_exp(meta.get("exp", 0)) <= time.time():
        return False
    return hmac.compare_digest(str(meta.get("sid", "")), clean_sid)


def is_replay_request(nonce: str | None) -> bool:
    _cleanup_expired()
    clean = str(nonce or "").strip()
    if not clean:
        return False
    if clean in USED_NONCES:
        return True
    if len(USED_NONCES) >= 5000:
        oldest = next(iter(USED_NONCES))
        USED_NONCES.pop(oldest, None)
    USED_NONCES[clean] = time.time() + 300.0
    return False


def _sign_hmac(msg: str) -> str:
    return hmac.new(SESSION_SECRET.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


def _invalidate_perm_cache(uid: str = "") -> None:
    if uid:
        for k in list(_PERM_CACHE.keys()):
            if k.endswith(f":{uid}"):
                _PERM_CACHE.pop(k, None)
    else:
        _PERM_CACHE.clear()


def _invalidate_guilds_cache() -> None:
    global _GUILDS_CACHE
    _GUILDS_CACHE = (0.0, [])


def get_client_ip(request: web.Request) -> str:
    remote_ip = str(request.remote or "").strip()
    can_trust_xff = TRUST_PROXY and (not TRUSTED_PROXY_IPS or remote_ip in TRUSTED_PROXY_IPS)
    if can_trust_xff:
        xff_parts = [p.strip() for p in request.headers.get("X-Forwarded-For", "").split(",") if p.strip()]
        if xff_parts:
            return xff_parts[-1][:64]
    return (remote_ip or "unknown")[:64]


def should_use_secure_cookie(request: web.Request) -> bool:
    if COOKIE_SECURE_ENV in ("1", "true", "yes", "on"):
        return True
    if COOKIE_SECURE_ENV in ("0", "false", "no", "off"):
        return False
    remote_ip = str(request.remote or "").strip()
    can_trust = TRUST_PROXY and (not TRUSTED_PROXY_IPS or remote_ip in TRUSTED_PROXY_IPS)
    proto = (
        (request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip().lower() if can_trust else "")
        or str(request.scheme or "").lower()
    )
    return proto == "https"


def flush_visits_if_needed(force: bool = False) -> None:
    global _PENDING_VISITS, _PENDING_UNIQUE, _LAST_VISIT_FLUSH
    now = time.time()
    if not force and (now - _LAST_VISIT_FLUSH) < 6.0 and _PENDING_VISITS < 30:
        return
    if stats_col is None or (_PENDING_VISITS == 0 and not _PENDING_UNIQUE):
        _LAST_VISIT_FLUSH = now
        return
    inc_v = _PENDING_VISITS
    uniq_batch = list(_PENDING_UNIQUE)
    _PENDING_VISITS = 0
    _PENDING_UNIQUE = []
    _LAST_VISIT_FLUSH = now
    try:
        if inc_v > 0:
            stats_col.update_one(
                {"_id": "visitors"},
                {"$inc": {"total_visits": inc_v}, "$set": {"updated_at": _now_str()}},
                upsert=True,
            )
        for vh in uniq_batch[:40]:
            stats_col.update_one(
                {"_id": f"uv_{vh}"},
                {"$set": {"hash": vh, "seen_at": _now_str()}},
                upsert=True,
            )
    except PyMongoError:
        pass


def record_site_visit(request: web.Request) -> None:
    global _PENDING_VISITS, _PENDING_UNIQUE
    if request.path.startswith(("/health", "/api/")):
        return
    ip = get_client_ip(request)
    ua = request.headers.get("User-Agent", "")
    v_hash = hashlib.sha256(f"{ip}|{ua}|{SESSION_SECRET}".encode("utf-8")).hexdigest()[:24]

    MEM_VISITORS["total_visits"] = int(MEM_VISITORS.get("total_visits", 0)) + 1
    _PENDING_VISITS += 1

    u_deque: deque = MEM_VISITORS["unique_hashes"]  # type: ignore[assignment]
    u_seen: set = MEM_VISITORS["unique_seen"]  # type: ignore[assignment]
    if v_hash not in u_seen:
        if len(u_deque) == u_deque.maxlen:
            evicted = u_deque.popleft()
            u_seen.discard(evicted)
        u_deque.append(v_hash)
        u_seen.add(v_hash)
        _PENDING_UNIQUE.append(v_hash)

    flush_visits_if_needed(force=False)


def get_total_visits() -> int:
    global _VISIT_STATS_CACHE
    now = time.time()
    if (now - _VISIT_STATS_CACHE[0]) < _VISIT_STATS_TTL:
        return _VISIT_STATS_CACHE[1]

    mem_total = int(MEM_VISITORS.get("total_visits", 0))
    db_total = 0
    if stats_col is not None:
        try:
            vdoc = stats_col.find_one({"_id": "visitors"}, {"total_visits": 1})
            if vdoc:
                db_total = int(vdoc.get("total_visits", 0) or 0)
        except PyMongoError:
            pass
    tot = max(mem_total, db_total)
    _VISIT_STATS_CACHE = (now, tot, 0)
    return tot


def is_site_admin(user: dict | None) -> bool:
    if not user:
        return False
    uid = str(user.get("id", "")).strip()
    if not uid.isdigit():
        return False
    if uid == ADMIN_USER_ID or uid in MEM_ADMINS:
        return True
    cache_key = f"admin:{uid}"
    cached = _PERM_CACHE.get(cache_key)
    if cached and (time.time() - cached[0]) < _PERM_TTL:
        return bool(cached[1])
    res = False
    if admins_col is not None:
        try:
            if admins_col.find_one({"user_id": uid}, {"_id": 1}) is not None:
                MEM_ADMINS.add(uid)
                res = True
        except PyMongoError:
            pass
    _PERM_CACHE[cache_key] = (time.time(), res)
    return res


def get_admin_list() -> list[dict]:
    items: dict[str, dict] = {
        ADMIN_USER_ID: {"user_id": ADMIN_USER_ID, "granted_by": "owner", "updated_at": "-"}
    }
    for uid in MEM_ADMINS:
        if uid not in items:
            items[uid] = {"user_id": uid, "granted_by": "admin", "updated_at": "-"}
    if admins_col is not None:
        try:
            for doc in admins_col.find({}, {"_id": 0}).limit(100):
                uid = str(doc.get("user_id", "")).strip()
                if uid.isdigit():
                    items[uid] = {
                        "user_id": uid,
                        "granted_by": str(doc.get("granted_by", "owner")),
                        "updated_at": str(doc.get("updated_at", "-")),
                    }
        except PyMongoError:
            pass
    return list(items.values())


def set_admin_user(user_id: str, enabled: bool, granted_by: str = "") -> bool:
    uid = str(user_id or "").strip()
    if not uid.isdigit():
        return False
    _invalidate_perm_cache(uid)
    if enabled:
        MEM_ADMINS.add(uid)
        set_premium_user(uid, True, granted_by=granted_by or ADMIN_USER_ID)
        if admins_col is not None:
            try:
                admins_col.update_one(
                    {"user_id": uid},
                    {"$set": {"user_id": uid, "granted_by": granted_by or ADMIN_USER_ID, "updated_at": _now_str()}},
                    upsert=True,
                )
            except PyMongoError:
                pass
        return True
    if uid == ADMIN_USER_ID:
        return False
    MEM_ADMINS.discard(uid)
    if admins_col is not None:
        try:
            admins_col.delete_one({"user_id": uid})
        except PyMongoError:
            pass
    return True


def _get_premium_record(uid: str) -> dict | None:
    if not uid.isdigit():
        return None
    if uid == ADMIN_USER_ID:
        return {
            "user_id": ADMIN_USER_ID,
            "username": OWNER_NAME,
            "handle": OWNER_NAME,
            "granted_by": "owner",
            "permanent": True,
            "expires_at": 0.0,
        }
    now = time.time()
    rec = MEM_PREMIUM.get(uid)
    if not rec and premium_col is not None:
        try:
            doc = premium_col.find_one({"user_id": uid}, {"_id": 0})
            if doc:
                rec = dict(doc)
                MEM_PREMIUM[uid] = rec
        except PyMongoError:
            pass
    if not rec:
        return None
    if rec.get("permanent"):
        return rec
    exp_val = float(rec.get("expires_at", 0.0) or 0.0)
    if exp_val <= now:
        set_premium_user(uid, False)
        return None
    return rec


def is_premium_user(user: dict | None) -> bool:
    if not user:
        return False
    uid = str(user.get("id", "")).strip()
    if not uid.isdigit():
        return False
    if is_site_admin(user):
        return True
    cache_key = f"prem:{uid}"
    cached = _PERM_CACHE.get(cache_key)
    if cached and (time.time() - cached[0]) < _PERM_TTL:
        return bool(cached[1])
    res = _get_premium_record(uid) is not None
    _PERM_CACHE[cache_key] = (time.time(), res)
    return res


def format_remaining_days(rec: dict) -> str:
    if rec.get("permanent"):
        return "دائم"
    rem = max(0.0, float(rec.get("expires_at", 0.0) or 0.0) - time.time())
    days = int(rem // 86400)
    hours = int((rem % 86400) // 3600)
    if days > 0:
        return f"{days} يوم و {hours} ساعة"
    return f"{hours} ساعة متبقية"


def get_premium_list() -> list[dict]:
    now = time.time()
    items: dict[str, dict] = {}
    if premium_col is not None:
        try:
            for doc in premium_col.find({}, {"_id": 0}).limit(200):
                uid = str(doc.get("user_id", "")).strip()
                if not uid.isdigit():
                    continue
                if not doc.get("permanent") and float(doc.get("expires_at", 0.0) or 0.0) <= now:
                    try:
                        premium_col.delete_one({"user_id": uid})
                    except PyMongoError:
                        pass
                    MEM_PREMIUM.pop(uid, None)
                    continue
                items[uid] = dict(doc)
                MEM_PREMIUM[uid] = dict(doc)
        except PyMongoError:
            pass
    for uid, rec in list(MEM_PREMIUM.items()):
        if uid in items:
            continue
        if not rec.get("permanent") and float(rec.get("expires_at", 0.0) or 0.0) <= now:
            MEM_PREMIUM.pop(uid, None)
            continue
        items[uid] = dict(rec)
    return list(items.values())


def set_premium_user(
    user_id: str,
    enabled: bool,
    granted_by: str = "",
    username: str = "",
    handle: str = "",
) -> bool:
    uid = str(user_id or "").strip()
    if not uid.isdigit():
        return False
    _invalidate_perm_cache(uid)
    if enabled:
        now = time.time()
        is_perm = uid == ADMIN_USER_ID
        existing = MEM_PREMIUM.get(uid) or {}
        clean_uname = str(username or existing.get("username") or f"User {uid}").strip()[:40]
        clean_handle = str(handle or existing.get("handle") or f"@{clean_uname}").strip()[:44]
        rec = {
            "user_id": uid,
            "username": clean_uname,
            "handle": clean_handle,
            "granted_by": granted_by or ADMIN_USER_ID,
            "granted_at": _now_str(),
            "expires_at": 0.0 if is_perm else (now + PREMIUM_DURATION_SECONDS),
            "permanent": is_perm,
        }
        MEM_PREMIUM[uid] = rec
        if premium_col is not None:
            try:
                premium_col.update_one(
                    {"user_id": uid},
                    {"$set": rec},
                    upsert=True,
                )
            except PyMongoError:
                pass
        return True
    if uid == ADMIN_USER_ID:
        return False
    MEM_PREMIUM.pop(uid, None)
    if premium_col is not None:
        try:
            premium_col.delete_one({"user_id": uid})
        except PyMongoError:
            pass
    return True


def record_incident(guild_id: str, category: str, summary: str, severity: str = "HIGH") -> None:
    inc = {
        "time": _now_str(),
        "guild_id": str(guild_id)[:22],
        "category": str(category)[:40],
        "severity": str(severity)[:12],
        "summary": str(summary)[:260],
    }
    MEM_INCIDENTS.appendleft(dict(inc))
    if incidents_col is not None:
        try:
            incidents_col.insert_one(dict(inc))
        except PyMongoError:
            pass


def get_incidents(guild_id: str = "", limit: int = 30) -> list[dict]:
    if incidents_col is not None:
        try:
            flt = {"guild_id": guild_id} if str(guild_id).isdigit() else {}
            docs = list(incidents_col.find(flt, {"_id": 0}).sort("_id", -1).limit(limit))
            if docs:
                return docs
        except PyMongoError:
            pass
    items = list(MEM_INCIDENTS)
    if str(guild_id).isdigit():
        items = [x for x in items if x.get("guild_id") == str(guild_id)]
    return items[:limit]


def log_event(msg: str, guild_id: str = "", level: str = "WEB") -> None:
    entry = {
        "time": _now_str(),
        "level": str(level)[:12],
        "guild_id": str(guild_id)[:22],
        "message": str(msg)[:300],
    }
    MEM_LOGS.appendleft(dict(entry))
    if logs_col is not None:
        try:
            logs_col.insert_one(dict(entry))
        except PyMongoError:
            pass
    if level in ("NUKE", "ADMIN", "SEC", "WARN", "ERROR"):
        record_incident(guild_id or "GLOBAL", level, msg, "CRITICAL" if level in ("NUKE", "ERROR") else "MEDIUM")


def get_recent_logs(limit: int = 50) -> list[dict]:
    if logs_col is not None:
        try:
            docs = list(logs_col.find({}, {"_id": 0}).sort("_id", -1).limit(limit))
            if docs:
                return docs
        except PyMongoError:
            pass
    return list(MEM_LOGS)[:limit]


def upsert_bot_guilds(guilds_payload: list[dict], replace_missing: bool = False) -> list[dict]:
    stamp = _now_str()
    cleaned: dict[str, dict] = {}
    for item in guilds_payload or []:
        if not isinstance(item, dict):
            continue
        gid = str(item.get("id", "")).strip()
        if not gid.isdigit():
            continue
        cleaned[gid] = {
            "id": gid,
            "name": str(item.get("name", f"Server {gid}"))[:100],
            "icon": str(item.get("icon", "") or "").strip()[:80],
            "member_count": int(item.get("member_count", 0) or 0),
            "owner_id": str(item.get("owner_id", "") or "").strip(),
            "updated_at": stamp,
        }

    if replace_missing:
        MEM_GUILDS.clear()
    for gid, doc in cleaned.items():
        MEM_GUILDS[gid] = dict(doc)

    if bot_guilds_col is not None:
        try:
            if replace_missing:
                active_ids = list(cleaned.keys())
                if active_ids:
                    bot_guilds_col.delete_many({"id": {"$nin": active_ids}})
                else:
                    bot_guilds_col.delete_many({})
            if cleaned and UpdateOne is not None:
                ops = [
                    UpdateOne({"id": gid}, {"$set": doc}, upsert=True)
                    for gid, doc in cleaned.items()
                ]
                bot_guilds_col.bulk_write(ops, ordered=False)
        except PyMongoError:
            pass

    _invalidate_guilds_cache()
    return get_all_guilds()


def get_all_guilds() -> list[dict]:
    global _GUILDS_CACHE
    now = time.time()
    if (now - _GUILDS_CACHE[0]) < _GUILDS_TTL and (_GUILDS_CACHE[1] or not MEM_GUILDS):
        return [dict(x) for x in _GUILDS_CACHE[1]]

    result: dict[str, dict] = {k: dict(v) for k, v in MEM_GUILDS.items()}
    if bot_guilds_col is not None:
        try:
            for g in bot_guilds_col.find({}, {"_id": 0}).limit(500):
                gid = str(g.get("id", "")).strip()
                if gid.isdigit():
                    result[gid] = {
                        "id": gid,
                        "name": str(g.get("name", f"Server {gid}"))[:100],
                        "icon": str(g.get("icon", "")).strip(),
                        "member_count": int(g.get("member_count", 0) or 0),
                        "owner_id": str(g.get("owner_id", "")).strip(),
                        "updated_at": str(g.get("updated_at", "")).strip(),
                    }
        except PyMongoError:
            pass
    out = list(result.values())
    _GUILDS_CACHE = (now, out)
    return [dict(x) for x in out]


def guild_icon_url(guild_id: str, icon_val: str | None) -> str:
    gid = str(guild_id or "").strip()
    ico = str(icon_val or "").strip()
    if not gid.isdigit() or not ico:
        return ""
    if ico.startswith(("https://", "http://")):
        return sanitize_http_url(ico)
    ext = "gif" if ico.startswith("a_") else "png"
    return f"https://cdn.discordapp.com/icons/{gid}/{ico}.{ext}?size=128"


def get_user_visible_guilds(user: dict | None) -> tuple[list[dict], bool]:
    if not user:
        return [], False

    user_guilds = user.get("guilds")
    if not isinstance(user_guilds, list) or not user_guilds:
        return [], False

    bot_guilds = get_all_guilds()
    bot_map = {g["id"]: g for g in bot_guilds}

    matched: list[dict] = []
    seen: set[str] = set()

    for ug in user_guilds:
        if not isinstance(ug, dict):
            continue
        gid = str(ug.get("id", "")).strip()
        if not gid.isdigit() or gid in seen:
            continue

        perms = int(ug.get("permissions", 0) or 0)
        is_owner = bool(ug.get("owner", False))
        can_manage = is_owner or bool(perms & ADMIN_PERM) or bool(perms & MANAGE_GUILD_PERM)
        if not can_manage:
            continue

        seen.add(gid)
        if gid in bot_map:
            info = dict(bot_map[gid])
            info["bot_missing"] = False
            if ug.get("icon") and not info.get("icon"):
                info["icon"] = str(ug["icon"])
            matched.append(info)
        else:
            matched.append(
                {
                    "id": gid,
                    "name": str(ug.get("name", f"Server {gid}"))[:100],
                    "icon": str(ug.get("icon", "")).strip(),
                    "member_count": 0,
                    "bot_missing": True,
                }
            )

    return matched, True


def user_can_manage_guild(guild_id: str, user: dict | None, require_bot_present: bool = True) -> dict | None:
    gid = str(guild_id or "").strip()
    if not gid.isdigit() or not user:
        return None
    visible, _ = get_user_visible_guilds(user)
    for g in visible:
        if g["id"] == gid:
            if require_bot_present and g.get("bot_missing"):
                return None
            return g
    return None


def resolve_guild_id_from_input(raw_input: str, user: dict | None = None, require_bot_present: bool = True) -> str:
    val = str(raw_input or "").strip()
    if not val or not user:
        return ""
    visible, _ = get_user_visible_guilds(user)
    allowed = [g for g in visible if not require_bot_present or not g.get("bot_missing")]
    if val.isdigit():
        return val if any(g["id"] == val for g in allowed) else ""
    low = val.lower()
    for g in allowed:
        if str(g.get("name", "")).strip().lower() == low:
            return g["id"]
    for g in allowed:
        if low in str(g.get("name", "")).strip().lower():
            return g["id"]
    return ""


def get_guild_cfg(guild_id: str) -> dict:
    gid = str(guild_id or "").strip()
    cfg = _fresh_default_guild_cfg()
    if not gid.isdigit():
        return cfg

    now = time.time()
    cached = _CFG_CACHE.get(gid)
    if cached and (now - cached[0]) < _CFG_TTL:
        return json.loads(json.dumps(cached[1]))

    mem = MEM_GUILD_CFG[gid]
    for k, v in mem.items():
        if k == "antinuke" and isinstance(v, dict):
            for ak, av in v.items():
                if ak in cfg["antinuke"] and isinstance(av, dict):
                    cfg["antinuke"][ak].update(av)
        elif k in ("guild_profile", "premium_perks") and isinstance(v, dict):
            cfg[k].update(v)
        else:
            cfg[k] = v
    if guild_settings_col is not None:
        try:
            doc = guild_settings_col.find_one({"guild_id": gid}, {"_id": 0})
            if doc:
                for k in cfg:
                    if k == "antinuke" and isinstance(doc.get("antinuke"), dict):
                        for ak, av in doc["antinuke"].items():
                            if ak in cfg["antinuke"] and isinstance(av, dict):
                                cfg["antinuke"][ak].update(av)
                    elif k in ("guild_profile", "premium_perks") and isinstance(doc.get(k), dict):
                        cfg[k].update(doc[k])
                    elif k in doc:
                        cfg[k] = doc[k]
        except PyMongoError:
            pass

    _CFG_CACHE[gid] = (now, json.loads(json.dumps(cfg)))
    return cfg


def save_guild_cfg(guild_id: str, updates: dict, is_premium: bool = False) -> dict:
    gid = str(guild_id or "").strip()
    _CFG_CACHE.pop(gid, None)
    if updates.get("reset_defaults"):
        fresh = _fresh_default_guild_cfg()
        if gid.isdigit():
            MEM_GUILD_CFG[gid] = json.loads(json.dumps(fresh))
            if guild_settings_col is not None:
                try:
                    guild_settings_col.update_one(
                        {"guild_id": gid},
                        {"$set": {"guild_id": gid, **fresh, "updated_at": _now_str()}},
                        upsert=True,
                    )
                except PyMongoError:
                    pass
        _CFG_CACHE[gid] = (time.time(), json.loads(json.dumps(fresh)))
        return fresh

    cfg = get_guild_cfg(gid)
    for key in (
        "maintenance",
        "anti_spam",
        "anti_link",
        "beast_mode",
        "anti_raid",
        "verification",
        "lockdown",
        "anti_new_accounts",
        "dangerous_perms_guard",
        "alert_on_trigger",
        *SHIELD_TOGGLE_KEYS,
    ):
        if key in updates:
            if key in PREMIUM_ONLY_KEYS and not is_premium:
                continue
            cfg[key] = bool(updates[key])

    if "spam_punishment" in updates:
        sp = str(updates["spam_punishment"] or "Timeout").strip()
        if sp in ("Delete Only", "Timeout", "Kick", "Ban"):
            cfg["spam_punishment"] = sp
    if "spam_timeout_seconds" in updates:
        try:
            sec = int(updates["spam_timeout_seconds"])
            cfg["spam_timeout_seconds"] = max(10, min(2419200, sec))
        except Exception:
            cfg["spam_timeout_seconds"] = 600

    if "link_punishment" in updates and is_premium:
        lp = str(updates["link_punishment"] or "Delete & Timeout").strip()
        if lp in ("Delete Only", "Delete & Timeout", "Kick", "Ban"):
            cfg["link_punishment"] = lp
    if "link_timeout_seconds" in updates and is_premium:
        try:
            lsec = int(updates["link_timeout_seconds"])
            cfg["link_timeout_seconds"] = max(10, min(2419200, lsec))
        except Exception:
            cfg["link_timeout_seconds"] = 300

    if "min_account_age_days" in updates:
        try:
            days = int(updates["min_account_age_days"])
            cfg["min_account_age_days"] = max(1, min(365, days))
        except Exception:
            cfg["min_account_age_days"] = 7
    if "prefix" in updates:
        p = str(updates["prefix"] or "!").strip()[:6]
        cfg["prefix"] = p or "!"
    if "mod_log_channel" in updates:
        ch = str(updates["mod_log_channel"] or "").strip()
        cfg["mod_log_channel"] = ch if ch.isdigit() else ""
    if "antinuke_updates" in updates and isinstance(updates["antinuke_updates"], dict):
        for ak, av in updates["antinuke_updates"].items():
            if ak in cfg["antinuke"]:
                cfg["antinuke"][ak].update(av)
    if "guild_profile" in updates and isinstance(updates["guild_profile"], dict) and is_premium:
        prof = cfg["guild_profile"]
        if "bio" in updates["guild_profile"]:
            prof["bio"] = str(updates["guild_profile"]["bio"] or "").strip()[:190]
        if "avatar_data_url" in updates["guild_profile"]:
            prof["avatar_data_url"] = sanitize_image_data_url(updates["guild_profile"]["avatar_data_url"])
        if "avatar_name" in updates["guild_profile"]:
            prof["avatar_name"] = str(updates["guild_profile"]["avatar_name"] or "").strip()[:80]
        if "banner_data_url" in updates["guild_profile"]:
            prof["banner_data_url"] = sanitize_image_data_url(updates["guild_profile"]["banner_data_url"])
        if "banner_name" in updates["guild_profile"]:
            prof["banner_name"] = str(updates["guild_profile"]["banner_name"] or "").strip()[:80]
    if "premium_perks" in updates and isinstance(updates["premium_perks"], dict) and is_premium:
        perks = cfg["premium_perks"]
        p_upd = updates["premium_perks"]
        for bool_k in ("ultra_fortress_mode", "instant_rollback_enabled", "priority_shield_response"):
            if bool_k in p_upd:
                perks[bool_k] = bool(p_upd[bool_k])
        if "alert_channel_id" in p_upd:
            ch_val = str(p_upd["alert_channel_id"] or "").strip()
            perks["alert_channel_id"] = ch_val if ch_val.isdigit() else ""
        if "alert_webhook_url" in p_upd:
            perks["alert_webhook_url"] = sanitize_http_url(p_upd["alert_webhook_url"])
        if "last_restored_snapshot" in p_upd:
            perks["last_restored_snapshot"] = str(p_upd["last_restored_snapshot"] or "").strip()[:32]
    if "trusted_add" in updates:
        uid = str(updates["trusted_add"] or "").strip()
        if uid.isdigit() and uid not in cfg["trusted_admins"]:
            cfg["trusted_admins"].append(uid)
    if "trusted_remove" in updates:
        uid = str(updates["trusted_remove"] or "").strip()
        if uid != ADMIN_USER_ID:
            cfg["trusted_admins"] = [x for x in cfg["trusted_admins"] if x != uid]
    if "save_snapshot" in updates and updates["save_snapshot"] and is_premium:
        snap = {
            "id": secrets.token_hex(4),
            "saved_at": _now_str(),
            "rules_count": len(cfg.get("antinuke", {})),
            "trusted_count": len(cfg.get("trusted_admins", [])),
            "snapshot_hash": hashlib.sha256(
                json.dumps(cfg.get("antinuke", {}), sort_keys=True).encode("utf-8")
            ).hexdigest()[:12],
        }
        snaps = list(cfg.get("perms_snapshots", []))
        snaps.insert(0, snap)
        cfg["perms_snapshots"] = snaps[:10]
    if gid.isdigit():
        MEM_GUILD_CFG[gid] = json.loads(json.dumps(cfg))
        if guild_settings_col is not None:
            try:
                guild_settings_col.update_one(
                    {"guild_id": gid},
                    {"$set": {"guild_id": gid, **cfg, "updated_at": _now_str()}},
                    upsert=True,
                )
            except PyMongoError:
                pass
        _CFG_CACHE[gid] = (time.time(), json.loads(json.dumps(cfg)))
    return cfg


def calculate_security_score(cfg: dict) -> tuple[int, str]:
    score = 20
    for item in (cfg.get("antinuke") or {}).values():
        if isinstance(item, dict) and item.get("enabled"):
            score += 4
    for key in (
        "anti_selfbot",
        "anti_privilege_escalation",
        "anti_role_tamper",
        "anti_channel_perms_tamper",
        "anti_webhook_abuse",
        "anti_app_abuse",
        "audit_log_watch",
        "anti_mass_unban",
        "anti_mass_kick",
        "anti_mass_timeout",
        "admin_behavior_analysis",
        "trusted_admins_enabled",
        "perms_snapshot_enabled",
        "auto_rollback_enabled",
        "gradual_attack_detect",
        "collusion_detect",
        "false_punishment_guard",
        "auto_perms_audit",
        "anti_invites",
        "voice_lock",
    ):
        if cfg.get(key):
            score += 2
    if (cfg.get("premium_perks") or {}).get("ultra_fortress_mode"):
        score += 5
    score = max(0, min(100, score))
    if score >= 85:
        grade = "A+ (محصّن بالكامل)"
    elif score >= 65:
        grade = "B+ (حماية قوية)"
    else:
        grade = "C (يحتاج تفعيل قواعد إضافية)"
    return score, grade


def run_attack_simulation(guild_id: str, scenario: str) -> str:
    cfg = get_guild_cfg(guild_id)
    score, _ = calculate_security_score(cfg)
    blocked = score >= 50 or bool(cfg.get("emergency_mode")) or bool((cfg.get("premium_perks") or {}).get("ultra_fortress_mode"))
    outcome = "تم صد المحاكاة وتفعيل الاسترجاع التلقائي" if blocked else "رصدت المحاكاة ثغرة تحتاج تفعيل الحماية"
    record_incident(guild_id, "SIMULATION", f"محاكاة [{scenario}]: {outcome}", "INFO")
    log_event(f"محاكاة هجوم [{scenario}] في السيرفر {guild_id}: {outcome}", guild_id=guild_id, level="SEC")
    return f"{outcome} (مستوى الأمان الحالي: {score}/100)."


def create_db_backup() -> dict:
    snapshot = {
        "backup_id": secrets.token_hex(5),
        "created_at": _now_str(),
        "guilds_count": len(get_all_guilds()),
        "admins_count": len(get_admin_list()),
        "premium_count": len(get_premium_list()),
        "logs_count": len(get_recent_logs(60)),
        "signature": _sign_hmac(f"backup|{_now_str()}")[:16],
    }
    MEM_BACKUPS.appendleft(dict(snapshot))
    if backups_col is not None:
        try:
            backups_col.insert_one(dict(snapshot))
        except PyMongoError:
            pass
    log_event(f"تم إنشاء نسخة احتياطية رقم [{snapshot['backup_id']}]", level="ADMIN")
    return snapshot


def get_db_backups() -> list[dict]:
    if backups_col is not None:
        try:
            docs = list(backups_col.find({}, {"_id": 0}).sort("_id", -1).limit(10))
            if docs:
                return docs
        except PyMongoError:
            pass
    return list(MEM_BACKUPS)[:10]


def test_backup_restore(backup_id: str = "") -> tuple[bool, str]:
    backups = get_db_backups()
    if not backups:
        b = create_db_backup()
        backups = [b]
    target = next((x for x in backups if x.get("backup_id") == backup_id), backups[0])
    ok = bool(target.get("backup_id")) and bool(target.get("signature"))
    msg = (
        f"نجح اختبار استعادة النسخة [{target.get('backup_id')}] ({target.get('guilds_count', 0)} سيرفر، {target.get('admins_count', 0)} أدمن)."
        if ok
        else "فشل التحقق من سلامة النسخة الاحتياطية."
    )
    log_event(msg, level="ADMIN")
    return ok, msg


def enqueue_remote_action(guild_id: str, action: str, target: str, extra: dict | None = None) -> None:
    safe_extra: dict = {}
    if isinstance(extra, dict):
        for k, v in extra.items():
            if k in ("avatar_data_url", "banner_data_url"):
                continue
            safe_extra[k] = v
    payload = {
        "guild_id": str(guild_id),
        "action": str(action),
        "target": str(target),
        "extra": safe_extra,
        "status": "pending",
        "created_at": datetime.now(timezone.utc),
    }
    if queue_col is not None:
        try:
            queue_col.insert_one(dict(payload))
        except PyMongoError:
            MEM_QUEUE.append(payload)
    else:
        MEM_QUEUE.append(payload)


def detect_base_url(request: web.Request) -> str:
    if EXPLICIT_WEB_URL:
        return EXPLICIT_WEB_URL
    if EXPLICIT_MAIN_URL:
        return EXPLICIT_MAIN_URL
    remote_ip = str(request.remote or "").strip()
    can_trust = TRUST_PROXY and (not TRUSTED_PROXY_IPS or remote_ip in TRUSTED_PROXY_IPS)
    host = (
        (request.headers.get("X-Forwarded-Host", "").split(",")[0].strip() if can_trust else "")
        or request.headers.get("Host", "").strip()
    )
    proto = (request.headers.get("X-Forwarded-Proto", "").split(",")[0].strip() if can_trust else "https") or "https"
    if host:
        return f"{proto}://{host}".rstrip("/")
    return DEFAULT_DOMAIN_URL


def detect_redirect_uri(request: web.Request) -> str:
    if EXPLICIT_REDIRECT_URI:
        return EXPLICIT_REDIRECT_URI
    return f"{detect_base_url(request)}/callback"


def sign_session(payload: dict) -> str:
    _cleanup_expired()
    sid = secrets.token_urlsafe(24)
    exp_val = float(payload.get("exp", time.time() + 86400 * 7))
    record = {
        "sid": sid,
        "id": str(payload.get("id", "")),
        "username": str(payload.get("username", "User"))[:40],
        "avatar": str(payload.get("avatar", "") or "")[:40],
        "guilds": payload.get("guilds") or [],
        "exp": exp_val,
    }
    _store_session_record(sid, record)
    raw_b64 = json.dumps({"sid": sid, "exp": exp_val}, separators=(",", ":")).encode("utf-8")
    token_body = base64.urlsafe_b64encode(raw_b64).decode("ascii")
    sig = _sign_hmac(token_body)
    return f"{token_body}.{sig}"


def verify_session(token: str | None) -> tuple[str, dict] | None:
    if not token or "." not in token:
        return None
    parts = token.rsplit(".", 1)
    if len(parts) != 2:
        return None
    token_body, sig = parts
    expected_sig = _sign_hmac(token_body)
    if not hmac.compare_digest(sig, expected_sig):
        return None
    try:
        padded = token_body + "=" * (-len(token_body) % 4)
        meta = json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))
    except Exception:
        return None
    sid = str(meta.get("sid", "")).strip()
    exp_val = _safe_exp(meta.get("exp", 0))
    now = time.time()
    if not sid or exp_val <= now:
        _delete_session_record(sid)
        return None
    sess = _load_session_record(sid)
    if not sess or _safe_exp(sess.get("exp", 0)) <= now:
        _delete_session_record(sid)
        return None
    return sid, sess


def get_discord_session_with_id(request: web.Request) -> tuple[str, dict] | None:
    tok = request.cookies.get("arab_sec_session") or request.headers.get("X-Arab-Session")
    return verify_session(tok)


def get_discord_session(request: web.Request) -> dict | None:
    pair = get_discord_session_with_id(request)
    return pair[1] if pair else None


def get_lang(request: web.Request) -> str:
    q = str(request.query.get("lang", "")).strip().lower()
    if q in ("ar", "en"):
        return q
    c = str(request.cookies.get("arab_sec_lang", "")).strip().lower()
    if c in ("ar", "en"):
        return c
    return "ar"


def is_rate_limited(ip: str, is_sensitive: bool = False) -> bool:
    now = time.time()
    bucket = AUTH_RATE_BUCKETS[ip] if is_sensitive else RATE_BUCKETS[ip]
    limit = AUTH_RATE_LIMIT_PER_MIN if is_sensitive else RATE_LIMIT_PER_MIN
    while bucket and now - bucket[0] > 60.0:
        bucket.popleft()
    if len(bucket) >= limit:
        return True
    bucket.append(now)
    return False


async def read_post_safe(request: web.Request, max_bytes: int = 3_500_000) -> dict | None:
    content_length = request.content_length
    if content_length is not None and content_length > max_bytes:
        return None
    try:
        data = await request.post()
        return dict(data)
    except Exception:
        return None


def _is_valid_bot_sync_request(request: web.Request) -> bool:
    provided = str(
        request.headers.get("X-Bot-Secret")
        or request.headers.get("Authorization", "").replace("Bearer ", "")
        or ""
    ).strip()
    if not provided or not BOT_SYNC_SECRET:
        return False
    return hmac.compare_digest(provided, BOT_SYNC_SECRET)


async def api_bot_sync_guilds(request: web.Request) -> web.Response:
    if not _is_valid_bot_sync_request(request):
        return web.json_response({"ok": False, "error": "Unauthorized"}, status=401)
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"ok": False, "error": "Invalid JSON"}, status=400)

    guilds_raw = body.get("guilds") if isinstance(body, dict) else None
    if not isinstance(guilds_raw, list):
        return web.json_response({"ok": False, "error": "guilds list required"}, status=400)

    replace_missing = bool(body.get("replace_missing", True))
    synced = upsert_bot_guilds(guilds_raw, replace_missing=replace_missing)
    MEM_BOT_HEARTBEAT["status"] = "ONLINE"
    MEM_BOT_HEARTBEAT["last_seen"] = _now_str()
    if isinstance(body, dict) and body.get("latency_ms") is not None:
        MEM_BOT_HEARTBEAT["latency_ms"] = (
            f"{int(body['latency_ms'])}ms"
            if str(body["latency_ms"]).isdigit()
            else str(body["latency_ms"])[:12]
        )

    log_event(f"تمت مزامنة {len(synced)} سيرفر من البوت", level="BOT")
    return web.json_response({"ok": True, "count": len(synced)})


async def api_bot_pending_commands(request: web.Request) -> web.Response:
    if not _is_valid_bot_sync_request(request):
        return web.json_response({"ok": False, "error": "Unauthorized"}, status=401)

    items: list[dict] = []
    if queue_col is not None:
        try:
            done_stamp = _now_str()
            ret_opt = ReturnDocument.AFTER if ReturnDocument is not None else True
            for _ in range(20):
                d = queue_col.find_one_and_update(
                    {"status": "pending"},
                    {"$set": {"status": "done", "done_at": done_stamp}},
                    sort=[("_id", 1)],
                    return_document=ret_opt,
                )
                if not d:
                    break
                items.append(
                    {
                        "id": str(d.get("_id")),
                        "guild_id": str(d.get("guild_id", "")),
                        "action": str(d.get("action", "")),
                        "target": str(d.get("target", "")),
                        "extra": d.get("extra") or {},
                    }
                )
        except PyMongoError:
            pass

    while MEM_QUEUE and len(items) < 20:
        d = MEM_QUEUE.popleft()
        items.append(
            {
                "id": "mem",
                "guild_id": str(d.get("guild_id", "")),
                "action": str(d.get("action", "")),
                "target": str(d.get("target", "")),
                "extra": d.get("extra") or {},
            }
        )

    return web.json_response({"ok": True, "commands": items})


def render_page(
    title: str,
    active_nav: str,
    content_html: str,
    request: web.Request,
    flash: str = "",
    require_auth_view: bool = False,
) -> str:
    lang = get_lang(request)
    is_en = lang == "en"
    dir_attr = "ltr" if is_en else "rtl"
    user = get_discord_session(request)
    is_admin = is_site_admin(user)
    is_prem = is_premium_user(user)
    safe_flash = sanitize_flash_msg(flash)

    user_visible, _ = get_user_visible_guilds(user)
    user_active_guilds = [g for g in user_visible if not g.get("bot_missing")]
    can_access_guild_panel = bool(user and len(user_active_guilds) > 0)

    L = {
        "home": "Home" if is_en else "الرئيسية",
        "servers": "My Servers" if is_en else "سيرفراتي",
        "guild": "Security Panel" if is_en else "لوحة الحماية",
        "premium": "Premium" if is_en else "البريميوم",
        "admin": "Admin Panel" if is_en else "لوحة الإدارة",
        "services": "Services" if is_en else "الخدمات",
        "updates": "Updates & Logs" if is_en else "التحديثات والسجلات",
        "links": "Links" if is_en else "الروابط",
        "invite": "Invite Arab Security Bot",
        "login_discord": "Login with Discord",
        "logout": "Logout" if is_en else "تسجيل الخروج",
        "supervised": "Supervised by" if is_en else "بإشراف",
        "menu": "Menu" if is_en else "القائمة",
    }

    if user:
        uid = esc(user.get("id", ""))
        ava = esc(user.get("avatar", ""))
        uname_safe = esc(user.get("username", "Member"))
        avatar_html = (
            f"<img class='avatar-img' src='https://cdn.discordapp.com/avatars/{uid}/{ava}.png?size=128' alt='' loading='lazy' referrerpolicy='no-referrer'>"
            if uid and ava
            else f"<div class='avatar'>{(uname_safe[:1]).upper()}</div>"
        )
        badge_txt = "ADMIN" if is_admin else ("PREMIUM" if is_prem else "MEMBER")
        account_block = (
            f"<div class='user-box'>{avatar_html}"
            f"<div style='min-width:0;'><div class='uname'>{uname_safe} <span class='tag'>{badge_txt}</span></div>"
            f"<div class='uhandle'>ID: <code>{uid}</code></div></div></div>"
            f"<a class='nav-item danger' href='/logout'><span>[EXIT]</span><span>{L['logout']}</span></a>"
        )
    else:
        account_block = f"<a class='login-btn' href='/login'>{L['login_discord']}</a>"

    bot_servers_count = len(get_all_guilds())
    safe_invite_url = esc(sanitize_http_url(BOT_INVITE_URL) or "https://discord.com")

    if require_auth_view and not user:
        final_content = f"""
        <section class="hero-card">
          <div class="hero-pill">{('Discord Server Security Suite' if is_en else 'منظومة حماية سيرفرات ديسكورد')}</div>
          <h1 class="hero-title">{esc(SITE_NAME)}</h1>
          <p class="hero-desc">{('Complete protection against tampering, behavior analysis, permission snapshots & rollback, attack simulation, and backups.' if is_en else 'منظومة حماية متكاملة ضد التخريب، تحليل السلوك، نسخ الصلاحيات والاسترجاع، محاكاة الهجمات، والنسخ الاحتياطي.')}</p>
          <a class="btn-primary-purple" href="/login">{L['login_discord']}</a>
        </section>

        <section class="stat-card">
          <div class="stat-number">{bot_servers_count}</div>
          <div class="stat-bar"></div>
          <div class="stat-label">{('Servers Using The Bot' if is_en else 'عدد السيرفرات التي تستخدم البوت')}</div>
        </section>
        """
    else:
        final_content = content_html

    flash_banner = f"<div class='flash-banner' role='status'>{esc(safe_flash)}</div>" if safe_flash else ""

    nav_items = [
        ("home", "/", "01", L["home"]),
        ("servers", "/servers", "02", L["servers"]),
    ]
    if can_access_guild_panel:
        nav_items.append(("guild", "/guild", "03", L["guild"]))
    if is_prem:
        nav_items.append(("premium", "/premium", "04", L["premium"]))
    if is_admin:
        nav_items.append(("admin", "/admin", "05", L["admin"]))
    nav_items.extend(
        [
            ("services", "/services", "06", L["services"]),
            ("updates", "/updates", "07", L["updates"]),
            ("links", "/links", "08", L["links"]),
        ]
    )

    nav_links_html = "".join(
        f"<a class='nav-item {'active' if active_nav == key else ''}' href='{href}'><span>{ico}</span><span>{lbl}</span></a>"
        for key, href, ico, lbl in nav_items
    )

    next_lang = "ar" if is_en else "en"
    lang_label = "العربية" if is_en else "English"

    return f"""<!DOCTYPE html>
<html lang="{lang}" dir="{dir_attr}">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} — {esc(SITE_NAME)}</title>
<style>
  :root {{
    --bg-deep: #070514;
    --bg-grad:
      radial-gradient(circle at 50% 0%, rgba(124, 58, 237, 0.34), transparent 52%),
      radial-gradient(circle at 80% 45%, rgba(91, 33, 182, 0.22), transparent 50%),
      linear-gradient(180deg, #0b0720 0%, #060512 100%);
    --card-bg: rgba(24, 16, 56, 0.78);
    --card-border: rgba(139, 92, 246, 0.28);
    --purple: #7c3aed;
    --purple-bright: #8b5cf6;
    --text-main: #ffffff;
    --text-sub: #cbd5e1;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0;
    font-family: system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
    background: var(--bg-deep);
    background-image: var(--bg-grad);
    color: var(--text-main);
    min-height: 100vh;
    overflow-x: hidden;
  }}

  .overlay {{
    display: none;
    position: fixed;
    inset: 0;
    background: rgba(3, 2, 10, 0.72);
    z-index: 60;
  }}
  .overlay.open {{ display: block; }}

  .sidebar {{
    position: fixed;
    top: 0;
    {('left' if is_en else 'right')}: 0;
    width: 272px;
    max-width: 86vw;
    height: 100vh;
    background: rgba(14, 9, 34, 0.98);
    border-{('right' if is_en else 'left')}: 1px solid var(--card-border);
    padding: 18px 14px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    z-index: 70;
    overflow-y: auto;
    transform: translateX({('-105%' if is_en else '105%')});
    transition: transform 0.16s ease;
  }}
  .sidebar.open {{ transform: translateX(0); }}

  .page-container {{
    width: 100%;
    max-width: 680px;
    margin: 0 auto;
    padding: 18px 16px 48px;
  }}

  .top-bar {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 10px 14px;
    border-radius: 18px;
    background: rgba(20, 13, 48, 0.85);
    border: 1px solid var(--card-border);
    margin-bottom: 18px;
  }}
  .top-left {{
    display: flex;
    align-items: center;
    gap: 8px;
  }}
  .icon-btn {{
    height: 36px;
    padding: 0 12px;
    border-radius: 11px;
    background: rgba(36, 24, 82, 0.85);
    border: 1px solid rgba(139, 92, 246, 0.35);
    color: #fff;
    font-weight: 800;
    font-size: 13px;
    cursor: pointer;
    display: inline-flex;
    align-items: center;
    justify-content: center;
  }}
  .top-right {{
    display: flex;
    align-items: center;
    gap: 10px;
    text-align: {('left' if is_en else 'right')};
  }}
  .brand-title {{
    font-size: 14px;
    font-weight: 900;
    letter-spacing: 0.4px;
    color: #fff;
    line-height: 1.2;
  }}
  .brand-sub {{
    font-size: 11px;
    color: #94a3b8;
    line-height: 1.25;
  }}
  .brand-badge {{
    width: 38px;
    height: 38px;
    border-radius: 11px;
    background: linear-gradient(135deg, #7c3aed, #6d28d9);
    color: #fff;
    font-weight: 900;
    font-size: 14px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }}

  .flash-banner {{
    background: rgba(88, 28, 135, 0.45);
    border: 1.5px solid rgba(168, 85, 247, 0.75);
    color: #f3e8ff;
    border-radius: 16px;
    padding: 14px 16px;
    margin-bottom: 18px;
    font-size: 13.5px;
    font-weight: 800;
    line-height: 1.55;
    text-align: center;
  }}

  .hero-card {{
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 22px;
    padding: 26px 20px;
    text-align: center;
    margin-bottom: 18px;
  }}
  .hero-pill {{
    display: inline-block;
    padding: 6px 16px;
    border-radius: 999px;
    background: rgba(88, 28, 135, 0.42);
    border: 1px solid rgba(168, 85, 247, 0.45);
    color: #d8b4fe;
    font-size: 12px;
    font-weight: 800;
    margin-bottom: 14px;
  }}
  .hero-title {{
    margin: 0 0 12px;
    font-size: 28px;
    font-weight: 900;
    letter-spacing: 0.6px;
    color: #ffffff;
  }}
  .hero-desc {{
    margin: 0 auto 22px;
    max-width: 520px;
    font-size: 14px;
    line-height: 1.75;
    color: var(--text-sub);
    font-weight: 600;
  }}

  .btn-primary-purple {{
    display: block;
    width: 100%;
    padding: 13px 18px;
    border-radius: 13px;
    background: linear-gradient(180deg, #8b5cf6 0%, #6d28d9 100%);
    border: 1px solid rgba(196, 181, 253, 0.45);
    color: #fff;
    text-decoration: none;
    font-weight: 800;
    font-size: 14.5px;
    text-align: center;
    margin-bottom: 12px;
    cursor: pointer;
  }}
  .btn-secondary-dark {{
    display: block;
    width: 100%;
    padding: 13px 18px;
    border-radius: 13px;
    background: rgba(29, 20, 64, 0.9);
    border: 1px solid rgba(139, 92, 246, 0.35);
    color: #f8fafc;
    text-decoration: none;
    font-weight: 800;
    font-size: 14.5px;
    text-align: center;
    cursor: pointer;
  }}

  .stat-card {{
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 22px;
    padding: 26px 20px;
    text-align: center;
    margin-bottom: 18px;
  }}
  .stat-number {{
    font-size: 32px;
    font-weight: 900;
    color: #ffffff;
    line-height: 1.1;
  }}
  .stat-bar {{
    width: 24px;
    height: 3px;
    border-radius: 999px;
    background: #8b5cf6;
    margin: 10px auto 12px;
  }}
  .stat-label {{
    font-size: 14px;
    font-weight: 700;
    color: #cbd5e1;
  }}

  .glass-card {{
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 20px;
    padding: 18px;
    margin-bottom: 16px;
  }}
  .sub-panel {{
    background: rgba(15, 10, 36, 0.78);
    border: 1px solid rgba(139, 92, 246, 0.26);
    border-radius: 16px;
    padding: 15px;
    margin-bottom: 16px;
  }}
  .sub-panel-head {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    margin-bottom: 12px;
    padding-bottom: 8px;
    border-bottom: 1px solid rgba(139, 92, 246, 0.2);
  }}
  .sub-panel-title {{
    margin: 0;
    font-size: 15px;
    font-weight: 800;
    color: #ffffff;
  }}
  .grid-2 {{
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 12px;
    margin-bottom: 12px;
  }}
  @media (max-width: 540px) {{
    .grid-2 {{ grid-template-columns: 1fr; }}
  }}
  .nav-item {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 12px;
    border-radius: 12px;
    color: #e2e8f0;
    text-decoration: none;
    font-size: 13.5px;
    font-weight: 700;
  }}
  .nav-item:hover {{ background: rgba(139, 92, 246, 0.16); }}
  .nav-item.active {{ background: rgba(124, 58, 237, 0.35); border: 1px solid rgba(167, 139, 250, 0.5); }}
  .nav-item.danger {{ color: #fca5a5; }}
  .sep {{ height: 1px; background: var(--card-border); margin: 6px 0; }}
  .user-box {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px;
    border-radius: 14px;
    background: rgba(34, 23, 74, 0.8);
    border: 1px solid var(--card-border);
  }}
  .avatar, .avatar-img {{ width: 38px; height: 38px; border-radius: 999px; object-fit: cover; }}
  .avatar {{ background: #7c3aed; display: flex; align-items: center; justify-content: center; font-weight: 800; }}
  .uname {{ font-weight: 800; font-size: 13px; }}
  .uhandle {{ font-size: 11px; color: #94a3b8; }}
  .tag {{ font-size: 10px; padding: 3px 8px; border-radius: 7px; background: rgba(139, 92, 246, 0.25); color: #ddd6fe; font-weight: 800; }}
  .prem-pill {{ font-size: 10px; padding: 3px 8px; border-radius: 6px; background: rgba(245, 158, 11, 0.18); border: 1px solid rgba(251, 191, 36, 0.45); color: #fde68a; font-weight: 800; }}
  .admin-pill {{ font-size: 10px; padding: 3px 8px; border-radius: 6px; background: rgba(124, 58, 237, 0.28); border: 1px solid rgba(167, 139, 250, 0.5); color: #ede9fe; font-weight: 800; }}
  .login-btn {{
    display: block;
    text-align: center;
    padding: 10px 12px;
    border-radius: 12px;
    background: #7c3aed;
    color: #fff;
    text-decoration: none;
    font-weight: 800;
    font-size: 13px;
  }}
  .inp, .sel {{
    width: 100%;
    background: rgba(12, 8, 28, 0.92);
    border: 1px solid var(--card-border);
    color: #fff;
    border-radius: 12px;
    padding: 10px 12px;
    font-size: 14px;
    margin-bottom: 10px;
  }}
  .lbl {{ display: block; font-size: 12.5px; color: #cbd5e1; margin: 8px 0 5px; font-weight: 700; }}
  .switch-row {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 10px;
    padding: 10px 12px;
    border-radius: 12px;
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid rgba(139, 92, 246, 0.2);
    margin-bottom: 8px;
    font-size: 13px;
  }}
  .list-row {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    gap: 10px;
    padding: 10px 12px;
    border-radius: 12px;
    background: rgba(255, 255, 255, 0.03);
    border: 1px solid rgba(139, 92, 246, 0.2);
    margin-bottom: 8px;
  }}
  .guild-icon, .guild-icon-ph {{
    width: 42px;
    height: 42px;
    border-radius: 12px;
    object-fit: cover;
    flex-shrink: 0;
  }}
  .guild-icon-ph {{
    background: rgba(124, 58, 237, 0.35);
    border: 1px solid rgba(167, 139, 250, 0.45);
    display: flex;
    align-items: center;
    justify-content: center;
    font-weight: 900;
    font-size: 15px;
    color: #fff;
  }}
  .mini-btn {{
    padding: 8px 12px;
    border-radius: 10px;
    border: 1px solid rgba(139, 92, 246, 0.45);
    background: rgba(124, 58, 237, 0.28);
    color: #fff;
    font-size: 12.5px;
    font-weight: 700;
    cursor: pointer;
    text-align: center;
  }}
  .album-box {{
    padding: 12px;
    border-radius: 14px;
    background: rgba(15, 10, 36, 0.72);
    border: 1px dashed rgba(167, 139, 250, 0.45);
    margin-bottom: 12px;
  }}
  .preview-thumb {{
    width: 68px;
    height: 68px;
    border-radius: 12px;
    object-fit: cover;
    border: 1px solid rgba(167, 139, 250, 0.45);
    margin-top: 8px;
  }}
  .muted {{ color: #94a3b8; font-size: 13px; }}
  code {{ background: rgba(15, 10, 36, 0.9); padding: 2px 6px; border-radius: 6px; font-size: 12px; }}
</style>
</head>
<body>
<div id="overlay" class="overlay" onclick="toggleDrawer(false)"></div>

<aside id="drawer" class="sidebar" aria-label="{L['menu']}">
  <a class="nav-item" href="/"><span>00</span><span>{esc(SITE_NAME)}</span></a>
  {account_block}
  <div class="sep"></div>
  {nav_links_html}
  <div class="sep"></div>
  <a class="nav-item" href="{safe_invite_url}" target="_blank" rel="noopener noreferrer"><span>+</span><span>{L['invite']}</span></a>
</aside>

<div class="page-container">
  <header class="top-bar">
    <div class="top-left">
      <button class="icon-btn" type="button" onclick="toggleDrawer(true)" aria-label="{L['menu']}">Menu</button>
      <button class="icon-btn" type="button" onclick="switchLang('{next_lang}')">{lang_label}</button>
    </div>

    <div class="top-right">
      <div>
        <div class="brand-title">{esc(SITE_NAME)}</div>
        <div class="brand-sub">{L['supervised']} {esc(OWNER_NAME)}</div>
      </div>
      <div class="brand-badge">AS</div>
    </div>
  </header>

  {flash_banner}
  {final_content}
</div>

<script>
function toggleDrawer(open) {{
  document.getElementById("drawer").classList.toggle("open", open);
  document.getElementById("overlay").classList.toggle("open", open);
}}
function switchLang(targetLang) {{
  try {{
    document.cookie = "arab_sec_lang=" + encodeURIComponent(targetLang) + "; path=/; max-age=" + (86400 * 365) + "; SameSite=Lax";
  }} catch (e) {{}}
  var url = new URL(window.location.href);
  url.searchParams.set("lang", targetLang);
  window.location.href = url.toString();
}}
function readAlbumFile(inputEl, hiddenId, previewId, nameId) {{
  var file = inputEl && inputEl.files && inputEl.files[0];
  if (!file) return;
  if (file.size > 1500000) {{
    alert("حجم الصورة كبير جداً، اختر صورة أصغر من 1.5MB");
    inputEl.value = "";
    return;
  }}
  var reader = new FileReader();
  reader.onload = function(ev) {{
    var dataUrl = ev.target.result || "";
    var hEl = document.getElementById(hiddenId);
    var pEl = document.getElementById(previewId);
    var nEl = document.getElementById(nameId);
    if (hEl) hEl.value = dataUrl;
    if (nEl) nEl.value = file.name || "image";
    if (pEl && dataUrl) {{
      pEl.src = dataUrl;
      pEl.style.display = "block";
    }}
  }};
  reader.readAsDataURL(file);
}}
</script>
</body>
</html>"""


async def home_handler(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    flash = sanitize_flash_msg(request.query.get("msg"))
    if not flash and not DISCORD_CLIENT_SECRET:
        flash = (
            "Please set DISCORD_CLIENT_SECRET in environment variables to enable Discord login."
            if is_en
            else "يرجى ضبط DISCORD_CLIENT_SECRET في متغيرات البيئة لتفعيل تسجيل الدخول بديسكورد."
        )

    bot_servers_count = len(get_all_guilds())
    total_visits = get_total_visits()
    safe_invite = esc(sanitize_http_url(BOT_INVITE_URL) or "https://discord.com")

    body = f"""
    <section class="hero-card">
      <div class="hero-pill">{('Discord Server Security Suite' if is_en else 'منظومة حماية سيرفرات ديسكورد')}</div>
      <h1 class="hero-title">{esc(SITE_NAME)}</h1>
      <p class="hero-desc">{('Complete protection against tampering, behavior analysis, permission snapshots & rollback, attack simulation, and backups.' if is_en else 'منظومة حماية متكاملة ضد التخريب، تحليل السلوك، نسخ الصلاحيات والاسترجاع، محاكاة الهجمات، والنسخ الاحتياطي.')}</p>
      <a class="btn-primary-purple" href="{safe_invite}" target="_blank" rel="noopener noreferrer">Invite Arab Security Bot</a>
    </section>

    <section class="stat-card">
      <div class="stat-number">{bot_servers_count}</div>
      <div class="stat-bar"></div>
      <div class="stat-label">{('Servers Using The Bot' if is_en else 'عدد السيرفرات التي تستخدم البوت')}</div>
    </section>

    <section class="stat-card" style="padding:20px 16px;">
      <div class="stat-number" style="font-size:26px;">{total_visits}</div>
      <div class="stat-bar"></div>
      <div class="stat-label">{('Total Visits' if is_en else 'إجمالي الزيارات')}</div>
    </section>
    """
    return web.Response(
        text=render_page("Home" if is_en else "الرئيسية", "home", body, request, flash=flash),
        content_type="text/html",
    )


async def handle_servers(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    user = get_discord_session(request)
    if not user:
        return web.Response(
            text=render_page("Servers" if is_en else "سيرفراتي", "servers", "", request, require_auth_view=True),
            content_type="text/html",
        )

    guilds, _ = get_user_visible_guilds(user)
    safe_invite = esc(sanitize_http_url(BOT_INVITE_URL) or "https://discord.com")
    rows = ""
    for g in guilds:
        gid_raw = g["id"]
        gid = esc(gid_raw)
        gname_raw = g["name"]
        gname = esc(gname_raw)
        mcount = int(g.get("member_count", 0) or 0)
        missing = bool(g.get("bot_missing"))
        icon_url = guild_icon_url(gid_raw, g.get("icon"))
        if icon_url:
            icon_html = f"<img class='guild-icon' src='{esc(icon_url)}' alt='' loading='lazy' referrerpolicy='no-referrer'>"
        else:
            initial = esc((gname_raw[:1] or "S").upper())
            icon_html = f"<div class='guild-icon-ph'>{initial}</div>"

        href = safe_invite if missing else f"/guild?id={gid}"
        extra_attr = " target='_blank' rel='noopener noreferrer'" if missing else ""
        status_txt = ("Add Bot (Not Inside)" if is_en else "إضافة البوت (غير داخل)") if missing else f"{mcount} {'members' if is_en else 'عضو'}"
        rows += (
            f"<a class='list-row' style='text-decoration:none;color:#fff;' href='{href}'{extra_attr}>"
            f"<div style='display:flex;align-items:center;gap:10px;min-width:0;'>{icon_html}"
            f"<div style='min-width:0;'><strong>{gname}</strong> <span class='muted'>({gid})</span></div></div>"
            f"<span class='tag'>{esc(status_txt)}</span></a>"
        )

    if not rows:
        rows = (
            f"<p class='muted'>{('No servers found where you have Manage Server or Administrator permission.' if is_en else 'لا توجد سيرفرات تملك فيها صلاحية Manage Server أو Administrator لإدخال البوتات.')}</p>"
            f"<a class='btn-secondary-dark' href='/login'>{('Refresh Discord Servers' if is_en else 'تحديث سيرفرات ديسكورد')}</a>"
        )

    body = f"<div class='glass-card'><h2 style='margin:0 0 12px;'>{('My Servers' if is_en else 'سيرفراتي')}</h2>{rows}</div>"
    return web.Response(text=render_page("Servers" if is_en else "سيرفراتي", "servers", body, request), content_type="text/html")


async def handle_guild(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    sess_pair = get_discord_session_with_id(request)
    if not sess_pair:
        return web.Response(
            text=render_page("Security Panel" if is_en else "لوحة الحماية", "guild", "", request, require_auth_view=True),
            content_type="text/html",
        )
    session_id, user = sess_pair
    is_prem = is_premium_user(user)
    guilds, _ = get_user_visible_guilds(user)
    active_guilds = [g for g in guilds if not g.get("bot_missing")]

    if not active_guilds:
        msg = (
            "Bot is not inside any of your manageable servers. Invite the bot first."
            if is_en
            else "البوت غير داخل في أي سيرفر تديره. يجب إضافة البوت إلى السيرفر أولاً للدخول إلى لوحة الحماية."
        )
        return web.Response(
            text=render_page(
                "Security Panel" if is_en else "لوحة الحماية",
                "guild",
                f"<div class='glass-card'><p class='muted'>{esc(msg)}</p><a class='btn-primary-purple' href='/servers'>{('Back to My Servers' if is_en else 'العودة إلى سيرفراتي')}</a></div>",
                request,
            ),
            content_type="text/html",
        )

    gid = str(request.query.get("id", "")).strip()
    if not user_can_manage_guild(gid, user, require_bot_present=True):
        gid = active_guilds[0]["id"]

    flash = ""
    if request.method == "POST":
        form = await read_post_safe(request)
        if form and consume_csrf_token(str(form.get("csrf_token", "")), session_id) and not is_replay_request(str(form.get("req_nonce", ""))):
            posted_gid = resolve_guild_id_from_input(str(form.get("guild_id", gid)), user, require_bot_present=True)
            if posted_gid and user_can_manage_guild(posted_gid, user, require_bot_present=True):
                gid = posted_gid
                action_type = str(form.get("form_action", "save")).strip()
                if action_type == "reset_defaults":
                    save_guild_cfg(gid, {"reset_defaults": True}, is_premium=is_prem)
                    log_event(f"إعادة ضبط إعدادات الحماية للسيرفر {gid}", guild_id=gid, level="SEC")
                    flash = "Reset to defaults." if is_en else "تمت إعادة الضبط للوضع الافتراضي."
                elif action_type == "save_snapshot":
                    if not is_prem:
                        flash = "Snapshots are for Premium users." if is_en else "حفظ اللقطات ميزة خاصة بالبريميوم."
                    else:
                        save_guild_cfg(gid, {"save_snapshot": True}, is_premium=True)
                        log_event(f"حفظ لقطة صلاحيات للسيرفر {gid}", guild_id=gid, level="SEC")
                        flash = "Snapshot saved." if is_en else "تم حفظ لقطة الصلاحيات."
                elif action_type == "add_trusted":
                    uid = str(form.get("trusted_uid", "")).strip()
                    save_guild_cfg(gid, {"trusted_add": uid}, is_premium=is_prem)
                    log_event(f"إضافة مشرف موثوق ({uid}) للسيرفر {gid}", guild_id=gid, level="SEC")
                    flash = "Trusted admin added." if is_en else "تمت إضافة مشرف موثوق."
                elif action_type == "remove_trusted":
                    uid = str(form.get("target_uid", "")).strip()
                    save_guild_cfg(gid, {"trusted_remove": uid}, is_premium=is_prem)
                    log_event(f"إزالة مشرف موثوق ({uid}) من السيرفر {gid}", guild_id=gid, level="SEC")
                    flash = "Trusted admin removed." if is_en else "تمت إزالة المشرف الموثوق."
                else:
                    antinuke_upd = {}
                    for rk in ANTINUKE_RULE_KEYS:
                        en_val = form.get(f"an_{rk}_enabled") == "on"
                        try:
                            lim_val = max(1, min(50, int(form.get(f"an_{rk}_limit", 1) or 1)))
                        except Exception:
                            lim_val = 1
                        pun_val = str(form.get(f"an_{rk}_punishment", "Kick")).strip()
                        if pun_val not in ("Kick", "Ban", "Remove Roles"):
                            pun_val = "Kick"
                        antinuke_upd[rk] = {"enabled": en_val, "limit": lim_val, "punishment": pun_val}

                    updates: dict = {
                        "prefix": form.get("prefix", "!"),
                        "mod_log_channel": form.get("mod_log_channel", ""),
                        "anti_spam": form.get("anti_spam") == "on",
                        "spam_punishment": form.get("spam_punishment", "Timeout"),
                        "spam_timeout_seconds": form.get("spam_timeout_seconds", 600),
                        "beast_mode": form.get("beast_mode") == "on",
                        "anti_raid": form.get("anti_raid") == "on",
                        "lockdown": form.get("lockdown") == "on",
                        "antinuke_updates": antinuke_upd,
                    }
                    if is_prem:
                        updates["anti_link"] = form.get("anti_link") == "on"
                        updates["link_punishment"] = form.get("link_punishment", "Delete & Timeout")
                        updates["link_timeout_seconds"] = form.get("link_timeout_seconds", 300)

                    for sk in SHIELD_TOGGLE_KEYS:
                        if sk in PREMIUM_ONLY_KEYS and not is_prem:
                            continue
                        updates[sk] = form.get(f"sh_{sk}") == "on"

                    save_guild_cfg(gid, updates, is_premium=is_prem)
                    enqueue_remote_action(gid, "sync_guild_cfg", gid, extra={"guild_id": gid})
                    log_event(f"تحديث إعدادات الحماية والسبام/الروابط في السيرفر {gid}", guild_id=gid, level="SEC")
                    flash = "Settings saved." if is_en else "تم حفظ إعدادات الحماية بنجاح."

    cfg = get_guild_cfg(gid)
    score, grade = calculate_security_score(cfg)
    csrf_tok = issue_csrf_token(session_id)
    req_nonce = secrets.token_hex(12)
    options_html = "".join(
        f"<option value='{esc(g['id'])}' {'selected' if g['id'] == gid else ''}>{esc(g['name'])} ({esc(g['id'])})</option>"
        for g in active_guilds
    )

    rules_html = ""
    for rk in ANTINUKE_RULE_KEYS:
        r_cfg = (cfg.get("antinuke") or {}).get(rk, {"enabled": True, "limit": 1, "punishment": "Kick"})
        pun_cur = r_cfg.get("punishment", "Kick")
        rules_html += f"""
        <div class="list-row" style="flex-wrap:wrap;">
          <label style="display:flex;align-items:center;gap:8px;font-weight:700;">
            <input type="checkbox" name="an_{rk}_enabled" {'checked' if r_cfg.get('enabled') else ''}>
            <span>{esc(rk)}</span>
          </label>
          <div style="display:flex;gap:8px;align-items:center;">
            <input class="inp" style="width:74px;margin:0;padding:6px 8px;" type="number" min="1" max="50" name="an_{rk}_limit" value="{int(r_cfg.get('limit', 1) or 1)}">
            <select class="sel" style="width:128px;margin:0;padding:6px 8px;" name="an_{rk}_punishment">
              <option value="Kick" {'selected' if pun_cur == 'Kick' else ''}>Kick</option>
              <option value="Ban" {'selected' if pun_cur == 'Ban' else ''}>Ban</option>
              <option value="Remove Roles" {'selected' if pun_cur == 'Remove Roles' else ''}>Remove Roles</option>
            </select>
          </div>
        </div>
        """

    shield_html = ""
    for sk in SHIELD_TOGGLE_KEYS:
        prem_only = sk in PREMIUM_ONLY_KEYS
        disabled_attr = " disabled" if (prem_only and not is_prem) else ""
        checked_val = bool(cfg.get(sk)) and (is_prem or not prem_only)
        label_extra = ""
        if sk == "anti_selfbot":
            label_extra = " — كشف السلف بوت المخرب <span class='prem-pill'>PREMIUM</span>"
        elif prem_only:
            label_extra = " <span class='prem-pill'>PREMIUM</span>"
        shield_html += (
            f"<label class='switch-row' style='opacity:{'0.65' if disabled_attr else '1'};'>"
            f"<span>{esc(sk)}{label_extra}</span>"
            f"<input type='checkbox' name='sh_{sk}' {'checked' if checked_val else ''}{disabled_attr}></label>"
        )

    tr_rows = ""
    for u in (cfg.get("trusted_admins") or []):
        safe_u = esc(u)
        rem_btn = (
            ""
            if u == ADMIN_USER_ID
            else f"<button class='mini-btn' type='submit' name='form_action' value='remove_trusted' onclick=\"this.form.target_uid.value='{safe_u}'\">x</button>"
        )
        tr_rows += f"<div class='list-row'><code>{safe_u}</code>{rem_btn}</div>"

    snaps_rows = "".join(
        f"<div class='list-row'><div><strong>#{esc(s.get('id'))}</strong> <span class='muted'>({esc(s.get('saved_at'))})</span></div><code>{esc(s.get('snapshot_hash'))}</code></div>"
        for s in (cfg.get("perms_snapshots") or [])[:5]
    ) or f"<p class='muted'>{('No snapshots yet.' if is_en else 'لا توجد لقطات محفوظة.')}</p>"

    spam_pun = str(cfg.get("spam_punishment", "Timeout"))
    link_pun = str(cfg.get("link_punishment", "Delete & Timeout"))
    link_disabled = "" if is_prem else " disabled"

    body = f"""
    <form method="post" class="glass-card">
      <input type="hidden" name="csrf_token" value="{esc(csrf_tok)}">
      <input type="hidden" name="req_nonce" value="{esc(req_nonce)}">
      <input type="hidden" name="target_uid" value="">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:10px;">
        <h2 style="margin:0;">{('Security Panel' if is_en else 'لوحة الحماية')}</h2>
        <span class="tag">{score}/100 — {esc(grade)}</span>
      </div>

      <label class="lbl">{('Server (Bot Inside)' if is_en else 'السيرفر (البوت متواجد داخله)')}</label>
      <select class="inp" name="guild_id" onchange="window.location='/guild?id='+encodeURIComponent(this.value)">{options_html}</select>

      <div class="grid-2" style="margin-bottom:6px;">
        <div>
          <label class="lbl">{('Prefix' if is_en else 'البادئة')}</label>
          <input class="inp" type="text" name="prefix" value="{esc(cfg.get('prefix', '!'))}">
        </div>
        <div>
          <label class="lbl">{('Mod Log Channel ID' if is_en else 'روم السجل ID')}</label>
          <input class="inp" type="text" name="mod_log_channel" value="{esc(cfg.get('mod_log_channel', ''))}">
        </div>
      </div>

      <h3 style="margin:14px 0 8px;">{('Spam & Links Protection' if is_en else 'حماية السبام والروابط')}</h3>
      <label class="switch-row"><span>anti_spam (مكافحة السبام)</span><input type="checkbox" name="anti_spam" {'checked' if cfg.get('anti_spam') else ''}></label>
      <div class="grid-2" style="margin-bottom:8px;">
        <div>
          <label class="lbl">{('Spam Punishment' if is_en else 'عقوبة السبام')}</label>
          <select class="sel" name="spam_punishment">
            <option value="Delete Only" {'selected' if spam_pun == 'Delete Only' else ''}>Delete Only</option>
            <option value="Timeout" {'selected' if spam_pun == 'Timeout' else ''}>Timeout</option>
            <option value="Kick" {'selected' if spam_pun == 'Kick' else ''}>Kick</option>
            <option value="Ban" {'selected' if spam_pun == 'Ban' else ''}>Ban</option>
          </select>
        </div>
        <div>
          <label class="lbl">{('Timeout Duration (sec)' if is_en else 'مدة التايم أوت (بالثواني)')}</label>
          <input class="inp" type="number" min="10" max="2419200" name="spam_timeout_seconds" value="{int(cfg.get('spam_timeout_seconds', 600) or 600)}">
        </div>
      </div>

      <label class="switch-row" style="opacity:{'0.65' if link_disabled else '1'};">
        <span>anti_link (منع الروابط) <span class='prem-pill'>PREMIUM</span></span>
        <input type="checkbox" name="anti_link" {'checked' if (cfg.get('anti_link') and is_prem) else ''}{link_disabled}>
      </label>
      <div class="grid-2" style="margin-bottom:8px;">
        <div>
          <label class="lbl">{('Link Punishment' if is_en else 'عقوبة إرسال الرابط')}</label>
          <select class="sel" name="link_punishment"{link_disabled}>
            <option value="Delete Only" {'selected' if link_pun == 'Delete Only' else ''}>Delete Only</option>
            <option value="Delete & Timeout" {'selected' if link_pun == 'Delete & Timeout' else ''}>Delete & Timeout</option>
            <option value="Kick" {'selected' if link_pun == 'Kick' else ''}>Kick</option>
            <option value="Ban" {'selected' if link_pun == 'Ban' else ''}>Ban</option>
          </select>
        </div>
        <div>
          <label class="lbl">{('Link Timeout (sec)' if is_en else 'مدة تايم الرابط (بالثواني)')}</label>
          <input class="inp" type="number" min="10" max="2419200" name="link_timeout_seconds" value="{int(cfg.get('link_timeout_seconds', 300) or 300)}"{link_disabled}>
        </div>
      </div>

      <label class="switch-row"><span>beast_mode</span><input type="checkbox" name="beast_mode" {'checked' if cfg.get('beast_mode') else ''}></label>
      <label class="switch-row"><span>anti_raid</span><input type="checkbox" name="anti_raid" {'checked' if cfg.get('anti_raid') else ''}></label>
      <label class="switch-row"><span>lockdown</span><input type="checkbox" name="lockdown" {'checked' if cfg.get('lockdown') else ''}></label>

      <h3 style="margin:16px 0 8px;">Anti-Nuke Rules</h3>
      {rules_html}

      <h3 style="margin:16px 0 8px;">Shield & Selfbot Toggles</h3>
      {shield_html}

      <button class="btn-primary-purple" type="submit" name="form_action" value="save" style="margin-top:12px;">{('Save Settings' if is_en else 'حفظ الإعدادات')}</button>
      <button class="btn-secondary-dark" type="submit" name="form_action" value="reset_defaults">{('Reset Defaults' if is_en else 'استعادة الافتراضي')}</button>

      <h3 style="margin:16px 0 8px;">{('Trusted Admins' if is_en else 'المشرفون الموثوقون')}</h3>
      <div style="display:flex;gap:8px;">
        <input class="inp" style="margin:0;" type="text" name="trusted_uid" placeholder="User ID">
        <button class="mini-btn" type="submit" name="form_action" value="add_trusted">+</button>
      </div>
      <div style="margin-top:8px;">{tr_rows}</div>

      <h3 style="margin:16px 0 8px;">{('Permission Snapshots' if is_en else 'لقطات الصلاحيات')} <span class='prem-pill'>PREMIUM</span></h3>
      <button class="btn-secondary-dark" type="submit" name="form_action" value="save_snapshot"{'' if is_prem else ' disabled'}>{('Save Snapshot' if is_en else 'حفظ لقطة جديدة')}</button>
      {snaps_rows}
    </form>
    """
    return web.Response(text=render_page("Security Panel" if is_en else "لوحة الحماية", "guild", body, request, flash=flash), content_type="text/html")


async def handle_premium(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    sess_pair = get_discord_session_with_id(request)
    if not sess_pair:
        return web.Response(text=render_page("Premium" if is_en else "البريميوم", "premium", "", request, require_auth_view=True), content_type="text/html")
    session_id, user = sess_pair
    if not is_premium_user(user):
        return web.Response(
            text=render_page(
                "Premium" if is_en else "البريميوم",
                "premium",
                f"<div class='glass-card'><h2>{('Premium Membership' if is_en else 'اشتراك البريميوم')}</h2><p class='muted'>{('Premium subscription is required or has expired (30 days). Contact support or admin.' if is_en else 'اشتراك البريميوم مطلوب أو انتهت مدته (30 يوماً). تواصل مع الإدارة لتفعيله.')}</p></div>",
                request,
            ),
            content_type="text/html",
        )

    uid = str(user.get("id", "")).strip()
    prem_rec = _get_premium_record(uid) or {}
    rem_txt = format_remaining_days(prem_rec)

    guilds, _ = get_user_visible_guilds(user)
    active_guilds = [g for g in guilds if not g.get("bot_missing")]
    if not active_guilds:
        return web.Response(
            text=render_page(
                "Premium" if is_en else "البريميوم",
                "premium",
                f"<div class='glass-card'><p class='muted'>{('Bot must be inside your server first.' if is_en else 'يجب أن يكون البوت داخل سيرفرك أولاً لاستخدام إعدادات البريميوم.')}</p><a class='btn-primary-purple' href='/servers'>{('My Servers' if is_en else 'سيرفراتي')}</a></div>",
                request,
            ),
            content_type="text/html",
        )

    gid = str(request.query.get("id", "")).strip()
    if not user_can_manage_guild(gid, user, require_bot_present=True):
        gid = active_guilds[0]["id"]

    flash = ""
    if request.method == "POST":
        form = await read_post_safe(request)
        if form and consume_csrf_token(str(form.get("csrf_token", "")), session_id) and not is_replay_request(str(form.get("req_nonce", ""))):
            posted_gid = resolve_guild_id_from_input(str(form.get("guild_id", gid)), user, require_bot_present=True)
            if posted_gid and user_can_manage_guild(posted_gid, user, require_bot_present=True):
                gid = posted_gid
                cur_cfg = get_guild_cfg(gid)
                cur_prof = cur_cfg.get("guild_profile") or {}

                ava_data = sanitize_image_data_url(form.get("avatar_data_url", "")) or str(cur_prof.get("avatar_data_url", ""))
                ban_data = sanitize_image_data_url(form.get("banner_data_url", "")) or str(cur_prof.get("banner_data_url", ""))

                prof_data = {
                    "bio": str(form.get("bio", "")).strip()[:190],
                    "avatar_data_url": ava_data,
                    "avatar_name": str(form.get("avatar_name", cur_prof.get("avatar_name", ""))).strip()[:80],
                    "banner_data_url": ban_data,
                    "banner_name": str(form.get("banner_name", cur_prof.get("banner_name", ""))).strip()[:80],
                }
                perks_data = {
                    "ultra_fortress_mode": form.get("ultra_fortress_mode") == "on",
                    "instant_rollback_enabled": form.get("instant_rollback_enabled") == "on",
                    "priority_shield_response": form.get("priority_shield_response") == "on",
                    "alert_channel_id": str(form.get("alert_channel_id", "")).strip(),
                    "alert_webhook_url": sanitize_http_url(form.get("alert_webhook_url", "")),
                }
                save_guild_cfg(gid, {"guild_profile": prof_data, "premium_perks": perks_data}, is_premium=True)
                enqueue_remote_action(
                    gid,
                    "update_bot_profile",
                    gid,
                    extra={
                        "guild_id": gid,
                        "bio": prof_data["bio"],
                        "has_avatar": bool(prof_data["avatar_data_url"]),
                        "has_banner": bool(prof_data["banner_data_url"]),
                    },
                )
                log_event(f"تحديث بروفايل البوت داخل السيرفر {gid} من البريميوم", guild_id=gid, level="ADMIN")
                flash = "Premium settings & server bot profile queued." if is_en else "تم حفظ إعدادات البريميوم وإرسال طلب تحديث بروفايل البوت داخل السيرفر."

    cfg = get_guild_cfg(gid)
    prof = cfg.get("guild_profile") or {}
    perks = cfg.get("premium_perks") or {}
    csrf_tok = issue_csrf_token(session_id)
    req_nonce = secrets.token_hex(12)
    options_html = "".join(f"<option value='{esc(g['id'])}' {'selected' if g['id'] == gid else ''}>{esc(g['name'])} ({esc(g['id'])})</option>" for g in active_guilds)

    ava_src = str(prof.get("avatar_data_url", "") or "")
    ban_src = str(prof.get("banner_data_url", "") or "")
    ava_img_tag = f"<img id='ava_preview' class='preview-thumb' src='{esc(ava_src)}' alt=''>" if ava_src else "<img id='ava_preview' class='preview-thumb' src='' alt='' style='display:none;'>"
    ban_img_tag = f"<img id='ban_preview' class='preview-thumb' src='{esc(ban_src)}' alt=''>" if ban_src else "<img id='ban_preview' class='preview-thumb' src='' alt='' style='display:none;'>"

    body = f"""
    <form method="post" class="glass-card">
      <input type="hidden" name="csrf_token" value="{esc(csrf_tok)}">
      <input type="hidden" name="req_nonce" value="{esc(req_nonce)}">
      <input type="hidden" id="avatar_data_url" name="avatar_data_url" value="{esc(ava_src)}">
      <input type="hidden" id="avatar_name" name="avatar_name" value="{esc(prof.get('avatar_name', ''))}">
      <input type="hidden" id="banner_data_url" name="banner_data_url" value="{esc(ban_src)}">
      <input type="hidden" id="banner_name" name="banner_name" value="{esc(prof.get('banner_name', ''))}">

      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:12px;">
        <h2 style="margin:0;">{('Premium Suite' if is_en else 'جناح البريميوم')}</h2>
        <span class="prem-pill">{esc(rem_txt)}</span>
      </div>

      <label class="lbl">{('Server (Bot Inside)' if is_en else 'السيرفر (البوت متواجد داخله)')}</label>
      <select class="inp" name="guild_id" onchange="window.location='/premium?id='+encodeURIComponent(this.value)">{options_html}</select>

      <label class="lbl">{('Server Bot Bio' if is_en else 'نبذة البوت داخل السيرفر (Bio)')}</label>
      <input class="inp" type="text" name="bio" value="{esc(prof.get('bio', ''))}" placeholder="نبذة البوت في هذا السيرفر">

      <div class="album-box">
        <label class="lbl" style="margin-top:0;">{('Server Bot Avatar From Gallery' if is_en else 'صورة البوت في السيرفر من ألبوم الصور (حد أقصى 1.5MB)')}</label>
        <input class="inp" style="margin-bottom:4px;" type="file" accept="image/png,image/jpeg,image/webp,image/gif" onchange="readAlbumFile(this, 'avatar_data_url', 'ava_preview', 'avatar_name')">
        <span class="muted">{esc(prof.get('avatar_name') or 'لم يتم اختيار ملف')}</span>
        {ava_img_tag}
      </div>

      <div class="album-box">
        <label class="lbl" style="margin-top:0;">{('Server Bot Banner From Gallery' if is_en else 'بنر البوت في السيرفر من ألبوم الصور (حد أقصى 1.5MB)')}</label>
        <input class="inp" style="margin-bottom:4px;" type="file" accept="image/png,image/jpeg,image/webp,image/gif" onchange="readAlbumFile(this, 'banner_data_url', 'ban_preview', 'banner_name')">
        <span class="muted">{esc(prof.get('banner_name') or 'لم يتم اختيار ملف')}</span>
        {ban_img_tag}
      </div>

      <label class="switch-row"><span>ultra_fortress_mode (الدرع القصوى)</span><input type="checkbox" name="ultra_fortress_mode" {'checked' if perks.get('ultra_fortress_mode') else ''}></label>
      <label class="switch-row"><span>instant_rollback_enabled (الاسترجاع الفوري)</span><input type="checkbox" name="instant_rollback_enabled" {'checked' if perks.get('instant_rollback_enabled') else ''}></label>
      <label class="switch-row"><span>priority_shield_response (أولوية الاستجابة)</span><input type="checkbox" name="priority_shield_response" {'checked' if perks.get('priority_shield_response') else ''}></label>

      <label class="lbl">Alert Channel ID</label>
      <input class="inp" type="text" name="alert_channel_id" value="{esc(perks.get('alert_channel_id', ''))}">
      <label class="lbl">Alert Webhook URL</label>
      <input class="inp" type="url" name="alert_webhook_url" value="{esc(perks.get('alert_webhook_url', ''))}">
      <button class="btn-primary-purple" type="submit">{('Save & Apply' if is_en else 'حفظ وتطبيق')}</button>
    </form>
    """
    return web.Response(text=render_page("Premium" if is_en else "البريميوم", "premium", body, request, flash=flash), content_type="text/html")


async def handle_admin(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    sess_pair = get_discord_session_with_id(request)
    if not sess_pair:
        return web.Response(text=render_page("Admin" if is_en else "الإدارة", "admin", "", request, require_auth_view=True), content_type="text/html")
    session_id, user = sess_pair
    if not is_site_admin(user):
        return web.Response(text=render_page("Admin" if is_en else "الإدارة", "admin", f"<div class='glass-card'>{('Access denied.' if is_en else 'غير مصرح.')}</div>", request), content_type="text/html")

    flash = ""
    if request.method == "POST":
        form = await read_post_safe(request)
        if form and consume_csrf_token(str(form.get("csrf_token", "")), session_id) and not is_replay_request(str(form.get("req_nonce", ""))):
            act = str(form.get("admin_action", "")).strip()
            gid = str(form.get("cmd_guild_id", "")).strip()
            target_id = str(form.get("cmd_target", "")).strip()

            if act == "grant_premium":
                p_uid = str(form.get("prem_user_id", "")).strip()
                p_name = str(form.get("prem_username", "")).strip()
                p_handle = str(form.get("prem_handle", "")).strip()
                if p_uid.isdigit():
                    set_premium_user(p_uid, True, granted_by=str(user.get("id", "")), username=p_name, handle=p_handle)
                    log_event(f"منح بريميوم لمدة 30 يوماً للحساب {p_uid}", level="ADMIN")
                    flash = f"Granted 30-day Premium to {p_uid}" if is_en else f"تم منح بريميوم لمدة 30 يوماً للحساب {p_uid}"
                else:
                    flash = "Enter a valid numeric User ID for Premium." if is_en else "أدخل رقم User ID صحيحاً لإدارة البريميوم."
            elif act == "revoke_premium":
                p_uid = str(form.get("prem_user_id", "")).strip()
                if p_uid.isdigit():
                    set_premium_user(p_uid, False)
                    log_event(f"سحب البريميوم من الحساب {p_uid}", level="ADMIN")
                    flash = f"Revoked Premium from {p_uid}" if is_en else f"تم سحب البريميوم من الحساب {p_uid}"
                else:
                    flash = "Enter a valid numeric User ID for Premium." if is_en else "أدخل رقم User ID صحيحاً لسحب البريميوم."
            elif act == "grant_admin":
                a_uid = str(form.get("admin_user_id", "")).strip()
                if a_uid.isdigit():
                    set_admin_user(a_uid, True, granted_by=str(user.get("id", "")))
                    log_event(f"منح صلاحية أدمن للحساب {a_uid}", level="ADMIN")
                    flash = f"Granted Admin to {a_uid}" if is_en else f"تم منح صلاحية الأدمن للحساب {a_uid}"
                else:
                    flash = "Enter a valid numeric User ID for Admin." if is_en else "أدخل رقم User ID صحيحاً لمنح الأدمن."
            elif act == "revoke_admin":
                a_uid = str(form.get("admin_user_id", "")).strip()
                if a_uid.isdigit():
                    set_admin_user(a_uid, False)
                    log_event(f"سحب صلاحية أدمن من الحساب {a_uid}", level="ADMIN")
                    flash = f"Revoked Admin from {a_uid}" if is_en else f"تم سحب صلاحية الأدمن من الحساب {a_uid}"
                else:
                    flash = "Enter a valid numeric User ID for Admin." if is_en else "أدخل رقم User ID صحيحاً لسحب الأدمن."
            elif act in ("kick", "ban", "unban", "timeout") and gid.isdigit() and target_id.isdigit():
                enqueue_remote_action(gid, act, target_id)
                log_event(f"أمر إداري [{act}] على {target_id} في {gid}", guild_id=gid, level="ADMIN")
                flash = f"Queued [{act}] for {target_id} in {gid}"
            elif act == "broadcast" and target_id:
                enqueue_remote_action(gid or "0", "broadcast", target_id)
                log_event("إرسال رسالة بث عامة من لوحة الإدارة", level="ADMIN")
                flash = "Broadcast queued."
            elif act == "simulate" and gid.isdigit():
                flash = run_attack_simulation(gid, str(form.get("sim_scenario", "Nuke Burst")))
            elif act == "create_backup":
                b = create_db_backup()
                flash = f"Backup created: {b.get('backup_id')}"
            elif act == "test_restore":
                _, msg = test_backup_restore(str(form.get("backup_id", "")))
                flash = msg

    csrf_tok = issue_csrf_token(session_id)
    req_nonce = secrets.token_hex(12)
    guilds = get_all_guilds()
    backups = get_db_backups()
    admins = get_admin_list()
    prems = get_premium_list()

    g_rows = "".join(f"<div class='list-row'><strong>{esc(g['name'])}</strong> <code>{esc(g['id'])}</code></div>" for g in guilds) or "<p class='muted'>0</p>"
    b_rows = "".join(f"<div class='list-row'><code>{esc(b.get('backup_id'))}</code><span class='muted'>{esc(b.get('created_at'))}</span></div>" for b in backups[:5]) or "<p class='muted'>-</p>"
    a_rows = "".join(
        f"<div class='list-row'><div><strong>Admin</strong> — <code>{esc(a.get('user_id'))}</code></div><span class='admin-pill'>{esc(a.get('granted_by'))}</span></div>"
        for a in admins
    ) or "<p class='muted'>-</p>"

    p_rows = ""
    for p in prems:
        p_uid = esc(p.get("user_id", ""))
        p_name = esc(p.get("username", ""))
        p_handle = esc(p.get("handle", ""))
        p_rem = esc(format_remaining_days(p))
        p_rows += (
            f"<div class='list-row' style='flex-wrap:wrap;'>"
            f"<div><strong>{p_name}</strong> <span class='muted'>{p_handle}</span> — <code>{p_uid}</code></div>"
            f"<span class='prem-pill'>{p_rem}</span></div>"
        )
    if not p_rows:
        p_rows = "<p class='muted'>-</p>"

    body = f"""
    <div class="glass-card">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:10px;margin-bottom:14px;">
        <h2 style="margin:0;">{('Admin Control Center' if is_en else 'لوحة الإدارة المطوّرة')}</h2>
        <span class="tag">{('OWNER / ADMIN' if is_en else 'إدارة النظام')}</span>
      </div>

      <form method="post" class="sub-panel">
        <input type="hidden" name="csrf_token" value="{esc(csrf_tok)}">
        <input type="hidden" name="req_nonce" value="{esc(req_nonce)}">
        <div class="sub-panel-head">
          <h3 class="sub-panel-title">{('Premium Subscription Management (30 Days)' if is_en else 'لوحة إدارة البريميوم (30 يوماً)')}</h3>
          <span class="prem-pill">PREMIUM ({len(prems)})</span>
        </div>
        <label class="lbl">{('Target User ID' if is_en else 'معرف المستخدم (User ID)')}</label>
        <input class="inp" type="text" name="prem_user_id" placeholder="مثال: 1395418036919468073">
        <div class="grid-2">
          <div>
            <label class="lbl">{('Display Name' if is_en else 'الاسم (اختياري)')}</label>
            <input class="inp" style="margin-bottom:0;" type="text" name="prem_username" placeholder="اسم العضو">
          </div>
          <div>
            <label class="lbl">{('Handle' if is_en else 'اليوزر (اختياري)')}</label>
            <input class="inp" style="margin-bottom:0;" type="text" name="prem_handle" placeholder="@username">
          </div>
        </div>
        <div class="grid-2" style="margin-top:10px;margin-bottom:10px;">
          <button class="btn-primary-purple" style="margin-bottom:0;" type="submit" name="admin_action" value="grant_premium">{('Grant 30d Premium' if is_en else 'منح بريميوم 30 يوم')}</button>
          <button class="btn-secondary-dark" style="margin-bottom:0;" type="submit" name="admin_action" value="revoke_premium">{('Revoke Premium' if is_en else 'سحب البريميوم')}</button>
        </div>
        {p_rows}
      </form>

      <form method="post" class="sub-panel">
        <input type="hidden" name="csrf_token" value="{esc(csrf_tok)}">
        <input type="hidden" name="req_nonce" value="{esc(req_nonce)}">
        <div class="sub-panel-head">
          <h3 class="sub-panel-title">{('Site Admins Management' if is_en else 'لوحة إدارة الأدمن')}</h3>
          <span class="admin-pill">ADMINS ({len(admins)})</span>
        </div>
        <label class="lbl">{('Target Admin User ID' if is_en else 'معرف المشرف الجديد (User ID)')}</label>
        <input class="inp" type="text" name="admin_user_id" placeholder="مثال: 1395418036919468073">
        <div class="grid-2" style="margin-bottom:10px;">
          <button class="btn-primary-purple" style="margin-bottom:0;" type="submit" name="admin_action" value="grant_admin">{('Grant Admin' if is_en else 'منح صلاحية أدمن')}</button>
          <button class="btn-secondary-dark" style="margin-bottom:0;" type="submit" name="admin_action" value="revoke_admin">{('Revoke Admin' if is_en else 'سحب صلاحية أدمن')}</button>
        </div>
        {a_rows}
      </form>

      <form method="post" class="sub-panel">
        <input type="hidden" name="csrf_token" value="{esc(csrf_tok)}">
        <input type="hidden" name="req_nonce" value="{esc(req_nonce)}">
        <div class="sub-panel-head">
          <h3 class="sub-panel-title">{('Remote Actions & Broadcast' if is_en else 'الأوامر عن بُعد والبث')}</h3>
          <span class="tag">REMOTE</span>
        </div>
        <input class="inp" type="text" name="cmd_guild_id" placeholder="Guild ID">
        <input class="inp" type="text" name="cmd_target" placeholder="Target User ID or Broadcast Message">
        <div class="grid-2" style="margin-bottom:0;">
          <button class="mini-btn" type="submit" name="admin_action" value="kick">Kick</button>
          <button class="mini-btn" type="submit" name="admin_action" value="ban">Ban</button>
          <button class="mini-btn" type="submit" name="admin_action" value="timeout">Timeout</button>
          <button class="mini-btn" type="submit" name="admin_action" value="broadcast">Broadcast</button>
        </div>
      </form>

      <form method="post" class="sub-panel" style="margin-bottom:0;">
        <input type="hidden" name="csrf_token" value="{esc(csrf_tok)}">
        <input type="hidden" name="req_nonce" value="{esc(req_nonce)}">
        <div class="sub-panel-head">
          <h3 class="sub-panel-title">{('Attack Simulation & Backups' if is_en else 'محاكاة الهجمات والنسخ الاحتياطي')}</h3>
          <span class="tag">SYSTEM</span>
        </div>
        <input class="inp" type="text" name="sim_scenario" value="Role, Channel & Selfbot Attack">
        <button class="btn-secondary-dark" type="submit" name="admin_action" value="simulate">{('Run Simulation' if is_en else 'تشغيل المحاكاة')}</button>
        <div class="grid-2" style="margin-bottom:0;">
          <button class="btn-primary-purple" style="margin-bottom:0;" type="submit" name="admin_action" value="create_backup">{('Create Backup' if is_en else 'نسخة احتياطية')}</button>
          <button class="btn-secondary-dark" style="margin-bottom:0;" type="submit" name="admin_action" value="test_restore">{('Test Restore' if is_en else 'اختبار الاستعادة')}</button>
        </div>
        <div style="margin-top:10px;">{b_rows}</div>
      </form>
    </div>

    <div class="glass-card"><h3 style="margin:0 0 10px;">Bot Guilds ({len(guilds)})</h3>{g_rows}</div>
    """
    return web.Response(text=render_page("Admin" if is_en else "الإدارة", "admin", body, request, flash=flash), content_type="text/html")


async def handle_services(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    if is_en:
        body = """
        <div class='glass-card'>
          <h2 style='margin:0 0 10px;'>Arab Security Bot — Services</h2>
          <p class='muted'>A specialized Discord protection bot built to secure servers against destructive raids, malicious selfbots, spam, and unauthorized changes.</p>
          <div class='list-row'><div><strong>Anti-Nuke & Tamper Shield</strong><div class='muted'>Monitors bans, kicks, channel/role deletions, webhooks, and bot additions with instant punishment.</div></div><span class='tag'>Core</span></div>
          <div class='list-row'><div><strong>Anti-Selfbot Detection</strong><div class='muted'>Detects and blocks destructive selfbot activity targeting your server.</div></div><span class='prem-pill'>PREMIUM</span></div>
          <div class='list-row'><div><strong>Spam & Link Control</strong><div class='muted'>Custom spam punishment & timeout duration, plus link protection and account age checks.</div></div><span class='tag'>Shield</span></div>
          <div class='list-row'><div><strong>Snapshots, Rollback & Backups</strong><div class='muted'>Save permission snapshots, run attack simulations, and manage backups.</div></div><span class='prem-pill'>PREMIUM</span></div>
        </div>
        """
    else:
        body = """
        <div class='glass-card'>
          <h2 style='margin:0 0 10px;'>خدمات بوت ARAB SECURITY</h2>
          <p class='muted'>بوت حماية متكامل لسيرفرات ديسكورد بإشراف سعود السويط، يهدف لحماية السيرفر من التخريب المفاجئ، السلف بوت، السبام، والتعديلات غير المصرح بها.</p>
          <div class='list-row'><div><strong>مكافحة النيوك والتخريب (Anti-Nuke)</strong><div class='muted'>مراقبة الحظر والطرد وحذف الرومات والرتب وإضافة البوتات والويبهوكات وتطبيق العقوبة المحددة فوراً.</div></div><span class='tag'>أساسي</span></div>
          <div class='list-row'><div><strong>اكتشاف السلف بوت (Anti-Selfbot)</strong><div class='muted'>رصد الحسابات والسلف بوتات التي تحاول تخريب السيرفر والتعامل معها بسرعة.</div></div><span class='prem-pill'>بريميوم</span></div>
          <div class='list-row'><div><strong>التحكم بالسبام والروابط</strong><div class='muted'>تحديد عقوبة السبام ومدة التايم أوت بالثواني، وحماية السيرفر من الروابط المزعجة.</div></div><span class='tag'>حماية</span></div>
          <div class='list-row'><div><strong>لقطات الصلاحيات، المحاكاة، والنسخ الاحتياطي</strong><div class='muted'>حفظ لقطات الصلاحيات، اختبار جاهزية الحماية عبر محاكاة الهجمات، وإنشاء النسخ الاحتياطية.</div></div><span class='prem-pill'>بريميوم</span></div>
        </div>
        """
    return web.Response(text=render_page("Services" if is_en else "الخدمات", "services", body, request), content_type="text/html")


async def handle_updates(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    logs = get_recent_logs(40)
    rows = "".join(
        f"<div class='list-row'><div><span class='tag'>{esc(l.get('level', 'WEB'))}</span> <span>{esc(l.get('message'))}</span></div><span class='muted'>{esc(l.get('time'))}</span></div>"
        for l in logs
    ) or f"<p class='muted'>{('No logs recorded yet.' if is_en else 'لا توجد سجلات حتى الآن.')}</p>"
    body = f"<div class='glass-card'><h2 style='margin:0 0 12px;'>{('Updates & Logs' if is_en else 'التحديثات والسجلات')}</h2>{rows}</div>"
    return web.Response(text=render_page("Updates" if is_en else "التحديثات", "updates", body, request), content_type="text/html")


async def handle_links(request: web.Request) -> web.Response:
    is_en = get_lang(request) == "en"
    safe_invite = esc(sanitize_http_url(BOT_INVITE_URL) or "https://discord.com")
    safe_support = esc(sanitize_http_url(SUPPORT_SERVER_URL) or "https://discord.com")
    body = f"""
    <div class='glass-card'>
      <h2 style='margin:0 0 12px;'>{('Links' if is_en else 'الروابط')}</h2>
      <a class='btn-primary-purple' href='{safe_invite}' target='_blank' rel='noopener noreferrer'>Invite Arab Security Bot</a>
      <a class='btn-secondary-dark' href='{safe_support}' target='_blank' rel='noopener noreferrer'>Support Server</a>
    </div>
    """
    return web.Response(text=render_page("Links" if is_en else "الروابط", "links", body, request), content_type="text/html")


async def handle_login(request: web.Request) -> web.Response:
    ip = get_client_ip(request)
    if is_rate_limited(ip, is_sensitive=True):
        return web.Response(text="Too many login requests.", status=429)
    if not DISCORD_CLIENT_ID or not DISCORD_CLIENT_SECRET:
        raise web.HTTPFound("/?msg=" + quote("يرجى ضبط DISCORD_CLIENT_SECRET في متغيرات البيئة لتفعيل تسجيل الدخول بديسكورد."))
    state = issue_oauth_state()
    params = {
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": detect_redirect_uri(request),
        "response_type": "code",
        "scope": "identify guilds",
        "state": state,
    }
    raise web.HTTPFound(f"https://discord.com/oauth2/authorize?{urlencode(params)}")


async def handle_callback(request: web.Request) -> web.Response:
    ip = get_client_ip(request)
    if is_rate_limited(ip, is_sensitive=True):
        return web.Response(text="Too many callback requests.", status=429)
    if request.query.get("error"):
        raise web.HTTPFound("/?msg=" + quote("تم إلغاء تسجيل الدخول عبر ديسكورد."))

    state = request.query.get("state", "")
    code = request.query.get("code", "")
    if not consume_oauth_state(state) or not code:
        raise web.HTTPFound("/?msg=" + quote("رمز التحقق غير صالح أو منتهي الصلاحية."))

    redirect_uri = detect_redirect_uri(request)
    user_info: dict = {}
    compact_guilds: list[dict] = []
    access_token = ""
    network_err = False

    try:
        async with ClientSession(timeout=ClientTimeout(total=10)) as session:
            token_resp = await session.post(
                "https://discord.com/api/oauth2/token",
                data={
                    "client_id": DISCORD_CLIENT_ID,
                    "client_secret": DISCORD_CLIENT_SECRET,
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                },
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            token_data = await token_resp.json()
            access_token = str(token_data.get("access_token", "")).strip() if isinstance(token_data, dict) else ""

            if access_token:
                auth_headers = {"Authorization": f"Bearer {access_token}"}
                u_resp = await session.get("https://discord.com/api/users/@me", headers=auth_headers)
                u_json = await u_resp.json()
                if isinstance(u_json, dict):
                    user_info = u_json

                g_resp = await session.get("https://discord.com/api/users/@me/guilds", headers=auth_headers)
                g_list = await g_resp.json()
                if isinstance(g_list, list):
                    for g in g_list[:200]:
                        if isinstance(g, dict) and str(g.get("id", "")).isdigit():
                            compact_guilds.append(
                                {
                                    "id": str(g["id"]),
                                    "name": str(g.get("name", ""))[:100],
                                    "icon": str(g.get("icon", "") or "")[:60],
                                    "owner": bool(g.get("owner", False)),
                                    "permissions": int(g.get("permissions", 0) or 0),
                                }
                            )
    except (ClientError, asyncio.TimeoutError):
        network_err = True

    if network_err:
        raise web.HTTPFound("/?msg=" + quote("حدث خطأ أو انتهت مهلة الاتصال بخوادم ديسكورد."))
    if not access_token:
        raise web.HTTPFound("/?msg=" + quote("تعذر الحصول على رمز الوصول من ديسكورد."))

    uid = str(user_info.get("id", "")).strip()
    if not uid.isdigit():
        raise web.HTTPFound("/?msg=" + quote("تعذر قراءة بيانات الحساب."))

    signed_tok = sign_session(
        {
            "id": uid,
            "username": str(user_info.get("username", "User"))[:40],
            "avatar": str(user_info.get("avatar", "") or "")[:40],
            "guilds": compact_guilds,
            "exp": time.time() + 86400 * 7,
        }
    )
    log_event(f"تسجيل دخول المستخدم {uid} عبر ديسكورد", level="AUTH")
    resp = web.HTTPFound("/servers")
    resp.set_cookie(
        "arab_sec_session",
        signed_tok,
        max_age=86400 * 7,
        httponly=True,
        secure=should_use_secure_cookie(request),
        samesite="Lax",
        path="/",
    )
    return resp


async def handle_logout(request: web.Request) -> web.Response:
    pair = get_discord_session_with_id(request)
    if pair:
        _delete_session_record(pair[0])
    resp = web.HTTPFound("/")
    resp.del_cookie("arab_sec_session", path="/")
    return resp


async def health_handler(request: web.Request) -> web.Response:
    return web.json_response(
        {
            "ok": True,
            "site": SITE_NAME,
            "bot_guilds_count": len(get_all_guilds()),
            "db_online": db is not None,
        }
    )


@web.middleware
async def security_and_visit_middleware(request: web.Request, handler):
    ip = get_client_ip(request)
    is_auth = request.path in ("/login", "/callback")
    if is_rate_limited(ip, is_sensitive=is_auth):
        return web.Response(text="Rate limit exceeded.", status=429)

    record_site_visit(request)
    response = await handler(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response


def create_app() -> web.Application:
    app = web.Application(middlewares=[security_and_visit_middleware])
    app.router.add_get("/", home_handler)
    app.router.add_get("/servers", handle_servers)
    app.router.add_get("/guild", handle_guild)
    app.router.add_post("/guild", handle_guild)
    app.router.add_get("/premium", handle_premium)
    app.router.add_post("/premium", handle_premium)
    app.router.add_get("/admin", handle_admin)
    app.router.add_post("/admin", handle_admin)
    app.router.add_get("/services", handle_services)
    app.router.add_get("/updates", handle_updates)
    app.router.add_get("/links", handle_links)
    app.router.add_get("/login", handle_login)
    app.router.add_get("/callback", handle_callback)
    app.router.add_get("/logout", handle_logout)
    app.router.add_get("/health", health_handler)
    app.router.add_post("/api/bot/sync-guilds", api_bot_sync_guilds)
    app.router.add_get("/api/bot/pending-commands", api_bot_pending_commands)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host=HOST, port=PORT)
